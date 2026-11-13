# -*- coding: utf-8 -*-
"""llm-gw: the LLM door for people and agents outside the bot (agent CLI, analysts over VPN).

Owner, 12-13.10.2026: «щоб не пішло по руках» and «щоб не було так що всі полізуть юзати і він ляже».
Before: VM :1234 was a bare TCP relay (systemd-socket-proxyd) to the rig's llama-swap - any VPN
client could use every model with no key, and a Agent request for a model that was not loaded
evicted the model a CLIENT analysis was using in the middle of its report.

Now (VM host network, :1234, OpenAI-compatible, streams pass through):
  * personal keys (Authorization: Bearer llm_...), sha256-only in keys.json, per-key model list,
    concurrency limit and daily token budget; keyless only from GRACE_IPS / while GRACE_ALL is on
  * priority: while a client DFIR analysis is running (dfir_run_jobs_v2), a request for a model
    that is NOT currently loaded in llama-swap waits (it would evict the analysis' model); loaded
    models are served at once. Waiting is bounded (HOLD_MAX_S) and ends with a clear 503.
  * every request -> requests.jsonl (who, ip, model, status, ms, tokens); /gw/status for admins
The bot itself does NOT go through here (it talks to 192.168.100.1:1234 directly), so this cannot
slow a client analysis down.
"""
import asyncio
import hashlib
import json
import os
import time

import aiohttp
from aiohttp import web
import psycopg

UPSTREAM = os.environ.get('UPSTREAM', 'http://192.168.100.1:1234')
LISTEN = int(os.environ.get('LISTEN_PORT', '1234'))
STATE = os.environ.get('STATE_DIR', '/data')
KEYS = os.path.join(STATE, 'keys.json')
LOG = os.path.join(STATE, 'requests.jsonl')
CONF = os.path.join(STATE, 'gw.json')            # {"grace_all": bool, "grace_ips": [...], "hold_max_s": int}
PG_DSN = os.environ.get('PG_DSN', '')
POLL = 10

_inflight = {}            # key name -> count
_usage = {}               # (key name, yyyy-mm-dd) -> tokens
_waiting = []             # [(name, model, since)]


def _conf():
    try:
        return json.load(open(CONF, encoding='utf-8'))
    except Exception:
        return {}


def _keys():
    try:
        return json.load(open(KEYS, encoding='utf-8'))
    except Exception:
        return {}


def _log(rec):
    try:
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:
        pass


def _ident(request):
    raw = request.headers.get('Authorization', '')
    tok = raw[7:].strip() if raw.lower().startswith('bearer ') else ''
    ip = request.remote or ''
    if tok:
        k = _keys().get(hashlib.sha256(tok.encode()).hexdigest())
        if k and not k.get('disabled'):
            return dict(k, ip=ip)
    c = _conf()
    if c.get('grace_all') or ip in (c.get('grace_ips') or []):
        # transition: Agent on agent-vm still sends a dummy key ('local'); logged so we see who it is
        return {'name': 'keyless@' + ip, 'models': '*', 'max_concurrent': 2, 'daily_tokens': 0, 'ip': ip,
                'keyless': True}
    return None


async def _running_models(session):
    try:
        async with session.get(UPSTREAM + '/running', timeout=aiohttp.ClientTimeout(total=5)) as r:
            d = await r.json(content_type=None)
            return {m.get('model') for m in d.get('running', []) if m.get('state') in ('ready', 'starting')}
    except Exception:
        return None


_DB_ERR_AT = [0.0]


def _client_job_running():
    if not PG_DSN:
        return False
    try:
        with psycopg.connect(PG_DSN, connect_timeout=5) as c:
            n = c.execute("SELECT count(*) FROM dfir_run_jobs_v2 WHERE status IN ('running','queued')").fetchone()[0]
            return n > 0
    except Exception as e:
        # 22-23.10.2026: the dfir_mcp password went stale for 32 h and this returned False on
        # every call - the guard that keeps a client analysis's model loaded was off, silently.
        # Still fail-open (a DB problem must not block the gateway), but now it says so.
        if time.time() - _DB_ERR_AT[0] > 600:
            _DB_ERR_AT[0] = time.time()
            print('[llm-gw] DB check failed, eviction guard is OFF until it recovers: %r' % (e,), flush=True)
        return False


async def _aliases(session):
    """alias -> canonical model id (llama-swap answers the canonical id in /running)."""
    try:
        async with session.get(UPSTREAM + '/v1/models', timeout=aiohttp.ClientTimeout(total=5)) as r:
            d = await r.json(content_type=None)
        out = {}
        for m in d.get('data', []):
            out[m['id']] = m['id']
            for a in (m.get('aliases') or []):
                out[a] = m['id']
        return out
    except Exception:
        return {}


async def _wait_turn(request, who, model):
    """Hold a request whose model would evict the one a client analysis is using."""
    hold_max = int(_conf().get('hold_max_s', 1800))
    t0 = time.time()
    session = request.app['session']
    canon = (await _aliases(session)).get(model, model)
    entry = (who['name'], canon, t0)
    try:
        while True:
            if not await asyncio.to_thread(_client_job_running):
                return None
            run = await _running_models(session)
            if run is None or canon in run:
                return None
            if entry not in _waiting:
                _waiting.append(entry)
            if time.time() - t0 > hold_max:
                return ('Модель %s зараз недоступна: іде аналіз справи клієнта, і її завантаження '
                        'вивантажило б модель аналізу. Спробуйте за кілька хвилин або візьміть модель, '
                        'яка вже завантажена: %s' % (model, ', '.join(sorted(run)) or '—'))
            await asyncio.sleep(POLL)
    finally:
        if entry in _waiting:
            _waiting.remove(entry)


def _err(status, msg):
    return web.json_response({'error': {'message': msg, 'type': 'gateway'}}, status=status)


async def proxy(request):
    t0 = time.time()
    who = _ident(request)
    if not who:
        return _err(401, 'API key required: Authorization: Bearer <key> (ask the DFIR admin)')
    path = request.path_qs
    body = await request.read() if request.can_read_body else b''
    model, stream = '', False
    if body:
        try:
            j = json.loads(body)
            model, stream = str(j.get('model') or ''), bool(j.get('stream'))
        except Exception:
            pass
    rec = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S'), 'who': who['name'], 'ip': who['ip'], 'path': request.path,
           'model': model, 'stream': stream}
    allowed = who.get('models', '*')
    if model and allowed != '*' and model not in allowed:
        rec.update(status=403, ms=0); _log(rec)
        return _err(403, 'model %s is not allowed for this key' % model)
    day = time.strftime('%Y-%m-%d')
    budget = int(who.get('daily_tokens') or 0)
    if budget and _usage.get((who['name'], day), 0) >= budget:
        rec.update(status=429, ms=0); _log(rec)
        return _err(429, 'daily token budget of this key is used up')
    if _inflight.get(who['name'], 0) >= int(who.get('max_concurrent') or 2):
        rec.update(status=429, ms=0); _log(rec)
        return _err(429, 'too many parallel requests for this key; wait for the previous answer')
    if model and request.method == 'POST':
        msg = await _wait_turn(request, who, model)
        rec['held_s'] = round(time.time() - t0)
        if msg:
            rec.update(status=503, ms=int((time.time() - t0) * 1000)); _log(rec)
            return _err(503, msg)
    _inflight[who['name']] = _inflight.get(who['name'], 0) + 1
    hdrs = {k: v for k, v in request.headers.items()
            if k.lower() in ('content-type', 'accept', 'user-agent')}
    tokens = None
    resp = None
    try:
        session = request.app['session']
        async with session.request(request.method, UPSTREAM + path, data=body or None, headers=hdrs,
                                   timeout=aiohttp.ClientTimeout(total=None, sock_read=3600)) as up:
            resp = web.StreamResponse(status=up.status, headers={
                'Content-Type': up.headers.get('Content-Type', 'application/json')})
            await resp.prepare(request)
            rec['status'] = up.status
            tail = b''
            async for chunk in up.content.iter_any():
                await resp.write(chunk)
                tail = (tail + chunk)[-8192:]
            await resp.write_eof()
            rec['status'] = up.status
            # usage: non-stream JSON or the last SSE chunk that carries it
            for part in reversed(tail.replace(b'data: ', b'\n').split(b'\n')):
                part = part.strip()
                if part.startswith(b'{') and b'"usage"' in part:
                    try:
                        u = json.loads(part).get('usage') or {}
                        tokens = int(u.get('total_tokens') or 0)
                        rec['prompt_tokens'], rec['completion_tokens'] = u.get('prompt_tokens'), u.get('completion_tokens')
                    except Exception:
                        pass
                    break
            return resp
    except Exception as e:
        if resp is not None and resp.prepared:
            # the answer was already flowing: the CLIENT went away (Agent closes the stream right
            # after [DONE]) - not an upstream failure, and a second response cannot be sent anyway
            rec['client_closed'] = str(e)[:120]
            return resp
        rec['status'] = 502
        rec['error'] = str(e)[:200]
        return _err(502, 'upstream LLM error: %s' % str(e)[:200])
    finally:
        _inflight[who['name']] -= 1
        if tokens:
            _usage[(who['name'], day)] = _usage.get((who['name'], day), 0) + tokens
        rec['ms'] = int((time.time() - t0) * 1000)
        _log(rec)


async def status(request):
    who = _ident(request)
    if not who or not who.get('admin'):
        return _err(403, 'admin key required')
    return web.json_response({'inflight': _inflight, 'waiting': [list(w) for w in _waiting],
                              'usage_today': {k[0]: v for k, v in _usage.items() if k[1] == time.strftime('%Y-%m-%d')},
                              'client_job_running': await asyncio.to_thread(_client_job_running),
                              'grace': _conf()})


async def health(request):
    return web.json_response({'ok': True, 'service': 'llm-gw'})


async def _start(app):
    app['session'] = aiohttp.ClientSession()


async def _stop(app):
    await app['session'].close()


def main():
    app = web.Application(client_max_size=64 * 1024 * 1024)
    app.on_startup.append(_start)
    app.on_cleanup.append(_stop)
    app.router.add_get('/health', health)
    app.router.add_get('/gw/status', status)
    app.router.add_route('*', '/{tail:.*}', proxy)
    web.run_app(app, host='0.0.0.0', port=LISTEN, access_log=None)


if __name__ == '__main__':
    main()
