#!/usr/bin/env python3
"""LLM router: the bot keeps calling its own model names (gpt-small-20b, reasoner-31b, big-120b...),
this maps each name onto a model of any OpenAI-compatible server or cloud provider.

  ROUTER_CONFIG=/config/router.json python3 router.py

router.json (written by install.sh / `dfir llm`):
  {"listen": "172.17.0.1:1234",
   "upstreams": {"main": {"base_url": "https://api.openai.com/v1", "api_key": "sk-...", "kind": "openai"}},
   "models": {"gpt-small-20b": {"upstream": "main", "model": "gpt-5-mini"}, ...}}

Standard library only. Behaviour the bot relies on:
  * /v1/chat/completions and /v1/completions, streaming passed through as it arrives;
  * llama.cpp-only parameters are dropped; a 400 that names a parameter drops it and retries;
  * /v1/models lists the bot's names; /running answers like llama-swap (nothing to unload in a cloud).
The config file is re-read when it changes, so `dfir llm` switches models without a restart.
"""
import json
import os
import re
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = os.environ.get('ROUTER_CONFIG', '/config/router.json')
STD = {'model', 'messages', 'prompt', 'temperature', 'top_p', 'max_tokens', 'max_completion_tokens', 'stream',
       'stream_options', 'stop', 'tools', 'tool_choice', 'parallel_tool_calls', 'response_format', 'seed', 'n',
       'presence_penalty', 'frequency_penalty', 'logprobs', 'top_logprobs', 'user', 'reasoning_effort'}
_cfg = {'mtime': None, 'data': None}
_lock = threading.Lock()


def config():
    with _lock:
        m = os.path.getmtime(CONFIG)
        if m != _cfg['mtime']:
            _cfg['data'] = json.load(open(CONFIG, encoding='utf-8'))
            _cfg['mtime'] = m
        return _cfg['data']


def resolve(name):
    cfg = config()
    models = cfg['models']
    m = models.get(name) or models.get(cfg.get('default', '')) or next(iter(models.values()))
    return m, cfg['upstreams'][m['upstream']]


def shape(body, up):
    out = {k: v for k, v in body.items() if k in STD}
    kind = up.get('kind', 'openai')
    if kind == 'openai' and 'max_tokens' in out:
        # newer OpenAI models refuse max_tokens; max_completion_tokens is accepted by all current ones
        out['max_completion_tokens'] = out.pop('max_tokens')
    if kind not in ('openai', 'openrouter', 'groq') :
        out.pop('reasoning_effort', None)
    return out


def call(path, body, up):
    req = urllib.request.Request(up['base_url'].rstrip('/') + path, data=json.dumps(body).encode(), method='POST')
    req.add_header('Content-Type', 'application/json')
    auth(req, up)
    return urllib.request.urlopen(req, timeout=float(up.get('timeout', 900)))


def auth(req, up):
    # every request to the upstream carries its key: the Host Agent answers 401 without the token
    # (passthrough GET /v1/models and /running went out bare - T7 wizard test 11.11)
    if up.get('api_key'):
        req.add_header('Authorization', 'Bearer ' + up['api_key'])
    for k, v in (up.get('headers') or {}).items():
        req.add_header(k, v)
    return req


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *a):
        sys.stderr.write('%s %s\n' % (self.address_string(), fmt % a))

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split('?')[0]
        if p in ('/health', '/healthz'):
            return self._json(200, {'status': 'ok'})
        up = self._passthrough()
        if up:
            return self._forward_get(up)
        if p == '/running':
            return self._json(200, {'running': []})
        if p in ('/v1/models', '/models'):
            names = sorted(config()['models'])
            return self._json(200, {'object': 'list', 'data': [{'id': n, 'object': 'model', 'owned_by': 'dfir-router'} for n in names]})
        return self._json(404, {'error': 'not found'})

    def _passthrough(self):
        # own llama-swap that already serves every bot name: forward everything as is (/running, /unload...)
        ups = config()['upstreams']
        up = ups.get('main') or next(iter(ups.values()))
        return up if up.get('passthrough') else None

    def _forward_get(self, up):
        root = up['base_url'].rstrip('/')
        root = root[:-3] if root.endswith('/v1') else root
        try:
            r = urllib.request.urlopen(auth(urllib.request.Request(root + self.path), up), timeout=30)
            code, data, ctype = r.status, r.read(), r.headers.get('Content-Type', 'application/json')
        except urllib.error.HTTPError as e:
            code, data, ctype = e.code, e.read(), 'application/json'
        except (urllib.error.URLError, socket.timeout) as e:
            return self._json(502, {'error': 'upstream unreachable: %s' % e})
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _forward_post(self, up, p, body):
        root = up['base_url'].rstrip('/')
        root = root[:-3] if root.endswith('/v1') else root
        req = urllib.request.Request(root + self.path, data=json.dumps(body).encode(), method='POST')
        req.add_header('Content-Type', 'application/json')
        auth(req, up)
        try:
            r = urllib.request.urlopen(req, timeout=900)
            code, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, data = e.code, e.read()
        except (urllib.error.URLError, socket.timeout) as e:
            return self._json(502, {'error': 'upstream unreachable: %s' % e})
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        p = self.path.split('?')[0]
        n = int(self.headers.get('Content-Length') or 0)
        try:
            body = json.loads(self.rfile.read(n) or b'{}')
        except ValueError:
            return self._json(400, {'error': 'bad json'})
        up0 = self._passthrough()
        if p == '/unload' and not up0:
            return self._json(200, {'status': 'ok'})
        if up0 and p not in ('/v1/chat/completions', '/v1/completions'):
            return self._forward_post(up0, p, body)
        if p not in ('/v1/chat/completions', '/v1/completions', '/chat/completions', '/completions'):
            return self._json(404, {'error': 'not found'})
        path = '/chat/completions' if 'chat' in p else '/completions'
        asked = body.get('model', '')
        try:
            m, up = resolve(asked)
        except Exception as e:
            return self._json(500, {'error': 'router config: %s' % e})
        if up.get('passthrough'):
            out = dict(body)
            out['model'] = m['model']
        else:
            out = shape(body, up)
            out['model'] = m['model']
        for k, v in (m.get('params') or {}).items():
            out.setdefault(k, v)
        for _ in range(4):
            try:
                r = call(path, out, up)
                break
            except urllib.error.HTTPError as e:
                err = e.read().decode('utf-8', 'replace')
                # "Unsupported parameter: 'temperature'" and similar: drop it and try again
                bad = [k for k in list(out) if k not in ('model', 'messages', 'prompt') and
                       re.search(r"\b%s\b" % re.escape(k), err) and re.search(r'unsupport|not support|unrecogni|unknown|extra|invalid', err, re.I)]
                if e.code in (400, 404) and m.get('fallback') and out.get('model') != m['fallback'] and 'model' in err.lower():
                    out['model'] = m['fallback']
                    continue
                if e.code == 400 and bad:
                    for k in bad:
                        out.pop(k, None)
                    sys.stderr.write('dropped %s for %s\n' % (bad, m['model']))
                    continue
                return self._json(e.code, {'error': {'message': err[:2000], 'upstream_model': m['model']}})
            except (urllib.error.URLError, socket.timeout) as e:
                return self._json(502, {'error': {'message': 'upstream unreachable: %s' % e}})
        else:
            return self._json(400, {'error': 'parameters rejected by upstream'})
        self.send_response(r.status)
        stream = bool(out.get('stream'))
        self.send_header('Content-Type', r.headers.get('Content-Type', 'application/json'))
        if stream:
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            try:
                while True:
                    chunk = r.read1(65536) if hasattr(r, 'read1') else r.read(4096)
                    if not chunk:
                        break
                    self.wfile.write(b'%x\r\n%s\r\n' % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b'0\r\n\r\n')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        data = r.read()
        try:
            # answer under the name the bot asked for, so its logs and checks stay unchanged
            obj = json.loads(data)
            obj['model'] = asked or obj.get('model')
            data = json.dumps(obj).encode()
        except ValueError:
            pass
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    host, _, port = config().get('listen', '0.0.0.0:1234').rpartition(':')
    srv = ThreadingHTTPServer((host or '0.0.0.0', int(port)), H)
    srv.daemon_threads = True
    print('dfir llm-router on %s:%s, %d names' % (host, port, len(config()['models'])), flush=True)
    srv.serve_forever()


if __name__ == '__main__':
    main()
