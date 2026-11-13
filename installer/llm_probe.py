#!/usr/bin/env python3
"""LLM helpers for install.sh and `dfir llm` (standard library only).

  llm_probe.py providers                      provider table: id|base_url|kind|fast|reasoner|big|key_page
  llm_probe.py models BASE_URL                model ids, one per line (key from $LLM_API_KEY)
  llm_probe.py test BASE_URL MODEL            one short chat request, prints seconds
  llm_probe.py has-all BASE_URL               exit 0 when the server already serves every name the bot calls
  llm_probe.py pick BASE_URL ROLE PREFERRED   best available model for a role (PREFERRED if present)
  llm_probe.py bench BASE_URL MODEL...        per model: seconds|tokens/s|DFIR check (pass/miss)|model
  llm_probe.py find-host                      print the host AI agent address (VM gateway :1234) if it answers
  llm_probe.py is-agent BASE_URL              exit 0 when BASE_URL is the DFIR VAO Host Agent (wants a token)
  llm_probe.py router OUT_JSON BASE_URL KIND FAST REASONER BIG LISTEN
                                              router.json mapping every bot name onto FAST/REASONER/BIG
                                              (KIND=llama-swap: forward everything unchanged)
"""
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_llm_stack as g  # noqa: E402  (the names the bot calls live there)

ROLE_NAMES = {
    'fast': ['gpt-small-20b'] + g.CHAT_NAMES,
    'reasoner': ['reasoner-31b'] + g.REASONER_NAMES,
    'big': ['big-120b'] + g.BIG_NAMES,
}
# Suggestions only: the installer lists the provider's real models and lets the person choose.
PROVIDERS = [
    ('openai', 'https://api.openai.com/v1', 'openai', 'gpt-5-mini', 'gpt-5', 'gpt-5', 'https://platform.openai.com/api-keys'),
    ('anthropic', 'https://api.anthropic.com/v1', 'anthropic', 'claude-haiku-5-5', 'claude-sonnet-5-5', 'claude-opus-5-5',
     'https://console.anthropic.com/settings/keys'),
    ('gemini', 'https://generativelanguage.googleapis.com/v1beta/openai', 'gemini', 'gemini-2.5-flash', 'gemini-2.5-pro',
     'gemini-2.5-pro', 'https://aistudio.google.com/apikey'),
    ('openrouter', 'https://openrouter.ai/api/v1', 'openrouter', 'openai/gpt-oss-20b', 'openai/gpt-oss-120b',
     'openai/gpt-oss-120b', 'https://openrouter.ai/keys'),
    ('groq', 'https://api.groq.com/openai/v1', 'groq', 'openai/gpt-oss-20b', 'openai/gpt-oss-120b', 'openai/gpt-oss-120b',
     'https://console.groq.com/keys'),
    ('mistral', 'https://api.mistral.ai/v1', 'mistral', 'mistral-small-latest', 'mistral-medium-latest',
     'mistral-large-latest', 'https://console.mistral.ai/api-keys'),
    ('deepseek', 'https://api.deepseek.com/v1', 'deepseek', 'deepseek-chat', 'deepseek-reasoner', 'deepseek-reasoner',
     'https://platform.deepseek.com/api_keys'),
]
ROLE_HINT = {'fast': ('mini', 'flash', 'haiku', 'small', '20b', 'chat', '8b', '9b'),
             'reasoner': ('pro', 'sonnet', 'medium', 'reason', '31b', '32b', '70b', '120b'),
             'big': ('opus', 'large', 'pro', '120b', '235b', '405b', 'reason')}


def _req(url, data=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None)
    req.add_header('Content-Type', 'application/json')
    key = os.environ.get('LLM_API_KEY', '')
    if key:
        req.add_header('Authorization', 'Bearer ' + key)
        if 'anthropic.com' in url:
            req.add_header('x-api-key', key)
            req.add_header('anthropic-version', '2023-06-01')
    return json.load(urllib.request.urlopen(req, timeout=float(os.environ.get('LLM_PROBE_TIMEOUT', 120))))


def models(base):
    d = _req(base.rstrip('/') + '/models')
    ids = [m.get('id') for m in d.get('data', d.get('models', [])) if isinstance(m, dict)]
    return sorted({i.split('/', 1)[1] if i.startswith('models/') else i for i in ids if i})


def pick(avail, role, preferred):
    if preferred in avail or not avail:
        return preferred
    low = [(m, m.lower()) for m in avail if 'embed' not in m.lower() and 'whisper' not in m.lower()
           and 'tts' not in m.lower() and 'image' not in m.lower()]
    for hint in ROLE_HINT[role]:
        for m, l in low:
            if hint in l:
                return m
    return low[0][0] if low else avail[0]


# one fixed DFIR question with a checkable answer + enough output to measure speed
BENCH_PROMPT = ('You are a DFIR analyst. First line: only the Windows Security event ID for a successful '
                'logon (number only). Then explain in about 120 words what logon type 10 means for an investigator.')


def bench(base, model):
    t = time.time()
    d = _req(base.rstrip('/') + '/chat/completions', {
        'model': model, 'messages': [{'role': 'user', 'content': BENCH_PROMPT}], 'max_tokens': 700,
        'temperature': 0})
    sec = time.time() - t
    msg = d['choices'][0]['message']
    content = msg.get('content') or ''
    txt = content + ' ' + (msg.get('reasoning_content') or '')
    toks = (d.get('usage') or {}).get('completion_tokens') or max(1, len(txt) // 4)
    ok = 'pass' if '4624' in (content or txt) else 'miss'
    return sec, toks / sec if sec > 0 else 0.0, ok


def agent_hello(base):
    '''/agent/hello of the DFIR VAO Host Agent (no token needed), else None'''
    root = base.rstrip('/')
    root = root[:-3] if root.endswith('/v1') else root
    try:
        r = urllib.request.urlopen(root + '/agent/hello', timeout=float(os.environ.get('LLM_PROBE_TIMEOUT', 5)))
        d = json.load(r)
        return d if d.get('agent') == 'dfir-vao-host-agent' else None
    except Exception:
        return None


def host_candidates():
    gws = []
    try:
        for line in open('/proc/net/route'):
            f = line.split()
            if len(f) > 2 and f[1] == '00000000' and f[2] != '00000000':
                gws.append('.'.join(str(int(f[2][i:i + 2], 16)) for i in (6, 4, 2, 0)))
    except OSError:
        pass
    out = []
    port = os.environ.get('DFIR_AGENT_PORT', '1234')
    for gw in gws:
        out.append('http://%s:%s/v1' % (gw, port))
        p = gw.split('.')
        if p[-1] == '2':  # VMware NAT: the host itself is .1, the gateway .2
            out.append('http://%s.1:%s/v1' % ('.'.join(p[:3]), port))
    return out


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else ''
    try:
        if cmd == 'providers':
            for p in PROVIDERS:
                print('|'.join(p))
        elif cmd == 'models':
            print('\n'.join(models(a[1])))
        elif cmd == 'test':
            t = time.time()
            d = _req(a[1].rstrip('/') + '/chat/completions', {
                'model': a[2], 'messages': [{'role': 'user', 'content': 'Reply with the single word OK.'}],
                'max_tokens': 400})
            txt = (d['choices'][0]['message'].get('content') or '').strip()
            print('%.1f s: %s' % (time.time() - t, txt[:60]))
        elif cmd == 'has-all':
            # our own llama-swap (Windows-host script or another install): it answers /running and
            # serves the bot's main name; aliases it does not list are mapped by the router
            root = a[1].rstrip('/')
            root = root[:-3] if root.endswith('/v1') else root
            try:
                _req(root + '/running')
            except Exception:
                sys.exit(3)
            sys.exit(0 if 'gpt-small-20b' in models(a[1]) else 3)
        elif cmd == 'pick':
            try:
                avail = models(a[1])
            except Exception:
                avail = []
            print(pick(avail, a[2], a[3]))
        elif cmd == 'bench':
            for m in a[2:]:
                try:
                    sec, tps, ok = bench(a[1], m)
                    print('%.1f|%.0f|%s|%s' % (sec, tps, ok, m))
                except Exception as e:
                    print('-|-|error %s|%s' % (type(e).__name__, m))
        elif cmd == 'find-host':
            os.environ.setdefault('LLM_PROBE_TIMEOUT', '3')
            for u in host_candidates():
                if agent_hello(u):  # the agent answers /v1/models only with its token
                    print(u)
                    return
                try:
                    if models(u):
                        print(u)
                        return
                except Exception:
                    pass
            sys.exit(3)
        elif cmd == 'is-agent':
            sys.exit(0 if agent_hello(a[1]) else 3)
        elif cmd == 'router':
            out, base, kind, fast, rea, big, listen = a[1:8]
            cfg = {'listen': listen, 'default': 'gpt-small-20b',
                   'upstreams': {'main': {'base_url': base, 'api_key': os.environ.get('LLM_API_KEY', ''), 'kind': kind}},
                   'models': {}}
            avail = set()
            if kind == 'llama-swap':
                # our own llama-swap: forward as is (/running, /unload too); a name it does not list
                # goes to its role's main model, else to the chat model
                cfg['upstreams']['main']['passthrough'] = True
                try:
                    avail = set(models(base))
                except Exception:
                    pass
            for role, model in (('fast', fast), ('reasoner', rea), ('big', big)):
                for n in ROLE_NAMES[role]:
                    entry = {'upstream': 'main', 'model': model}
                    if kind == 'llama-swap':
                        # unlisted names may still be llama-swap aliases: try as is, fall back on "not found"
                        main_name = ROLE_NAMES[role][0]
                        entry['model'] = n
                        if avail and n not in avail:
                            entry['fallback'] = main_name if main_name in avail else 'gpt-small-20b'
                    cfg['models'][n] = entry
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=1)
            print('%d names -> %s / %s / %s' % (len(cfg['models']), fast, rea, big))
        else:
            sys.exit(__doc__)
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write('%s: %s\n' % (type(e).__name__, str(e)[:300]))
        sys.exit(1)


if __name__ == '__main__':
    main()
