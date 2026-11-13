#!/usr/bin/env python3
"""From the VM: the host agent is found, wants its token, answers (plain + streamed) and queues.

  AGENT_URL=http://192.168.100.1:18234 AGENT_TOKEN=... python3 test_host_agent_vm.py
The agent under test runs with --parallel 1, so 4 requests at once must show a queue.
"""
import json, os, sys, threading, time, urllib.request, urllib.error

U = os.environ['AGENT_URL'].rstrip('/'); TOK = os.environ['AGENT_TOKEN']
ok = 0; bad = 0

def check(name, cond, info=''):
    global ok, bad
    ok, bad = (ok + 1, bad) if cond else (ok, bad + 1)
    print(('PASS ' if cond else 'FAIL ') + name + (' -- ' + str(info) if info else ''))

def req(path, data=None, token=None, timeout=300):
    r = urllib.request.Request(U + path, data=json.dumps(data).encode() if data is not None else None)
    r.add_header('Content-Type', 'application/json')
    if token: r.add_header('Authorization', 'Bearer ' + token)
    return urllib.request.urlopen(r, timeout=timeout)

def code(path, data=None, token=None):
    try: return req(path, data, token).status
    except urllib.error.HTTPError as e: return e.code

chat = {'model': 'gpt-small-20b', 'max_tokens': 16, 'messages': [{'role': 'user', 'content': 'Say hello'}]}
h = json.load(req('/agent/hello'))
check('hello without token names the agent', h.get('agent') == 'dfir-vao-host-agent', h)
check('models without token -> 401', code('/v1/models') == 401)
check('chat with wrong token -> 401', code('/v1/chat/completions', chat, 'vao_wrong') == 401)
check('status without token -> 401', code('/agent/status') == 401)
m = json.load(req('/v1/models', token=TOK))
ids = [x['id'] for x in m.get('data', [])]
check('models with token lists the bot names', 'gpt-small-20b' in ids, ids[:5])
t = time.time(); d = json.load(req('/v1/chat/completions', chat, TOK))
check('chat answer with token', bool(d['choices'][0]['message'].get('content')), '%.1f s: %r' % (time.time() - t, d['choices'][0]['message'].get('content', '')[:40]))
# streamed: several SSE chunks, ends with [DONE]
s = dict(chat, stream=True, max_tokens=24)
raw = req('/v1/chat/completions', s, TOK).read().decode()
check('streaming passes through', raw.count('data:') >= 3 and '[DONE]' in raw, '%d events' % raw.count('data:'))
check('llama-swap /running passes through (bot uses it)', 'running' in json.load(req('/running', token=TOK)))
# queue: 4 at once, max 1 answering
seen = {'waiting': 0, 'active': 0}; done = []
long = dict(chat, max_tokens=200, messages=[{'role': 'user', 'content': 'Write a long story about a forensic analyst.'}])
def one():
    try: json.load(req('/v1/chat/completions', long, TOK)); done.append(1)
    except Exception as e: done.append(e)
ths = [threading.Thread(target=one) for _ in range(4)]
[x.start() for x in ths]
while any(x.is_alive() for x in ths):
    st = json.load(req('/agent/status', token=TOK))
    seen['waiting'] = max(seen['waiting'], st['waiting']); seen['active'] = max(seen['active'], st['active'])
    time.sleep(0.2)
check('4 parallel requests all answered', done == [1, 1, 1, 1], done)
check('queue seen, never more than 1 answering', seen['waiting'] >= 1 and seen['active'] == 1, seen)
st = json.load(req('/agent/status', token=TOK))
check('status has GPUs, versions, counters', st['gpus'] and st['llama_cpp'].startswith('b') and st['refused'] >= 3 and st['served'] >= 6,
      {k: st[k] for k in ('llama_cpp', 'llama_swap', 'served', 'refused', 'waiting', 'active')} | {'gpus': len(st['gpus'])})
print('%d passed, %d failed' % (ok, bad)); sys.exit(1 if bad else 0)
