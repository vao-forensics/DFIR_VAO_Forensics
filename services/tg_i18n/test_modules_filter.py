#!/usr/bin/env python3
"""T9 test: tg-i18n hides the buttons of switched-off modules and refuses their taps.

Runs the REAL services/tg_i18n/i18n.py as a process between a fake Telegram and a fake n8n (both local
HTTP servers that record what they get). No real token, no network.
  python3 services/tg_i18n/test_modules_filter.py            exit 0 = all PASS
"""
import json, os, socket, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOKEN = '100000001:STUB_not_a_real_bot_token_xxxxxxxxxx'
got_tg, got_n8n = [], []


def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


class Rec(BaseHTTPRequestHandler):
    sink = None
    def log_message(self, *a): pass
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        self.sink.append((self.path, self.headers.get('Content-Type', ''), raw))
        b = b'{"ok":true,"result":[]}'
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do_POST


def serve(sink):
    h = type('R', (Rec,), {'sink': sink}); p = free_port()
    srv = ThreadingHTTPServer(('127.0.0.1', p), h); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return p


def start_i18n(off, tg, n8n):
    port, d = free_port(), tempfile.mkdtemp()
    env = dict(os.environ, TG_UPSTREAM='http://127.0.0.1:%d' % tg, N8N_INBOUND='http://127.0.0.1:%d' % n8n,
               DFIR_TG_BOT_TOKEN=TOKEN, I18N_DB=os.path.join(d, 'i.db'), I18N_LISTEN='127.0.0.1:%d' % port,
               DFIR_MODULES_OFF=off, DFIR_MODULES_FILE=os.path.join(ROOT, 'infra/modules.json'),
               DFIR_LLM_URL='http://127.0.0.1:9')
    p = subprocess.Popen([sys.executable, '-u', os.path.join(ROOT, 'services/tg_i18n/i18n.py')], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            urllib.request.urlopen('http://127.0.0.1:%d/health' % port, timeout=1); break
        except Exception:
            time.sleep(0.2)
    time.sleep(0.5)   # ensure_command() calls the fake Telegram once at start
    return p, port


def post(port, path, ctype, body):
    r = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), data=body, method='POST')
    r.add_header('Content-Type', ctype)
    return urllib.request.urlopen(r, timeout=10).read()


MENU = {'inline_keyboard': [
    [{'text': 'PDF', 'callback_data': 'tool:pdf_translate'}, {'text': 'OCR', 'callback_data': 'tool:ocr'}],
    [{'text': 'Audio', 'callback_data': 'tool:audio_clean'}],
    [{'text': 'RAM', 'callback_data': 'up_ram'}, {'text': 'Info', 'callback_data': 'show_stats'}],
    [{'text': 'Back', 'callback_data': 'menu_back'}]]}


def cbs(markup):
    m = json.loads(markup) if isinstance(markup, str) else markup
    return [b['callback_data'] for row in m['inline_keyboard'] for b in row]


def last_tg(method):
    for path, ct, raw in reversed(got_tg):
        if path.endswith('/' + method):
            return ct, raw
    return None, None


def fields_of(ct, raw):
    if 'json' in ct:
        return json.loads(raw)
    if 'urlencoded' in ct:
        return {k: v[-1] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
    import email, email.policy
    msg = email.message_from_bytes(b'Content-Type: ' + ct.encode() + b'\r\n\r\n' + raw, policy=email.policy.HTTP)
    return {p.get_param('name', header='content-disposition'): (p.get_payload(decode=True) or b'').decode('utf-8', 'replace')
            for p in msg.iter_parts()}


def multipart(fields, fname, data):
    b = uuid.uuid4().hex; out = b''
    for k, v in fields.items():
        out += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, k, v)).encode()
    out += ('--%s\r\nContent-Disposition: form-data; name="document"; filename="%s"\r\nContent-Type: application/pdf\r\n\r\n' % (b, fname)).encode() + data + b'\r\n'
    return 'multipart/form-data; boundary=' + b, out + ('--%s--\r\n' % b).encode()


npass = nfail = 0
def check(name, cond, extra=''):
    global npass, nfail
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond else '  ' + str(extra)))
    if cond: npass += 1
    else: nfail += 1


tg, n8n = serve(got_tg), serve(got_n8n)
api = '/bot%s/' % TOKEN

# ---- modules translate + media + ram off
p, port = start_i18n('translate media ram', tg, n8n)
try:
    post(port, api + 'sendMessage', 'application/json', json.dumps({'chat_id': 5, 'text': 'menu', 'reply_markup': MENU}).encode())
    ct, raw = last_tg('sendMessage'); c = cbs(fields_of(ct, raw)['reply_markup'])
    check('json sendMessage: off buttons removed', c == ['tool:ocr', 'show_stats', 'menu_back'], c)
    body = urllib.parse.urlencode({'chat_id': 5, 'text': 'x', 'reply_markup': json.dumps(MENU)}).encode()
    post(port, api + 'editMessageText', 'application/x-www-form-urlencoded', body)
    ct, raw = last_tg('editMessageText'); c = cbs(fields_of(ct, raw)['reply_markup'])
    check('form editMessageText: off buttons removed', c == ['tool:ocr', 'show_stats', 'menu_back'], c)
    ctm, bm = multipart({'chat_id': '5', 'caption': 'report', 'reply_markup': json.dumps(MENU)}, 'r.pdf', b'%PDF-1.4 test')
    post(port, api + 'sendDocument', ctm, bm)
    ct, raw = last_tg('sendDocument'); f = fields_of(ct, raw)
    check('multipart sendDocument: off buttons removed, file kept', cbs(f['reply_markup']) == ['tool:ocr', 'show_stats', 'menu_back']
          and f.get('document') == '%PDF-1.4 test', f)
    plain = json.dumps({'chat_id': 5, 'text': 'no buttons'}).encode()
    post(port, api + 'sendMessage', 'application/json', plain)
    check('message without buttons passes byte for byte', last_tg('sendMessage')[1] == plain)
    n0 = len(got_n8n)
    upd = {'update_id': 1, 'callback_query': {'id': 'cq1', 'from': {'id': 5}, 'data': 'tool:pdf_translate',
                                              'message': {'message_id': 9, 'chat': {'id': 5}}}}
    post(port, '/webhook/x', 'application/json', json.dumps(upd).encode())
    ct, raw = last_tg('answerCallbackQuery'); a = fields_of(ct, raw) if raw else {}
    check('tap on an off module: not forwarded to n8n', len(got_n8n) == n0)
    check('tap on an off module: alert to the user', a.get('callback_query_id') == 'cq1' and a.get('show_alert') is True
          and 'dfir modules' in a.get('text', ''), a)
    upd['callback_query'].update(id='cq2', data='tool:act:audio_clean:opt1')
    post(port, '/webhook/x', 'application/json', json.dumps(upd).encode())
    check('tool:act:<off tool>:... refused too', len(got_n8n) == n0)
    upd['callback_query'].update(id='cq3', data='show_stats')
    post(port, '/webhook/x', 'application/json', json.dumps(upd).encode())
    check('tap on a core button reaches n8n', len(got_n8n) == n0 + 1)
    h = json.loads(urllib.request.urlopen('http://127.0.0.1:%d/health' % port).read())
    check('health counts stripped/refused', h['module_stripped'] >= 3 and h['module_refused'] == 2, h)
finally:
    p.terminate(); out = p.communicate()[0].decode()
check('start log names the off modules', 'modules off: media ram translate' in out, out[-300:])

# ---- nothing off (unset): an existing install behaves exactly as before
p, port = start_i18n('', tg, n8n)
try:
    body = json.dumps({'chat_id': 5, 'text': 'menu', 'reply_markup': MENU}, ensure_ascii=False).encode()
    post(port, api + 'sendMessage', 'application/json', body)
    check('nothing off: menu passes byte for byte', last_tg('sendMessage')[1] == body)
    n0 = len(got_n8n)
    upd = {'update_id': 2, 'callback_query': {'id': 'cq4', 'from': {'id': 5}, 'data': 'tool:pdf_translate',
                                              'message': {'message_id': 9, 'chat': {'id': 5}}}}
    post(port, '/webhook/x', 'application/json', json.dumps(upd).encode())
    check('nothing off: every tap reaches n8n', len(got_n8n) == n0 + 1)
finally:
    p.terminate(); p.communicate()

print('modules filter: %d passed, %d failed' % (npass, nfail))
sys.exit(1 if nfail else 0)
