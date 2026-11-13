#!/usr/bin/env python3
"""tg-i18n: makes the Ukrainian-speaking bot answer every user in their own language.

The bot (n8n + case-maintainer) keeps writing Ukrainian. This service sits between it and Telegram:

  outbound  n8n credential baseUrl / TG_API_BASE -> http://tg-i18n:8098/bot<TOKEN>/<method>
            text, captions, button labels and small text documents are translated for the chat's
            language, then sent on to api.telegram.org. Chats in the source language pass through
            byte for byte. Any failure or timeout sends the original: the bot never goes silent.
  inbound   webhook-gate -> /webhook/... -> here -> n8n. /language (and the i18n:<code> buttons) are
            answered here; everything else is forwarded unchanged.

Translation: the LLM behind DFIR_LLM_URL. Before translating, code, paths, hashes, addresses,
numbers, HTML tags and Markdown marks are swapped for ⟦n⟧ tokens; the reply must return every token,
otherwise the original is used. Results are cached per language on the number-free template, so a
progress message that only changes its numbers is translated once.

Standard library only; state in /data/i18n.db (SQLite).
"""
import email.parser
import email.policy
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TG = os.environ.get('TG_UPSTREAM', 'https://api.telegram.org').rstrip('/')
N8N = os.environ.get('N8N_INBOUND', 'http://n8n:5678').rstrip('/')
TOKEN = os.environ.get('DFIR_TG_BOT_TOKEN', '')
SOURCE = os.environ.get('I18N_SOURCE_LANG', 'uk')
DEFAULT = (os.environ.get('DFIR_BOT_LANG') or SOURCE).strip().lower() or SOURCE
LLM = os.environ.get('DFIR_LLM_URL', 'http://172.17.0.1:1234').rstrip('/')
MODEL = os.environ.get('I18N_MODEL', 'translate-9b')
SHORT_DEADLINE = float(os.environ.get('I18N_TIMEOUT', '20'))
DOC_DEADLINE = float(os.environ.get('I18N_DOC_TIMEOUT', '600'))
DB = os.environ.get('I18N_DB', '/data/i18n.db')
LISTEN = os.environ.get('I18N_LISTEN', '0.0.0.0:8098')

LANGS = {  # code: (native name, English name, "choose" prompt, "set" confirmation)
    'en': ('English', 'English', 'Choose the bot language', 'Language: English'),
    'uk': ('Українська', 'Ukrainian', 'Оберіть мову бота', 'Мова: українська'),
    'pl': ('Polski', 'Polish', 'Wybierz język bota', 'Język: polski'),
    'de': ('Deutsch', 'German', 'Sprache des Bots wählen', 'Sprache: Deutsch'),
    'es': ('Español', 'Spanish', 'Elige el idioma del bot', 'Idioma: español'),
    'fr': ('Français', 'French', 'Choisissez la langue du bot', 'Langue : français'),
    'pt': ('Português', 'Portuguese', 'Escolha o idioma do bot', 'Idioma: português'),
    'it': ('Italiano', 'Italian', 'Scegli la lingua del bot', 'Lingua: italiano'),
    'nl': ('Nederlands', 'Dutch', 'Kies de taal van de bot', 'Taal: Nederlands'),
    'cs': ('Čeština', 'Czech', 'Vyberte jazyk bota', 'Jazyk: čeština'),
    'ro': ('Română', 'Romanian', 'Alegeți limba botului', 'Limba: română'),
    'tr': ('Türkçe', 'Turkish', 'Bot dilini seçin', 'Dil: Türkçe'),
    'ar': ('العربية', 'Arabic', 'اختر لغة البوت', 'اللغة: العربية'),
    'hi': ('हिन्दी', 'Hindi', 'बॉट की भाषा चुनें', 'भाषा: हिन्दी'),
    'zh': ('中文', 'Chinese (Simplified)', '选择机器人语言', '语言：中文'),
    'ja': ('日本語', 'Japanese', 'ボットの言語を選択', '言語：日本語'),
}
TEXT_METHODS = {'sendMessage': ['text'], 'editMessageText': ['text'], 'answerCallbackQuery': ['text'],
                'sendPhoto': ['caption'], 'sendDocument': ['caption'], 'sendVideo': ['caption'],
                'sendAudio': ['caption'], 'sendVoice': ['caption'], 'sendAnimation': ['caption'],
                'editMessageCaption': ['caption'], 'editMessageReplyMarkup': []}
DOC_EXT = ('.txt', '.md', '.log')
CYR = re.compile(r'[А-Яа-яЇїІіЄєҐґ]')

_db_lock = threading.Lock()
_db = None
_cbq = {}            # callback_query_id -> chat_id (answerCallbackQuery carries no chat)
_stats = {'pass': 0, 'translated': 0, 'cache_hit': 0, 'fallback': 0, 'module_stripped': 0, 'module_refused': 0}

# ---- T9 modules: a module switched off at install (dfir modules) has no buttons and its taps are refused.
# The list of callbacks per module is infra/modules.json (the same file install.sh reads), mounted here.
MODULES_OFF = set((os.environ.get('DFIR_MODULES_OFF') or '').replace(',', ' ').split())
MODULES_FILE = os.environ.get('DFIR_MODULES_FILE', '/modules.json')
MODULE_OFF_TEXT = {'uk': '⛔ Цей модуль вимкнено під час встановлення (увімкнути: dfir modules)',
                   'en': '⛔ This module was switched off at install (to switch it on: dfir modules)'}


def _blocked_callbacks():
    if not MODULES_OFF:
        return set()
    try:
        mods = json.load(open(MODULES_FILE, encoding='utf-8'))['modules']
    except Exception as e:
        print('tg-i18n: modules list unreadable, nothing hidden:', type(e).__name__, e, flush=True)
        return set()
    return {c for m in mods if m.get('id') in MODULES_OFF for c in m.get('callbacks') or []}


BLOCKED = _blocked_callbacks()


def blocked(data):
    """callback_data of a switched-off module: exact, a listed prefix + ':', or tool:act:<tool>:..."""
    if not BLOCKED or not isinstance(data, str) or not data:
        return False
    p = data.split(':')
    cands = {data} | {':'.join(p[:i]) for i in range(1, len(p))}
    if len(p) >= 3 and p[0] == 'tool' and p[1] == 'act':
        cands.add('tool:' + p[2])
    return bool(cands & BLOCKED)


def strip_markup(markup):
    """Remove the buttons of switched-off modules (rows left empty disappear)."""
    if not BLOCKED or not markup:
        return markup
    # a copy: the caller sees a change only through a new object (a dict body was edited in place before)
    obj = json.loads(markup if isinstance(markup, str) else json.dumps(markup))
    rows = obj.get('inline_keyboard') if isinstance(obj, dict) else None
    if not rows:
        return markup
    new = [[b for b in row if not (isinstance(b, dict) and blocked(b.get('callback_data')))] for row in rows]
    new = [r for r in new if r]
    if new == rows:
        return markup
    obj['inline_keyboard'] = new
    _stats['module_stripped'] += 1
    return json.dumps(obj, ensure_ascii=False) if isinstance(markup, str) else obj


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, file=sys.stderr, flush=True)


# ---- state ---------------------------------------------------------------------------------------
def db():
    global _db
    if _db is None:
        os.makedirs(os.path.dirname(DB) or '.', exist_ok=True)
        _db = sqlite3.connect(DB, check_same_thread=False)
        _db.execute('create table if not exists users (chat_id text primary key, lang text, hinted int default 0, updated real)')
        _db.execute('create table if not exists cache (lang text, key text, src text, dst text, used real, primary key (lang, key))')
        _db.commit()
    return _db


def user_lang(chat_id):
    if chat_id in (None, ''):
        return DEFAULT
    with _db_lock:
        r = db().execute('select lang from users where chat_id=?', (str(chat_id),)).fetchone()
    return (r[0] if r and r[0] else DEFAULT)


def set_user_lang(chat_id, lang):
    with _db_lock:
        db().execute('insert into users (chat_id, lang, updated) values (?,?,?) on conflict(chat_id) do update set '
                     'lang=excluded.lang, updated=excluded.updated', (str(chat_id), lang, time.time()))
        db().commit()


def first_contact(chat_id):
    with _db_lock:
        r = db().execute('select hinted from users where chat_id=?', (str(chat_id),)).fetchone()
        if r:
            return False
        db().execute('insert into users (chat_id, lang, hinted, updated) values (?,?,1,?)', (str(chat_id), None, time.time()))
        db().commit()
    return True


def cache_get(lang, key):
    with _db_lock:
        r = db().execute('select dst from cache where lang=? and key=?', (lang, key)).fetchone()
    return r[0] if r else None


def cache_put(lang, key, src, dst):
    with _db_lock:
        db().execute('insert or replace into cache (lang, key, src, dst, used) values (?,?,?,?,?)', (lang, key, src, dst, time.time()))
        db().commit()


# ---- masking -------------------------------------------------------------------------------------
PROTECT = re.compile('|'.join([
    r'<pre[^>]*>.*?</pre>', r'<code[^>]*>.*?</code>', r'```.*?```', r'`[^`\n]+`',
    r'<a\s[^>]*>', r'</?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?/?>',            # HTML tags, kept as they are
    r'https?://[^\s<>"]+', r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b',               # URLs, e-mails
    r'\b[A-Za-z]:\\(?:[^\s<>"|*?]*[^\s<>"|*?.,;:!)])?',                    # Windows path (not its full stop)
    r'(?<![\w/])/(?:[\w.@-]+/)+[\w@-]*(?:\.[\w-]+)*',                      # Unix path
    r'\b[0-9a-fA-F]{16,}\b', r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b',      # hashes, IPv4[:port]
    r'(?<![\w@])[@/][A-Za-z_][\w]*',                                       # @user, /command
    r'\b[\w-]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|lnk|zip|7z|rar|evtx|pf|csv|json|txt|md|pdf|docx|xlsx)\b',
    r'\d+(?:[.,:]\d+)*%?',                                                 # numbers, times, percents
    r'[*_~]{1,3}',                                                         # Markdown marks
]), re.S)
TOKEN_RX = re.compile(r'⟦(\d+)⟧')


def mask(text):
    kept = []

    def sub(m):
        kept.append(m.group(0))
        return '⟦%d⟧' % (len(kept) - 1)
    return PROTECT.sub(sub, text), kept


def unmask(text, kept):
    return TOKEN_RX.sub(lambda m: kept[int(m.group(1))] if int(m.group(1)) < len(kept) else m.group(0), text)


# ---- LLM -----------------------------------------------------------------------------------------
def llm_translate(chunk, lang, deadline):
    name = LANGS.get(lang, (lang, lang))[1]
    system = ('You translate the user interface and reports of a digital-forensics Telegram bot from Ukrainian '
              'into %s. Output ONLY the translation, nothing before or after it. Keep every token like ⟦3⟧ '
              'exactly as it is, each one exactly once, in a sensible position. Keep emoji, line breaks and '
              'list markers. Use standard forensic / IT terms of %s. Text that is already in %s or is not '
              'Ukrainian stays unchanged.' % (name, name, name))
    left = deadline - time.time()
    if left < 2:
        raise TimeoutError('no time left')
    # reasoning models (gpt-oss) spend tokens on thinking before the answer: leave room for both
    body = {'model': MODEL, 'temperature': 0.1, 'max_tokens': 1500 + len(chunk) * 4, 'reasoning_effort': 'low',
            'chat_template_kwargs': {'reasoning_effort': 'low'},
            'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': chunk}]}
    req = urllib.request.Request(LLM + '/v1/chat/completions', data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=left) as r:
        d = json.load(r)
    out = (d['choices'][0]['message'].get('content') or '').strip()
    out = re.sub(r'^```\w*\n|\n```$', '', out)
    return out


def _chunks(text, size=1400):
    parts, cur = [], ''
    for para in re.split(r'(\n\s*\n)', text):
        if len(cur) + len(para) > size and cur:
            parts.append(cur)
            cur = ''
        while len(para) > size:            # one huge paragraph: cut at a line break or a space
            cut = para.rfind('\n', 0, size)
            cut = cut if cut > size // 3 else para.rfind(' ', 0, size)
            cut = cut if cut > 0 else size
            parts.append(para[:cut])
            para = para[cut:]
        cur += para
    if cur:
        parts.append(cur)
    return parts


def translate(text, lang, deadline):
    """Translated text, or None when it cannot be done in time / faithfully."""
    if not text or lang == SOURCE or len(CYR.findall(text)) < 3:
        return text
    masked, kept = mask(text)
    key = hashlib.sha1(masked.encode('utf-8')).hexdigest()
    hit = cache_get(lang, key)
    if hit is not None:
        _stats['cache_hit'] += 1
        return unmask(hit, kept)
    out = []
    for ch in _chunks(masked):
        if len(CYR.findall(ch)) < 3:
            out.append(ch)
            continue
        want = sorted(TOKEN_RX.findall(ch))
        lead = re.match(r'\s*', ch).group(0)
        trail = ch[len(ch.rstrip()):]
        res = None
        for _ in range(2):
            try:
                cand = llm_translate(ch.strip(), lang, deadline)
            except Exception as e:
                log('llm', type(e).__name__, str(e)[:120])
                return None
            if sorted(TOKEN_RX.findall(cand)) == want and cand:
                res = lead + cand + trail
                break
            log('rejected (tokens %s, got %s): %r' % (len(want), len(TOKEN_RX.findall(cand)), cand[:120]))
        if res is None:
            return None
        out.append(res)
    dst = ''.join(out)
    cache_put(lang, key, masked, dst)
    _stats['translated'] += 1
    return unmask(dst, kept)


def translate_batch(texts, lang, deadline):
    """Short single-line labels (buttons) in one LLM call: label i -> line i. None entries = keep."""
    res = [None] * len(texts)
    todo = []
    for i, t in enumerate(texts):
        if not t or len(CYR.findall(t)) < 2 or '\n' in t:
            continue
        masked, kept = mask(t)
        key = hashlib.sha1(masked.encode('utf-8')).hexdigest()
        hit = cache_get(lang, key)
        if hit is not None:
            _stats['cache_hit'] += 1
            res[i] = unmask(hit, kept)
        else:
            todo.append((i, masked, kept, key))
    if todo:
        joined = '\n'.join('%d) %s' % (n + 1, m) for n, (_, m, _, _) in enumerate(todo))
        try:
            out = llm_translate('Translate each numbered line, keep the numbering:\n' + joined, lang, deadline)
        except Exception as e:
            log('llm batch', type(e).__name__, str(e)[:120])
            return res
        lines = {}
        for ln in out.splitlines():
            m = re.match(r'^\s*(\d+)\)\s?(.*)$', ln)
            if m:
                lines[int(m.group(1))] = m.group(2).strip()
        for n, (i, masked, kept, key) in enumerate(todo):
            cand = lines.get(n + 1)
            if cand and sorted(TOKEN_RX.findall(cand)) == sorted(TOKEN_RX.findall(masked)):
                cache_put(lang, key, masked, cand)
                res[i] = unmask(cand, kept)
        _stats['translated'] += 1
    return res


def translate_markup(markup, lang, deadline):
    if not markup:
        return markup
    obj = json.loads(markup if isinstance(markup, str) else json.dumps(markup))   # copy, see strip_markup
    changed = False
    buttons = [b for kb in ('inline_keyboard', 'keyboard') for row in (obj.get(kb) or []) for b in row
               if isinstance(b, dict) and b.get('text')]
    for b, t in zip(buttons, translate_batch([b['text'] for b in buttons], lang, deadline)):
        if t and t != b['text']:
            b['text'] = t
            changed = True
    if not changed:
        return markup
    return json.dumps(obj, ensure_ascii=False) if isinstance(markup, str) else obj


# ---- request bodies ------------------------------------------------------------------------------
def parse_body(ctype, raw, query):
    """-> (kind, fields, files) ; files: name -> (filename, content_type, bytes)"""
    fields = {k: v[-1] for k, v in urllib.parse.parse_qs(query).items()}
    files = {}
    if raw and 'application/json' in ctype:
        fields.update(json.loads(raw))
        return 'json', fields, files
    if raw and 'x-www-form-urlencoded' in ctype:
        fields.update({k: v[-1] for k, v in urllib.parse.parse_qs(raw.decode('utf-8')).items()})
        return 'form', fields, files
    if raw and 'multipart/form-data' in ctype:
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b'Content-Type: ' + ctype.encode() + b'\r\n\r\n' + raw)
        for part in msg.iter_parts():
            name = part.get_param('name', header='content-disposition')
            fn = part.get_filename()
            data = part.get_payload(decode=True) or b''
            if fn is not None:
                files[name] = (fn, part.get_content_type(), data)
            else:
                fields[name] = data.decode('utf-8', 'replace')
        return 'multipart', fields, files
    return 'query', fields, files


def build_body(kind, fields, files):
    if kind == 'json':
        return 'application/json', json.dumps(fields, ensure_ascii=False).encode('utf-8')
    if kind in ('form', 'query'):
        return 'application/x-www-form-urlencoded', urllib.parse.urlencode(
            {k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v) for k, v in fields.items()}).encode()
    b = uuid.uuid4().hex
    out = []
    for k, v in fields.items():
        v = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
        out.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n' % (b, k)).encode() + v.encode('utf-8') + b'\r\n')
    for k, (fn, ct, data) in files.items():
        fn_q = urllib.parse.quote(fn)
        out.append(('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"; filename*=UTF-8\'\'%s\r\n'
                    'Content-Type: %s\r\n\r\n' % (b, k, fn.encode('ascii', 'replace').decode(), fn_q, ct)).encode() + data + b'\r\n')
    out.append(('--%s--\r\n' % b).encode())
    return 'multipart/form-data; boundary=%s' % b, b''.join(out)


def tg_call(path, ctype, body, timeout=120):
    req = urllib.request.Request(TG + path, data=body if body else None, method='POST' if body else 'GET')
    if body:
        req.add_header('Content-Type', ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), r.headers.get('Content-Type', 'application/json')
    except urllib.error.HTTPError as e:
        return e.code, e.read(), 'application/json'
    except (urllib.error.URLError, OSError) as e:
        log('telegram unreachable', type(e).__name__, e)
        return 502, json.dumps({'ok': False, 'error_code': 502, 'description': 'tg-i18n: %s' % e}).encode(), 'application/json'


def chat_of(method, fields):
    if fields.get('chat_id') not in (None, ''):
        return fields['chat_id']
    if method == 'answerCallbackQuery':
        return _cbq.get(str(fields.get('callback_query_id')))
    return None


def localize(method, fields, files, lang, deadline):
    """Translate in place; returns True when something changed."""
    changed = False
    for f in TEXT_METHODS.get(method, []):
        if isinstance(fields.get(f), str) and fields[f]:
            t = translate(fields[f], lang, deadline)
            if t is None:
                _stats['fallback'] += 1
            elif t != fields[f]:
                fields[f] = t
                changed = True
    if fields.get('reply_markup'):
        try:
            m = translate_markup(fields['reply_markup'], lang, deadline)
            if m is not fields['reply_markup']:
                fields['reply_markup'] = m
                changed = True
        except Exception as e:
            log('markup', type(e).__name__, e)
    return changed


def localize_document(fields, files, lang):
    """Text documents (reports): translate the file content; slow, runs in the background."""
    for k, (fn, ct, data) in list(files.items()):
        if not fn.lower().endswith(DOC_EXT) or len(data) > 400 * 1024:
            continue
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            continue
        t = translate(text, lang, time.time() + DOC_DEADLINE)
        if t and t != text:
            files[k] = (fn, ct, t.encode('utf-8'))
    if isinstance(fields.get('caption'), str):
        t = translate(fields['caption'], lang, time.time() + 60)
        if t:
            fields['caption'] = t


# ---- inbound: the language picker ----------------------------------------------------------------
def picker(lang):
    names = list(LANGS.items())
    rows = [[{'text': ('✅ ' if c == lang else '') + v[0], 'callback_data': 'i18n:' + c} for c, v in names[i:i + 2]]
            for i in range(0, len(names), 2)]
    return {'inline_keyboard': rows}


def send_direct(method, payload):
    if not TOKEN:
        return
    tg_call('/bot%s/%s' % (TOKEN, method), 'application/json', json.dumps(payload, ensure_ascii=False).encode())


def handle_update(upd):
    """True when the update was answered here (not forwarded to n8n)."""
    cq = upd.get('callback_query')
    if cq:
        chat = ((cq.get('message') or {}).get('chat') or {}).get('id') or (cq.get('from') or {}).get('id')
        _cbq[str(cq.get('id'))] = chat
        if len(_cbq) > 5000:
            for k in list(_cbq)[:2500]:
                _cbq.pop(k, None)
        data = cq.get('data') or ''
        if blocked(data):
            _stats['module_refused'] += 1
            lang = user_lang(chat)
            send_direct('answerCallbackQuery', {'callback_query_id': cq['id'], 'show_alert': True,
                                                'text': MODULE_OFF_TEXT['uk' if lang == 'uk' else 'en']})
            return True
        if data.startswith('i18n:'):
            code = data[5:]
            if code in LANGS:
                set_user_lang(chat, code)
                send_direct('answerCallbackQuery', {'callback_query_id': cq['id'], 'text': LANGS[code][3]})
                msg = cq.get('message') or {}
                send_direct('editMessageText', {'chat_id': chat, 'message_id': msg.get('message_id'),
                                                'text': '🌐 ' + LANGS[code][3] + '\n/start', 'reply_markup': picker(code)})
            return True
        return False
    msg = upd.get('message') or {}
    text = (msg.get('text') or '').strip()
    chat = (msg.get('chat') or {}).get('id')
    if chat is None:
        return False
    if re.match(r'^/(language|lang|мова)(@\w+)?\s*$', text, re.I):
        cur = user_lang(chat)
        send_direct('sendMessage', {'chat_id': chat, 'text': '🌐 ' + LANGS.get(cur, LANGS['en'])[2],
                                    'reply_markup': picker(cur)})
        return True
    # a new person whose Telegram speaks another supported language: point once at /language
    code = ((msg.get('from') or {}).get('language_code') or '')[:2].lower()
    if first_contact(chat) and code in LANGS and code != DEFAULT:
        threading.Timer(3, send_direct, ('sendMessage', {'chat_id': chat, 'text': '🌐 ' + LANGS[code][2] + ': /language'})).start()
    return False


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *a):
        pass

    def reply(self, code, body, ctype='application/json'):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def raw(self):
        n = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(n) if n else b''

    def do_GET(self):
        if self.path.startswith('/health'):
            return self.reply(200, json.dumps({'status': 'ok', 'default': DEFAULT, **_stats}).encode())
        return self.api(b'')

    def do_POST(self):
        raw = self.raw()
        if self.path.startswith('/webhook/'):
            return self.inbound(raw)
        return self.api(raw)

    def inbound(self, raw):
        try:
            if handle_update(json.loads(raw or b'{}')):
                return self.reply(200, b'{"ok":true}')
        except Exception as e:
            log('inbound', type(e).__name__, e)
        req = urllib.request.Request(N8N + self.path, data=raw, method='POST')
        for h in ('Content-Type', 'X-Telegram-Bot-Api-Secret-Token'):
            if self.headers.get(h):
                req.add_header(h, self.headers[h])
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return self.reply(r.status, r.read(), r.headers.get('Content-Type', 'application/json'))
        except urllib.error.HTTPError as e:
            return self.reply(e.code, e.read())
        except Exception as e:
            log('n8n', type(e).__name__, e)
            return self.reply(502, b'{"ok":false}')

    def api(self, raw):
        path, _, query = self.path.partition('?')
        m = re.match(r'^/bot[^/]+/(\w+)$', path)
        ctype = self.headers.get('Content-Type', '')
        method = m.group(1) if m else ''
        parsed, stripped = None, False
        if BLOCKED and raw and b'callback_data' in raw:
            try:
                parsed = parse_body(ctype, raw, query)
                f = parsed[1]
                if f.get('reply_markup'):
                    mk = strip_markup(f['reply_markup'])
                    if mk is not f['reply_markup']:
                        f['reply_markup'] = mk
                        stripped = True
            except Exception as e:
                log('modules', method, type(e).__name__, e)
                parsed = None
        if method in TEXT_METHODS:
            try:
                kind, fields, files = parsed or parse_body(ctype, raw, query)
                lang = user_lang(chat_of(method, fields))
                if lang != SOURCE:
                    if method == 'sendDocument' and any(f[0].lower().endswith(DOC_EXT) for f in files.values()):
                        threading.Thread(target=self.doc_async, args=(path, kind, fields, files, lang), daemon=True).start()
                        return self.reply(200, json.dumps({'ok': True, 'result': {'message_id': 0, 'chat': {'id': fields.get('chat_id')},
                                                                                  'date': int(time.time())}}).encode())
                    if localize(method, fields, files, lang, time.time() + SHORT_DEADLINE):
                        ct, body = build_body(kind, fields, files)
                        code, out, oct_ = tg_call(path, ct, body)
                        return self.reply(code, out, oct_)
            except Exception as e:
                log('localize', method, type(e).__name__, e)
        if stripped:
            ct, body = build_body(*parsed)
            code, out, oct_ = tg_call(path, ct, body)
            return self.reply(code, out, oct_)
        _stats['pass'] += 1
        code, out, oct_ = tg_call(self.path, ctype, raw)
        return self.reply(code, out, oct_)

    @staticmethod
    def doc_async(path, kind, fields, files, lang):
        try:
            localize_document(fields, files, lang)
        except Exception as e:
            log('document', type(e).__name__, e)
        ct, body = build_body(kind, fields, files)
        code, out, _ = tg_call(path, ct, body, timeout=300)
        if code != 200:
            log('document send', code, out[:200])


def ensure_command():
    """Add /language to the bot's command menu once (keeps the commands the bot already has)."""
    if not TOKEN:
        return
    try:
        code, out, _ = tg_call('/bot%s/getMyCommands' % TOKEN, '', b'', timeout=20)
        cmds = json.loads(out).get('result') or []
        if code == 200 and not any(c.get('command') == 'language' for c in cmds):
            cmds.append({'command': 'language', 'description': '🌐 Language / Мова'})
            tg_call('/bot%s/setMyCommands' % TOKEN, 'application/json', json.dumps({'commands': cmds}, ensure_ascii=False).encode())
            log('added /language to the command menu')
    except Exception as e:
        log('commands', type(e).__name__, e)


def main():
    db()
    threading.Thread(target=ensure_command, daemon=True).start()
    host, _, port = LISTEN.rpartition(':')
    srv = ThreadingHTTPServer((host or '0.0.0.0', int(port)), H)
    srv.daemon_threads = True
    log('tg-i18n on %s, source %s, default %s, model %s, modules off: %s (%d buttons hidden)'
        % (LISTEN, SOURCE, DEFAULT, MODEL, ' '.join(sorted(MODULES_OFF)) or '-', len(BLOCKED)))
    srv.serve_forever()


if __name__ == '__main__':
    main()
