# -*- coding: utf-8 -*-
"""Owner-only chat-history viewer + manager.

Two sources, one page, reachable in the browser via the :8080 gateway:
  - Telegram free-chat  -> Postgres table bot_free_chat_log
  - Open WebUI chats    -> sqlite /webui_data/webui.db (chat.chat JSON blob)

AUTH (v2): no token in the URL. The Telegram admin button calls /ach-mint (internal-only:
the gateway proxies /admin-chats* but NOT /ach-mint, so it is unreachable from outside the
docker network) and sends the owner a ONE-TIME link /admin-chats?otp=<nonce> with a short
TTL. Opening it consumes the nonce, sets an HttpOnly session cookie (scoped to
Path=/admin-chats) and redirects to the clean URL. A nonce that leaked into a browser
history or the nginx access log is already spent and useless. The master token in
/data/state/admin_chats_token is accepted only via the X-ACH-Token HEADER (maintenance),
never from the URL.
"""
import json
import os
import time

WEBUI_DB = os.environ.get('DFIR_WEBUI_DB', '/webui_data/webui.db')
PUBLIC_BASE = os.environ.get('DFIR_PUBLIC_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080')
_TOKEN_FILE = '/data/state/admin_chats_token'
_AUTH_FILE = '/data/state/admin_chats_auth.json'
OTP_TTL = 10 * 60          # one-time link: 10 minutes, single use
SESS_TTL = 30 * 24 * 3600  # browser session cookie: 30 days
_TOKEN = None


def _token():
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    try:
        if os.path.isfile(_TOKEN_FILE):
            with open(_TOKEN_FILE) as f:
                _TOKEN = f.read().strip()
    except Exception:
        pass
    if not _TOKEN:
        import secrets
        _TOKEN = secrets.token_hex(16)
        try:
            os.makedirs(os.path.dirname(_TOKEN_FILE), exist_ok=True)
            with open(_TOKEN_FILE, 'w') as f:
                f.write(_TOKEN)
        except Exception:
            pass
    return _TOKEN


def _auth_load():
    try:
        with open(_AUTH_FILE) as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault('otps', {})
    d.setdefault('sessions', {})
    now = time.time()
    d['otps'] = {k: v for k, v in d['otps'].items() if v > now}
    d['sessions'] = {k: v for k, v in d['sessions'].items() if v > now}
    return d


def _auth_save(d):
    try:
        with open(_AUTH_FILE, 'w') as f:
            json.dump(d, f)
    except Exception:
        pass


def _tg_conversations(pg_dsn):
    import psycopg2
    convs = {}
    with psycopg2.connect(pg_dsn) as c, c.cursor() as cur:
        cur.execute("SELECT id, tg_id, display_name, question, answer, ts "
                    "FROM bot_free_chat_log ORDER BY ts ASC")
        for mid, tg_id, name, q, a, ts in cur.fetchall():
            key = str(tg_id)
            conv = convs.get(key)
            if conv is None:
                conv = {'id': key, 'who': name or key, 'tg_id': tg_id,
                        'count': 0, 'last': '', 'messages': []}
                convs[key] = conv
            conv['count'] += 1
            conv['last'] = ts.isoformat() if ts else ''
            conv['messages'].append({
                'mid': mid,
                'ts': ts.isoformat() if ts else '',
                'q': q or '', 'a': a or ''})
    out = list(convs.values())
    out.sort(key=lambda x: x['last'], reverse=True)
    return out


def _web_conversations():
    import sqlite3
    if not os.path.isfile(WEBUI_DB):
        return []
    con = sqlite3.connect(WEBUI_DB)
    try:
        users = {}
        try:
            for uid, email in con.execute("SELECT id, email FROM user"):
                users[uid] = email
        except Exception:
            pass
        out = []
        for cid, uid, title, chatjson, created, updated in con.execute(
                "SELECT id, user_id, title, chat, created_at, updated_at FROM chat ORDER BY updated_at DESC"):
            msgs = []
            try:
                d = json.loads(chatjson) if chatjson else {}
                arr = d.get('messages')
                if not isinstance(arr, list):
                    arr = []
                for m in arr:
                    if isinstance(m, dict):
                        msgs.append({'role': m.get('role', '?'),
                                     'content': (m.get('content') or '')})
            except Exception:
                pass

            def _ts(v):
                try:
                    import datetime
                    return datetime.datetime.utcfromtimestamp(int(v)).isoformat()
                except Exception:
                    return str(v or '')
            out.append({'id': str(cid), 'who': users.get(uid, uid or '?'),
                        'title': title or '(без назви)', 'count': len(msgs),
                        'last': _ts(updated), 'messages': msgs})
        return out
    finally:
        con.close()


def register_admin_chats(app, pg_dsn):
    from flask import request, Response, jsonify, redirect

    def _guard():
        sid = request.cookies.get('ach_sid', '')
        if sid:
            d = _auth_load()
            if d['sessions'].get(sid, 0) > time.time():
                return True
        # maintenance path: master token via HEADER only, never from the URL
        hdr = request.headers.get('X-ACH-Token', '')
        return bool(hdr) and hdr == _token()

    @app.route('/ach-mint', methods=['GET', 'POST'])
    def _ach_mint():
        # Internal-only: the :8080 gateway does not proxy /ach-mint, so this is reachable
        # solely from inside the docker network (n8n admin button).
        import secrets
        d = _auth_load()
        nonce = secrets.token_urlsafe(24)
        d['otps'][nonce] = time.time() + OTP_TTL
        _auth_save(d)
        return jsonify({'ok': True,
                        'url': PUBLIC_BASE.rstrip('/') + '/admin-chats?otp=' + nonce,
                        'ttl_min': OTP_TTL // 60})

    @app.get('/admin-chats/api')
    def _ach_api():
        if not _guard():
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
        src = request.args.get('src', 'tg')
        try:
            data = _tg_conversations(pg_dsn) if src == 'tg' else _web_conversations()
            return jsonify({'ok': True, 'src': src, 'conversations': data})
        except Exception as e:
            return jsonify({'ok': False, 'error': repr(e)[:200]}), 500

    @app.post('/admin-chats/del')
    def _ach_del():
        if not _guard():
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
        b = request.get_json(force=True, silent=True) or {}
        src = b.get('src', 'tg')
        try:
            if src == 'tg':
                import psycopg2
                with psycopg2.connect(pg_dsn) as c, c.cursor() as cur:
                    if b.get('mid'):
                        cur.execute("DELETE FROM bot_free_chat_log WHERE id=%s", (int(b['mid']),))
                    elif b.get('tg_id') is not None:
                        cur.execute("DELETE FROM bot_free_chat_log WHERE tg_id=%s", (int(b['tg_id']),))
                    else:
                        return jsonify({'ok': False, 'error': 'need mid or tg_id'}), 400
            else:
                import sqlite3
                con = sqlite3.connect(WEBUI_DB)
                try:
                    con.execute("DELETE FROM chat WHERE id=?", (str(b.get('id', '')),))
                    con.commit()
                finally:
                    con.close()
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': repr(e)[:200]}), 500

    @app.get('/admin-chats')
    def _ach_page():
        otp = request.args.get('otp', '')
        if otp:
            import secrets
            d = _auth_load()
            if d['otps'].pop(otp, 0) > time.time():   # valid -> consume it
                sid = secrets.token_hex(24)
                d['sessions'][sid] = time.time() + SESS_TTL
                _auth_save(d)
                resp = redirect('/admin-chats', code=302)
                resp.set_cookie('ach_sid', sid, max_age=SESS_TTL, httponly=True,
                                samesite='Lax', path='/admin-chats')
                return resp
            _auth_save(d)  # expired/unknown nonce: persist the prune, fall through to 401
        if not _guard():
            return Response(
                '<meta charset="utf-8"><h2>🔒 Посилання недійсне або сесія скінчилась</h2>'
                '<p>Відкрий у Telegram: <b>Адміністрування → 🗂 Історії чатів</b> — '
                'бот надішле свіже одноразове посилання (діє 10 хв).</p>',
                status=401, mimetype='text/html')
        return Response(_PAGE, mimetype='text/html; charset=utf-8')


_PAGE = r"""<!doctype html><html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Історії чатів</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--txt:#e6e8ec;--mut:#8b93a3;--acc:#4b8bff;--red:#ff5c5c;--user:#1e2a3f;--bot:#1c2620}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
header h1{font-size:16px;margin:0;font-weight:600}
.tab{padding:6px 14px;border:1px solid var(--line);border-radius:8px;cursor:pointer;background:var(--panel);color:var(--mut)}
.tab.on{color:#fff;border-color:var(--acc);background:#1b2740}
.wrap{display:flex;height:calc(100vh - 54px)}
.list{width:340px;min-width:280px;border-right:1px solid var(--line);overflow:auto}
.conv{padding:10px 14px;border-bottom:1px solid var(--line);cursor:pointer}
.conv:hover{background:#12151b}.conv.on{background:#1b2740}
.conv .who{font-weight:600}.conv .meta{color:var(--mut);font-size:12px;margin-top:2px}
.main{flex:1;overflow:auto;padding:16px}
.msg{margin:0 0 10px;padding:10px 12px;border-radius:10px;white-space:pre-wrap;word-break:break-word}
.q{background:var(--user)}.a{background:var(--bot)}
.role{color:var(--mut);font-size:12px;margin-bottom:4px;text-transform:uppercase;letter-spacing:.03em}
.del{color:var(--red);border:1px solid var(--red);background:none;border-radius:6px;padding:3px 9px;cursor:pointer;font-size:12px}
.del:hover{background:#2a1414}
.rowhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:10px;flex-wrap:wrap}
.empty{color:var(--mut);padding:30px;text-align:center}
.mid-del{float:right;margin-left:8px}
small.warn{color:var(--mut)}
</style></head><body>
<header>
  <h1>🗂️ Історії чатів</h1>
  <div class="tab on" id="tab-tg" onclick="setSrc('tg')">Telegram</div>
  <div class="tab" id="tab-web" onclick="setSrc('web')">Open WebUI</div>
  <small class="warn" id="cnt"></small>
</header>
<div class="wrap">
  <div class="list" id="list"></div>
  <div class="main" id="main"><div class="empty">Оберіть розмову ліворуч</div></div>
</div>
<script>
let SRC='tg', DATA=[], CUR=null;
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function load(){
  const r = await fetch(`admin-chats/api?src=${SRC}`, {credentials:'same-origin'});
  if(r.status===401){document.getElementById('cnt').textContent='сесія скінчилась — відкрий свіже посилання з Telegram';return;}
  const j = await r.json();
  DATA = j.ok ? j.conversations : [];
  document.getElementById('cnt').textContent = j.ok ? (DATA.length+' розмов') : ('помилка: '+(j.error||''));
  renderList();
  document.getElementById('main').innerHTML='<div class="empty">Оберіть розмову ліворуч</div>';
  CUR=null;
}
function renderList(){
  const el=document.getElementById('list');
  if(!DATA.length){el.innerHTML='<div class="empty">Порожньо</div>';return;}
  el.innerHTML = DATA.map((c,i)=>`<div class="conv" id="c${i}" onclick="open_(${i})">
     <div class="who">${esc(c.who)}</div>
     <div class="meta">${SRC==='web'?esc(c.title)+' · ':''}${c.count} повід. · ${(c.last||'').replace('T',' ').slice(0,16)}</div></div>`).join('');
}
function open_(i){
  CUR=i;
  [...document.querySelectorAll('.conv')].forEach(x=>x.classList.remove('on'));
  const cc=document.getElementById('c'+i); if(cc) cc.classList.add('on');
  const c=DATA[i]; const m=document.getElementById('main');
  let h=`<div class="rowhead"><div><b>${esc(c.who)}</b> <small class="warn">${SRC==='web'?esc(c.title):''}</small></div>
    <button class="del" onclick="delConv(${i})">🗑 Видалити всю розмову</button></div>`;
  if(SRC==='tg'){
    h += c.messages.map(x=>`
      <div class="msg q"><div class="role">користувач · ${(x.ts||'').replace('T',' ').slice(0,16)}
        <button class="del mid-del" onclick="delMsg(${x.mid},${i})">видалити</button></div>${esc(x.q)}</div>
      <div class="msg a"><div class="role">бот</div>${esc(x.a)}</div>`).join('');
  } else {
    h += c.messages.map(x=>`<div class="msg ${x.role==='user'?'q':'a'}"><div class="role">${esc(x.role)}</div>${esc(x.content)}</div>`).join('');
  }
  m.innerHTML=h;
}
async function post(body){
  const r=await fetch(`admin-chats/del`,{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(Object.assign({src:SRC},body))});
  return r.json();
}
async function delConv(i){
  const c=DATA[i];
  if(!confirm('Видалити всю розмову з "'+c.who+'"? Це незворотно.'))return;
  const body = SRC==='tg' ? {tg_id:c.tg_id} : {id:c.id};
  const j=await post(body); if(j.ok){load();}else{alert('Помилка: '+(j.error||''));}
}
async function delMsg(mid,i){
  if(!confirm('Видалити це повідомлення?'))return;
  const j=await post({mid:mid}); if(j.ok){load();}else{alert('Помилка: '+(j.error||''));}
}
function setSrc(s){SRC=s;document.getElementById('tab-tg').classList.toggle('on',s==='tg');
  document.getElementById('tab-web').classList.toggle('on',s==='web');load();}
load();
</script></body></html>"""
