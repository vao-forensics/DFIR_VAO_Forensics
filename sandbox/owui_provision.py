#!/usr/bin/env python3
"""Runs INSIDE the open-webui container (installer step "portal").
Installs the portal functions from /tmp/portal_fn/ (filters: active + global; pipes: active) and registers the
personal sandbox as an OpenAPI tool server for every user. Idempotent: re-running updates in place.
Env: WEBUI_SECRET_KEY (container), USBX_URL, USBX_TOKEN. Exit 1 if anything is not in place at the end."""
import json, os, sqlite3, sys, urllib.request, urllib.error
import jwt

BASE = "http://127.0.0.1:8080"
SRC = "/tmp/portal_fn"
FUNCS = [  # (id, file, type, name)
    ("dfir_model_router", "owui_filter_model_router.py", "filter", "DFIR — диспетчер моделей"),
    ("dfir_identity_guard", "owui_filter_identity_guard.py", "filter", "DFIR — ідентичність асистента"),
    ("dfir_user_profile", "owui_filter_user_profile.py", "filter", "DFIR — профіль користувача"),
    ("dfir_live_status", "owui_filter_live_status.py", "filter", "DFIR — статус завантаження моделі"),
    ("dfir_skills", "owui_filter_skills.py", "filter", "DFIR — навички"),
    ("dfir_storage", "owui_pipe_storage.py", "pipe", "📊 Сховище користувачів (адмін)"),
]

db = sqlite3.connect("/app/backend/data/webui.db")
admin = db.execute("select id from user where role='admin' order by created_at limit 1").fetchone()[0]
cols = [r[1] for r in db.execute("pragma table_info(auth)")]
stamp = db.execute("select session_stamp from auth where id=?", (admin,)).fetchone()[0] if "session_stamp" in cols else None
claims = {"id": admin}
if stamp is not None:
    claims["session_stamp"] = stamp
H = {"Authorization": "Bearer " + jwt.encode(claims, os.environ["WEBUI_SECRET_KEY"], algorithm="HS256"),
     "Content-Type": "application/json"}


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers=H,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


ok = True
for fid, fn, ftype, name in FUNCS:
    p = os.path.join(SRC, fn)
    if not os.path.exists(p):
        print("missing", fn); ok = False; continue
    form = {"id": fid, "name": name, "content": open(p, encoding="utf-8").read(), "meta": {"description": name}}
    st, cur = call("GET", "/api/v1/functions/id/" + fid)
    st2, _ = (call("POST", "/api/v1/functions/id/%s/update" % fid, form) if st == 200
              else call("POST", "/api/v1/functions/create", form))
    st, cur = call("GET", "/api/v1/functions/id/" + fid)
    if not isinstance(cur, dict):
        print(fid, "not created:", st2); ok = False; continue
    if not cur.get("is_active"):
        call("POST", "/api/v1/functions/id/%s/toggle" % fid)
    if ftype == "filter" and not cur.get("is_global"):
        call("POST", "/api/v1/functions/id/%s/toggle/global" % fid)
    st, cur = call("GET", "/api/v1/functions/id/" + fid)
    good = isinstance(cur, dict) and cur.get("is_active") and (ftype != "filter" or cur.get("is_global"))
    print(fid, "ok" if good else "NOT ACTIVE")
    ok = ok and bool(good)

# personal sandbox = tool server for everybody (the gateway identifies the user by the forwarded header)
url, key = os.environ.get("USBX_URL"), os.environ.get("USBX_TOKEN")
if url and key:
    st, cfg = call("GET", "/api/v1/configs/tool_servers")
    conns = (cfg or {}).get("TOOL_SERVER_CONNECTIONS", []) if st == 200 else []
    conns = [c for c in conns if (c.get("info") or {}).get("id") != "usandbox"]
    conns.append({"url": url, "path": "openapi.json", "type": "openapi", "auth_type": "bearer", "key": key,
                  "config": {"enable": True, "access_grants": [{"principal_type": "user", "principal_id": "*",
                                                                 "permission": "read"}]},
                  "info": {"id": "usandbox", "name": "Персональна пісочниця",
                           "description": "Виконання коду й встановлення інструментів у ізольованій персональній пісочниці"}})
    st, _ = call("POST", "/api/v1/configs/tool_servers", {"TOOL_SERVER_CONNECTIONS": conns})
    print("tool server usandbox:", st)
    ok = ok and st == 200
sys.exit(0 if ok else 1)
