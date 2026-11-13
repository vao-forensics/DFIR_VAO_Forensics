#!/usr/bin/env python3
"""Runs INSIDE open-webui. For every model the chat offers, switch OFF Open WebUI's built-in tools
(knowledge search, view/display file...). Attached files are analysed by the DFIR sandbox filter;
with built-in tools on, tool-calling models (e.g. Qwen3-30B) ignore that analysis and loop on
display_file / view_knowledge_file. Existing names, descriptions and other settings are kept."""
import json, os, sqlite3, sys, urllib.request, urllib.parse
import jwt

BASE = "http://127.0.0.1:8080"
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
    r = urllib.request.Request(BASE + path, method=method, headers=H,
                               data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]


st, models = call("GET", "/api/models")
if st != 200:
    sys.exit("cannot list models: %s %s" % (st, models))
changed = 0
for m in models.get("data", []):
    mid = m["id"]
    st, cur = call("GET", "/api/v1/models/model?id=" + urllib.parse.quote(mid))
    if st == 200 and isinstance(cur, dict):
        meta = cur.get("meta") or {}
        caps = meta.get("capabilities") or {}
        if caps.get("builtin_tools") is False:
            continue
        caps["builtin_tools"] = False
        meta["capabilities"] = caps
        form = {"id": mid, "name": cur.get("name") or mid, "base_model_id": cur.get("base_model_id"),
                "meta": meta, "params": cur.get("params") or {}, "is_active": cur.get("is_active", True)}
        if cur.get("access_grants") is not None:
            form["access_grants"] = cur["access_grants"]
        st2, _ = call("POST", "/api/v1/models/model/update?id=" + urllib.parse.quote(mid), form)
    else:
        form = {"id": mid, "name": m.get("name") or mid, "base_model_id": None,
                "meta": {"capabilities": {"builtin_tools": False}}, "params": {}, "is_active": True}
        st2, _ = call("POST", "/api/v1/models/create", form)
    print(mid, "->", st2)
    changed += st2 == 200
print("models updated:", changed)
