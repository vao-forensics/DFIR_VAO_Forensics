#!/usr/bin/env python3
# Runs INSIDE the open-webui container. Installs/updates the DFIR file filter,
# sets its valves (API url + token), and makes it active + global.
import json, os, sqlite3, urllib.request
import jwt

FID = "dfir_files"
BASE = "http://127.0.0.1:8080"
code = open("/tmp/owui_filter_dfir_files.py", encoding="utf-8").read()
token_api = os.environ["SBX_TOKEN"]

db = sqlite3.connect("/app/backend/data/webui.db")
admin = db.execute("select id from user where role='admin' order by created_at limit 1").fetchone()[0]
# Open WebUI >= 0.13 rejects a token whose session_stamp differs from the account's (new accounts have one)
_cols = [r[1] for r in db.execute("pragma table_info(auth)")]
_stamp = db.execute("select session_stamp from auth where id=?", (admin,)).fetchone()[0] if "session_stamp" in _cols else None
_claims = {"id": admin}
if _stamp is not None:
    _claims["session_stamp"] = _stamp
tok = jwt.encode(_claims, os.environ["WEBUI_SECRET_KEY"], algorithm="HS256")
H = {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers=H,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


form = {"id": FID, "name": "DFIR — файли в пісочниці", "content": code,
        "meta": {"description": "Розбір прикріплених файлів в ізольованій пісочниці + правила проти зациклення"}}
st, cur = call("GET", "/api/v1/functions/id/" + FID)
if st == 200:
    print("update:", call("POST", "/api/v1/functions/id/%s/update" % FID, form)[0])
else:
    print("create:", call("POST", "/api/v1/functions/create", form)[0])

print("valves:", call("POST", "/api/v1/functions/id/%s/valves/update" % FID,
                      {"api_url": os.environ.get("SBX_URL", "http://172.18.0.1:8791/analyze"), "token": token_api,
                       "max_chars_per_file": 30000, "timeout_s": 1100, "max_mb": 2048})[0])
# upload limit in the browser = the sandbox limit (2 GB): a bigger file is refused at once instead of
# after a long upload; big evidence goes through the bot (up to 10 GB)
st, rc = call("GET", "/api/v1/retrieval/config")
if st == 200 and isinstance(rc, dict):
    print("upload limit:", call("POST", "/api/v1/retrieval/config/update", {"FILE_MAX_SIZE": 2048})[0])

st, cur = call("GET", "/api/v1/functions/id/" + FID)
if isinstance(cur, dict):
    if not cur.get("is_active"):
        print("toggle active:", call("POST", "/api/v1/functions/id/%s/toggle" % FID)[0])
    if not cur.get("is_global"):
        print("toggle global:", call("POST", "/api/v1/functions/id/%s/toggle/global" % FID)[0])
st, cur = call("GET", "/api/v1/functions/id/" + FID)
print("final:", {k: cur.get(k) for k in ("id", "type", "is_active", "is_global")} if isinstance(cur, dict) else (st, cur))

# the installer relies on the exit code: anything but an active, global filter is a failure
import sys
sys.exit(0 if isinstance(cur, dict) and cur.get("is_active") and cur.get("is_global") else 1)
