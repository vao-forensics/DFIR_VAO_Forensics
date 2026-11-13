#!/usr/bin/env python3
# Runs INSIDE open-webui: upload a file as admin, then ask a model about it via
# the normal chat endpoint (filters apply exactly as for a browser user).
import json, os, sqlite3, sys, time, uuid, urllib.request
import jwt

BASE = "http://127.0.0.1:8080"
fpath, model, question = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect("/app/backend/data/webui.db")
admin = db.execute("select id from user where role='admin' order by created_at limit 1").fetchone()[0]
# Open WebUI >= 0.13 rejects a token whose session_stamp differs from the account's (new accounts have one)
_cols = [r[1] for r in db.execute("pragma table_info(auth)")]
_stamp = db.execute("select session_stamp from auth where id=?", (admin,)).fetchone()[0] if "session_stamp" in _cols else None
_claims = {"id": admin}
if _stamp is not None:
    _claims["session_stamp"] = _stamp
tok = jwt.encode(_claims, os.environ["WEBUI_SECRET_KEY"], algorithm="HS256")

# multipart upload
bnd = uuid.uuid4().hex
data = open(fpath, "rb").read()
body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
         "Content-Type: application/octet-stream\r\n\r\n" % (bnd, os.path.basename(fpath))).encode()
        + data + ("\r\n--%s--\r\n" % bnd).encode())
req = urllib.request.Request(BASE + "/api/v1/files/?process=false", data=body, method="POST",
                             headers={"Authorization": "Bearer " + tok,
                                      "Content-Type": "multipart/form-data; boundary=" + bnd})
f = json.loads(urllib.request.urlopen(req, timeout=120).read())
print("uploaded id:", f["id"][:8], "path ok:", bool(f.get("path")))

payload = {"model": model, "stream": False,
           "messages": [{"role": "user", "content": question}],
           "files": [{"type": "file", "id": f["id"], "file": f, "name": os.path.basename(fpath)}]}
t0 = time.time()
req = urllib.request.Request(BASE + "/api/chat/completions", data=json.dumps(payload).encode(),
                             method="POST", headers={"Authorization": "Bearer " + tok,
                                                     "Content-Type": "application/json"})
try:
    r = json.loads(urllib.request.urlopen(req, timeout=1800).read())
    ans = r["choices"][0]["message"]["content"]
except urllib.error.HTTPError as e:
    ans = "HTTP %s: %s" % (e.code, e.read().decode()[:500])
print("answer in %.0fs:\n" % (time.time() - t0) + ans)
