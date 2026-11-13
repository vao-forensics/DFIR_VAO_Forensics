#!/usr/bin/env python3
# Runs INSIDE open-webui: loads the INSTALLED dfir_files filter (code+valves from webui.db) and pushes a
# tiny CSV through the real sandbox API with the installed token. Checks: active+global, real token
# accepted (analysis returns ok), wrong token refused. Exit 0 = PASS.
import json, os, sqlite3, sys, types, uuid
db = sqlite3.connect("/app/backend/data/webui.db")
act, glob, content, valves = db.execute("select is_active,is_global,content,valves from function where id=\x27dfir_files\x27").fetchone()
res = {"active_global": bool(act and glob)}
mod = types.ModuleType("f"); exec(compile(content, "dfir_files", "exec"), mod.__dict__)
flt = mod.Filter(); flt.valves = flt.Valves(**(json.loads(valves or "{}")))
p = "/app/backend/data/uploads/suptest_%s.csv" % uuid.uuid4().hex[:8]
open(p, "w").write("ts,user\n2026-01-01T00:00:00Z,test\n")
try:
    r = flt._call(p, ticket="suptest")
    res["real_token_ok"] = bool(r.get("ok"))
    res["real_err"] = r.get("error")
    flt.valves.token = "wrong"
    r2 = flt._call(p, ticket="suptest2")
    res["wrong_token_refused"] = not r2.get("ok")
finally:
    os.remove(p)
print(json.dumps(res, ensure_ascii=False))
sys.exit(0 if res["active_global"] and res["real_token_ok"] and res["wrong_token_refused"] else 1)
