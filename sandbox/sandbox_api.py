#!/usr/bin/env python3
"""Tiny local API (VM host) used by the Open WebUI filter.
POST /analyze  {"path": "/app/backend/data/uploads/<id>_<name>"}  + header X-Token
-> runs analyze_file.sh (decrypt in trusted zone if needed, then the disposable
sandbox) and returns {"report": "...md...", "context": "...json (truncated)..."}.
Binds ONLY to the Docker bridge gateway, accepts only files from the OWUI
uploads dir (path-traversal guarded), at most N jobs in parallel."""
import hashlib, json, os, subprocess, threading, time, uuid, shutil, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = os.environ.get("SBX_BIND", "172.18.0.1")
PORT = int(os.environ.get("SBX_PORT", "8791"))
TOKEN = os.environ.get("SBX_TOKEN", "")
OWUI_DATA_IN = "/app/backend/data"
OWUI_DATA_HOST = "/var/lib/docker/volumes/open-webui/_data"
UPLOADS_HOST = os.path.realpath(OWUI_DATA_HOST + "/uploads")
_HERE = os.path.dirname(os.path.realpath(__file__))
ANALYZE = os.environ.get("SBX_ANALYZE", os.path.join(_HERE, "analyze_file.sh"))
JOBS = os.environ.get("SBX_JOBS", os.path.join(_HERE, "jobs"))
MAX_CTX = int(os.environ.get("SBX_MAX_CTX", "60000"))
MAX_IN_MB = int(os.environ.get("SBX_MAX_IN_MB", "2048"))   # bigger evidence goes through the bot (up to 10 GB)
RUN_TIMEOUT = int(os.environ.get("SBX_RUN_TIMEOUT", "1000"))   # run_sandbox.sh kills the container at 900 s
SLOTS = threading.BoundedSemaphore(int(os.environ.get("SBX_PARALLEL", "2")))
STATE = {"running": 0, "waiting": 0, "done": 0, "failed": 0}
LOCK = threading.Lock()
LIVE = {}            # job -> {state, queued, started, size_mb}; no file names (privacy)
SLOT_N = int(os.environ.get("SBX_PARALLEL", "2"))
LLM_URL = os.environ.get("SBX_LLM_URL", "http://192.168.100.1:1234")
HOST_SSH = os.environ.get("SBX_HOST_SSH", "user@<llm-host>")
_CACHE = {}


def _cached(key, ttl, fn):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    try:
        val = fn()
    except Exception as e:
        val = {"error": type(e).__name__}
    _CACHE[key] = (now, val)
    return val


def _models():
    with urllib.request.urlopen(LLM_URL + "/running", timeout=5) as r:
        d = json.loads(r.read().decode("utf-8"))
    return [{"model": m.get("model"), "state": m.get("state")} for m in d.get("running", [])]


def _gpus():
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", HOST_SSH,
                        "nvidia-smi --query-gpu=index,utilization.gpu,memory.used,memory.total,temperature.gpu"
                        " --format=csv,noheader,nounits"], capture_output=True, text=True, timeout=15)
    out = []
    for ln in r.stdout.splitlines():
        f = [x.strip() for x in ln.split(",")]
        if len(f) == 5 and f[0].isdigit():
            out.append({"gpu": int(f[0]), "util": int(f[1]), "mem_used_mb": int(f[2]),
                        "mem_total_mb": int(f[3]), "temp_c": int(f[4])})
    return out


def snapshot():
    now = time.time()
    with LOCK:
        st = dict(STATE)
        jobs = sorted(LIVE.items(), key=lambda kv: kv[1]["queued"])
    lst = []
    for j, v in jobs:
        lst.append({"job": j[-6:], "state": v["state"], "size_mb": v["size_mb"],
                    "waited_s": int((v["started"] or now) - v["queued"]),
                    "running_s": int(now - v["started"]) if v["started"] else 0})
    st.update({"slots": SLOT_N, "jobs": lst, "models": _cached("m", 15, _models),
               "gpus": _cached("g", 60, _gpus), "time": int(now)})
    return st


def queue_pos(job):
    with LOCK:
        w = sorted((v["queued"], j) for j, v in LIVE.items() if v["state"] == "waiting")
    for i, (_, j) in enumerate(w):
        if j == job:
            return i + 1
    return 0


PAGE = """<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=10>
<title>DFIR портал: стан</title><style>body{font:15px system-ui;margin:2em;background:#111;color:#ddd}
table{border-collapse:collapse;margin:.5em 0 1.5em}td,th{border:1px solid #444;padding:4px 10px}
h2{color:#7cf}.ok{color:#6d6}.w{color:#fc6}</style><h1>Стан DFIR-порталу</h1><div id=b>завантаження…</div>
<script>fetch('status').then(r=>r.json()).then(s=>{let h='<h2>Черга аналізу</h2><p>Слотів: '+s.slots+
' · виконується: <b class=ok>'+s.running+'</b> · чекає: <b class=w>'+s.waiting+'</b> · готово: '+s.done+
' · помилок: '+s.failed+'</p><table><tr><th>завдання</th><th>стан</th><th>МБ</th><th>чекало, с</th><th>працює, с</th></tr>';
for(const j of s.jobs)h+='<tr><td>'+j.job+'</td><td>'+(j.state=='running'?'розбір':'у черзі')+'</td><td>'+j.size_mb+
'</td><td>'+j.waited_s+'</td><td>'+j.running_s+'</td></tr>';h+='</table><h2>Модель ШІ</h2><p>'+
(Array.isArray(s.models)?(s.models.map(m=>m.model+' ('+m.state+')').join(', ')||'жодна не завантажена'):'недоступно')+
'</p><h2>Відеокарти</h2><table><tr><th>GPU</th><th>завантаж., %</th><th>памʼять, МБ</th><th>°C</th></tr>';
if(Array.isArray(s.gpus))for(const g of s.gpus)h+='<tr><td>'+g.gpu+'</td><td>'+g.util+'</td><td>'+g.mem_used_mb+' / '+
g.mem_total_mb+'</td><td>'+g.temp_c+'</td></tr>';h+='</table><p>Оновлено: '+new Date(s.time*1000).toLocaleTimeString()+
'</p>';document.getElementById('b').innerHTML=h})</script>"""


def _bump(k, d):
    with LOCK:
        STATE[k] += d


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *args):
        pass  # never log request bodies/paths with case names

    def do_GET(self):
        if self.path == "/status":
            return self._send(200, snapshot())
        if self.path.startswith("/queue/"):
            return self._send(200, {"position": queue_pos(self.path[7:])})
        if self.path in ("/", "/status.html"):
            b = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/analyze":
            return self._send(404, {"error": "not found"})
        if TOKEN and self.headers.get("X-Token") != TOKEN:
            return self._send(403, {"error": "forbidden"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n) or b"{}")
            p_in = str(req.get("path", ""))
            ticket = str(req.get("ticket", ""))[:40]
            who = req.get("user") if isinstance(req.get("user"), dict) else {}
        except Exception:
            return self._send(400, {"error": "bad request"})
        if not p_in.startswith(OWUI_DATA_IN + "/"):
            return self._send(400, {"error": "path outside OWUI data"})
        host = os.path.realpath(OWUI_DATA_HOST + p_in[len(OWUI_DATA_IN):])
        if not host.startswith(UPLOADS_HOST + "/") or not os.path.isfile(host):
            return self._send(400, {"error": "file not found in uploads"})
        size_mb = os.path.getsize(host) / 1048576
        arow = {"owui_user_id": who.get("id"), "owui_email": who.get("email"), "owui_name": who.get("name"),
                "client_ip": who.get("ip"), "file_name": who.get("file_name") or os.path.basename(host),
                "size_bytes": os.path.getsize(host), "job": ticket}
        if size_mb > MAX_IN_MB:
            audit(dict(arow, verdict="refused", reason="too_big"))
            return self._send(413, {"ok": False, "error": "too_big", "size_mb": round(size_mb),
                                    "limit_mb": MAX_IN_MB})
        job = "owui_" + (ticket if ticket.isalnum() else uuid.uuid4().hex[:12])
        with LOCK:
            LIVE[job] = {"state": "waiting", "queued": time.time(), "started": 0,
                         "size_mb": round(os.path.getsize(host) / 1048576, 1)}
        _bump("waiting", 1)
        with SLOTS:
            _bump("waiting", -1); _bump("running", 1)
            with LOCK:
                LIVE[job].update(state="running", started=time.time())
            t_run = time.time()
            try:
                arow["sha256"] = _sha256(host)   # before the run: the upload itself, as received
            except Exception:
                pass
            try:
                r = subprocess.run([ANALYZE, host, job], capture_output=True, text=True, timeout=RUN_TIMEOUT)
                out = os.path.join(JOBS, job, "out")
                rep = ""
                ctx = ""
                if os.path.isfile(out + "/report.md"):
                    rep = open(out + "/report.md", encoding="utf-8").read()
                if os.path.isfile(out + "/context.json"):
                    ctx = open(out + "/context.json", encoding="utf-8").read()[:MAX_CTX]
                ok = bool(rep)
                _bump("done" if ok else "failed", 1)
                bomb = "архів-бомби" in rep
                audit(dict(arow, verdict="ok" if ok and not bomb else "limited" if ok else "failed",
                           reason="bomb" if bomb else "" if ok else _why(r), seconds=round(time.time() - t_run, 1)))
                self._send(200 if ok else 500, {"ok": ok, "report": rep, "context": ctx,
                                               "encrypted": "encrypted=yes" in r.stdout,
                                               "error": "" if ok else _why(r),
                                               "stderr": "" if ok else r.stderr[-400:]})
            except subprocess.TimeoutExpired:
                _bump("failed", 1)
                audit(dict(arow, verdict="failed", reason="timeout", seconds=round(time.time() - t_run, 1)))
                self._send(504, {"ok": False, "error": "timeout"})
            finally:
                _bump("running", -1)
                with LOCK:
                    LIVE.pop(job, None)
                shutil.rmtree(os.path.join(JOBS, job), ignore_errors=True)  # privacy: keep nothing


AUDIT_DDL = """CREATE TABLE IF NOT EXISTS public.portal_upload_audit_v1 (
    id bigserial PRIMARY KEY,
    ts timestamptz NOT NULL DEFAULT now(),
    owui_user_id text, owui_email text, owui_name text, client_ip text,
    file_name text, size_bytes bigint, sha256 text,
    verdict text NOT NULL, reason text, job text, seconds real);
CREATE INDEX IF NOT EXISTS portal_upload_audit_v1_ts ON public.portal_upload_audit_v1 (ts DESC);
CREATE INDEX IF NOT EXISTS portal_upload_audit_v1_email ON public.portal_upload_audit_v1 (owui_email);
-- private: the MCP / LLM read-only role must not see who uploaded what
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dfir_mcp') THEN REVOKE ALL ON public.portal_upload_audit_v1 FROM dfir_mcp; END IF; END $$;
"""
AUDIT_COLS = ("owui_user_id", "owui_email", "owui_name", "client_ip", "file_name", "size_bytes", "sha256",
              "verdict", "reason", "job", "seconds")


def _psql(sql, params=None):
    """through the logdb container (same as the rest of the stack): no DB password on this side.
    Values go in as psql variables (:'v'), so they are quoted by psql, never pasted into SQL."""
    args = ["docker", "exec", "-i", "logdb", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "dfir", "-d", "dfir_logs"]
    for k, v in (params or {}).items():
        args += ["-v", "%s=%s" % (k, "" if v is None else str(v).replace("\n", " ")[:500])]
    return subprocess.run(args, input=sql, capture_output=True, text=True, timeout=30)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def audit(row):
    """one row per file; never breaks the analysis if the DB is down (then a local jsonl line stays)"""
    try:
        line = json.dumps(dict(row, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), ensure_ascii=False)
        with open(os.path.join(os.path.dirname(os.path.dirname(JOBS)), "state", "portal_upload_audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
        sql = ("INSERT INTO public.portal_upload_audit_v1 (%s) VALUES (%s);" % (
            ", ".join(AUDIT_COLS),
            ", ".join("NULLIF(:'%s','')%s" % (c, "::bigint" if c == "size_bytes" else "::real" if c == "seconds" else "")
                      for c in AUDIT_COLS)))
        r = _psql(sql, {c: row.get(c) for c in AUDIT_COLS})
        if r.returncode != 0:
            print("audit insert failed:", r.stderr[-200:], flush=True)
    except Exception as e:
        print("audit failed:", repr(e)[:200], flush=True)


def _why(r):
    """a short machine reason the filter turns into a sentence for the user"""
    t = (r.stdout or "") + (r.stderr or "")
    if "bomb cap" in t:
        return "bomb"
    if r.returncode in (137, -9) or "Killed" in t:
        return "killed"
    if "password" in t.lower() or "encrypted" in t.lower():
        return "password"
    return "failed"

if __name__ == "__main__":
    def _ensure_audit_table():
        # after a power loss postgres may still be recovering: retry quietly until it accepts the DDL
        for i in range(60):
            _r = _psql(AUDIT_DDL)
            if _r.returncode == 0:
                if i:
                    print("audit table ready after %d retries" % i, flush=True)
                return
            if i == 0:
                print("audit table not ready (will retry):", _r.stderr[-200:], flush=True)
            time.sleep(10)
        print("audit table still not ready after 10 min; jsonl fallback stays", flush=True)
    threading.Thread(target=_ensure_audit_table, daemon=True).start()
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
