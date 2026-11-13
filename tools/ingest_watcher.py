#!/usr/bin/env python3
"""Persistent ingest-progress watcher (SAFE: DB reads + Telegram + one /dfir-start call per case;
never edits case-maintainer state). Runs as systemd service dfir-ingest-watcher.

2026-10-08 rewrite after the 12-user training session:
- auto DFIR start is made ON BEHALF OF THE UPLOADER (chat_id from the upload's .info.json),
  not the owner — the report is delivered to whoever triggered the job, so reports were
  going to the owner instead of the clients;
- no auto start when the case already has a queued/running DFIR job or a fresh completed one
  (a second start reconciled the client's queued job as "stale" and pushed it to the end);
- jobs are watched for 6 h, not 45 min: under load ingest+scan took ~50 min and case 123
  dropped out of the window and never got its analysis;
- admin feed to the OWNER ONLY: who uploaded, parse done, analysis started, report delivered.
"""
import subprocess, json, time, urllib.request, io, os, glob

ADMIN = "CHANGE_ME_OWNER_CHAT_ID"
CASES = "/srv/dfir/cases"
WINDOW = "6 hours"


def token():
    try:
        return io.open("/root/.dfir_bot_token").read().strip()
    except Exception:
        r = subprocess.run(["docker", "exec", "case-maintainer", "python3", "-c",
                            "from core.config import TG_BOT_TOKEN; print(TG_BOT_TOKEN)"],
                           capture_output=True, text=True, timeout=15)
        return (r.stdout or "").strip()


TOKEN = token()
AUTO_DFIR = os.environ.get("AUTO_DFIR_ON_INGEST", "1") == "1"


def q(sql):
    r = subprocess.run(["docker", "exec", "logdb", "psql", "-U", "dfir", "-d", "dfir_logs", "-F", "|", "-tA", "-c", sql],
                       capture_output=True, text=True, timeout=20)
    return [l.split("|") for l in (r.stdout or "").splitlines() if l.strip()]


def uploader(ck):
    """chat_id of whoever uploaded the case's logs (newest .info.json)."""
    files = sorted(glob.glob(os.path.join(CASES, ck, "uploads", "logs", "*.info.json")), key=os.path.getmtime)
    for f in reversed(files):
        try:
            cid = str((json.load(open(f)).get("MetaData") or {}).get("chat_id") or "")
            if cid.isdigit():
                return cid
        except Exception:
            pass
    return None


_names = {}
def who(cid):
    if not cid:
        return "невідомо"
    if cid not in _names:
        rows = q("select coalesce(first_name,'')||' '||coalesce(last_name,''), coalesce(username,'') "
                 "from bot_users where user_id::text='%s'" % cid.replace("'", ""))
        if rows:
            name, un = rows[0][0].strip(), rows[0][1].strip()
            _names[cid] = "%s%s (%s)" % (name or "?", (" @" + un) if un else "", cid)
        else:
            _names[cid] = cid
    return _names[cid]


def recent_scans():
    out = []
    for p in q("select job_id,case_key,status,coalesce(stage,''),coalesce(progress,0) from trigger_scan_jobs_v2 "
               "where started_at > now() - interval '%s' order by started_at desc limit 60" % WINDOW):
        if len(p) >= 5:
            try:
                out.append((p[0], p[1], p[2].strip(), p[3].strip(), int(float(p[4] or 0))))
            except Exception:
                pass
    return out


def dfir_busy(ck):
    rows = q("select count(*) from dfir_run_jobs_v2 where case_key='%s' and (status in ('queued','running') "
             "or (status='completed' and finished_at > now() - interval '3 hours'))" % ck.replace("'", ""))
    return bool(rows and rows[0][0] not in ("0", ""))


def auto_start_dfir(ck, cid):
    try:
        payload = json.dumps({"case_key": ck, "chat_id": cid, "user_id": cid})
        code = ("import urllib.request,json;"
                "req=urllib.request.Request('http://localhost:8787/dfir-start',"
                "data=%r.encode(),headers={'Content-Type':'application/json'});"
                "print(urllib.request.urlopen(req,timeout=25).getcode())" % payload)
        r = subprocess.run(["docker", "exec", "case-maintainer", "python3", "-c", code],
                           capture_output=True, text=True, timeout=35)
        return (r.stdout or r.stderr or "").strip()[:60]
    except Exception as e:
        return "err:%s" % str(e)[:40]


def tg(method, payload):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request("https://api.telegram.org/bot%s/%s" % (TOKEN, method),
                                 data=data, headers={"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=12).read().decode("utf-8"))
    except Exception:
        return {}


def admin(text):
    tg("sendMessage", {"chat_id": ADMIN, "text": text})


scan_state = {}   # job_id -> {mid, last, done}
dfir_seen = {}    # job_id -> last announced state
first = True
while True:
    try:
        # ── parse progress + auto DFIR start ──────────────────────────────
        for job_id, ck, status, stage, pct in recent_scans():
            pct = max(0, min(100, pct))
            s = scan_state.setdefault(job_id, {"mid": None, "last": -1, "done": False})
            if first and status in ("done", "failed", "interrupted"):
                s["done"] = True
                continue
            cid = uploader(ck)
            if status in ("done", "failed"):
                if not s["done"]:
                    if status == "done":
                        res = ""
                        if AUTO_DFIR and cid and not dfir_busy(ck):
                            res = auto_start_dfir(ck, cid)
                            tail = "🚀 DFIR-аналіз запущено автоматично від імені клієнта — звіт піде йому."
                        elif dfir_busy(ck):
                            tail = "ℹ️ Аналіз уже в черзі/роботі (клієнт запустив сам) — дубль не створюю."
                        else:
                            tail = "⚠️ Не знайшов, хто заливав, — аналіз НЕ запущено автоматично."
                        txt = "✅ Парсинг завершено 100%%\nКейс: %s\n👤 %s\n\n%s" % (ck, who(cid), tail)
                    else:
                        txt = "❌ Парсинг завершився помилкою\nКейс: %s\n👤 %s\nЕтап: %s" % (ck, who(cid), stage)
                    if s["mid"]:
                        tg("editMessageText", {"chat_id": ADMIN, "message_id": s["mid"], "text": txt})
                    else:
                        admin(txt)
                    s["done"] = True
            elif status == "running" and pct != s["last"]:
                s["last"] = pct
                bar = ("#" * (pct // 10)) + ("-" * (10 - pct // 10))
                txt = "🔬 Парсинг логів у кейс…\n[%s] %d%%\nЕтап: %s\nКейс: %s\n👤 %s" % (bar, pct, stage, ck, who(cid))
                if s["mid"]:
                    tg("editMessageText", {"chat_id": ADMIN, "message_id": s["mid"], "text": txt})
                else:
                    r = tg("sendMessage", {"chat_id": ADMIN, "text": txt})
                    s["mid"] = (r.get("result") or {}).get("message_id")

        # ── admin feed: analysis started / report delivered (owner only) ──
        for p in q("select j.job_id, j.case_key, j.status, coalesce(j.triggered_by_chat_id,''), "
                   "(select count(*) from dfir_case_reports_v1 r where r.job_id=j.job_id::text) "
                   "from dfir_run_jobs_v2 j where j.created_at > now() - interval '%s'" % WINDOW):
            if len(p) < 5:
                continue
            jid, ck, st, cid, delivered = p[0], p[1], p[2], p[3], p[4] not in ("0", "")
            key = "delivered" if delivered else st
            if first:
                dfir_seen[jid] = key
                continue
            if dfir_seen.get(jid) == key:
                continue
            dfir_seen[jid] = key
            if key == "running":
                admin("▶️ Почався DFIR-аналіз\nКейс: %s\n👤 Звіт отримає: %s" % (ck, who(cid)))
            elif key == "delivered":
                admin("📨 Звіт ДОСТАВЛЕНО клієнту\nКейс: %s\n👤 %s" % (ck, who(cid)))
            elif key == "failed":
                # a reconciled job that already has a newer replacement is bookkeeping (planned
                # restart, client re-pressed start), not a failure the owner must act on
                newer = q("select count(*) from dfir_run_jobs_v2 where case_key='%s' and created_at > "
                          "(select created_at from dfir_run_jobs_v2 where job_id::text='%s')"
                          % (ck.replace("'", ""), jid.replace("'", "")))
                if not (newer and newer[0][0] not in ("0", "")):
                    admin("⚠️ DFIR-аналіз позначено failed\nКейс: %s\n👤 %s" % (ck, who(cid)))
        first = False
        if len(scan_state) > 400:
            scan_state.clear()
    except Exception:
        pass
    time.sleep(5)
