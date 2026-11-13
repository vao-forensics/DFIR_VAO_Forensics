#!/usr/bin/env python3
"""DFIR portal supervisor (runs on the VM, called every 3h by the host task).
Checks that built components still work and that open tasks are progressing.
Writes /srv/dfir/state/supervisor_last.json. Exit codes:
  0  = all good, nothing to do
  10 = the repair agent must be woken (component broken, or open tasks stalled)
Notifies the owner (chat CHANGE_ME_OWNER_CHAT_ID ONLY) when the verdict changes or every 12h
while not ok. Never sends secrets or case data."""
import json, os, subprocess, sys, time, datetime, urllib.request, urllib.parse

ROOT = os.environ.get("DFIR_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
LEDGER = ROOT + "/docs/portal_tasks.json"
OUT = ROOT + "/state/supervisor_last.json"
STALL_H = 8          # open tasks + no relevant commit for this long = stall
NOTIFY_EVERY_H = 12
OWNER_CHAT = "CHANGE_ME_OWNER_CHAT_ID"


def sh(cmd, t=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.returncode, (r.stdout or "").strip()
    except Exception as e:
        return 1, str(e)


def checks():
    bad = []
    rc, o = sh("systemctl is-active owui-retention.timer")
    if o != "active":
        bad.append("чистка 24 год (owui-retention.timer) не активна")
    rc, o = sh("systemctl is-active dfir-sandbox-api")
    if o != "active":  # right after a reboot the unit may still be starting: give it a minute
        time.sleep(60)
        rc, o = sh("systemctl is-active dfir-sandbox-api")
    if o != "active":
        bad.append("API пісочниці (dfir-sandbox-api) не працює")
    rc, o = sh("docker image inspect dfir-sandbox:0.1 >/dev/null 2>&1 && echo ok")
    if o != "ok":
        bad.append("образ dfir-sandbox:0.1 зник")
    rc, o = sh("""docker exec open-webui python3 -c "import sqlite3;r=sqlite3.connect('/app/backend/data/webui.db').execute(\\"select is_active,is_global from function where id='dfir_files'\\").fetchone();print(r)" """)
    if "(1, 1)" not in o:
        bad.append("фільтр OWUI dfir_files вимкнено/видалено (%s)" % o[:40])
    rc, o = sh("""docker exec open-webui python3 -c "import urllib.request;print(urllib.request.urlopen('http://172.18.0.1:8791/status',timeout=5).status)" """)
    if o.strip() != "200":
        bad.append("OWUI не досягає API пісочниці")
    # smoke: a tiny plain file through the whole pipeline (no case data)
    sh("printf 'ts,user\\n2026-01-01T00:00:00Z,test\\n' > /tmp/sup_smoke.csv")
    rc, o = sh("{r}/sandbox/analyze_file.sh /tmp/sup_smoke.csv sup_smoke && test -s {r}/sandbox/jobs/sup_smoke/out/report.md && echo ok; rm -rf {r}/sandbox/jobs/sup_smoke /tmp/sup_smoke.csv".format(r=ROOT), 300)
    if not o.endswith("ok"):
        bad.append("димовий тест пісочниці не пройшов")
    # isolation must hold
    rc, o = sh("docker run --rm --network none --user 65534:65534 --cap-drop ALL --read-only "
               "--tmpfs /work:size=16m --tmpfs /tmp:size=8m -v " + ROOT + "/sandbox/isolation_probe.py:/p.py:ro "
               "dfir-sandbox:0.1 python3 /p.py | python3 -c \"import sys,json;print(json.load(sys.stdin)['all_contained'])\"", 120)
    if o.strip() != "True":
        bad.append("ІЗОЛЯЦІЯ пісочниці порушена")
    return bad


def progress():
    led = json.load(open(LEDGER, encoding="utf-8"))
    tasks = led.get("tasks", [])
    open_t = [t for t in tasks if t.get("status") in ("todo", "doing")]
    fake = [t["id"] for t in tasks if t.get("status") == "done" and not t.get("evidence")]
    rc, o = sh("cd %s && git log -1 --format=%%ct -- sandbox docs scripts" % ROOT)
    last = int(o) if o.isdigit() else 0
    idle_h = (time.time() - last) / 3600 if last else 999
    return open_t, fake, idle_h


def notify(text):
    try:
        tok = ""
        for ln in open(ROOT + "/.env", encoding="utf-8"):
            if ln.startswith("DFIR_TG_BOT_TOKEN="):
                tok = ln.split("=", 1)[1].strip()
        if not tok:
            return
        data = urllib.parse.urlencode({"chat_id": OWNER_CHAT, "text": text}).encode()
        urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % tok, data=data, timeout=20)
    except Exception:
        pass


def main():
    bad = checks()
    open_t, fake, idle_h = progress()
    stalled = bool(open_t) and idle_h >= STALL_H
    verdict = "ok"
    if bad or fake:
        verdict = "broken"
    elif stalled:
        verdict = "stalled"
    prev = {}
    if os.path.exists(OUT):
        try:
            prev = json.load(open(OUT))
        except Exception:
            prev = {}
    now = int(time.time())
    res = {"ts": now, "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), "verdict": verdict,
           "broken": bad, "done_without_evidence": fake, "open_tasks": [t["id"] + " " + t["title"] for t in open_t],
           "hours_since_progress": round(idle_h, 1), "last_notify": prev.get("last_notify", 0)}
    if verdict != "ok" and (verdict != prev.get("verdict") or now - prev.get("last_notify", 0) > NOTIFY_EVERY_H * 3600):
        msg = ["🛡 Наглядач DFIR-порталу: %s" % {"broken": "ПОЛАМКА", "stalled": "ЗАСТІЙ"}[verdict]]
        msg += ["• " + b for b in bad]
        if fake:
            msg.append("• позначено «зроблено» без доказу: " + ", ".join(fake))
        if stalled:
            msg.append("• відкритих завдань: %d, прогресу нема %.0f год" % (len(open_t), idle_h))
        msg.append("Запускаю агента-ремонтника, щоб довів до кінця.")
        notify("\n".join(msg))
        res["last_notify"] = now
    json.dump(res, open(OUT, "w"), ensure_ascii=False, indent=1)
    print(json.dumps({k: res[k] for k in ("verdict", "broken", "hours_since_progress")}, ensure_ascii=False))
    sys.exit(0 if verdict == "ok" else 10)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--notify":
        notify(sys.argv[2][:3500]); sys.exit(0)
    main()
