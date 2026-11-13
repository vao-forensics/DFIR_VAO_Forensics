#!/usr/bin/env python3
"""Автономна QA-система порталу (Web UI + бот Telegram). Ролі:
  ТЕСТУВАЛЬНИК — ганяє перевірки (контейнери, сервіси, портал, GPU, бот, інструменти, диск).
  НАЧАЛЬНИК    — перевіряє результати тестувальника (крос-валідація + опц. LLM-рецензія).
  ФІКСЕР       — лагодить ЛИШЕ безпечне зі списку (рестарт мертвого, вбивство завислого); решта → алерт.
  НАДЗОРНИК    — пише журнал і сповіщає власника (чат CHANGE_ME_OWNER_CHAT_ID) про справжні збої/фікси.
Нічого руйнівного. Без секретів і даних справ."""
import json, os, re, subprocess, time, urllib.request, urllib.error, sys
ROOT = os.environ.get("DFIR_ROOT", "/srv/dfir")

OWNER_CHAT = "CHANGE_ME_OWNER_CHAT_ID"
STATE = os.path.join(ROOT, "state")
QA_LOG = os.path.join(STATE, "qa_log.jsonl")
VM_SWAP = os.environ.get("DFIR_PORTAL_LLM", "http://192.168.100.1:1234")
LLM = VM_SWAP + "/v1/chat/completions"


def sh(cmd, t=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:
        return 124, "", str(e)[:200]


def http(url, timeout=10, data=None, headers=None, method=None):
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)[:120]


# ---------------- ТЕСТУВАЛЬНИК ----------------
def tester():
    f = []  # findings: {name, status(ok/warn/fail), evidence, fix(cmd or None)}

    def add(name, status, ev, fix=None):
        f.append({"name": name, "status": status, "evidence": ev, "fix": fix})

    # 1. контейнери
    rc, out, _ = sh("docker ps --format '{{.Names}}|{{.Status}}'")
    running = {}
    for ln in out.splitlines():
        if "|" in ln:
            n, s = ln.split("|", 1); running[n] = s
    for c in ["open-webui", "logdb", "case-maintainer", "dfir-uploader"]:
        if c not in running:
            add("container:" + c, "fail", "не запущений", "docker start %s" % c)
        elif "unhealthy" in running[c].lower():
            add("container:" + c, "fail", running[c], "docker restart %s" % c)
        else:
            add("container:" + c, "ok", running[c])

    # 2. сервіси
    for s in ["dfir-sp-gateway", "dfir-usandbox-gw", "nginx", "tinyproxy"]:
        if sh("systemctl cat %s" % s)[0] != 0:
            continue  # not part of this install (e.g. no Silent Push key, no host nginx)
        rc, out, _ = sh("systemctl is-active %s" % s)
        add("service:" + s, "ok" if out == "active" else "fail", out, None if out == "active" else "systemctl restart %s" % s)

    # 3. портал HTTPS
    st, _ = http("https://127.0.0.1/api/config", timeout=10)
    if st != 200:
        st2, _ = http("http://127.0.0.1:3000/api/config", timeout=10)
        add("portal", "ok" if st2 == 200 else "fail", "https=%s http3000=%s" % (st, st2), None if st2 == 200 else "docker restart open-webui")
    else:
        add("portal", "ok", "https 200")

    # 4. GPU-hog: завислий бенч/перебір, що тримає карти під час роботи.
    # точний матч python-процесу run_bench.py / hashcat, без ловлення власних команд
    rc, out, _ = sh("pgrep -af 'python3? .*run_bench\\.py|[h]ashcat' | grep -vE 'pgrep|portal_qa' || true")
    hog = [ln for ln in out.splitlines() if ln.strip() and "run_bench.py" in ln or "hashcat" in ln.lower()]
    # легітимний керований бенч має свіжий flag — не вбивати (вбиваємо лише ОРФАНІВ/застряглих >2год)
    _flag = os.path.join(ROOT, "state/bench_active")
    _legit = os.path.exists(_flag) and (time.time() - os.path.getmtime(_flag) < 7200)
    if hog and _legit:
        add("gpu-hog", "ok", "легітимний бенч (flag свіжий)")
        hog = []
    if hog:
        pid = hog[0].split()[0]
        add("gpu-hog", "fail", "завислий процес тримає карти: " + hog[0][:120], "kill -9 %s" % pid)
    else:
        add("gpu-hog", "ok", "немає сторонніх на GPU")

    # 5. сервер моделей
    st, body = http(VM_SWAP + "/running", timeout=8)
    add("model-server", "ok" if st == 200 else "warn", "running=%s" % st)

    # 6. шлюз Silent Push функціонально (/quota — не витрачає ліміт)
    try:
        import sqlite3
        tok = [x for x in json.loads(sqlite3.connect("/var/lib/docker/volumes/open-webui/_data/webui.db").execute(
            "select value from config where key='tool_server.connections'").fetchone()[0]) if x["info"]["id"] == "silentpush"][0]["key"]
        st, body = http("http://172.18.0.1:8795/quota", timeout=8, data=b"{}",
                        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, method="POST")
        add("silentpush", "ok" if st == 200 else "fail", "quota http=%s" % st, None if st == 200 else "systemctl restart dfir-sp-gateway")
    except Exception as e:
        add("silentpush", "warn", "перевірка не вдалась: " + repr(e)[:80])

    # 7. бот Telegram: n8n живий + вебхук (урок n8n-webhook-404)
    if "n8n" in running:
        st, _ = http("http://127.0.0.1:5678/healthz", timeout=8)
        add("bot-n8n", "ok" if st in (200, 401, 404) else "fail", "n8n http=%s" % st,
            None if st else "docker restart n8n")
    else:
        rc, out, _ = sh("docker ps -a --format '{{.Names}}' | grep -i n8n | head -1")
        if out.strip():
            add("bot-n8n", "fail", "n8n не запущений", "docker start %s" % out.strip())

    # 8. диск
    rc, out, _ = sh("df --output=pcent / | tail -1 | tr -dc '0-9'")
    pct = int(out or 0)
    add("disk", "fail" if pct >= 95 else ("warn" if pct >= 88 else "ok"), "%d%% зайнято" % pct)

    # 9. провалені systemd-юніти
    rc, out, _ = sh("systemctl --failed --no-legend --plain | awk '{print $1}' | grep -v '^$' | head -5")
    if out.strip():
        add("systemd-failed", "warn", "провалені: " + out.replace("\n", ", "), "systemctl reset-failed")
    else:
        add("systemd-failed", "ok", "немає")

    return f


# ---------------- НАЧАЛЬНИК (крос-валідація + опц. LLM) ----------------
def boss(findings):
    notes = []
    names = {x["name"]: x["status"] for x in findings}
    # крос-перевірки логіки тестувальника
    if names.get("portal") == "ok" and names.get("container:open-webui") == "fail":
        notes.append("суперечність: портал ok, але контейнер open-webui fail — перепровірити")
    if names.get("gpu-hog") == "fail":
        notes.append("виявлено сторонній процес на GPU — пріоритетно вбити (користувачі чекають)")
    fails = [x for x in findings if x["status"] == "fail"]
    # LLM-рецензія лише коли є збої (щоб не вантажити карти марно)
    llm_note = ""
    if fails:
        try:
            summary = "; ".join("%s=%s (%s)" % (x["name"], x["status"], x["evidence"][:60]) for x in findings)
            body = {"model": "gpt-small-20b", "max_tokens": 250, "temperature": 0.2,
                    "messages": [{"role": "system", "content": "Ти — старший SRE-наглядач DFIR-порталу. Тобі дають результати автоперевірок. Коротко (3-4 рядки) скажи, що найкритичніше і чи згоден з авто-фіксами. Без вигадок, лише по фактах."},
                                 {"role": "user", "content": summary}]}
            st, out = http(LLM, timeout=60, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
            if st == 200:
                llm_note = json.loads(out)["choices"][0]["message"].get("content", "")[:400]
        except Exception:
            pass
    return notes, llm_note


# ---------------- ФІКСЕР (лише безпечний whitelist) ----------------
SAFE = re.compile(r"^(docker (start|restart) [\w.-]+|systemctl restart [\w.-]+|systemctl reset-failed|kill -9 \d+)$")


def fixer(findings):
    done = []
    for x in findings:
        if x["status"] == "fail" and x.get("fix") and SAFE.match(x["fix"]):
            rc, out, err = sh(x["fix"], t=90)
            done.append({"name": x["name"], "fix": x["fix"], "rc": rc, "err": err[:120]})
    return done


# ---------------- НАДЗОРНИК (журнал + алерт власнику) ----------------
def notify(text):
    try:
        tok = ""
        for ln in open(os.path.join(ROOT, ".env"), encoding="utf-8"):
            if ln.startswith("DFIR_TG_BOT_TOKEN="):
                tok = ln.split("=", 1)[1].strip()
        if not tok:
            return False
        import urllib.parse
        data = urllib.parse.urlencode({"chat_id": OWNER_CHAT, "text": text[:3500]}).encode()
        urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % tok, data=data, timeout=20)
        return True
    except Exception:
        return False


def main():
    findings = tester()
    notes, llm_note = boss(findings)
    fixes = fixer(findings)
    # перевіряємо ще раз те, що фіксили
    if fixes:
        time.sleep(3)
        findings2 = tester()
        after = {x["name"]: x["status"] for x in findings2}
    else:
        after = {x["name"]: x["status"] for x in findings}
    fails = [x for x in findings if x["status"] == "fail"]
    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "fails": [x["name"] for x in fails],
           "fixes": fixes, "boss": notes, "llm": llm_note,
           "still_bad": [n for n, s in after.items() if s == "fail"]}
    with open(QA_LOG, "a", encoding="utf-8") as fp:
        fp.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # алерт власнику лише якщо є збій (і окремо — що полагоджено)
    prev = {}
    pf = os.path.join(STATE, "qa_last.json")
    if os.path.exists(pf):
        try: prev = json.load(open(pf))
        except Exception: prev = {}
    cur_fail = set(rec["still_bad"])
    if fixes or cur_fail:
        msg = ["🛡️ QA-наглядач порталу"]
        if fixes:
            msg.append("🔧 Полагоджено: " + ", ".join("%s" % x["name"] for x in fixes))
        if cur_fail:
            msg.append("❌ Потребує уваги: " + ", ".join(cur_fail))
            if llm_note: msg.append("🧠 " + llm_note)
        # не спамити: слати якщо стан змінився або раз на 6 год
        changed = cur_fail != set(prev.get("still_bad", [])) or bool(fixes)
        if changed or time.time() - prev.get("last_notify", 0) > 6 * 3600:
            if notify("\n".join(msg)):
                rec["last_notify"] = time.time()
    rec_out = {"still_bad": rec["still_bad"], "last_notify": rec.get("last_notify", prev.get("last_notify", 0))}
    json.dump(rec_out, open(pf, "w"))
    print(json.dumps(rec, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
