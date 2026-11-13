#!/usr/bin/env python3
"""DFIR VM self-check after every boot (and on demand).

Added 2026-10-08 after a morning of power cuts (no UPS, never will be) that left zero-filled
files all over the VM: containerd meta.db, docker local-kv.db, qdrant segment.json, a lost
postgres WAL segment. Each of those was found by hand; this script finds them on its own.

Policy: repair only what is proven safe and reversible (copy first), report everything else
to the owner with the exact next step. Destructive repairs (pg_resetwal, dropping containerd
metadata, restoring qdrant from backup) need the owner's word and are only reported.

Report goes ONLY to the owner chat (owner-only-dm rule). Log: /srv/dfir/var/selfcheck/.
Usage: dfir_selfcheck.py [--boot] [--no-telegram] [--no-deep]
Status for the host watchdog: /srv/dfir/state/selfcheck_last.json (final=green|red).
"""
import json, os, re, shutil, sqlite3, subprocess, sys, time, urllib.request, urllib.parse

ENV_FILE = "/etc/dfir/selfcheck.env"


def _root():
    """Install directory: DFIR_ROOT in the environment or in ENV_FILE (written by install.sh),
    else /srv/dfir - this VM, where the script was born."""
    if os.environ.get("DFIR_ROOT"):
        return os.environ["DFIR_ROOT"].rstrip("/")
    try:
        for line in open(ENV_FILE):
            if line.startswith("DFIR_ROOT="):
                return line.split("=", 1)[1].strip().rstrip("/")
    except OSError:
        pass
    return "/srv/dfir"


ROOT = _root()
LOG_DIR = ROOT + "/var/selfcheck"
BBOLT = ROOT + "/var/tools/bbolt"
COMPOSE_DIR = ROOT
N8N_DB = ROOT + "/services/n8n/database.sqlite"
WEBUI_DB = "/var/lib/docker/volumes/open-webui/_data/webui.db"
N8N_WORKFLOWS = ["d2pWxJwjQxJUpxwZ", "DFIRErrHandler01"]
QDRANT_DIR = ROOT + "/services/qdrant/collections"

ok, fixed, need = [], [], []   # need = needs the owner


def sh(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def env():
    e = {}
    try:
        for line in open(ENV_FILE):
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                e[k] = v
    except OSError:
        pass
    return e


def stamp():
    return time.strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------- checks

def check_disk_flush():
    """Guest must send cache flushes, otherwise fsync never reaches the host disk."""
    p = "/sys/block/sda/queue/write_cache"
    try:
        cur = open(p).read().strip()
    except OSError:
        return
    if cur == "write back":
        ok.append("диск: flush увімкнено")
        return
    for f in os.listdir("/sys/class/scsi_disk"):
        try:
            open(f"/sys/class/scsi_disk/{f}/cache_type", "w").write("temporary write back")
        except OSError:
            pass
    if open(p).read().strip() == "write back":
        fixed.append("диск: flush був вимкнений (правило udev не спрацювало) — увімкнув")
    else:
        need.append("диск: не вдалось увімкнути flush — записи можуть губитись при вимкненні світла")


def bolt_ok(path):
    if not os.path.exists(BBOLT):
        return None
    rc, out = sh(f"{BBOLT} check {path}", 120)
    return out.splitlines()[-1:] == ["OK"] if rc == 0 else False


def check_docker():
    for _ in range(36):                       # up to 3 min for docker to settle after boot
        rc, out = sh("systemctl is-active docker")
        if out == "active":
            ok.append("docker: працює")
            return True
        time.sleep(5)
    rc, j = sh("journalctl -u docker -u containerd -b --no-pager | tail -400")
    if "local-kv.db" in j or "libnetwork" in j and "bbolt" in j:
        f = "/var/lib/docker/network/files/local-kv.db"
        if bolt_ok(f) is False:
            bak = f"{LOG_DIR}/local-kv.db.corrupt_{stamp()}"
            shutil.copy2(f, bak)
            sh(f"{BBOLT} surgery freelist abandon {f} --output {f}.fixed")
            if bolt_ok(f + ".fixed"):
                os.replace(f + ".fixed", f)
                sh("systemctl reset-failed docker; systemctl restart docker", 180)
                fixed.append(f"docker: мережева база local-kv.db мала биту freelist — полагодив (копія {bak})")
                return sh("systemctl is-active docker")[1] == "active"
    if "meta.db" in j or ("containerd" in j and "bbolt" in j):
        f = "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
        if bolt_ok(f) is False:
            need.append("containerd: база meta.db пошкоджена — Docker не стартує. Лікування як 08.10 "
                        "(OCI-відновлення образів з blobs). Напиши адміністратору «лагодь containerd».")
            return False
    need.append("docker не стартував за 3 хв; причину не розпізнав — потрібен адміністратор (journalctl -u docker -b)")
    return False


SIGNATURES = [
    ("logdb", "could not locate a valid checkpoint record",
     "postgres: зник WAL-сегмент (як 08.10). Лікування = холодна копія + pg_resetwal -f — тільки з твого дозволу. "
     "Бот без бази не бачить кейсів."),
    ("qdrant", "Failed to read segment state",
     "qdrant: сегменти затерті нулями. Лікування = відкат з останнього backups/qdrant_*.tar.gz — з твого дозволу."),
]


def check_containers():
    rc, out = sh(f"cd {COMPOSE_DIR} && docker compose ps -a --format json", 60)
    if rc != 0:
        need.append("compose: не вдалось отримати список контейнерів")
        return
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("["):
            rows.extend(json.loads(line))
        elif line.startswith("{"):
            rows.append(json.loads(line))
    bad = []
    for r in rows:
        name, state = r.get("Name"), r.get("State")
        if state == "running" and "restarting" not in (r.get("Status") or "").lower():
            continue
        _, logs = sh(f"docker logs --tail 60 {name} 2>&1", 30)
        hit = next((msg for svc, sig, msg in SIGNATURES if svc == name and sig in logs), None)
        if hit:
            need.append(hit)
        else:
            bad.append(name)
    running = sum(1 for r in rows if r.get("State") == "running")
    # running but failing its own healthcheck (dfir-mcp / llm-gw log into the DB): 22-23.10 a stale
    # password went unnoticed for 32 h because "running" was all this looked at
    _, unh = sh("docker ps --filter health=unhealthy --format '{{.Names}}'", 30)
    unh = [u for u in unh.split() if u]
    if unh:
        need.append("контейнери працюють, але не проходять перевірку здоров'я: " + ", ".join(unh)
                    + " (docker inspect --format '{{json .State.Health}}' ІМ'Я)")
    if bad:
        sh(f"cd {COMPOSE_DIR} && docker compose up -d --pull never --no-build " + " ".join(r.get("Service", "") for r in rows if r.get("Name") in bad), 300)
        time.sleep(20)
        _, still = sh("docker ps --format '{{.Names}}'")
        up = [b for b in bad if b in still.split()]
        if up:
            fixed.append("контейнери перезапущено: " + ", ".join(up))
        rest = [b for b in bad if b not in up]
        if rest:
            need.append("контейнери не піднялись: " + ", ".join(rest))
    ok.append(f"контейнери: {running}/{len(rows)} працюють")


def check_zeroed_configs():
    """Torn writes leave whole files of NUL bytes. Docker skips such containers silently."""
    z = []
    for d in os.listdir("/var/lib/docker/containers"):
        f = f"/var/lib/docker/containers/{d}/config.v2.json"
        try:
            b = open(f, "rb").read()
        except OSError:
            continue
        if b and not b.strip(b"\x00"):
            z.append(d[:12])
    if z:
        # Docker never loads these; compose creates fresh containers beside them. Move the dead
        # directories aside (not delete) so the next run does not report them again.
        rc, _ = sh(f"cd {COMPOSE_DIR} && docker compose up -d --pull never --no-build", 400)
        dst = f"{LOG_DIR}/orphan_containers_{stamp()}"
        os.makedirs(dst, exist_ok=True)
        for d in os.listdir("/var/lib/docker/containers"):
            if d[:12] in z:
                shutil.move(f"/var/lib/docker/containers/{d}", dst)
        fixed.append(f"{len(z)} конфігів контейнерів були затерті нулями — compose перестворив (rc={rc}), "
                     f"мертві теки відкладено в {dst}")


def check_qdrant_files():
    z = []
    for root, _, fs in os.walk(QDRANT_DIR):
        for f in fs:
            if f.endswith(".json"):
                p = os.path.join(root, f)
                try:
                    b = open(p, "rb").read()
                except OSError:
                    continue
                if b and not b.strip(b"\x00"):
                    z.append(p)
    if z:
        need.append(f"qdrant: {len(z)} файлів затерто нулями (перший: {z[0].split('collections/')[-1]}). "
                    "Відкат з бекапу — з твого дозволу.")
    else:
        ok.append("qdrant: файли цілі")


def check_postgres():
    rc, out = sh("docker exec logdb psql -U dfir -d dfir_logs -Atc "
                 "\"select (select count(*) from cases)||' кейсів, '||(select count(*) from bot_users)||' користувачів'\"", 60)
    if rc == 0:
        ok.append("postgres: " + out)
    else:
        if not any(n.startswith("postgres") for n in need):
            need.append("postgres не відповідає: " + out[-200:])
    rc, out = sh(f"ls -1t {ROOT}/backups/pg/logdb_*.dump 2>/dev/null | head -1")
    if out:
        age_h = (time.time() - os.path.getmtime(out)) / 3600
        (ok if age_h < 30 else need).append(f"бекап postgres: {os.path.basename(out)} ({age_h:.0f} год тому)")
    else:
        need.append("бекап postgres: немає жодного дампа")


def check_sqlite():
    for name, p in (("n8n", N8N_DB), ("open-webui", WEBUI_DB)):
        if not os.path.exists(p):
            continue
        try:
            r = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=10).execute("pragma quick_check").fetchone()[0]
        except Exception as e:
            r = str(e)
        if r == "ok" or all(l.endswith("never used") for l in r.splitlines()[1:]):
            ok.append(f"{name}: база ціла")
        else:
            need.append(f"{name}: SQLite пошкоджена: {r[:150]}")


def check_n8n(e):
    try:
        c = sqlite3.connect(f"file:{N8N_DB}?mode=ro", uri=True, timeout=10)
        inactive = [w for w in N8N_WORKFLOWS
                    if not (c.execute("select active from workflow_entity where id=?", (w,)).fetchone() or [0])[0]]
    except Exception:
        inactive = []
    token = e.get("TG_TOKEN")
    info = {}
    if token:
        try:
            info = json.load(urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getWebhookInfo", timeout=20))["result"]
        except Exception:
            pass
    recent_404 = "404" in info.get("last_error_message", "") and time.time() - info.get("last_error_date", 0) < 600
    if inactive or (recent_404 and info.get("pending_update_count", 0) > 0):
        for w in N8N_WORKFLOWS:
            sh(f"docker exec n8n n8n update:workflow --id={w} --active=true", 60)
        sh("docker restart n8n", 120)
        time.sleep(25)
        fixed.append("n8n: вебхук бота віддавав 404 / воркфлоу неактивні — активував і перезапустив n8n")
    else:
        ok.append("n8n: вебхук бота працює")


def check_silent():
    """Failures that return "no data" instead of crashing. Found by hand on 24.10.2026: two host
    services dead for six days, two agent tools answering ERROR for weeks, a nightly cleanup that
    never deleted anything - all visible only in the Postgres log and the cron logs."""
    # 1) one role failing to log in again and again = a service holding a stale password
    _, out = sh("docker logs --since 1h logdb 2>&1 | grep -o 'password authentication failed for user \"[^\"]*\"' "
                "| sort | uniq -c", 60)
    for line in out.splitlines():
        m = re.match(r'\s*(\d+) .*user "([^"]+)"', line)
        if m and int(m.group(1)) >= 5:
            need.append(f"Postgres: {m.group(1)} невдалих входів користувача {m.group(2)} за годину - "
                        "якась служба тримає застарілий пароль або бере не той рядок PG_DSN")
    # 2) code that names a column which does not exist (our own guards probe ZZ_ cases - skip them)
    _, out = sh("docker logs --since 24h logdb 2>&1 | grep -A3 -E 'ERROR:  (column \"[^\"]+\" does not exist|operator does not exist)'", 60)
    hits, cur = {}, None
    for line in out.splitlines():
        m = re.search(r'ERROR:  (column "[^"]+" does not exist|operator does not exist: [^ ]+ [^ ]+ [^ ]+)', line)
        if m:
            cur = m.group(1)
            hits.setdefault(cur, [0, False])
            hits[cur][0] += 1
        elif cur and re.search(r"(?i)zz_", line):
            hits[cur][1] = True
    for msg, (n, guard) in sorted(hits.items(), key=lambda x: -x[1][0]):
        if n >= 5 and not guard:
            need.append(f"SQL у коді падає: «{msg}» - {n} разів за добу (шукати запит у логах logdb)")
    # 3) host-side services: the same error line repeating in the last hour
    for f in ("vpn_sync.log", "ram_worker.log"):
        path = ROOT + "/var/logs/" + f
        try:
            cutoff = time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() - 3600))
            with open(path, "rb") as fh:
                fh.seek(max(0, os.path.getsize(path) - 400000))
                tail = fh.read().decode("utf-8", "replace").splitlines()
            # only time-stamped lines: traceback lines carry no time and would always count as "now"
            errs = [l for l in tail if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d", l) and l[:16] >= cutoff
                    and re.search(r"(?i)error|traceback|failed", l)]
            if len(errs) >= 10:
                need.append(f"{f}: {len(errs)} помилок за годину, остання: {errs[-1][20:160]}")
        except OSError:
            pass
    if not any(x.startswith(("Postgres:", "SQL у коді", "vpn_sync", "ram_worker")) for x in need):
        ok.append("тихих збоїв не видно (входи в БД, SQL-помилки коду, служби хоста)")


def check_stuck_queries():
    """2026-10-08: after pg_resetwal reused xids, one UPDATE spun for 20+ min holding a lock and
    every bot restart hung in _startup() behind it -> the bot was silent with all containers 'Up'."""
    rc, out = sh("docker exec logdb psql -U dfir -d dfir_logs -Atc "
                 "\"select pid||' '||to_char(now()-query_start,'HH24:MI:SS')||' '||left(regexp_replace(query,'\\s+',' ','g'),60) "
                 "from pg_stat_activity where datname='dfir_logs' and state='active' and now()-query_start > interval '15 minutes' "
                 "and query not ilike '%pg_dump%' and query not ilike 'COPY %'\"", 60)
    if rc == 0 and out:
        need.append("postgres: запити висять >15 хв (можуть блокувати старт бота): " + "; ".join(out.splitlines()[:3]))


def check_jobs():
    rc, out = sh("docker exec logdb psql -U dfir -d dfir_logs -Atc "
                 "\"select case_key||' ('||status||')' from dfir_run_jobs_v2 where status in ('queued','running') order by created_at\"", 60)
    if rc == 0 and out:
        need.append("перервані аналізи (бот підхопить або позначить на старті): " + "; ".join(out.splitlines()[:5]))


def wip_snapshot():
    """Snapshot uncommitted work to refs/wip/autosave without touching the branch or index."""
    rc, sha = sh(f"cd {COMPOSE_DIR} && git stash create")
    if rc == 0 and sha:
        sh(f"cd {COMPOSE_DIR} && git update-ref -m 'selfcheck autosave {stamp()}' refs/wip/autosave {sha}")
        _, n = sh(f"cd {COMPOSE_DIR} && git status --short | wc -l")
        ok.append(f"git: {n} незакомічених змін збережено в refs/wip/autosave")



LLM_URL = "http://192.168.100.1:1234/v1/models"
STATUS_FILE = ROOT + "/state/selfcheck_last.json"
AMCHECK_SQL = ("with ix as materialized (select c.oid from pg_class c join pg_am a on a.oid=c.relam "
               "where a.amname='btree' and c.relkind='i') select count(*) from (select bt_index_check(ix.oid,true) from ix) z")


def check_llm():
    """2026-10-17: the host LLM (llama-swap) was only checked by hand after a boot."""
    last = ""
    for _ in range(12):                      # host services may still be starting: up to ~3 min
        try:
            d = json.load(urllib.request.urlopen(LLM_URL, timeout=10))
            ok.append(f"LLM на хості: {len(d.get('data', []))} моделей доступні")
            return
        except Exception as ex:
            last = str(ex)[:120]
            time.sleep(15)
    need.append(f"LLM на хості (llama-swap :1234) не відповідає: {last}")


def check_bot_log():
    _, n = sh("docker logs --since 15m case-maintainer 2>&1 | grep -c Traceback", 30)
    n = int(n) if n.strip().isdigit() else -1
    (ok if n == 0 else need).append(f"лог бота: {n} Traceback за 15 хв")


def check_pg_deep():
    """Index integrity (amcheck) + TOAST read of pg_statistic: what the manual post-boot check did.
    08.10 a power cut left broken pages that a plain 'select 1' never touches. Slow after boot
    (cold cache, minutes), so it runs AFTER the main report and speaks again only if it fails."""
    rc, out = sh("docker exec logdb psql -U dfir -d dfir_logs -Atc "
                 "\"select count(*) from (select s::text from pg_catalog.pg_statistic s) x\"", 600)
    res = {}
    if rc == 0 and out.strip().isdigit():
        res["pg_statistic"] = int(out)
    else:
        res["error"] = "pg_statistic: " + out[-200:]
        return res
    sh("docker exec logdb psql -U dfir -d dfir_logs -Atc \"create extension if not exists amcheck\"", 60)
    # після старту ВМ кеш холодний: повна перевірка з читанням таблиць (heapallindexed) йде >15 хв і сторож
    # хоста вважає самоперевірку завислою. На старті — лише структура індексів, повна — у щоденному запуску.
    sql = AMCHECK_SQL.replace("bt_index_check(ix.oid,true)", "bt_index_check(ix.oid,false)") if "--boot" in sys.argv else AMCHECK_SQL
    rc, out = sh(f"docker exec logdb psql -U dfir -d dfir_logs -Atc \"{sql}\"", 3000)
    if rc == 0 and out.strip().isdigit():
        res["amcheck_indexes"] = int(out)
    else:
        res["error"] = "amcheck: " + out[-300:]
    return res


def _esc(x):
    return str(x).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def write_status(**kw):
    try:
        boot_id = open("/proc/sys/kernel/random/boot_id").read().strip()
    except OSError:
        boot_id = ""
    st = {"boot_id": boot_id, "ts": int(time.time()), "need": need, "fixed": fixed, **kw}
    tmp = STATUS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, ensure_ascii=False)
    os.replace(tmp, STATUS_FILE)

# ---------------------------------------------------------------- main

def send(e, text):
    token, chat = e.get("TG_TOKEN"), e.get("ADMIN_CHAT", "CHANGE_ME_OWNER_CHAT_ID")
    if not token:
        return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text, "parse_mode": "HTML"}).encode()
    for _ in range(10):                      # network may still be coming up after a power cut
        try:
            urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data, timeout=20)
            return
        except Exception:
            time.sleep(15)


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    e = env()
    boot = "--boot" in sys.argv
    check_disk_flush()
    if check_docker():
        check_zeroed_configs()
        check_containers()
        check_postgres()
        check_stuck_queries()
        check_n8n(e)
        check_jobs()
        check_bot_log()
        check_silent()
    check_llm()
    check_qdrant_files()
    check_sqlite()
    wip_snapshot()

    _, up = sh("uptime -p")
    head = "🔴" if need else ("🟡" if fixed else "🟢")
    when = 'після старту' if boot else ('щоденна' if '--quiet-green' in sys.argv else 'вручну')
    lines = [f"{head} <b>Самоперевірка ВМ</b> ({when}, {up})"]
    if need:
        lines += ["", "<b>Потрібне твоє рішення:</b>"] + [f"• {_esc(x)}" for x in need]
    if fixed:
        lines += ["", "<b>Полагоджено автоматично:</b>"] + [f"• {_esc(x)}" for x in fixed]
    lines += ["", "<b>В порядку:</b>"] + [f"• {_esc(x)}" for x in ok]
    text = "\n".join(lines)
    open(f"{LOG_DIR}/selfcheck_{stamp()}.txt", "w").write(re.sub(r"<[^>]+>", "", text))
    print(re.sub(r"<[^>]+>", "", text))
    write_status(stage="main", head=head)
    # --quiet-green: the daily run speaks only when something is wrong
    if "--no-telegram" not in sys.argv and not ("--quiet-green" in sys.argv and head == "🟢"):
        send(e, text)
    if "--no-deep" in sys.argv:
        return
    deep = check_pg_deep()
    final = "red" if (need or deep.get("error")) else "green"
    write_status(stage="done", head=head, deep=deep, final=final)
    print("deep:", deep, "final:", final)
    if deep.get("error") and "--no-telegram" not in sys.argv:
        send(e, "🔴 <b>Самоперевірка ВМ: цілісність бази</b>" + chr(10) + deep["error"] + chr(10) +
             "За замовчуванням нічого не чіпаю — потрібне твоє рішення.")


if __name__ == "__main__":
    main()
