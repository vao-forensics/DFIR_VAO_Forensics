#!/usr/bin/env python3
"""Холодне архівування справ у logdb.
- archive <case>  : COPY рядків справи з важких таблиць у zstd-файли, звірка кількості, потім DELETE. Місце звільняється VACUUM-ом (full лише в maintenance).
- restore <case>  : COPY назад із zstd, звірка, видалення архіву.
- scan            : показати «холодні» справи (нема активності >1 дня і ще не заархівовані).
- autorestore <c> : розпакувати, якщо справа в архіві (idempotent, для виклику з коду бота).
Дані справ священні: DELETE лише після успішної звірки кількості рядків в архіві.
"""
import subprocess, sys, os, json, datetime

CASE_TABLES = ["filesystem_v2", "event_logs_v2", "raw_fallback_v2", "srum_v2",
               "program_exec_v2", "tool_alerts_v2"]
COLD_DIR = "/srv/dfir/cases_cold"
PG = ["docker", "exec", "-i", "logdb", "psql", "-U", "dfir", "-d", "dfir_logs", "-v", "ON_ERROR_STOP=1"]

def q(sql, t=False):
    r = subprocess.run(PG + (["-tA"] if t else []) + ["-c", sql], capture_output=True, text=True)
    if r.returncode: raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()

def count(tbl, case):
    return int(q("SELECT count(*) FROM %s WHERE case_key=%s" % (tbl, lit(case)), t=True) or 0)

def lit(s):  # безпечний літерал
    return "'" + s.replace("'", "''") + "'"

def archived_set():
    q("""CREATE TABLE IF NOT EXISTS archived_cases(
         case_key text PRIMARY KEY, info jsonb, archived_at timestamptz DEFAULT now())""")
    return set(q("SELECT case_key FROM archived_cases", t=True).splitlines()) - {""}

def archive2(case):
    """COPY ... TO STDOUT | zstd -> файл на хості; звірка кількості; лише потім DELETE."""
    os.makedirs(COLD_DIR, exist_ok=True)
    if case in archived_set():
        print("вже заархівована:", case); return
    info, total = {}, 0
    for t in CASE_TABLES:
        n = count(t, case)
        if n == 0: continue
        f = "%s/%s__%s.zst" % (COLD_DIR, case, t)
        # COPY ... TO STDOUT | zstd -> файл на хості
        p1 = subprocess.Popen(PG + ["-c", "COPY (SELECT * FROM %s WHERE case_key=%s) TO STDOUT" % (t, lit(case))],
                              stdout=subprocess.PIPE)
        with open(f, "wb") as out:
            p2 = subprocess.Popen(["zstd", "-q", "-T0", "-19"], stdin=p1.stdout, stdout=out)
            p1.stdout.close(); p2.communicate(); p1.wait()
        if p1.returncode or p2.returncode:
            raise RuntimeError("COPY/zstd fail %s" % t)
        # звірка: кількість рядків у архіві
        back = subprocess.run("zstd -dc %s | wc -l" % f, shell=True, capture_output=True, text=True)
        got = int(back.stdout.strip())
        if got != n:
            raise RuntimeError("ЗВІРКА НЕ ЗІЙШЛАСЯ %s: у БД %d, в архіві %d — DELETE СКАСОВАНО" % (t, n, got))
        info[t] = {"rows": n, "bytes": os.path.getsize(f)}
        total += n
        print("  %-18s %d рядків -> %s (%.1f МБ, звірка ok)" % (t, n, f, os.path.getsize(f)/1e6))
    if not info:
        print("порожня справа, нема що архівувати:", case); return
    # усі звірки пройшли — тепер видаляємо
    for t in info:
        q("DELETE FROM %s WHERE case_key=%s" % (t, lit(case)))
    q("INSERT INTO archived_cases(case_key, info) VALUES(%s, %s) ON CONFLICT (case_key) DO UPDATE SET info=EXCLUDED.info, archived_at=now()" %
      (lit(case), lit(json.dumps(info))))
    print("ЗААРХІВОВАНО %s: %d рядків у %d таблицях" % (case, total, len(info)))

def restore(case):
    arch = archived_set()
    if case not in arch:
        print("не в архіві (нічого робити):", case); return
    info = json.loads(q("SELECT info FROM archived_cases WHERE case_key=%s" % lit(case), t=True))
    for t, meta in info.items():
        f = "%s/%s__%s.zst" % (COLD_DIR, case, t)
        if not os.path.exists(f):
            raise RuntimeError("АРХІВ ВІДСУТНІЙ: %s" % f)
        p1 = subprocess.Popen(["zstd", "-dc", f], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(PG + ["-c", "COPY %s FROM STDIN" % t], stdin=p1.stdout)
        p1.stdout.close(); p2.communicate(); p1.wait()
        if p1.returncode or p2.returncode:
            raise RuntimeError("restore COPY fail %s" % t)
        got = count(t, case)
        if got != meta["rows"]:
            raise RuntimeError("ПІСЛЯ RESTORE %s: очікувано %d, є %d" % (t, meta["rows"], got))
        print("  %-18s відновлено %d рядків (ok)" % (t, got))
    # успіх — прибрати архів і запис
    for t in info:
        os.remove("%s/%s__%s.zst" % (COLD_DIR, case, t))
    q("DELETE FROM archived_cases WHERE case_key=%s" % lit(case))
    print("ВІДНОВЛЕНО %s, архів видалено" % case)

def scan():
    arch = archived_set()
    rows = q("""SELECT c.case_key, COALESCE(MAX(f.ingested_at), c.created_at)
                FROM cases c LEFT JOIN ingest_files f USING(case_key)
                GROUP BY c.case_key, c.created_at ORDER BY 2""", t=True).splitlines()
    now = datetime.datetime.now(datetime.timezone.utc)
    print("ХОЛОДНІ (нема активності >1 дня, не заархівовані):")
    for ln in rows:
        if not ln.strip(): continue
        ck, ts = ln.split("|", 1)
        if ck in arch: continue
        try:
            last = datetime.datetime.fromisoformat(ts.strip().replace(" ", "T"))
            age = (now - last).days
        except Exception:
            age = "?"
        if age == "?" or age >= 1:
            print("  %-50s остання активність %s дн тому" % (ck, age))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if cmd == "archive": archive2(sys.argv[2])
    elif cmd == "restore": restore(sys.argv[2])
    elif cmd == "autorestore": restore(sys.argv[2]) if sys.argv[2] in archived_set() else print("не в архіві")
    elif cmd == "scan": scan()
    else: print(__doc__)
