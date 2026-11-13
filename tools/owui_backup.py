#!/usr/bin/env python3
"""Нічний бекап «прокачаних» акаунтів: webui.db (WAL-безпечно через sqlite backup API + integrity_check),
профілі, скіли, персональні пісочниці. Зберігає 7 останніх. Без вмісту в логах."""
import gzip, os, shutil, sqlite3, subprocess, tarfile, time
ROOT = os.environ.get("DFIR_ROOT", "/srv/dfir")

V = "/var/lib/docker/volumes/open-webui/_data"
D = os.path.join(ROOT, "backups/owui")
KEEP = 7
os.makedirs(D, exist_ok=True)
ts = time.strftime("%Y%m%d_%H%M")

# 1) БД — консистентна копія навіть під час роботи
tmp = os.path.join(D, "webui_%s.db" % ts)
src = sqlite3.connect("file:%s/webui.db?mode=ro" % V, uri=True)
dst = sqlite3.connect(tmp)
src.backup(dst)
ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
dst.close(); src.close()
with open(tmp, "rb") as fi, gzip.open(tmp + ".gz", "wb") as fo:
    shutil.copyfileobj(fi, fo)
os.remove(tmp)

# 2) стан користувачів
with tarfile.open(os.path.join(D, "userstate_%s.tgz" % ts), "w:gz") as t:
    for p, arc in [(V + "/user_profiles", "user_profiles"), (V + "/skills", "skills"), (os.path.join(ROOT, "user_envs"), "user_envs")]:
        if os.path.exists(p):
            t.add(p, arcname=arc)

# 3) ротація
for pref in ("webui_", "userstate_"):
    fs = sorted([f for f in os.listdir(D) if f.startswith(pref) and f[len(pref):len(pref)+8].isdigit()], reverse=True)
    for f in fs[KEEP:]:
        os.remove(os.path.join(D, f))

print("owui backup %s: integrity=%s" % (ts, ok))
if ok != "ok":
    try:
        import sys; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import portal_qa
        portal_qa.notify("⚠️ Бекап веб-уі: перевірка цілісності БД НЕ пройшла (%s). Подивитись." % ok)
    except Exception:
        pass
