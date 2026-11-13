#!/usr/bin/env python3
"""Будівник: дотестувати Bolt-74B. Flag → run_bench → save_db → оновити журнал → сповістити → зняти flag."""
import json, os, subprocess, sys, time
sys.path.insert(0, "/srv/dfir/tools")
FLAG = "/srv/dfir/state/bench_active"
MB = "/srv/dfir/var/modelbench"
ROAD = "/srv/dfir/docs/autobuild_roadmap.json"

open(FLAG, "w").write(str(time.time()))
try:
    subprocess.run(["python3", "run_bench.py", "cand-bolt74"], cwd=MB, timeout=7200)
    subprocess.run(["python3", "save_db.py"], cwd=MB, timeout=120)
    R = json.load(open(os.path.join(MB, "results.json")))
    b = {k: v.get("score", "err") for k, v in R.get("cand-bolt74", {}).items() if "score" in v or "error" in v}
    n_ok = sum(1 for k, v in R.get("cand-bolt74", {}).items() if "score" in v)
    # оновити журнал
    d = json.load(open(ROAD))
    for t in d["tasks"]:
        if t["id"] == "T-bolt":
            if n_ok >= 6:
                t["status"] = "done"; t["evidence"] = "cand-bolt74 %d/8 тестів: %s" % (n_ok, b)
            else:
                t["evidence"] = "частково %d/8: %s" % (n_ok, b)
    json.dump(d, open(ROAD, "w"), ensure_ascii=False, indent=2)
    try:
        import portal_qa
        portal_qa.notify("🤖 Будівник: Bolt-74B дотестовано (%d/8). Бали: %s. Далі — наступна задача роадмепу." % (n_ok, b))
    except Exception:
        pass
    print("BOLT DONE", n_ok, b)
finally:
    if os.path.exists(FLAG):
        os.remove(FLAG)
