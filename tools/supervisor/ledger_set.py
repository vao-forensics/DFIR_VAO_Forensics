import json, sys
p = "/srv/dfir/docs/portal_tasks.json"; d = json.load(open(p, encoding="utf-8"))
for t in d["tasks"]:
    if t["id"] == sys.argv[1]:
        t["status"] = sys.argv[2]; t["evidence"] = sys.argv[3]
        if len(sys.argv) > 4: t["note"] = sys.argv[4]
json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
