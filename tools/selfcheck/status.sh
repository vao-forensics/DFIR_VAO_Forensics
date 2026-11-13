#!/bin/sh
# For the host watchdog (rc-loop): green | red | pending | stale | missing
F=/srv/dfir/state/selfcheck_last.json
[ -f "$F" ] || { echo missing; exit 0; }
python3 -I - "$F" <<"PY"
import json, sys
d = json.load(open(sys.argv[1]))
b = open("/proc/sys/kernel/random/boot_id").read().strip()
if d.get("boot_id") != b: print("stale")
elif d.get("stage") != "done": print("red" if d.get("need") else "pending")
else: print(d.get("final", "red"))
PY
