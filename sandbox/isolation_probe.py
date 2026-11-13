#!/usr/bin/env python3
"""Runs INSIDE a sandbox launched with the SAME hardening flags. Attempts
things an attacker who captured the LLM would try. Each must FAIL for the
sandbox to be sound. Prints a PASS/FAIL table and exits non-zero if any
containment check failed (i.e. an escape succeeded)."""
import os, socket, json

results = []


def check(name, escaped, detail=""):
    # escaped=True means the dangerous action SUCCEEDED (bad). We want escaped=False.
    results.append({"check": name, "contained": (not escaped), "detail": detail})


# 1. Outbound network (DNS/TCP) must be impossible (--network none)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("1.1.1.1", 53))
    check("network_egress_tcp", True, "connected to 1.1.1.1:53")
    s.close()
except Exception as e:
    check("network_egress_tcp", False, type(e).__name__)

# 2. docker socket must be absent (no host control)
check("docker_socket_absent", os.path.exists("/var/run/docker.sock"), "/var/run/docker.sock present" if os.path.exists("/var/run/docker.sock") else "absent")

# 3. host filesystem / model weights must not be mounted
leaks = [p for p in ("/srv/dfir", "/host", "/root/.agent", "/models", "/var/lib/docker") if os.path.exists(p)]
check("no_host_mounts", bool(leaks), ("visible: " + ",".join(leaks)) if leaks else "none visible")

# 4. rootfs must be read-only (write outside tmpfs must fail)
try:
    with open("/opt/escape_test", "w") as f:
        f.write("x")
    os.remove("/opt/escape_test")
    check("rootfs_readonly", True, "wrote to /opt")
except Exception as e:
    check("rootfs_readonly", False, type(e).__name__)

# 5. running as non-root
uid = os.getuid()
check("non_root", uid == 0, "uid=%d" % uid)

# 6. evidence mount (if present) must be read-only
if os.path.exists("/in/archive"):
    try:
        with open("/in/archive", "ab") as f:
            f.write(b"x")
        check("evidence_readonly", True, "wrote to /in/archive")
    except Exception as e:
        check("evidence_readonly", False, type(e).__name__)

all_contained = all(r["contained"] for r in results)
print(json.dumps({"all_contained": all_contained, "results": results}, indent=2))
raise SystemExit(0 if all_contained else 1)
