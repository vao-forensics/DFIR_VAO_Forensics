#!/usr/bin/env python3
"""T6 test: DFIR Collector Builder always fetches the newest tools, verifies them and falls back
to the mirror. Runs the REAL builder EXE (--cli --check-tools) on Windows against the real
upstream sources and a local mirror made by tools/collector_mirror_sync.py.

    python -I test_builder_tools.py BUILDER_EXE TOOLS_JSON MIRROR_DIR

Cases:
  A  live: every tool resolves, newest version named, verified; mirror-only tools via SHA256SUMS
  B  cache: second run re-checks "latest" URLs (same file -> cache), a changed server file -> re-download
  C  fallback: official URL dead (404) -> verified copy from the mirror, warning
  D  tampered mirror: official dead + mirror file altered -> rejected, tool left out
  E  signer required: wrong publisher -> official AND mirror copies rejected
  F  official link gone, no mirror -> verified cached copy used, loud warning
  G  GitHub API refuses (rate limit / bad token) -> last known release, still digest-checked
"""
import glob
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading

EXE, TOOLS, MIRROR = sys.argv[1:4]
CACHE = os.path.join(os.environ["LOCALAPPDATA"], "DFIR_Builder", "cache")
res = []


def serve(d):
    h = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=d, **k)
    http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return "http://127.0.0.1:%d" % s.server_address[1]


def run(manifest, mirror, out, env=None):
    os.makedirs(out, exist_ok=True)
    mp = os.path.join(out, "tools.json")
    json.dump(manifest, io.open(mp, "w", encoding="utf-8"))
    p = subprocess.run([EXE, "--cli", "--check-tools", "--lang", "en", "--tools-json", mp, "--mirror", mirror, "--out", out],
                       capture_output=True, timeout=1500, env=dict(os.environ, **(env or {})))
    log = (p.stdout + p.stderr).decode("utf-8", "replace")
    io.open(os.path.join(out, "log.txt"), "w", encoding="utf-8").write(log)
    prov = io.open(os.path.join(out, "TOOLS_PROVENANCE.txt"), encoding="utf-8-sig").read() if os.path.exists(os.path.join(out, "TOOLS_PROVENANCE.txt")) else ""
    return p.returncode, log, prov


def row(prov, tid):
    return [l for l in prov.splitlines() if l.startswith(tid + " ")]


def check(name, cond, detail=""):
    res.append(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -- " + detail))


base = json.load(io.open(TOOLS, encoding="utf-8"))
tools = {t["id"]: t for t in base["tools"]}
good = serve(MIRROR)
work = tempfile.mkdtemp(prefix="t6_")


def mini(*specs):
    m = dict(base)
    m["tools"] = list(specs)
    return m


# A ---------------------------------------------------------------------------------------
rc, log, prov = run(base, good, os.path.join(work, "A"))
nrows = len([l for l in prov.splitlines() if l[:1].strip() and "  [" in l])
check("A exit 0, no warnings", rc == 0 and "WARNING" not in log, "rc=%d" % rc)
for tid, want in [("hayabusa", "GitHub digest"), ("chainsaw", "GitHub digest"), ("hindsight", "GitHub digest"),
                  ("7-Zip", "GitHub digest"), ("PECmd", "signed ZimTech LLC"), ("EvtxECmd", "signed ZimTech LLC"),
                  ("Autoruns", "signed Microsoft Corporation"), ("AmcacheParser", "mirror SHA256SUMS"),
                  ("SQLECmd", "mirror SHA256SUMS"), ("WxTCmd", "mirror SHA256SUMS"), ("vao_bitsparser", "pinned SHA-256")]:
    r = row(prov, tid)
    check("A %s verified by %s" % (tid, want), bool(r) and all(want in l for l in r), str(r[:1]))
r = row(prov, "hayabusa")
check("A hayabusa names its release tag", bool(r) and " v4." in r[0], str(r[:1]))
check("A no tool left unbuilt", "NOT BUILT" not in prov, prov[-400:])
print("   (A: %d provenance rows)" % nrows)

# B ---------------------------------------------------------------------------------------
pe = mini(tools["PECmd"], tools["rla"])
rc, log, prov = run(pe, good, os.path.join(work, "B1"))
check("B same server file -> served from cache after a HEAD check", "same version on the server): PECmd.zip" in log, log[-600:])
meta = glob.glob(os.path.join(CACHE, "PECmd_" + "?" * 12 + "_PECmd.zip.meta"))
for m in meta:
    io.open(m, "w").write('"stale-etag"|Sun, 01 Jan 2023 00:00:00 GMT|1')
rc, log, prov = run(pe, good, os.path.join(work, "B2"))
check("B changed server file -> downloaded again", "the server has a newer file: PECmd.zip" in log and "downloading https://download.ericzimmermanstools.com/PECmd.zip" in log, log[-600:])
check("B version = server date", any(re.search(r"\s20\d\d-\d\d-\d\d\s", l) for l in row(prov, "PECmd")), str(row(prov, "PECmd")))

# C ---------------------------------------------------------------------------------------
dead = dict(tools["PECmd"], url="https://download.ericzimmermanstools.com/PECmd_t6_gone.zip")
rc, log, prov = run(mini(dead), good, os.path.join(work, "C"))
r = row(prov, "PECmd")
check("C dead official URL -> mirror tried", "trying the fallback mirror" in log, log[-600:])
check("C mirror copy verified (SHA256SUMS + signature)", bool(r) and "mirror SHA256SUMS" in r[0] and "signed ZimTech LLC" in r[0] and "127.0.0.1" in r[0], str(r))
check("C fallback reported as a warning (exit 3)", rc == 3 and "taken from the mirror" in log, "rc=%d" % rc)

# D ---------------------------------------------------------------------------------------
badm = os.path.join(work, "mirror_bad")
shutil.copytree(MIRROR, badm)
with open(os.path.join(badm, "rla.zip"), "ab") as f:
    f.write(b"tampered")
deadr = dict(tools["rla"], url="https://download.ericzimmermanstools.com/rla_t6_gone.zip")
rc, log, prov = run(mini(deadr), serve(badm), os.path.join(work, "D"))
check("D tampered mirror file rejected", "does not match the mirror's SHA256SUMS" in log, log[-600:])
check("D tool left out, listed as NOT BUILT", not row(prov.split("NOT BUILT")[0], "rla") and "NOT BUILT" in prov and rc == 3, prov[-400:])

# E ---------------------------------------------------------------------------------------
evil = dict(tools["rla"], signer="Evil Corp")
rc, log, prov = run(mini(evil), good, os.path.join(work, "E"))
check("E wrong publisher rejected on official and mirror", log.count("no valid signature of Evil Corp") >= 2 and not row(prov.split("NOT BUILT")[0], "rla"), log[-600:])

# F ---------------------------------------------------------------------------------------
gone_url = "https://download.ericzimmermanstools.com/rla_t6_gone_cached.zip"
src = glob.glob(os.path.join(CACHE, "rla_" + "?" * 12 + "_rla.zip"))[0]
key = hashlib.sha256(gone_url.encode()).hexdigest()[:12]
shutil.copyfile(src, os.path.join(CACHE, "rla_%s_rla_t6_gone_cached.zip" % key))
rc, log, prov = run(mini(dict(tools["rla"], url=gone_url)), "", os.path.join(work, "F"))
r = row(prov, "rla")
check("F gone link + no mirror -> cached copy, still signature-checked", bool(r) and "signed ZimTech LLC" in r[0], str(r))
check("F loud warning about the 404", rc == 3 and "official link is gone (404)" in log, log[-600:])
os.remove(os.path.join(CACHE, "rla_%s_rla_t6_gone_cached.zip" % key))

# G ---------------------------------------------------------------------------------------
rc, log, prov = run(mini(tools["hindsight"]), good, os.path.join(work, "G"), env={"GITHUB_TOKEN": "t6-invalid-token"})
r = row(prov, "hindsight")
check("G API refused -> last known release used", "using the last known release of obsidianforensics/hindsight" in log, log[-600:])
check("G that release still verified by GitHub digest", bool(r) and "GitHub digest" in r[0], str(r))

print("%d/%d PASS  (work: %s)" % (sum(res), len(res), work))
sys.exit(0 if all(res) else 1)
