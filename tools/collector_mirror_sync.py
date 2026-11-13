#!/usr/bin/env python3
"""Fill the collector tools mirror - the fallback DFIR Collector Builder uses when an official
source is gone, changed shape or fails verification.

For every entry of src/collector_src/tools.json (and 7-Zip) one file lands in OUT under the
name the builder asks the mirror for (<id>.exe / .zip / .msi / .nupkg, or "mirror_name"):

  * official tools: newest release, exactly as the builder resolves it; GitHub's per-asset
    sha256 digest must match, pins hold for their pin_tag;
  * mirror-only tools ("url": "{mirror}/..."): upstream is gone or dropped the .NET Framework
    build; taken from --seed DIR (e.g. %LOCALAPPDATA%\\DFIR_Builder\\cache) or --from-mirror URL
    and must match their sha256 pins.

Then OUT/SHA256SUMS is written; the builder refuses any mirror file not listed there.
--upload pushes OUT to the release "tools-mirror" of the repository with gh (PRIVATE repo only:
third-party binaries are not ours to publish).

    python3 tools/collector_mirror_sync.py --out /tmp/mirror --seed cache_dir [--only PECmd,rla] [--upload]
"""
import argparse
import glob
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

UA = {"User-Agent": "DFIR-Collector-Mirror-Sync"}
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JSON = os.path.join(HERE, "..", "src", "collector_src", "tools.json")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def http(url, dest=None):
    hdr = dict(UA)
    tok = os.environ.get("GITHUB_TOKEN")
    if tok and url.startswith("https://api.github.com/"):
        hdr["Authorization"] = "Bearer " + tok
    with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=300) as r:
        if dest is None:
            return r.read().decode("utf-8")
        with open(dest + ".part", "wb") as f:
            shutil.copyfileobj(r, f)
    os.replace(dest + ".part", dest)
    return dest


def github_asset(repo, rx, prerelease):
    if prerelease:
        rels = json.loads(http("https://api.github.com/repos/%s/releases?per_page=10" % repo))
        rel = next(r for r in rels if not r.get("draft"))
    else:
        rel = json.loads(http("https://api.github.com/repos/%s/releases/latest" % repo))
    for a in rel["assets"]:
        if re.search(rx, a["name"]):
            d = a.get("digest") or ""
            return a["browser_download_url"], rel["tag_name"], d[7:].lower() if d.startswith("sha256:") else ""
    raise RuntimeError("%s %s has no asset %s" % (repo, rel["tag_name"], rx))


def mirror_name(t):
    if t.get("mirror_name"):
        return t["mirror_name"]
    ext = {"file": ".exe", "msi": ".msi", "nupkg": ".nupkg"}.get(t.get("kind"), ".zip")
    return t["id"] + ext


def check_pins(t, path):
    """Pins name the FINAL files (inside the archive for zip kinds)."""
    pins = t.get("sha256") or {}
    if not pins:
        return False
    if t.get("kind") == "file":
        if sha256(path) not in [v.lower() for v in pins.values()]:
            raise RuntimeError("%s: pinned SHA-256 mismatch" % t["id"])
        return True
    with zipfile.ZipFile(path) as z:
        for key, want in pins.items():
            base = key.replace("\\", "/").split("/")[-1].lower()
            hits = [n for n in z.namelist() if n.lower().rsplit("/", 1)[-1] == base]
            if not any(hashlib.sha256(z.read(n)).hexdigest() == want.lower() for n in hits):
                raise RuntimeError("%s: pinned SHA-256 of %s not found in the archive" % (t["id"], key))
    return True


def from_seed(seed, t, name):
    if not seed:
        return None
    direct = os.path.join(seed, name)
    if os.path.isfile(direct):
        return direct
    # the builder's cache: <id>_<12 hex>_<file name>; newest first
    ext = os.path.splitext(name)[1].lower()
    c = [p for p in glob.glob(os.path.join(seed, t["id"] + "_" + "?" * 12 + "_*"))
         if p.lower().endswith(ext)]
    return max(c, key=os.path.getmtime) if c else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tools-json", default=DEFAULT_JSON)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", help="folder with mirror-only files (names as in the mirror, or the builder cache)")
    ap.add_argument("--from-mirror", help="current mirror URL to copy mirror-only files from")
    ap.add_argument("--only", help="comma-separated tool ids (7-Zip = 7zip)")
    ap.add_argument("--upload", action="store_true", help="gh release upload to tools-mirror (private repository)")
    a = ap.parse_args()

    man = json.load(io.open(a.tools_json, encoding="utf-8"))
    only = set(a.only.split(",")) if a.only else None
    os.makedirs(a.out, exist_ok=True)
    ok, bad = [], []

    jobs = list(man["tools"])
    sz = man.get("sevenzip") or {}
    if sz.get("github"):
        jobs.append({"id": "7zip", "_7z": "bootstrap_asset", "mirror_name": "7zr.exe", "github": sz["github"], "asset": sz["bootstrap_asset"]})
        jobs.append({"id": "7zip", "_7z": "extra_asset", "mirror_name": "7z-extra.7z", "github": sz["github"], "asset": sz["extra_asset"]})

    for t in jobs:
        if only and t["id"] not in only:
            continue
        name = mirror_name(t)
        dst = os.path.join(a.out, name)
        try:
            url = t.get("url", "")
            if url.startswith("{mirror}"):
                src = from_seed(a.seed, t, name)
                if src:
                    shutil.copyfile(src, dst)
                elif a.from_mirror:
                    http(a.from_mirror.rstrip("/") + url[8:], dst)
                else:
                    raise RuntimeError("mirror-only tool: give --seed or --from-mirror")
                check_pins(t, dst)
                how, ver = "pinned SHA-256", "mirror"
            else:
                digest, ver = "", "-"
                if not url:
                    url, ver, digest = github_asset(t["github"], t["asset"], bool(t.get("prerelease")))
                http(url, dst)
                how = "HTTPS only"
                if digest:
                    if sha256(dst) != digest:
                        raise RuntimeError("GitHub digest mismatch for %s" % url)
                    how = "GitHub digest"
                if t.get("sha256") and (not t.get("pin_tag") or t.get("pin_tag") == ver):
                    check_pins(t, dst)
                    how = "pinned SHA-256"
            ok.append((name, sha256(dst), ver, how))
            print("ok   %-28s %-10s %s" % (name, ver, how))
        except Exception as e:  # one broken upstream must not stop the rest
            bad.append((name, str(e)))
            if os.path.exists(dst):
                os.remove(dst)
            print("FAIL %-28s %s" % (name, e))

    # keep lines for files synced earlier and still present (a partial --only run)
    sums = {}
    sp = os.path.join(a.out, "SHA256SUMS")
    if os.path.exists(sp):
        for line in io.open(sp, encoding="utf-8"):
            m = re.match(r"^([0-9a-f]{64})\s+\*?(.+)$", line.strip())
            if m and os.path.exists(os.path.join(a.out, m.group(2))):
                sums[m.group(2)] = m.group(1)
    for name, h, _, _ in ok:
        sums[name] = h
    with io.open(sp, "w", encoding="utf-8", newline="\n") as f:
        for n in sorted(sums):
            f.write("%s  %s\n" % (sums[n], n))
    print("SHA256SUMS: %d files, %d failed" % (len(sums), len(bad)))

    if a.upload:
        # a full mirror (third-party binaries) only ever goes to a PRIVATE repository; a public one
        # may carry just the mirror-only files the notices list (MIT, upstream gone)
        vis = subprocess.run(["gh", "repo", "view", "--json", "visibility", "-q", ".visibility"],
                             capture_output=True, text=True).stdout.strip()
        mirror_only = {mirror_name(t) for t in man["tools"] if t.get("url", "").startswith("{mirror}")}
        extra = sorted(set(sums) - mirror_only)
        if vis != "PRIVATE" and extra:
            print("refusing to upload to a %s repository: %s" % (vis or "unknown", ", ".join(extra)))
            return 2
        files = [os.path.join(a.out, n) for n in sorted(sums)] + [sp]
        r = subprocess.run(["gh", "release", "upload", "tools-mirror", "--clobber"] + files)
        if r.returncode:
            return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
