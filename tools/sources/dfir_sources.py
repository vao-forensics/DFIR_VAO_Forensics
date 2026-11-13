#!/usr/bin/env python3
"""External datasets of the analysis side: find the latest official version, download, verify, build, swap.

Why (T1, 07.11.2026): the hash/path reference databases were fetched once by hand (Aug/Oct) with no
record of where they came from, no check of what was downloaded and no way to see they went stale.
The MalwareBazaar public dump even disappeared (410 Gone) without anyone noticing.

Manifest: infra/sources/sources.json (official URL, how the version is found, how a file is verified).
State:    state/sources/installed.json   what is installed now (version, sha256, size, time)
          state/sources/provenance.jsonl  one line per attempt: source, url (key masked), upstream version,
                                         sha256, size, every verification and its result, outcome
Rules: a file is replaced only after ALL its checks pass and the database built from it is sane;
the previous file is kept as .prev until then and put back on any failure. Keys never get logged.

  dfir_sources.py check            what is installed vs what upstream has (no download)
  dfir_sources.py update [--only ID] [--force]
  dfir_sources.py log [N]          last N provenance records
Exit: 0 ok / everything current, 1 something failed, 3 (check) updates available or a key is missing.
"""
import datetime, hashlib, json, os, shutil, subprocess, sys, time, urllib.error, urllib.request, zipfile

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.environ.get("DFIR_ROOT") or os.path.dirname(os.path.dirname(HERE))
MANIFEST = os.environ.get("DFIR_SOURCES_MANIFEST") or os.path.join(ROOT, "infra/sources/sources.json")
STATE = os.environ.get("DFIR_SOURCES_STATE") or os.path.join(ROOT, "state/sources")
INSTALLED = os.path.join(STATE, "installed.json")
PROV = os.path.join(STATE, "provenance.jsonl")
UA = {"User-Agent": "dfir-vao-sources/1.0"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env_value(name):
    if os.environ.get(name):
        return os.environ[name]
    try:
        for ln in open(os.path.join(ROOT, ".env"), encoding="utf-8"):
            if ln.startswith(name + "="):
                return ln.split("=", 1)[1].strip().strip('"\'')
    except OSError:
        pass
    return ""


def mask(url, src):
    k = env_value(src.get("auth_env", "")) if src.get("auth_env") else ""
    return url.replace(k, "***") if k else url


def load_json(p, default):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return default


def http(url, method="GET", timeout=60):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA, method=method), timeout=timeout)


# ---------- upstream version ----------
def resolve(src):
    """-> dict(url, version, size|None, expect{}) or dict(status=needs_key|error, detail)"""
    if src["kind"] == "github_file":
        api = "https://api.github.com/repos/%s/contents/%s" % (src["repo"], src["path"])
        meta = json.load(http(api, timeout=30))
        return {"url": meta["download_url"], "version": "git:" + meta["sha"], "size": meta["size"],
                "expect": {"git_blob_sha1": meta["sha"], "size": meta["size"]}}
    url = src["url"]
    if src.get("auth_env"):
        key = env_value(src["auth_env"])
        if not key:
            return {"status": "needs_key", "detail": src.get("auth_note", src["auth_env"] + " not set")}
        url = url.replace("{%s}" % src["auth_env"], key)
    if src.get("refresh_days"):
        # generated hourly upstream, no stable version tag: refresh by age
        return {"url": url, "version": "date:" + now()[:10], "size": None, "expect": {}, "by_age": src["refresh_days"]}
    h = http(url, method="HEAD", timeout=30)
    ver = h.headers.get("ETag") or h.headers.get("Last-Modified") or ""
    size = int(h.headers.get("Content-Length") or 0) or None
    return {"url": url, "version": "etag:" + ver.strip('"'), "size": size, "expect": {"content_length": size},
            "last_modified": h.headers.get("Last-Modified")}


def adopt(src, up, inst):
    """Files fetched by hand before this manifest existed: record them once if they provably match
    upstream (git blob hash / exact size) or, for age-refreshed sources, by their file time.
    Nothing is downloaded; the provenance line says how weak or strong the match is."""
    f = os.path.join(dest_dir(), src["file"])
    if src["id"] in inst or not os.path.exists(f) or not os.path.exists(os.path.join(dest_dir(), src["output"])):
        return
    how = None
    if "git_blob_sha1" in up["expect"] and git_blob_sha1(f) == up["expect"]["git_blob_sha1"]:
        how = "git blob sha1 equals upstream"
    elif up["expect"].get("content_length") and os.path.getsize(f) == up["expect"]["content_length"]:
        how = "size equals upstream Content-Length (pre-manifest file, no published hash)"
    elif up.get("by_age"):
        how = "pre-manifest file, age from mtime"
    if not how:
        return
    h = hashlib.sha256()
    with open(f, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    mt = int(os.path.getmtime(f))
    ver = up["version"] if not up.get("by_age") else "date:" + time.strftime("%Y-%m-%d", time.gmtime(mt))
    inst[src["id"]] = {"version": ver, "sha256": h.hexdigest(), "size": os.path.getsize(f),
                       "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mt)), "installed_ts": mt,
                       "url": mask(up["url"], src), "adopted": how, "rows": db_rows(src)}
    os.makedirs(STATE, exist_ok=True)
    json.dump(inst, open(INSTALLED + ".tmp", "w"), indent=1); os.replace(INSTALLED + ".tmp", INSTALLED)
    record({"ts": now(), "id": src["id"], "outcome": "adopted", "detail": how, "sha256": inst[src["id"]]["sha256"],
            "size": inst[src["id"]]["size"], "url": mask(up["url"], src), "upstream_version": up["version"],
            "license": src.get("license"), "homepage": src.get("homepage")})


def is_current(src, up, inst):
    adopt(src, up, inst)
    cur = inst.get(src["id"])

    if not cur or not os.path.exists(os.path.join(dest_dir(), src["output"])):
        return False
    if up.get("by_age"):
        age = time.time() - cur.get("installed_ts", 0)
        return age < up["by_age"] * 86400
    return cur.get("version") == up["version"]


# ---------- paths / container ----------
def manifest():
    return load_json(MANIFEST, None) or sys.exit("no manifest " + MANIFEST)


def dest_dir():
    return os.path.join(ROOT, manifest()["dest_dir"])


def in_container(path):
    m = manifest()
    return os.path.join(m["container_dest_dir"], os.path.relpath(path, dest_dir()))


def cexec(code, timeout=3600):
    m = manifest()
    r = subprocess.run(["docker", "exec", "-w", "/app", m["container"], "python3", "-c", code],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


# ---------- download + verify ----------
def download(url, dest):
    sha256 = hashlib.sha256()
    with http(url, timeout=120) as r, open(dest, "wb") as fh:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            fh.write(b); sha256.update(b)
    return sha256.hexdigest(), os.path.getsize(dest)


def git_blob_sha1(path):
    h = hashlib.sha1(b"blob %d\0" % os.path.getsize(path))
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def verify(src, up, path, size, inst):
    res = []
    for v in src["verify"]:
        ok, detail = False, ""
        try:
            if v == "git_blob_sha1":
                got = git_blob_sha1(path); ok = got == up["expect"]["git_blob_sha1"]; detail = got
            elif v == "size":
                ok = size == up["expect"]["size"]; detail = "%d vs %d" % (size, up["expect"]["size"])
            elif v == "content_length":
                exp = up["expect"].get("content_length"); ok = bool(exp) and size == exp; detail = "%d vs %s" % (size, exp)
            elif v == "zip_crc":
                with zipfile.ZipFile(path) as z:
                    bad = z.testzip(); ok = bad is None; detail = "members=%d bad=%s" % (len(z.namelist()), bad)
            elif v == "7z_test":
                rc, o = cexec("import py7zr;a=py7zr.SevenZipFile(%r);print(a.testzip())" % in_container(path), 900)
                ok = rc == 0 and o.splitlines()[-1] == "None"; detail = o[-200:]
            elif v == "bloom_selftest":
                rc, o = cexec("from analysis import hash_lookup as h\nfrom flor import BloomFilter\n"
                              "bf=BloomFilter();bf.read(open(%r,'rb'))\nr=h.bloom_self_test(bf)\n"
                              "print(r, r<=h.MAX_FP_RATE)" % in_container(path), 1800)
                ok = rc == 0 and o.splitlines()[-1].endswith("True"); detail = "fp_rate " + o[-120:]
            elif v == "rows_not_shrinking":
                ok = True; detail = "checked after build"
            else:
                detail = "unknown check"
        except Exception as e:  # a check that cannot run is a failed check
            detail = "%s: %s" % (type(e).__name__, e)
        res.append({"check": v, "ok": ok, "detail": detail})
    return res


# ---------- build ----------
def build(src, final_path):
    """Build the derived database from the (already swapped-in) source file. -> (ok, detail)"""
    d = in_container(os.path.dirname(final_path))
    if src["build"] == "none":
        return True, "file is the database"
    if src["build"] == "vanilla":
        code = ("import py7zr,tempfile,subprocess,sys,glob\nt=tempfile.mkdtemp()\n"
                "py7zr.SevenZipFile(%r).extractall(t)\nc=glob.glob(t+'/**/UniqueDirectoryAndNames.csv',recursive=True)[0]\n"
                "r=subprocess.run([sys.executable,'/app/analysis/build_vanilla.py',c,%r],capture_output=True,text=True)\n"
                "print(r.stdout[-300:],r.stderr[-300:]);import shutil;shutil.rmtree(t)\nsys.exit(r.returncode)"
                % (in_container(final_path), d + "/" + src["output"]))
        rc, o = cexec(code, 3600)
        return rc == 0 and "rows: paths=" in o, o[-300:]
    if src["build"] == "known_bad":
        rc, o = cexec("import subprocess,sys;r=subprocess.run([sys.executable,'/app/analysis/hash_db_build.py','--dir',%r,"
                      "'--skip-download','--only','bad'],capture_output=True,text=True);print(r.stdout[-400:],r.stderr[-400:]);"
                      "sys.exit(r.returncode)" % d, 3600)
        return rc == 0, o[-400:]
    return False, "unknown build " + src["build"]


def db_rows(src):
    p = in_container(os.path.join(dest_dir(), src["output"]))
    q = {"known_bad": "SELECT count(*) FROM bad", "vanilla": "SELECT count(*) FROM vpath"}.get(src["build"])
    if not q:
        return None
    rc, o = cexec("import sqlite3;print(sqlite3.connect('file:%s?mode=ro',uri=True).execute(%r).fetchone()[0])" % (p, q), 300)
    return int(o.splitlines()[-1]) if rc == 0 and o.splitlines()[-1].isdigit() else None


# ---------- commands ----------
def record(rec):
    os.makedirs(STATE, exist_ok=True)
    with open(PROV, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def cmd_check(only=None):
    inst, rc = load_json(INSTALLED, {}), 0  # adopt() fills it during the loop
    rows = []
    for src in manifest()["sources"]:
        if only and src["id"] != only:
            continue
        try:
            up = resolve(src)
        except Exception as e:
            up = {"status": "error", "detail": "%s: %s" % (type(e).__name__, e)}
        if up.get("status"):
            st = up["status"]; rc = max(rc, 3 if st == "needs_key" else 1)
        else:
            st = "current" if is_current(src, up, inst) else "outdated"
            if st == "outdated":
                rc = max(rc, 3)
        cur = load_json(INSTALLED, {}).get(src["id"], {})
        rows.append({"id": src["id"], "status": st, "installed": cur.get("version"), "installed_at": cur.get("installed_at"),
                     "upstream": up.get("version"), "detail": up.get("detail", "")})
    for r in rows:
        print("%-26s %-9s installed=%s (%s) upstream=%s %s" % (r["id"], r["status"], r["installed"], r["installed_at"],
                                                             r["upstream"], r["detail"][:160]))
    return rc, rows


def update_one(src, force=False):
    inst = load_json(INSTALLED, {})
    rec = {"ts": now(), "id": src["id"], "license": src.get("license"), "homepage": src.get("homepage")}
    try:
        up = resolve(src)
    except Exception as e:
        rec.update(outcome="error", detail="resolve %s: %s" % (type(e).__name__, e)); record(rec); return False
    if up.get("status"):
        rec.update(outcome=up["status"], detail=up["detail"]); record(rec); print(src["id"], up["status"]); return up["status"] == "needs_key"
    rec.update(url=mask(up["url"], src), upstream_version=up["version"], last_modified=up.get("last_modified"))
    if not force and is_current(src, up, inst):
        print(src["id"], "current", up["version"]); return True
    dd = dest_dir(); stg = os.path.join(dd, ".staging"); os.makedirs(stg, exist_ok=True)
    part = os.path.join(stg, src["file"])
    rows_before = db_rows(src)
    print(src["id"], "downloading", mask(up["url"], src)); t0 = time.time()
    try:
        sha, size = download(up["url"], part)
    except Exception as e:
        rec.update(outcome="download_failed", detail="%s: %s" % (type(e).__name__, mask(str(e), src)))
        record(rec); shutil.rmtree(stg, ignore_errors=True); print(src["id"], rec["detail"]); return False
    rec.update(sha256=sha, size=size, download_s=round(time.time() - t0, 1))
    checks = verify(src, up, part, size, inst); rec["checks"] = checks
    if not all(c["ok"] for c in checks):
        rec["outcome"] = "verify_failed"; record(rec); shutil.rmtree(stg, ignore_errors=True)
        print(src["id"], "VERIFY FAILED", checks); return False
    final = os.path.join(dd, src["file"]); prev = final + ".prev"
    out = os.path.join(dd, src["output"]); out_prev = out + ".prev"
    if os.path.exists(final):
        os.replace(final, prev)
    if src["output"] != src["file"] and os.path.exists(out):
        shutil.copy2(out, out_prev)
    os.replace(part, final)
    ok, detail = build(src, final)
    rows_after = db_rows(src)
    rec.update(build=detail, rows_before=rows_before, rows_after=rows_after)
    if ok and "rows_not_shrinking" in src["verify"] and rows_before and (rows_after or 0) < rows_before * 0.9:
        ok = False; rec["build"] += " | rows shrank %s -> %s" % (rows_before, rows_after)
    if not ok:
        os.replace(prev, final) if os.path.exists(prev) else os.remove(final)
        if os.path.exists(out_prev):
            os.replace(out_prev, out)
        rec["outcome"] = "build_failed_rolled_back"; record(rec); shutil.rmtree(stg, ignore_errors=True)
        print(src["id"], "BUILD FAILED, rolled back:", detail[-200:]); return False
    for p in (prev, out_prev):
        if os.path.exists(p):
            os.remove(p)
    shutil.rmtree(stg, ignore_errors=True)
    inst = load_json(INSTALLED, {})
    inst[src["id"]] = {"version": up["version"], "sha256": sha, "size": size, "installed_at": now(),
                       "installed_ts": int(time.time()), "url": rec["url"], "rows": rows_after}
    os.makedirs(STATE, exist_ok=True)
    json.dump(inst, open(INSTALLED + ".tmp", "w"), indent=1); os.replace(INSTALLED + ".tmp", INSTALLED)
    rec["outcome"] = "installed"; record(rec)
    print(src["id"], "installed", up["version"], "sha256", sha[:16], "rows", rows_after); return True


def main(a):
    cmd = a[0] if a else "check"
    if cmd == "check":
        return cmd_check(a[a.index("--only") + 1] if "--only" in a else None)[0]
    if cmd == "update":
        only = a[a.index("--only") + 1] if "--only" in a else None
        res = [update_one(s, "--force" in a) for s in manifest()["sources"] if not only or s["id"] == only]
        return 0 if all(res) else 1
    if cmd == "log":
        n = int(a[1]) if len(a) > 1 else 20
        for ln in open(PROV, encoding="utf-8").readlines()[-n:] if os.path.exists(PROV) else []:
            print(ln.rstrip())
        return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
