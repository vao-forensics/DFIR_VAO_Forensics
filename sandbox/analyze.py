#!/usr/bin/env python3
"""Runs INSIDE the disposable sandbox (dfir-sandbox image, NO network, non-root,
read-only rootfs, size-capped tmpfs /work). Understands whatever is dropped in:
an archive (zip/tar/7z/rar, incl. AES zip with a one-time password), a single
file (log/csv/json/evtx/registry/sqlite/text/binary), or an already-extracted
directory. Produces an inventory, a light read-only indicator scan, a per-file
type/preview summary and a report for the LLM. NEVER executes extracted content.
Anti-bomb: caps on total/one-file size and file count, path-traversal guard."""
from __future__ import annotations
import argparse, csv, datetime as dt, hashlib, json, os, subprocess, sys, tarfile, zipfile
from pathlib import Path

MAX_TOTAL = 2 * 1024 * 1024 * 1024   # < tmpfs /work (run_sandbox.sh)
MAX_FILES = 300_000
MAX_ONE = 600 * 1024 * 1024          # = ulimit fsize in run_sandbox.sh
PREVIEW_BYTES = 1500
ZIP_PW = os.environ.get("SANDBOX_ZIP_PW")  # one-time password for an AES archive
if not ZIP_PW and os.path.isfile("/run/sbx_pw"):   # preferred: a ro file, not visible in ps / docker inspect
    ZIP_PW = open("/run/sbx_pw", encoding="utf-8").read().strip() or None


def iso(ts): return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(p: Path):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _safe_join(root: Path, name: str):
    dest = (root / name).resolve()
    try:
        dest.relative_to(root.resolve()); return dest
    except ValueError:
        return None


def _extract_stdlib_zip(archive, work, rep):
    total = count = 0
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            count += 1; total += info.file_size
            if count > MAX_FILES or total > MAX_TOTAL:
                raise RuntimeError("archive bomb cap exceeded")
            if info.file_size > MAX_ONE:
                raise RuntimeError("single-file cap exceeded: %s" % info.filename)
            dest = _safe_join(work, info.filename)
            if dest is None:
                rep["rejected_paths"].append(info.filename); continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as s, dest.open("wb") as o:
                while True:
                    c = s.read(1 << 20)
                    if not c:
                        break
                    o.write(c)
    rep["extracted_files"] = count; rep["extracted_bytes"] = total


def _extract_stdlib_tar(archive, work, rep):
    total = count = 0
    with tarfile.open(archive) as t:
        for m in t.getmembers():
            if not m.isreg():
                continue
            count += 1; total += m.size
            if count > MAX_FILES or total > MAX_TOTAL:
                raise RuntimeError("archive bomb cap exceeded")
            if m.size > MAX_ONE:
                raise RuntimeError("single-file cap exceeded: %s" % m.name)
            dest = _safe_join(work, m.name)
            if dest is None:
                rep["rejected_paths"].append(m.name); continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            f = t.extractfile(m)
            if f is None:
                continue
            with dest.open("wb") as o:
                while True:
                    c = f.read(1 << 20)
                    if not c:
                        break
                    o.write(c)
    rep["extracted_files"] = count; rep["extracted_bytes"] = total


def _extract_7za(archive, work, rep):
    # handles zip/7z/rar and AES zip (password via env, passed once, no key here)
    cmd = ["7za", "x", "-y", "-bd", "-o%s" % str(work), str(archive)]
    cmd.insert(2, "-p%s" % (ZIP_PW or ""))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError("7za failed: %s" % (r.stderr.strip()[:200] or r.stdout.strip()[:200]))
    n = b = 0
    for p in work.rglob("*"):
        if p.is_file():
            n += 1; b += p.stat().st_size
    rep["extracted_files"] = n; rep["extracted_bytes"] = b


def ingest(inp: Path, work: Path, rep: dict):
    if inp.is_dir():
        rep["input_kind"] = "directory"
        # already-extracted content: use it directly as the work tree
        rep["workroot"] = str(inp)
        return inp
    rep["input_kind"] = "file"
    name = inp.name.lower()
    if zipfile.is_zipfile(inp):
        # stdlib first; if it is an AES zip (method 99) stdlib fails -> 7za
        try:
            _extract_stdlib_zip(inp, work, rep); rep["archive_type"] = "zip"
        except (NotImplementedError, RuntimeError) as e:
            if "cap exceeded" in str(e):
                raise
            _extract_7za(inp, work, rep); rep["archive_type"] = "zip-aes/7za"
        return work
    if tarfile.is_tarfile(inp):
        _extract_stdlib_tar(inp, work, rep); rep["archive_type"] = "tar"; return work
    if name.endswith((".7z", ".rar")):
        _extract_7za(inp, work, rep); rep["archive_type"] = name.rsplit(".", 1)[-1]; return work
    # a single non-archive file: copy it into the work tree and analyze as-is
    dest = work / inp.name
    with inp.open("rb") as s, dest.open("wb") as o:
        while True:
            c = s.read(1 << 20)
            if not c:
                break
            o.write(c)
    rep["archive_type"] = "single-file"; rep["extracted_files"] = 1
    rep["extracted_bytes"] = dest.stat().st_size
    return work


SUSPICIOUS = {"authorized_keys": "SSH authorized key", ".bash_history": "shell history",
              ".php": "server-side script", ".sh": "shell script", "cron": "scheduled task",
              ".ps1": "PowerShell script", ".vbs": "script", ".hta": "script host",
              ".scr": "executable disguised", "mimikatz": "cred-dump tool name"}
TEXT_EXT = (".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".md", ".tsv")


def classify(p: Path):
    import deep
    k = deep.sniff(p)          # by signature first: a single upload is called just 'archive' in here
    if k:
        return k
    try:
        import magic
        t = magic.from_file(str(p), mime=True)
    except Exception:
        t = ""
    low = p.name.lower()
    if low.endswith(".evtx"):
        return "windows-eventlog"
    if low.endswith((".dat", ".hiv")) or low in ("ntuser.dat", "system", "software", "sam", "security"):
        return "registry-hive?"
    if low.endswith((".sqlite", ".db", ".sqlite3")):
        return "sqlite-db"
    if low.endswith(TEXT_EXT):
        return "text/" + low.rsplit(".", 1)[-1]
    return t or "binary"


def analyze(root: Path, rep: dict, out: Path):
    inv, hits, types = [], [], {}
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        st = p.stat()
        kind = classify(p)
        types[kind] = types.get(kind, 0) + 1
        row = {"path": rel, "size": st.st_size, "mtime_utc": iso(st.st_mtime),
               "sha256": sha256(p), "kind": kind, "preview": ""}
        if kind.startswith("text/") and st.st_size <= 5_000_000:
            try:
                row["preview"] = p.read_text(encoding="utf-8", errors="replace")[:PREVIEW_BYTES].replace("\n", "\\n")
            except Exception:
                pass
        inv.append(row)
        base = rel.lower().rsplit("/", 1)[-1]
        for key, desc in SUSPICIOUS.items():
            if base.endswith(key) or key in base:
                hits.append({"path": rel, "indicator": key, "note": desc})
    with (out / "inventory.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["path", "size", "mtime_utc", "sha256", "kind"])
        w.writeheader()
        for r in inv:
            w.writerow({k: r[k] for k in ("path", "size", "mtime_utc", "sha256", "kind")})
    with (out / "indicators.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["path", "indicator", "note"]); w.writeheader(); w.writerows(hits)
    # deep read-only parsing: event logs, registry hives, SQLite, CSV (bounded in deep.py)
    import deep
    deep_res = deep.run([(root / r["path"], r["kind"], r["path"]) for r in inv], rep)
    (out / "deep.json").write_text(json.dumps(deep_res, ensure_ascii=False, indent=1), encoding="utf-8")
    rep["deep"] = deep.report_lines(deep_res)
    # context pack for the LLM: ALWAYS valid JSON within CTX_LIMIT; deep summaries first, then
    # indicators, then the file list - shrink the least useful parts until it fits
    ctx = {"deep": deep_res, "types": types, "indicator_hits": hits[:200],
           "files": [{"path": r["path"], "kind": r["kind"], "size": r["size"],
                      "preview": r["preview"]} for r in inv[:400]]}
    _fit(ctx)
    (out / "context.json").write_text(json.dumps(ctx, ensure_ascii=False), encoding="utf-8")
    rep["inventory_count"] = len(inv); rep["indicator_count"] = len(hits); rep["types"] = types


CTX_LIMIT = 28000   # the OWUI filter passes 30000 chars per file to the model


def _size(o):
    return len(json.dumps(o, ensure_ascii=False))


def _fit(ctx):
    steps = [
        lambda: ctx["files"] and [f.update(preview=f["preview"][:200]) for f in ctx["files"]],
        lambda: ctx.__setitem__("files", ctx["files"][:60]),
        lambda: [n.__setitem__("examples", n["examples"][:3]) for d in ctx["deep"] for n in d.get("notable", [])],
        lambda: [d.pop(k, None) for d in ctx["deep"] for k in ("first_rows", "root_subkeys")],
        lambda: [t.pop("sample", None) for d in ctx["deep"] for t in d.get("tables", [])],
        lambda: ctx.__setitem__("files", ctx["files"][:10]),
        lambda: [n.__setitem__("examples", []) for d in ctx["deep"] for n in d.get("notable", [])],
        lambda: ctx.__setitem__("indicator_hits", ctx["indicator_hits"][:30]),
        lambda: [d.__setitem__("top_event_ids", d["top_event_ids"][:10]) for d in ctx["deep"] if "top_event_ids" in d],
    ]
    for st in steps:
        if _size(ctx) <= CTX_LIMIT:
            return
        st()
    while _size(ctx) > CTX_LIMIT and len(ctx["deep"]) > 1:
        ctx["deep"].pop()
        ctx["deep_trimmed"] = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    ap.add_argument("--work", dest="work", default="/work")
    a = ap.parse_args()
    inp, out, work = Path(a.inp), Path(a.out), Path(a.work)
    out.mkdir(parents=True, exist_ok=True); work.mkdir(parents=True, exist_ok=True)
    rep = {"utc_start": iso(dt.datetime.now(dt.timezone.utc).timestamp()), "input_name": inp.name,
           "input_kind": None, "archive_type": None, "rejected_paths": [], "extracted_files": 0,
           "extracted_bytes": 0, "inventory_count": 0, "indicator_count": 0, "types": {},
           "errors": [], "limitations": ["read-only; no execution; previews truncated"]}
    try:
        root = ingest(inp, work, rep)
        analyze(root, rep, out)
    except Exception as e:
        rep["errors"].append(str(e))
    rep["utc_end"] = iso(dt.datetime.now(dt.timezone.utc).timestamp())
    (out / "runmeta.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# Розбір вхідних даних (пісочниця)", "",
             "Файл: %s · тип входу: %s (%s)" % (rep["input_name"], rep["input_kind"], rep["archive_type"]),
             "Файлів усередині: %d · типи: %s" % (rep["inventory_count"],
                 ", ".join("%s×%d" % (k, v) for k, v in sorted(rep["types"].items(), key=lambda x: -x[1])[:12]) or "—"),
             "Індикаторів до перегляду: %d" % rep["indicator_count"],
             "Відхилено (path-traversal): %d" % len(rep["rejected_paths"]),
             "Помилки: %s" % ("; ".join(rep["errors"]) or "немає"), ""]
    if any("cap exceeded" in e for e in rep["errors"]):
        lines[1:1] = ["**УВАГА: розпакування зупинено захистом від архів-бомби** (ліміти: %d МБ разом, %d МБ на файл, "
                      "%d файлів). Вміст архіву НЕ розібрано; це не означає, що архів порожній." % (
                          MAX_TOTAL >> 20, MAX_ONE >> 20, MAX_FILES), ""]
    if rep.get("deep"):
        lines.append("## Глибокий розбір (лише читання)")
        lines.extend(rep["deep"])
        if rep.get("deep_skipped"):
            lines.append("- не встигли за ліміт часу: %d файл(ів)" % len(rep["deep_skipped"]))
        lines.append("")
    if rep["indicator_count"]:
        lines.append("## Індикатори (до перегляду фахівцем)")
        with (out / "indicators.csv").open(encoding="utf-8") as f:
            for r in list(csv.DictReader(f))[:50]:
                lines.append("- `%s` — %s (%s)" % (r["path"], r["note"], r["indicator"]))
        lines.append("")
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
    man = []
    for p in sorted(out.iterdir()):
        if p.name != "SHA256SUMS":
            man.append("%s  %s" % (sha256(p), p.name))
    (out / "SHA256SUMS").write_text("\n".join(man) + "\n", encoding="utf-8")
    print("done: files=%d indicators=%d types=%d errors=%d" % (
        rep["inventory_count"], rep["indicator_count"], len(rep["types"]), len(rep["errors"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
