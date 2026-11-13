"""vao_parser_browser - our own all-browser artefact parser.

WHY IT EXISTS
    NirSoft BrowsingHistoryView / WebBrowserDownloadsView stay in the collector and are NOT
    replaced; this runs ALONGSIDE them so the two can be compared and nothing regresses.
    What ours adds, and NirSoft cannot give:
      * downloads_url_chain  - the FULL redirect chain a download travelled (the single most
        useful field for answering "звідки взявся файл")
      * visit transition type + the referring visit (from_visit -> referrer URL)
      * opener/tab referrer, MOTW-style host, and per-profile signed-in identity
    It reads the RAW databases the collector now drops into `_raw/browsers/`, so it can be
    re-run over archives collected months ago (the raw-to-bot principle).

WHY PYTHON AND NOT THE COLLECTOR
    Chromium `History` and Firefox `places.sqlite` are SQLite. .NET/PowerShell has no built-in
    SQLite reader, and rolling our own would have to handle WAL - ignoring the `-wal` sidecar
    silently drops the MOST RECENT history, which is exactly the evidence that matters.
    Python's stdlib sqlite3 replays the WAL correctly.

LAYOUT IT EXPECTS (written by the collector script collect_browser_raw.ps1):
    _raw/browsers/<user>/<Browser>/<profile>__<FileName>
"""
from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import re
import shutil
import sqlite3
import tempfile

SOURCE = "vao_parser_browser"

# ---------------------------------------------------------------- timestamps
_CHROME_EPOCH = _dt.datetime(1601, 1, 1)


def chrome_ts(v):
    """Chromium: microseconds since 1601-01-01."""
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return (_CHROME_EPOCH + _dt.timedelta(microseconds=v)).isoformat(sep=" ")
    except (OverflowError, OSError):
        return None


def firefox_ts(v):
    """Firefox: microseconds since the Unix epoch (moz_historyvisits) or ms (some tables)."""
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    if v > 1_000_000_000_000_000:      # microseconds
        v = v / 1_000_000
    elif v > 1_000_000_000_000:        # milliseconds
        v = v / 1_000
    try:
        return _dt.datetime.fromtimestamp(v, _dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
    except (OverflowError, OSError, ValueError):
        return None


def unix_ts(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return _dt.datetime.fromtimestamp(v, _dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------- Chromium visit transitions
# low byte of `visits.transition` - core transition type
_TRANSITION = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe",
    5: "generated", 6: "start_page", 7: "form_submit", 8: "reload", 9: "keyword",
    10: "keyword_generated",
}
_QUALIFIER = {
    0x00800000: "forward_back", 0x01000000: "from_address_bar",
    0x02000000: "home_page", 0x04000000: "from_api",
    0x10000000: "chain_start", 0x20000000: "chain_end",
    0x40000000: "client_redirect", 0x80000000: "server_redirect",
}


def decode_transition(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    core = _TRANSITION.get(v & 0xFF, "unknown")
    quals = [n for bit, n in _QUALIFIER.items() if v & bit]
    return core + ("|" + "|".join(sorted(quals)) if quals else "")


# ---------------------------------------------------------------- sqlite helpers
def open_ro(path):
    """Open a throwaway COPY of the database, with its WAL replayed.

    The evidence file itself is never touched: everything happens on a copy in a temp dir.
    The copy is then opened READ-WRITE on purpose - SQLite can only replay a `-wal` sidecar
    when it can write. Verified against a fixture whose newest row exists ONLY in the WAL:
    read-write on the copy recovers it. Read-only can also work when the -shm is present,
    but read-write on a throwaway copy is the option that cannot silently return stale data.
    Falls back to `immutable=1` when the WAL is missing or corrupt (ignores locks/journal).
    """
    tmpdir = tempfile.mkdtemp(prefix="vaobrowser_")
    base = os.path.join(tmpdir, os.path.basename(path))
    shutil.copy2(path, base)
    for suffix in ("-wal", "-shm", "-journal"):
        side = path + suffix
        if os.path.exists(side):
            shutil.copy2(side, base + suffix)
    try:
        con = sqlite3.connect(base)          # read-write on the COPY -> WAL is replayed
        con.execute("SELECT 1").fetchone()
        return con, tmpdir
    except sqlite3.Error:
        try:
            con = sqlite3.connect(f"file:{base}?immutable=1", uri=True)
            return con, tmpdir
        except sqlite3.Error:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise


def tables(con):
    try:
        return {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.Error:
        return set()


def _q(con, sql, args=()):
    try:
        return con.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []


# ---------------------------------------------------------------- Chromium
def parse_chromium_history(path, ctx, limit=200000):
    """urls + visits (transition, referrer) + downloads (with the full URL chain) + searches."""
    hist, dls, searches = [], [], []
    con, tmp = open_ro(path)
    try:
        tabs = tables(con)

        if "urls" in tabs and "visits" in tabs:
            # join each visit to its referring visit so the chain is explicit
            rows = _q(con, """
                SELECT v.visit_time, u.url, u.title, v.transition,
                       ru.url AS referrer_url, u.visit_count, u.typed_count
                FROM visits v
                JOIN urls u ON u.id = v.url
                LEFT JOIN visits rv ON rv.id = v.from_visit
                LEFT JOIN urls ru  ON ru.id = rv.url
                ORDER BY v.visit_time DESC LIMIT ?""", (limit,))
            for ts, url, title, trans, ref, vc, tc in rows:
                hist.append(dict(ctx, visited_at=chrome_ts(ts), url=url or "",
                                 title=title or "", transition=decode_transition(trans),
                                 referrer_url=ref or "", visit_count=vc or 0,
                                 typed_count=tc or 0))
        elif "urls" in tabs:  # history with visits pruned
            for url, title, vc, tc, lv in _q(con,
                    "SELECT url,title,visit_count,typed_count,last_visit_time "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,)):
                hist.append(dict(ctx, visited_at=chrome_ts(lv), url=url or "",
                                 title=title or "", transition="", referrer_url="",
                                 visit_count=vc or 0, typed_count=tc or 0))

        if "downloads" in tabs:
            # The real Chromium/Edge table is downloads_url_chainS (plural). An earlier
            # singular spelling silently matched nothing on real data - the synthetic
            # fixture had reproduced the same typo, so it validated the mistake.
            chains = {}
            _chain_tbl = None
            for _c in ("downloads_url_chains", "downloads_url_chain"):
                if _c in tabs:
                    _chain_tbl = _c
                    break
            if _chain_tbl:
                for did, idx, url in _q(con,
                        "SELECT id,chain_index,url FROM " + _chain_tbl +
                        " ORDER BY id,chain_index"):
                    chains.setdefault(did, []).append((idx, url))
            cols = {r[1] for r in _q(con, "PRAGMA table_info(downloads)")}
            sel = ["id", "target_path", "start_time", "end_time", "received_bytes",
                   "total_bytes", "danger_type", "opened"]
            for opt in ("tab_url", "tab_referrer_url", "mime_type", "original_mime_type",
                        "site_url", "referrer"):
                if opt in cols:
                    sel.append(opt)
            rows = _q(con, "SELECT " + ",".join(sel) + " FROM downloads "
                           "ORDER BY start_time DESC LIMIT ?", (limit,))
            for r in rows:
                rec = dict(zip(sel, r))
                chain = [u for _i, u in sorted(chains.get(rec.get("id"), []))]
                dls.append(dict(
                    ctx,
                    started_at=chrome_ts(rec.get("start_time")),
                    finished_at=chrome_ts(rec.get("end_time")),
                    target_path=rec.get("target_path") or "",
                    # the LAST link of the chain is the host that actually served the bytes
                    source_url=(chain[-1] if chain else (rec.get("referrer") or "")),
                    url_chain=" -> ".join(chain),
                    chain_len=len(chain),
                    tab_url=rec.get("tab_url") or "",
                    tab_referrer_url=rec.get("tab_referrer_url") or "",
                    mime_type=rec.get("mime_type") or rec.get("original_mime_type") or "",
                    received_bytes=rec.get("received_bytes") or 0,
                    total_bytes=rec.get("total_bytes") or 0,
                    danger_type=rec.get("danger_type"),
                    opened=rec.get("opened")))

        if "keyword_search_terms" in tabs:
            for term, url, lv in _q(con,
                    "SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                    "JOIN urls u ON u.id = k.url_id ORDER BY u.last_visit_time DESC LIMIT ?",
                    (limit,)):
                searches.append(dict(ctx, searched_at=chrome_ts(lv),
                                     term=term or "", url=url or ""))
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return hist, dls, searches


def parse_chromium_webdata(path, ctx, limit=50000):
    """`Web Data` - autofill values are strong identity evidence (emails, phones, names)."""
    out = []
    con, tmp = open_ro(path)
    try:
        if "autofill" in tables(con):
            for name, value, count, dc, du in _q(con,
                    "SELECT name,value,count,date_created,date_last_used "
                    "FROM autofill ORDER BY count DESC LIMIT ?", (limit,)):
                out.append(dict(ctx, field=name or "", value=value or "",
                                use_count=count or 0,
                                first_used=unix_ts(dc), last_used=unix_ts(du)))
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def parse_chromium_prefs(path, ctx):
    """`Preferences` JSON - the signed-in Google/Microsoft account for this profile."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return out
    accounts = (((data.get("account_info") or []) if isinstance(data, dict) else []))
    for a in accounts if isinstance(accounts, list) else []:
        if isinstance(a, dict):
            out.append(dict(ctx, account_email=a.get("email", ""),
                            account_name=a.get("full_name", ""),
                            account_id=a.get("gaia", "")))
    prof = (data.get("profile") or {}) if isinstance(data, dict) else {}
    if isinstance(prof, dict) and prof.get("name"):
        out.append(dict(ctx, account_email="", account_name=prof.get("name", ""),
                        account_id=""))
    return out


# ---------------------------------------------------------------- Firefox
def parse_firefox_places(path, ctx, limit=200000):
    hist, dls, searches = [], [], []
    con, tmp = open_ro(path)
    try:
        tabs = tables(con)
        if "moz_places" in tabs and "moz_historyvisits" in tabs:
            rows = _q(con, """
                SELECT v.visit_date, p.url, p.title, v.visit_type,
                       rp.url AS referrer_url, p.visit_count, p.typed
                FROM moz_historyvisits v
                JOIN moz_places p ON p.id = v.place_id
                LEFT JOIN moz_historyvisits rv ON rv.id = v.from_visit
                LEFT JOIN moz_places rp ON rp.id = rv.place_id
                ORDER BY v.visit_date DESC LIMIT ?""", (limit,))
            # Firefox visit_type: 1 link, 2 typed, 3 bookmark, 5 permanent redirect,
            # 6 temporary redirect, 7 download
            ftypes = {1: "link", 2: "typed", 3: "bookmark", 4: "embed",
                      5: "redirect_permanent", 6: "redirect_temporary", 7: "download",
                      8: "framed_link", 9: "reload"}
            for ts, url, title, vt, ref, vc, typed in rows:
                hist.append(dict(ctx, visited_at=firefox_ts(ts), url=url or "",
                                 title=title or "", transition=ftypes.get(vt, str(vt or "")),
                                 referrer_url=ref or "", visit_count=vc or 0,
                                 typed_count=typed or 0))
                if vt == 7:
                    dls.append(dict(ctx, started_at=firefox_ts(ts), finished_at=None,
                                    target_path="", source_url=url or "",
                                    url_chain=(ref + " -> " + (url or "")) if ref else (url or ""),
                                    chain_len=2 if ref else 1, tab_url="",
                                    tab_referrer_url=ref or "", mime_type="",
                                    received_bytes=0, total_bytes=0, danger_type=None,
                                    opened=None))
        elif "moz_places" in tabs:
            for url, title, vc, lv in _q(con,
                    "SELECT url,title,visit_count,last_visit_date FROM moz_places "
                    "ORDER BY last_visit_date DESC LIMIT ?", (limit,)):
                hist.append(dict(ctx, visited_at=firefox_ts(lv), url=url or "",
                                 title=title or "", transition="", referrer_url="",
                                 visit_count=vc or 0, typed_count=0))

        # downloads recorded as annotations (Firefox 26+)
        if {"moz_annos", "moz_anno_attributes", "moz_places"} <= tabs:
            for url, target, ts in _q(con, """
                    SELECT p.url, a.content, a.dateAdded
                    FROM moz_annos a
                    JOIN moz_places p ON p.id = a.place_id
                    JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id
                    WHERE t.name = 'downloads/destinationFileURI' LIMIT ?""", (limit,)):
                dls.append(dict(ctx, started_at=firefox_ts(ts), finished_at=None,
                                target_path=target or "", source_url=url or "",
                                url_chain=url or "", chain_len=1, tab_url="",
                                tab_referrer_url="", mime_type="", received_bytes=0,
                                total_bytes=0, danger_type=None, opened=None))
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return hist, dls, searches


def parse_firefox_formhistory(path, ctx, limit=50000):
    out = []
    con, tmp = open_ro(path)
    try:
        if "moz_formhistory" in tables(con):
            for name, value, count, first, last in _q(con,
                    "SELECT fieldname,value,timesUsed,firstUsed,lastUsed "
                    "FROM moz_formhistory ORDER BY timesUsed DESC LIMIT ?", (limit,)):
                out.append(dict(ctx, field=name or "", value=value or "",
                                use_count=count or 0,
                                first_used=firefox_ts(first), last_used=firefox_ts(last)))
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def parse_firefox_logins(path, ctx):
    """logins.json - METADATA ONLY. Passwords stay encrypted and are never touched."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return out
    for e in (data.get("logins") or []) if isinstance(data, dict) else []:
        if isinstance(e, dict):
            out.append(dict(ctx, account_email=e.get("usernameField", ""),
                            account_name=e.get("hostname", ""),
                            account_id=str(e.get("timeCreated", ""))))
    return out


# ---------------------------------------------------------------- discovery
_FILE_RE = re.compile(r"^(?P<profile>.+?)__(?P<name>.+)$")


def iter_browser_files(root):
    """Yield (path, ctx) for every file under _raw/browsers/<user>/<browser>/."""
    for dirpath, _dirs, files in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        parts = [p for p in rel.split(os.sep) if p and p != "."]
        if len(parts) < 2:
            continue
        user, browser = parts[0], parts[1]
        for fn in files:
            m = _FILE_RE.match(fn)
            profile = m.group("profile") if m else ""
            name = (m.group("name") if m else fn)
            yield os.path.join(dirpath, fn), {
                "user": user, "browser": browser, "profile": profile,
                "source_file": fn, "parser": SOURCE,
            }, name.lower()


def parse_tree(root):
    """Parse everything under the browsers root. Returns dict of row-lists."""
    hist, dls, searches, autofill, profiles = [], [], [], [], []
    errors = []
    for path, ctx, name in iter_browser_files(root):
        # sidecars are consumed with their parent DB, never on their own
        if name.endswith(("-wal", "-shm", "-journal")):
            continue
        try:
            if name == "history":
                h, d, s = parse_chromium_history(path, ctx)
                hist += h; dls += d; searches += s
            elif name == "web data":
                autofill += parse_chromium_webdata(path, ctx)
            elif name in ("preferences", "secure preferences"):
                profiles += parse_chromium_prefs(path, ctx)
            elif name == "places.sqlite":
                h, d, s = parse_firefox_places(path, ctx)
                hist += h; dls += d; searches += s
            elif name == "formhistory.sqlite":
                autofill += parse_firefox_formhistory(path, ctx)
            elif name == "logins.json":
                profiles += parse_firefox_logins(path, ctx)
        except Exception as exc:                      # never let one bad DB stop the rest
            errors.append(f"{ctx['user']}/{ctx['browser']}/{ctx['source_file']}: {exc}")
    return {"history": hist, "downloads": dls, "searches": searches,
            "autofill": autofill, "profiles": profiles, "errors": errors}


_CSV_FIELDS = {
    "history": ["user", "browser", "profile", "visited_at", "url", "title", "transition",
                "referrer_url", "visit_count", "typed_count", "source_file", "parser"],
    "downloads": ["user", "browser", "profile", "started_at", "finished_at", "target_path",
                  "source_url", "url_chain", "chain_len", "tab_url", "tab_referrer_url",
                  "mime_type", "received_bytes", "total_bytes", "danger_type", "opened",
                  "source_file", "parser"],
    "searches": ["user", "browser", "profile", "searched_at", "term", "url",
                 "source_file", "parser"],
    "autofill": ["user", "browser", "profile", "field", "value", "use_count",
                 "first_used", "last_used", "source_file", "parser"],
    "profiles": ["user", "browser", "profile", "account_email", "account_name",
                 "account_id", "source_file", "parser"],
}


def write_csvs(result, outdir):
    os.makedirs(outdir, exist_ok=True)
    written = {}
    for kind, fields in _CSV_FIELDS.items():
        rows = result.get(kind) or []
        if not rows:
            continue
        path = os.path.join(outdir, f"{SOURCE}_{kind}.csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        written[kind] = (path, len(rows))
    return written


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="vao_parser_browser")
    ap.add_argument("root", help="path to _raw/browsers")
    ap.add_argument("-o", "--out", default=".", help="directory for the CSVs")
    a = ap.parse_args(argv)
    res = parse_tree(a.root)
    written = write_csvs(res, a.out)
    for kind in _CSV_FIELDS:
        print(f"{kind}|{len(res.get(kind) or [])}")
    for e in res["errors"]:
        print("ERROR|" + e)
    for kind, (path, n) in written.items():
        print(f"CSV|{kind}|{n}|{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ------------------------------------------------------------------ zip ingest
# Families match what parsers/browser_sqlite.py already emits, so the existing
# raw_fallback_v2 consumers (agent_tools.get_browser_downloads / get_browser_activity)
# pick these rows up with no other change.
_FAMILY = {
    "history": "browser_history",
    "downloads": "browser_downloads",
    "searches": "browser_searches",
    "autofill": "browser_autofill",
    "profiles": "browser_profiles",
}
_RAW_PREFIX = "_raw/browsers/"


def zip_members(all_names):
    """_raw/browsers members, sidecars excluded (they are copied with their parent DB)."""
    out = []
    for n in all_names:
        p = str(n).replace("\\", "/").lower()
        if _RAW_PREFIX not in p:
            continue
        base = p.rsplit("/", 1)[-1]
        if not base:
            continue          # a directory entry: zip keeps them, they are not files
        if base.endswith(("-wal", "-shm", "-journal")):
            continue
        out.append(n)
    return out


def parse_from_zip(zf, all_names):
    """Parse every `_raw/browsers/**` member of an OPEN zipfile.

    Returns (records, errors) where records are (parser_family, payload) tuples - the same
    shape parsers/browser_sqlite.py returns. Each DB is extracted together with its -wal/-shm
    sidecars, otherwise the newest history is invisible.
    """
    recs, errors = [], []
    for rel in zip_members(all_names):
        parts = str(rel).replace("\\", "/").split("/")
        low = [x.lower() for x in parts]
        try:
            i = low.index("browsers")
        except ValueError:
            continue
        user = parts[i + 1] if len(parts) > i + 1 else ""
        browser = parts[i + 2] if len(parts) > i + 2 else ""
        fn = parts[-1]
        m = _FILE_RE.match(fn)
        profile = m.group("profile") if m else ""
        name = (m.group("name") if m else fn).lower()
        ctx = {"user": user, "browser": browser, "profile": profile,
               "source_file": fn, "parser": SOURCE}

        td = tempfile.mkdtemp(prefix="vaozip_")
        try:
            main = os.path.join(td, fn)
            with zf.open(rel, "r") as src, open(main, "wb") as dst:
                shutil.copyfileobj(src, dst)
            for suf in ("-wal", "-shm", "-journal"):
                sib = rel + suf
                if sib in all_names:
                    with zf.open(sib, "r") as s2, open(main + suf, "wb") as d2:
                        shutil.copyfileobj(s2, d2)

            buckets = {}
            if name == "history":
                h, d, s = parse_chromium_history(main, ctx)
                buckets = {"history": h, "downloads": d, "searches": s}
            elif name == "web data":
                buckets = {"autofill": parse_chromium_webdata(main, ctx)}
            elif name in ("preferences", "secure preferences"):
                buckets = {"profiles": parse_chromium_prefs(main, ctx)}
            elif name == "places.sqlite":
                h, d, s = parse_firefox_places(main, ctx)
                buckets = {"history": h, "downloads": d, "searches": s}
            elif name == "formhistory.sqlite":
                buckets = {"autofill": parse_firefox_formhistory(main, ctx)}
            elif name == "logins.json":
                buckets = {"profiles": parse_firefox_logins(main, ctx)}

            for kind, rows in buckets.items():
                fam = _FAMILY[kind]
                for r in rows:
                    recs.append((fam, r))
        except Exception as exc:                     # one bad DB must not stop the rest
            errors.append(f"{fn}: {exc}")
        finally:
            shutil.rmtree(td, ignore_errors=True)
    return recs, errors
