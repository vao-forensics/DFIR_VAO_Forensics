"""Глибокий розбір у пісочниці (лише читання): журнали Windows (.evtx), кущі реєстру, SQLite, CSV
(зокрема вихід збирача / EZ-tools). Кожен розбір обмежений часом і кількістю записів, щоб великий
файл не з'їв увесь час пісочниці. Повертає компактні зведення для моделі і для звіту.
Нічого не виконує і нічого не пише поза /out."""
import csv, io, re, sqlite3, time
from collections import Counter
from pathlib import Path

PER_FILE_S = 60          # секунд на один файл
TOTAL_S = 420            # на весь глибокий розбір (пісочниця живе 900 с)
MAX_EVTX_REC = 300_000
MAX_CSV_ROWS = 2_000_000
csv.field_size_limit(10_000_000)   # у CSV EZ-tools бувають дуже довгі поля
CELL = 160               # обрізання значень у прикладах

# ID подій, які варто показати окремо (канал, ID) -> що це
NOTABLE = {
    ("Security", 1102): "журнал безпеки очищено",
    ("Security", 4624): "успішний вхід",
    ("Security", 4625): "невдалий вхід",
    ("Security", 4648): "вхід з явними обліковими даними",
    ("Security", 4672): "вхід з адмін-привілеями",
    ("Security", 4688): "запуск процесу",
    ("Security", 4697): "встановлено службу",
    ("Security", 4698): "створено заплановане завдання",
    ("Security", 4720): "створено обліковий запис",
    ("Security", 4722): "увімкнено обліковий запис",
    ("Security", 4724): "скидання пароля",
    ("Security", 4728): "додано до глобальної групи",
    ("Security", 4732): "додано до локальної групи",
    ("Security", 4756): "додано до універсальної групи",
    ("System", 104): "журнал очищено",
    ("System", 7034): "служба аварійно завершилась",
    ("System", 7040): "змінено тип запуску служби",
    ("System", 7045): "встановлено службу",
    ("Microsoft-Windows-PowerShell/Operational", 4104): "блок скрипта PowerShell",
    ("Windows PowerShell", 400): "запуск рушія PowerShell",
    ("Microsoft-Windows-TaskScheduler/Operational", 106): "зареєстровано завдання",
    ("Microsoft-Windows-TaskScheduler/Operational", 200): "запущено дію завдання",
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149): "RDP: автентифікація",
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21): "RDP: вхід у сесію",
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25): "RDP: перепідключення",
    ("Microsoft-Windows-Windows Defender/Operational", 1116): "Defender: виявлено загрозу",
    ("Microsoft-Windows-Windows Defender/Operational", 1117): "Defender: вжито дію",
    ("Microsoft-Windows-Windows Defender/Operational", 5001): "Defender: захист у реальному часі ВИМКНЕНО",
    ("Microsoft-Windows-Windows Defender/Operational", 5007): "Defender: змінено налаштування",
    ("Microsoft-Windows-Bits-Client/Operational", 59): "BITS: почато передачу",
    ("Microsoft-Windows-Sysmon/Operational", 1): "Sysmon: запуск процесу",
    ("Microsoft-Windows-Sysmon/Operational", 3): "Sysmon: мережеве з'єднання",
}
# які поля варто зібрати з окремих подій (до 30 прикладів на (канал, ID))
DETAIL_FIELDS = ("TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName", "LogonType",
                 "ServiceName", "ImagePath", "NewProcessName", "CommandLine", "ParentProcessName",
                 "TaskName", "MemberName", "TargetSid", "Threat Name", "Path", "Action Name",
                 "ScriptBlockText", "Image", "DestinationIp", "DestinationPort", "url", "Param1", "Param2")

RX_EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
RX_CH = re.compile(r"<Channel>([^<]*)</Channel>")
RX_TS = re.compile(r'<TimeCreated SystemTime="([^"]+)"')
RX_DATA = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
RX_PDATA = re.compile(r"<Data>([^<]*)</Data>")
RX_UD = re.compile(r"<UserData>(.*?)</UserData>", re.S)
RX_TAG = re.compile(r"<(\w+)>([^<]+)</\1>")


def _cut(v):
    v = str(v)
    return v if len(v) <= CELL else v[:CELL] + "…"


def sniff(p: Path):
    """тип за сигнатурою: одиночний файл у пісочниці називається просто 'archive'"""
    try:
        with p.open("rb") as f:
            h = f.read(16)
    except OSError:
        return None
    if h.startswith(b"ElfFile\x00"):
        return "windows-eventlog"
    if h.startswith(b"regf"):
        return "registry-hive"
    if h.startswith(b"SQLite format 3\x00"):
        return "sqlite-db"
    return None


# ---------------------------------------------------------------- EVTX
def evtx(p: Path, deadline):
    from Evtx.Evtx import Evtx
    by = Counter(); first = last = None; n = 0; partial = False
    samples = {}
    with Evtx(str(p)) as log:
        for rec in log.records():
            if n >= MAX_EVTX_REC or time.time() > deadline:
                partial = True; break
            try:
                x = rec.xml()
            except Exception:
                continue
            n += 1
            m = RX_EID.search(x); c = RX_CH.search(x); t = RX_TS.search(x)
            eid = int(m.group(1)) if m else -1
            ch = c.group(1) if c else "?"
            ts = t.group(1)[:19].replace(" ", "T") if t else None
            if ts:
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
            by[(ch, eid)] += 1
            if (ch, eid) in NOTABLE:
                lst = samples.setdefault("%s|%d" % (ch, eid), [])
                if len(lst) < 30:
                    d = {k: _cut(v) for k, v in RX_DATA.findall(x) if k in DETAIL_FIELDS and v and v != "-"}
                    if not d:   # 1102, 1149 та ін. кладуть поля в <UserData>
                        u = RX_UD.search(x)
                        if u:
                            d = {k: _cut(v) for k, v in RX_TAG.findall(u.group(1)) if v and v != "-"}
                    if not d:
                        pd = [v for v in RX_PDATA.findall(x) if v][:4]
                        if pd:
                            d = {"data": _cut(" | ".join(pd))}
                    lst.append({"time": ts, **d})
    notable = []
    for (ch, eid), cnt in sorted(by.items(), key=lambda kv: -kv[1]):
        if (ch, eid) in NOTABLE:
            notable.append({"channel": ch, "event_id": eid, "count": cnt, "meaning": NOTABLE[(ch, eid)],
                            "examples": samples.get("%s|%d" % (ch, eid), [])[:10]})
    return {"records_read": n, "partial": partial, "first": first, "last": last,
            "channels": dict(sum((Counter({ch: c}) for (ch, _), c in by.items()), Counter())),
            "top_event_ids": [{"channel": ch, "event_id": e, "count": c} for (ch, e), c in by.most_common(25)],
            "notable": notable}


# ---------------------------------------------------------------- REGISTRY
RUN_PATHS = (r"Microsoft\Windows\CurrentVersion\Run", r"Microsoft\Windows\CurrentVersion\RunOnce",
             r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
             r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run")


def _val(v):
    """REG_BINARY з текстом UTF-16 (TimeZoneKeyName тощо) -> рядок до першого нуля"""
    if isinstance(v, (bytes, bytearray)):
        try:
            t = bytes(v).decode("utf-16-le", "ignore").split("\x00", 1)[0]
            if t and t.isprintable():
                return t
        except Exception:
            pass
        return v[:32].hex() + ("…" if len(v) > 32 else "")
    return v


def _vals(hive, path):
    try:
        k = hive.get_key(path)
    except Exception:
        return None
    out = []
    for v in k.iter_values():
        out.append({"name": _cut(v.name), "value": _cut(_val(v.value))})
        if len(out) >= 40:
            break
    return out


def registry(p: Path, deadline):
    from regipy.registry import RegistryHive
    h = RegistryHive(str(p))
    res = {"hive_type": str(getattr(h, "hive_type", "") or "невідомо"), "root_subkeys": []}
    try:
        res["root_subkeys"] = [s.name for s in h.root.iter_subkeys()][:40]
    except Exception:
        pass
    autoruns = {}
    for rp in RUN_PATHS:
        v = _vals(h, "\\" + rp)
        if v:
            autoruns[rp] = v
    if autoruns:
        res["autoruns"] = autoruns
    info = {}
    for path, names in ((r"\Microsoft\Windows NT\CurrentVersion", ("ProductName", "DisplayVersion", "InstallDate", "RegisteredOwner")),
                        (r"\ControlSet001\Control\ComputerName\ComputerName", ("ComputerName",)),
                        (r"\ControlSet001\Control\TimeZoneInformation", ("TimeZoneKeyName",))):
        v = _vals(h, path) or []
        for it in v:
            if it["name"] in names:
                info[it["name"]] = it["value"]
    if str(info.get("InstallDate", "")).isdigit():
        import datetime as _dt
        info["InstallDate"] = _dt.datetime.fromtimestamp(int(info["InstallDate"]), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if info:
        res["system_info"] = info
    # служби з незвичним шляхом (SYSTEM): не з Windows\System32 / Program Files
    try:
        svc = h.get_key(r"\ControlSet001\Services")
        odd = []
        for s in svc.iter_subkeys():
            if time.time() > deadline:
                res["partial"] = True; break
            ip = ""
            for v in s.iter_values():
                if v.name == "ImagePath":
                    ip = str(v.value); break
            low = ip.lower()
            if ip and not any(x in low for x in ("system32", "syswow64", "program files", "\\windows\\", "systemroot")):
                odd.append({"service": _cut(s.name), "image_path": _cut(ip)})
            if len(odd) >= 40:
                break
        res["services_unusual_path"] = odd
    except Exception:
        pass
    return res


# ---------------------------------------------------------------- SQLITE
BROWSER_Q = (
    ("chrome_history", "select url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') t from urls order by last_visit_time desc limit 30"),
    ("firefox_history", "select url, title, datetime(last_visit_date/1000000,'unixepoch') t from moz_places where last_visit_date is not null order by last_visit_date desc limit 30"),
    ("chrome_downloads", "select target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch') t from downloads order by start_time desc limit 30"),
)


def sqlite_db(p: Path, deadline):
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % p, uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    tabs = [r[0] for r in con.execute("select name from sqlite_master where type='table' order by name")]
    res = {"tables": []}
    for t in tabs[:60]:
        if time.time() > deadline:
            res["partial"] = True; break
        q = '"%s"' % t.replace('"', '""')
        try:
            cols = [r[1] for r in con.execute("pragma table_info(%s)" % q)]
            cnt = con.execute("select count(*) from %s" % q).fetchone()[0]
            rows = [[_cut(c) for c in r] for r in con.execute("select * from %s limit 3" % q)]
        except Exception as e:
            res["tables"].append({"table": t, "error": _cut(e)}); continue
        res["tables"].append({"table": t, "rows": cnt, "columns": cols[:30], "sample": rows})
    for name, sql in BROWSER_Q:
        try:
            res[name] = [[_cut(c) for c in r] for r in con.execute(sql)]
        except Exception:
            pass
    con.close()
    return res


# ---------------------------------------------------------------- CSV
COUNT_COLS = ("EventId", "EventID", "Channel", "Provider", "ExecutableName", "SourceFile", "RuleTitle",
              "Level", "Computer", "UserName", "PluginDetailFile")


def csv_file(p: Path, deadline):
    raw = p.open("rb")
    head = raw.read(65536)
    skip = 3 if head.startswith(b"\xef\xbb\xbf") else 0
    first_line = head[skip:].split(b"\n", 1)[0].decode("utf-8", "replace")
    raw.seek(skip)
    txt = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
    try:
        dialect = csv.Sniffer().sniff(first_line + "\n", delimiters=",;\t|")
    except Exception:
        dialect = csv.excel
    rd = csv.reader(txt, dialect)
    header = next(rd, [])
    idx = {c: i for i, c in enumerate(header) if c in COUNT_COLS}
    counters = {c: Counter() for c in idx}
    rows = 0; first = []; partial = False
    tcols = [i for i, c in enumerate(header) if c.lower() in ("timecreated", "timestamp", "lastrun", "sourcemodified", "datetime", "time")]
    tmin = tmax = None
    for r in rd:
        rows += 1
        if len(first) < 5:
            first.append([_cut(c) for c in r[:20]])
        for c, i in idx.items():
            if i < len(r):
                counters[c][r[i][:120]] += 1
        for i in tcols[:1]:
            if i < len(r) and r[i]:
                v = r[i][:19]
                tmin = v if tmin is None or v < tmin else tmin
                tmax = v if tmax is None or v > tmax else tmax
        if rows >= MAX_CSV_ROWS or (rows % 5000 == 0 and time.time() > deadline):
            partial = True; break
    raw.close()
    return {"rows": rows, "partial": partial, "columns": header[:60], "first_rows": first,
            "time_range": [tmin, tmax] if tmin else None,
            "top_values": {c: cnt.most_common(15) for c, cnt in counters.items() if cnt}}


PARSERS = {"windows-eventlog": evtx, "registry-hive": registry, "registry-hive?": registry,
           "sqlite-db": sqlite_db, "text/csv": csv_file, "text/tsv": csv_file}


def run(files, rep):
    """files: [(path, kind, rel)]; повертає список зведень (у порядку важливості)"""
    t_end = time.time() + TOTAL_S
    out = []
    order = {"windows-eventlog": 0, "registry-hive": 1, "registry-hive?": 1, "text/csv": 2, "sqlite-db": 3, "text/tsv": 4}
    for p, kind, rel in sorted(files, key=lambda f: (order.get(f[1], 9), -f[0].stat().st_size)):
        fn = PARSERS.get(kind)
        if not fn:
            continue
        if time.time() > t_end:
            rep.setdefault("deep_skipped", []).append(rel); continue
        t0 = time.time()
        try:
            res = fn(p, min(t0 + PER_FILE_S, t_end))
            res = {"file": rel, "kind": kind, "seconds": round(time.time() - t0, 1), **res}
        except Exception as e:
            res = {"file": rel, "kind": kind, "error": _cut("%s: %s" % (type(e).__name__, e))}
        out.append(res)
    return out


def report_lines(deep):
    """коротко для людини (report.md)"""
    L = []
    for d in deep:
        if "error" in d:
            L.append("- `%s` (%s): не розібрано: %s" % (d["file"], d["kind"], d["error"])); continue
        k = d["kind"]
        if k == "windows-eventlog":
            L.append("- `%s`: %d подій%s, %s → %s; канали: %s" % (
                d["file"], d["records_read"], " (частково, ліміт)" if d["partial"] else "", d["first"], d["last"],
                ", ".join("%s×%d" % kv for kv in sorted(d["channels"].items(), key=lambda kv: -kv[1])[:4])))
            for n in d["notable"][:12]:
                L.append("  - %s %d — %s: **%d**" % (n["channel"], n["event_id"], n["meaning"], n["count"]))
        elif k.startswith("registry"):
            ar = sum(len(v) for v in d.get("autoruns", {}).values())
            L.append("- `%s`: кущ реєстру %s; автозапусків: %d; служб з незвичним шляхом: %d%s" % (
                d["file"], d.get("hive_type"), ar, len(d.get("services_unusual_path", [])),
                ("; " + ", ".join("%s=%s" % kv for kv in d["system_info"].items())) if d.get("system_info") else ""))
        elif k == "sqlite-db":
            L.append("- `%s`: SQLite, таблиць %d: %s" % (d["file"], len(d["tables"]), ", ".join(
                "%s(%s)" % (t["table"], t.get("rows", "?")) for t in d["tables"][:8])))
            for b in ("chrome_history", "firefox_history", "chrome_downloads"):
                if d.get(b):
                    L.append("  - %s: %d останніх записів" % (b, len(d[b])))
        else:
            L.append("- `%s`: CSV, рядків %d%s; стовпців %d%s" % (
                d["file"], d["rows"], " (частково)" if d["partial"] else "", len(d["columns"]),
                ("; час " + " → ".join(d["time_range"])) if d.get("time_range") else ""))
            for c, top in list(d.get("top_values", {}).items())[:3]:
                L.append("  - %s: %s" % (c, ", ".join("%s×%d" % (v, n) for v, n in top[:6])))
    return L
