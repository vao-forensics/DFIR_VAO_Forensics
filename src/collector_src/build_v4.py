#!/usr/bin/env python3
"""Build collector v4: one native C# executable + an uncompressed ZIP overlay.

Difference from build_v3.py, and the whole point of v4: the payload no longer carries
Run_KAPE_DFIR.bat, because there is no .bat any more. The C# program in pybuild\\v4 IS the
collector. On the 2026-08-13 ransomware host, Group Policy blocked .ps1 files outright and
-ExecutionPolicy Bypass could not override it, so the shell-driven design was a dead end.

Layout of the produced file:  [ PE ][ stored zip ][ int64 zip offset ][ "DFIRPAY1" ]

Usage:  python C:\\DFIR\\pybuild\\build_v4.py
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile

DFIR = r"C:\DFIR"
V4 = os.path.join(DFIR, "pybuild", "v4")
ZIPOUT = os.path.join(DFIR, "pybuild", "_payload_store_v4.zip")
TIERS = os.path.join(DFIR, "pybuild", "tiers_v4.json")
MANIFEST = os.path.join(DFIR, "pybuild", "launcher.manifest")
ICON = os.path.join(DFIR, "pybuild", "collector.ico")
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
FINAL = os.path.join(DFIR, "DFIR_Collector_v4.exe")
MAGIC = b"DFIRPAY1"

# The .bat is deliberately absent. Everything else is the same toolkit v3 shipped.
INCLUDE = ["kape.exe", "7za", "bin", "Targets", "Modules"]
DROP_SEG = {".git", "__pycache__"}
_BAK = re.compile(r"\.(bak|utf8bak)(_|\.|$)", re.I)

# Steps.cs calls these by name; if one silently stops shipping, the step degrades to a gap
# row in collection_gaps.csv and nobody notices for weeks. Assert them at build time instead.
#
# The list is what Steps.cs ACTUALLY invokes, not what happens to be in the folder. The six
# helper scripts named below used to be here individually; since 2026-08-15 they are merged
# into vao_collect_all.ps1 and nothing calls them by name, so requiring them would only fail
# the build for a file that no longer matters.
REQUIRED = [
    "kape.exe",
    "Modules/bin/vao_triage.exe",
    "Modules/!DFIRbot/vao_collect_all.ps1",
    "Targets/!DFIRbot/DFIRbot_Fast.tkape",
    "Targets/!DFIRbot/DFIRbot_Full.tkape",
    "Targets/!DFIRbot/DFIRbot_Comms.tkape",
    "7za/7za.exe",
]


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def _skip(rel):
    segs = rel.split(os.sep)
    for s in segs:
        if s in DROP_SEG or s.startswith("tmp-"):
            return True
    name = segs[-1]
    return bool(_BAK.search(name)) or name.lower().endswith(".pyc")


_COMBINED = os.path.join(DFIR, "Modules", "!DFIRbot", "vao_collect_all.ps1")
_COMBINED_SRC = ["build_fs_tree.ps1", "find_suspicious.ps1", "hash_targets.ps1",
                 "hunt_encrypted.ps1", "collect_motw.ps1", "collect_liveresponse.ps1"]


def step_preflight():
    """Fail loudly on the two things that are silently wrong otherwise.

    vao_collect_all.ps1 is GENERATED from the six helpers by build_combined_ps.py. Editing a
    helper and rebuilding the exe without regenerating ships the old behaviour under the new
    name - the build succeeds, every check passes, and the collector runs last week's code.
    Comparing timestamps costs nothing and makes that impossible.
    """
    if not os.path.isfile(_COMBINED):
        raise SystemExit("!! немає %s — запустіть build_combined_ps.py" % _COMBINED)
    comb = os.path.getmtime(_COMBINED)
    stale = []
    for fn in _COMBINED_SRC:
        p = os.path.join(DFIR, "Modules", "!DFIRbot", fn)
        if os.path.isfile(p) and os.path.getmtime(p) > comb + 1:
            stale.append(fn)
    if stale:
        raise SystemExit("!! vao_collect_all.ps1 старіший за %s — спершу:\n"
                         "   python C:\\DFIR\\pybuild\\build_combined_ps.py" % ", ".join(stale))

    # PowerShell 5.1 reads a BOM-less .ps1 in the machine's ANSI codepage, so a single
    # non-ASCII byte turns the banner - the marker a forensic analyst is meant to recognise -
    # into mojibake. This has already happened once.
    with open(_COMBINED, "rb") as fh:
        blob = fh.read()
    bad = [b for b in bytearray(blob) if b > 127]
    if bad:
        raise SystemExit("!! у vao_collect_all.ps1 %d не-ASCII байтів" % len(bad))
    log("перевірка перед збіркою: об'єднаний скрипт свіжий, %.0f KB, чистий ASCII"
        % (len(blob) / 1024.0))


def step_zip():
    sys.path.insert(0, os.path.join(DFIR, "pybuild"))
    import build_tiers

    log("пишу store-mode zip з живого дерева C:\\DFIR ...")
    t0 = time.time()
    tiers = {"core": [], "fast": [], "full": [], "extra": []}
    entries = []
    dropped = [0, 0]
    for top in INCLUDE:
        p = os.path.join(DFIR, top)
        if os.path.isfile(p):
            entries.append((p, top))
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, DFIR)
                    if _skip(rel):
                        dropped[0] += 1
                        dropped[1] += os.path.getsize(full)
                    else:
                        entries.append((full, rel))
        else:
            raise SystemExit("!! немає %s" % p)

    # 'extra' never leaves the exe, so shipping it only lengthens Defender's first-run scan
    # of an unsigned binary - measured at 48.8 s, which the owner read as "it does not start".
    SHIP_EXTRA = False
    skipped = [0, 0]
    with zipfile.ZipFile(ZIPOUT, "w", zipfile.ZIP_STORED, allowZip64=True) as z:
        for full, rel in entries:
            arc = rel.replace("\\", "/")
            tier = build_tiers.classify(rel)
            if tier == "extra" and not SHIP_EXTRA:
                skipped[0] += 1
                skipped[1] += os.path.getsize(full)
                continue
            tiers[tier].append(arc)
            z.write(full, arc)
        man = "".join("%s\t%s\n" % (t, p)
                      for t in ("core", "fast", "full") for p in tiers[t])
        z.writestr("_tiers.txt", man.encode("utf-8"))

    with open(TIERS, "w", encoding="utf-8") as fh:
        json.dump(tiers, fh)
    log("zip: %d файлів, %.1f MB за %.0f c (сміття %d; невживані інструменти %d / %.1f MB)"
        % (len(entries) - skipped[0], os.path.getsize(ZIPOUT) / 1048576, time.time() - t0,
           dropped[0], skipped[0], skipped[1] / 1048576))


def step_compile():
    log("компілюю збирач (C#) ...")
    exe = os.path.join(V4, "_dist", "DFIR_Collector_v4.exe")
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    srcs = sorted(os.path.join(V4, f) for f in os.listdir(V4) if f.endswith(".cs"))
    if not srcs:
        raise SystemExit("!! немає жодного .cs у %s" % V4)
    r = subprocess.run([CSC, "/nologo", "/target:exe", "/platform:anycpu", "/optimize+",
                        "/codepage:65001",             # sources are UTF-8 without a BOM
                        "/win32manifest:" + MANIFEST,  # requireAdministrator
                        "/win32icon:" + ICON,
                        "/reference:System.Management.dll",
                        "/reference:System.IO.Compression.dll",
                        "/reference:System.IO.Compression.FileSystem.dll",
                        "/out:" + exe] + srcs,
                       capture_output=True)
    if r.returncode:
        print(r.stdout.decode("utf-8", "replace"))
        print(r.stderr.decode("utf-8", "replace"))
        raise SystemExit("!! csc failed")
    log("збирач: %.0f KB з %d файлів" % (os.path.getsize(exe) / 1024, len(srcs)))
    return exe


def step_append(exe):
    log("дописую оверлей ...")
    with open(FINAL, "wb") as out:
        with open(exe, "rb") as fh:
            shutil.copyfileobj(fh, out, 1 << 20)
        off = out.tell()
        with open(ZIPOUT, "rb") as fh:
            shutil.copyfileobj(fh, out, 1 << 20)
        out.write(struct.pack("<Q", off) + MAGIC)
    log("готово: %s  %.1f MB (оверлей з %d)"
        % (FINAL, os.path.getsize(FINAL) / 1048576, off))


def step_verify():
    with open(FINAL, "rb") as fh:
        fh.seek(-16, os.SEEK_END)
        tail = fh.read(16)
        assert tail[8:] == MAGIC, "footer magic missing"
        off = struct.unpack("<Q", tail[:8])[0]
        fh.seek(off)
        with zipfile.ZipFile(fh) as z:
            names = set(z.namelist())
            tiers = {"core": [], "fast": [], "full": []}
            for line in z.read("_tiers.txt").decode("utf-8").splitlines():
                t, _, p = line.partition("\t")
                if p:
                    tiers[t].append(p)

            # No CONTROL batch file may ship: v4 must never depend on cmd.exe. Third-party
            # tools may still carry their own .bat deep in Modules\bin (RegRipper's regrip.bat)
            # - we never invoke those, our modules call rip.exe directly, so they are inert.
            own_bats = [n for n in names if n.lower().endswith(".bat") and "/" not in n]
            assert not own_bats, "керуючий .bat досі у payload: %s" % own_bats

            missing = [p for p in REQUIRED if p not in names]
            assert not missing, "у payload немає: %s" % missing[:5]

            # a member listed in a tier but absent from the zip would be dropped in silence
            for tier, lst in tiers.items():
                miss = [p for p in lst if p not in names]
                assert not miss, "%s: %d членів немає у zip, напр. %s" % (tier, len(miss), miss[:2])

            seen = {}
            for t, lst in tiers.items():
                for p in lst:
                    assert p not in seen, "%s у двох рівнях: %s і %s" % (p, seen[p], t)
                    seen[p] = t
            for p in REQUIRED:
                assert seen.get(p) in ("core", "fast", "full"), \
                    "%s не потрапив у жоден рівень -> ніколи не розпакується" % p

            # RECmd refused the whole batch over 17 plugins declaring HiveType: User, which is
            # not a value it accepts. The effect was invisible and total: no registry analysis
            # in ANY collection. Assert the corrected file is the one that shipped.
            reb = z.read("Modules/bin/RECmd/BatchExamples/DFIRBatch.reb").decode("utf-8", "replace")
            assert "HiveType: User\n" not in reb.replace("\r", ""), \
                "DFIRBatch.reb досі містить HiveType: User -> RECmd відхилить весь пакет"
            assert reb.count("NtUser") >= 17, "у DFIRBatch.reb замало NtUser — виправлення не потрапило"

            stored = sum(1 for i in z.infolist() if i.compress_type == zipfile.ZIP_STORED)
            assert stored == len(z.infolist()), "частина членів стиснена"

            fast_n = len(tiers["core"]) + len(tiers["fast"])
            log("перевірка: %d членів; FAST розпакує %d, FULL %d, лишиться в EXE %d"
                % (len(names), fast_n, fast_n + len(tiers["full"]), len(names) - len(seen) - 1))


def main():
    step_preflight()
    step_zip()
    exe = step_compile()
    step_append(exe)
    step_verify()
    os.remove(ZIPOUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
