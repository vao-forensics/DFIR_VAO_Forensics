#!/usr/bin/env python3
"""Build the collector as: small PyInstaller launcher + uncompressed ZIP overlay.

Replaces the old design where payload.7z was a PyInstaller data file, which forced
PyInstaller to unpack 670 MB into %TEMP% before the launcher could even start.

Steps
  1. extract payload.7z to a staging tree (guarantees the overlay has identical content)
  2. write _tiers.json (which member belongs to core/fast/full/extra)
  3. build a STORE-mode zip - no compression, so extraction is a plain copy
  4. build the launcher exe with PyInstaller (payload NOT bundled)
  5. append the zip + a 16-byte footer (offset + magic) to the exe
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
ZIPOUT = os.path.join(DFIR, "pybuild", "_payload_store.zip")
TIERS = os.path.join(DFIR, "pybuild", "tiers.json")
CS = os.path.join(DFIR, "pybuild", "Launcher.cs")
MANIFEST = os.path.join(DFIR, "pybuild", "launcher.manifest")
ICON = os.path.join(DFIR, "pybuild", "collector.ico")
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
FINAL = os.path.join(DFIR, "DFIR_Collector_v3.exe")
MAGIC = b"DFIRPAY1"


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


# Exactly the members the shipped collector needs - same set the old payload.7z recipe used
# (BUILD_RECIPE.txt), verified against a listing of the built payload.
INCLUDE = ["Run_KAPE_DFIR.bat", "kape.exe", "RUNBOOK.md", "DFIR_Collector_README.txt",
           "7za", "bin", "Targets", "Modules"]
# Excluded SEGMENT-wise, never by substring - a substring rule is how "\temp" once matched
# "templates". Verified against the live tree: these three rules hit exactly
#   Modules\bin\zircolite\tmp-DOXB9FF6, tmp-SM9DO7SG  (695 MB of leftover output from a
#     zircolite run ON THIS HOST - our own WHEA/Security/Defender logs; must never ship)
#   Modules\bin\hayabusa\rules\.git                   (36 MB of VCS history, unused at runtime)
DROP_SEG = {".git", "__pycache__"}
_BAK = re.compile(r"\.(bak|utf8bak)(_|\.|$)", re.I)


def _skip(rel):
    segs = rel.split(os.sep)
    for s in segs:
        if s in DROP_SEG or s.startswith("tmp-"):
            return True
    name = segs[-1]
    return bool(_BAK.search(name)) or name.lower().endswith(".pyc")


def step_zip():
    """Build the overlay straight from the live C:\\DFIR tree.

    The old pipeline zipped payload.7z, which was built separately - so the collector shipped
    a v2.8 .bat while C:\\DFIR already held v3.0 (caught by a live run: the bat drew its own
    banner a second time). Sourcing the tree directly removes that second source of truth.
    """
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

    # SHIP_EXTRA=False drops the tier that is never extracted at runtime.
    # WHY IT MATTERS (measured 2026-08-09): the EXE is unsigned, so Defender scans it in full
    # on FIRST execution - and on a machine we are investigating, every run is the first run.
    # Measured on a 1.19 GB build: 56.9 s before the window appeared; second run 0.4 s (cached).
    # The owner read that silence as "it does not even start". The 'extra' tier is 5263 files /
    # 576 MB that NO module of ours ever invokes, so shipping them buys nothing and costs half
    # that wait. Nothing is deleted: the tools stay in C:\DFIR, and adding one to
    # FAST_BIN/FULL_BIN in build_tiers.py puts it straight back into the EXE.
    SHIP_EXTRA = False
    skipped_extra = [0, 0]
    with zipfile.ZipFile(ZIPOUT, "w", zipfile.ZIP_STORED, allowZip64=True) as z:
        for full, rel in entries:
            arc = rel.replace("\\", "/")   # zipfile stores forward slashes; tiers must match
            tier = build_tiers.classify(rel)
            if tier == "extra" and not SHIP_EXTRA:
                skipped_extra[0] += 1
                skipped_extra[1] += os.path.getsize(full)
                continue
            tiers[tier].append(arc)
            z.write(full, arc)
        man = "".join("%s\t%s\n" % (t, p)
                      for t in ("core", "fast", "full") for p in tiers[t])
        z.writestr("_tiers.txt", man.encode("utf-8"))

    with open(TIERS, "w", encoding="utf-8") as fh:
        json.dump(tiers, fh)
    log("zip: %d файлів, %.1f MB за %.0f c (сміття %d / %.1f MB; невживані інструменти %d / %.1f MB)"
        % (len(entries) - skipped_extra[0], os.path.getsize(ZIPOUT) / 1048576, time.time() - t0,
           dropped[0], dropped[1] / 1048576, skipped_extra[0], skipped_extra[1] / 1048576))


def step_launcher():
    log("компілюю лаунчер (C#, payload НЕ вкладається) ...")
    exe = os.path.join(DFIR, "pybuild", "_dist", "DFIR_Launcher.exe")
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    r = subprocess.run([CSC, "/nologo", "/target:exe", "/platform:anycpu", "/optimize+",
                        "/codepage:65001",          # Launcher.cs is UTF-8 without a BOM
                        "/win32manifest:" + MANIFEST,   # requireAdministrator
                        "/win32icon:" + ICON,
                        "/reference:System.IO.Compression.dll",
                        "/reference:System.IO.Compression.FileSystem.dll",
                        "/out:" + exe, CS],
                       capture_output=True)
    if r.returncode:
        print(r.stdout.decode("utf-8", "replace"))
        print(r.stderr.decode("utf-8", "replace"))
        raise SystemExit("!! csc failed")
    log("лаунчер: %.0f KB" % (os.path.getsize(exe) / 1024))
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
            names = z.namelist()
            tiers = {"core": [], "fast": [], "full": []}
            for line in z.read("_tiers.txt").decode("utf-8").splitlines():
                t, _, p = line.partition("\t")
                if p:
                    tiers[t].append(p)
            tiers["extra"] = [n for n in names
                              if n != "_tiers.txt"
                              and n not in set(sum(tiers.values(), []))]
            assert "Run_KAPE_DFIR.bat" in names, "bat missing from overlay"
            stored = sum(1 for i in z.infolist() if i.compress_type == zipfile.ZIP_STORED)
            assert stored == len(names), "some members are compressed"
            # the filter the launcher applies must not silently drop members
            nameset = set(names)
            for tier, lst in tiers.items():
                miss = [p for p in lst if p not in nameset]
                assert not miss, "%s: %d imenies not in zip, e.g. %s" % (tier, len(miss), miss[:2])
            # the bug this catches: the collector shipped a stale .bat while C:\DFIR held a
            # newer one, so the .bat drew its own banner over the launcher's
            shipped = z.read("Run_KAPE_DFIR.bat")
            on_disk = open(os.path.join(DFIR, "Run_KAPE_DFIR.bat"), "rb").read()
            assert shipped == on_disk, "shipped .bat differs from C:\\DFIR\\Run_KAPE_DFIR.bat"
            assert b"_from_launcher" in shipped, ".bat does not accept DFIR_SCEN/DFIR_MODE"
            seen = {}
            for t, lst in tiers.items():
                for p in lst:
                    assert p not in seen, "%s in both %s and %s" % (p, seen.get(p), t)
                    seen[p] = t
            assert seen.get("Run_KAPE_DFIR.bat") == "core"
            assert seen.get("Modules/bin/MFTECmd.exe") == "fast"
            fast_n = len(tiers["core"]) + len(tiers["fast"])
            log("перевірка: %d членів, усі без стиснення; FAST розпакує %d, FULL %d, "
                "лишиться в EXE %d" % (len(names), fast_n, fast_n + len(tiers["full"]),
                                       len(tiers["extra"])))


def main():
    step_zip()
    exe = step_launcher()
    step_append(exe)
    step_verify()
    os.remove(ZIPOUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
