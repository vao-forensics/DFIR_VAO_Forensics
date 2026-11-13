#!/usr/bin/env python3
"""Classify every payload member into an extraction tier.

Design (owner's decision 2026-08-09, "мінімум"): the launcher asks only LIVE/IMAGE and
FAST/FULL, then extracts ONLY the tier that combination needs. Nothing is deleted from the
EXE - tools we never invoke still ship inside it, they are simply never written to disk.

Tiers
  core   everything outside Modules\\bin  (kape.exe, Targets, module definitions, our scripts)
  fast   the binaries the FAST module set invokes
  full   the extra binaries only FULL invokes
  extra  present in the EXE but not invoked by any of our modules - never extracted
"""
import json
import os
import re
import subprocess
import sys

PAYLOAD = r"C:\DFIR\sfxbuild\payload.7z"
SEVENZ = r"C:\DFIR\sfxbuild\7zx64_2301\7za.exe"
OUT = r"C:\DFIR\pybuild\tiers.json"

# Directories/files under Modules\bin, keyed by the tier that first needs them.
# Derived from which_tools.py (resolves our MODS -> .mkape -> Executable/CommandLine).
FAST_BIN = [
    # EZ Tools - !EZParser drives all of these
    "AmcacheParser.exe", "AppCompatCacheParser.exe", "EvtxECmd", "JLECmd.exe", "LECmd.exe",
    "MFTECmd.exe", "PECmd.exe", "RBCmd.exe", "RECmd", "SBECmd.exe", "SrumECmd.exe",
    "SQLECmd", "WxTCmd.exe", "bstrings.exe",
    # Present on disk but absent from this list until 2026-09-09, so they were classified
    # 'extra' and never extracted - which is why KAPE reported "Cannot find executable
    # RecentFileCacheParser.exe / SumECmd.exe" on every FAST run.
    "RecentFileCacheParser.exe", "SumECmd.exe",
    # rla.exe replays registry transaction logs; new to the toolkit 2026-09-09.
    "rla.exe",
    # AppCompatCacheParser 2026.5 needs this assembly and its own zip does not ship it.
    # Without the entry the DLL would sit in the EXE and the parser would still die.
    "Microsoft.Win32.Registry.dll",
    # browsers
    "Browserparser.exe", "Browserparser", "BrowserDownloadsView.exe", "hindsight.exe",
    # event logs / timeline
    "hayabusa", "ForensicTimeliner", "LogParser.exe", "logparser.exe",
    # defender + bits (added v2.8)
    "vao_dhparser.exe", "vao_triage.exe", "vao_mplogparser.exe", "vao_bitsparser.exe",
    # memory acquisition (v4). Listed even though the binary is not in the toolkit yet:
    # dropping DumpIt.exe into Modules\bin without this line would land it in tier 'extra',
    # which never gets extracted - the tool would be inside the exe and still "not found".
    "DumpIt.exe", "DumpIt64.exe", "MagnetRAMCapture.exe", "RamCapture64.exe",
    "RamCapture.exe", "memory",
    # NOTE: these five binaries are NOT in the toolkit yet (KAPE BinaryUrl downloads them);
    # the entries stay so the tier mapping is correct once they are fetched.
]
FULL_BIN = [
    "chainsaw", "DeepBlueCLI", "thor-lite", "thor10.7lite-win-pack",
    # real folder names on disk are "regripper" and "Reghunter" - verified, not guessed
    "regripper", "Reghunter",
    "Autoruns", "autorunsc.exe", "autorunsc64.exe",
    "vao_leveldbdumper.exe", "TeamsParser", "vao_loldriverscan.exe",
    "winhello2hashcat.exe",
]


def members():
    out = subprocess.run([SEVENZ, "l", "-slt", PAYLOAD], capture_output=True)
    txt = out.stdout.decode("utf-8", "replace")
    res = []
    cur = {}
    for line in txt.split("\n"):
        line = line.rstrip("\r")
        if line.startswith("Path = "):
            cur = {"path": line[7:]}
        elif line.startswith("Size = ") and "path" in cur:
            try:
                cur["size"] = int(line[7:] or 0)
            except ValueError:
                cur["size"] = 0
        elif line.startswith("Attributes = ") and "path" in cur:
            cur["dir"] = "D" in line[13:]
            res.append(cur)
            cur = {}
    return res


def first_seg_under_bin(p):
    """'Modules\\bin\\chainsaw\\rules\\x.yml' -> 'chainsaw'"""
    parts = p.replace("/", "\\").split("\\")
    for i, seg in enumerate(parts):
        if seg.lower() == "bin" and i >= 1 and parts[i - 1].lower() == "modules":
            return parts[i + 1] if len(parts) > i + 1 else None
    return None


def classify(p):
    seg = first_seg_under_bin(p)
    if seg is None:
        return "core"
    low = seg.lower()
    for n in FAST_BIN:
        if low == n.lower():
            return "fast"
    for n in FULL_BIN:
        if low == n.lower():
            return "full"
    return "extra"


def main():
    ms = [m for m in members() if not m.get("dir")]
    tiers = {"core": [], "fast": [], "full": [], "extra": []}
    sizes = {k: 0 for k in tiers}
    for m in ms:
        t = classify(m["path"])
        tiers[t].append(m["path"])
        sizes[t] += m.get("size", 0)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(tiers, fh)
    total = sum(sizes.values())
    for t in ("core", "fast", "full", "extra"):
        print("%-6s %6d файлів  %8.1f MB" % (t, len(tiers[t]), sizes[t] / 1048576))
    print("-" * 40)
    print("%-6s %6d файлів  %8.1f MB" % ("разом", len(ms), total / 1048576))
    print()
    print("розпакується у FAST : %.1f MB" % ((sizes["core"] + sizes["fast"]) / 1048576))
    print("розпакується у FULL : %.1f MB"
          % ((sizes["core"] + sizes["fast"] + sizes["full"]) / 1048576))
    print("ніколи не розпакується (лишається в EXE): %.1f MB" % (sizes["extra"] / 1048576))
    return 0


if __name__ == "__main__":
    sys.exit(main())
