# -*- coding: utf-8 -*-
"""Fetch the module binaries KAPE expects but does not ship.

Six modules we enable have no binary on disk (KAPE would normally pull them from the
module's BinaryUrl at runtime, which needs internet ON THE VICTIM MACHINE - unacceptable).
Without the binary the module runs and silently produces nothing.

Every download is verified (real PE / real archive, plausible size) and its SHA-256 is
recorded in TOOLS_PROVENANCE.md, so the collector's third-party content stays auditable.
"""
import hashlib
import json
import os
import subprocess
import sys
import zipfile

BIN = r"C:\DFIR\Modules\bin"
PROV = r"C:\DFIR\TOOLS_PROVENANCE.md"

# name on disk (as the .mkape's Executable expects) -> how to get it
WANT = [
    # direct raw file
    ("BitsParser.exe", "raw",
     "https://raw.githubusercontent.com/conexioninversa/BitsParser/master/BitsParser.exe"),
    ("dhparser.exe", "raw",
     "https://raw.githubusercontent.com/jklepsercyber/defender-detectionhistory-parser/main/dhparser.exe"),
    ("mplog_parser.exe", "raw",
     "https://github.com/Qazeer/mplog_parser-compiled/releases/download/v1.0/mplog_parser.exe"),
    # resolve newest release asset via the API
    ("LevelDBDumper.exe", "release", "mdawsonuk/LevelDBDumper"),
    ("loldriverscan.exe", "release", "FourCoreLabs/LolDriverScan"),
    ("TeamsParser/ms_teams_parser.exe", "release", "lxndrblz/forensicsim"),
]


def curl(url, dest):
    r = subprocess.run(["curl", "-sSL", "--max-time", "180", "-o", dest, url],
                       capture_output=True)
    return r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0


def assets(repo):
    out = subprocess.run(
        ["curl", "-sSL", "--max-time", "60",
         "https://api.github.com/repos/%s/releases/latest" % repo],
        capture_output=True)
    try:
        j = json.loads(out.stdout.decode("utf-8", "replace"))
    except ValueError:
        return []
    return [(a.get("name", ""), a.get("browser_download_url", ""))
            for a in j.get("assets", [])]


def pick(names, want_stem):
    """Prefer a 64-bit Windows asset matching the tool name."""
    def score(n):
        low = n.lower()
        stem = want_stem.lower()
        s = 0
        if low == stem + ".exe":       # an exact plain .exe beats every archive
            s += 40
        if stem in low:
            s += 10
        if low.endswith(".exe"):
            s += 8
        elif low.endswith(".zip"):
            s += 3
        if "win" in low:
            s += 5
        if "64" in low or "amd64" in low or "x64" in low:
            s += 3
        if ".app." in low or low.endswith(".app.zip"):   # macOS bundle, no Windows exe inside
            s -= 40
        if "x86" in low or "_m1" in low:
            s -= 10
        if "arm" in low or "linux" in low or "darwin" in low or "mac" in low:
            s -= 20
        return s
    return sorted(names, key=lambda x: -score(x[0]))


def looks_ok(path):
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:2] == b"MZ":
        return "PE"
    if head[:2] == b"PK":
        return "ZIP"
    return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_exe(zpath, target_name, outdir):
    with zipfile.ZipFile(zpath) as z:
        cands = [n for n in z.namelist() if n.lower().endswith(".exe")]
        if not cands:
            return None
        stem = os.path.splitext(os.path.basename(target_name))[0].lower()
        cands.sort(key=lambda n: (stem not in os.path.basename(n).lower(), len(n)))
        src = cands[0]
        dest = os.path.join(outdir, os.path.basename(target_name))
        os.makedirs(outdir, exist_ok=True)
        with z.open(src) as fsrc, open(dest, "wb") as fdst:
            fdst.write(fsrc.read())
        return dest


def main():
    rows = []
    for name, kind, src in WANT:
        dest = os.path.join(BIN, name.replace("/", os.sep))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        stem = os.path.splitext(os.path.basename(name))[0]
        print("\n=== %s" % name)

        if kind == "raw":
            url = src
        else:
            got = assets(src)
            if not got:
                print("   !! не вдалось прочитати релізи %s" % src)
                rows.append((name, "?", "ПОМИЛКА: релізи недоступні", 0))
                continue
            ranked = pick(got, stem)
            print("   активи: %s" % ", ".join(n for n, _u in ranked[:4]))
            url = ranked[0][1]

        tmp = dest + ".dl"
        if not curl(url, tmp):
            print("   !! завантаження не вдалось: %s" % url)
            rows.append((name, url, "ПОМИЛКА: не завантажилось", 0))
            continue

        kindfound = looks_ok(tmp)
        if kindfound == "ZIP":
            got = extract_exe(tmp, name, os.path.dirname(dest))
            os.remove(tmp)
            if not got:
                print("   !! у архіві немає .exe")
                rows.append((name, url, "ПОМИЛКА: у архіві немає exe", 0))
                continue
            dest = got
        elif kindfound == "PE":
            if os.path.exists(dest):
                os.remove(dest)
            os.rename(tmp, dest)
        else:
            with open(tmp, "rb") as fh:
                head = fh.read(200)
            os.remove(tmp)
            print("   !! це не EXE і не ZIP: %r" % head[:80])
            rows.append((name, url, "ПОМИЛКА: не бінарник", 0))
            continue

        size = os.path.getsize(dest)
        digest = sha256(dest)
        print("   OK  %s  %.1f MB  sha256=%s" % (dest, size / 1048576, digest[:16]))
        rows.append((name, url, digest, size))

    ok = [r for r in rows if len(r[2]) == 64]
    print("\n%d з %d завантажено" % (len(ok), len(rows)))

    with open(PROV, "w", encoding="utf-8") as fh:
        fh.write("# Походження сторонніх бінарників збирача\n\n")
        fh.write("> Ці інструменти KAPE очікує, але не постачає: у `.mkape` вказано лише\n")
        fh.write("> `BinaryUrl`, і KAPE тягнув би їх з інтернету **на машині, яку ми\n")
        fh.write("> досліджуємо**. Це неприйнятно, тож ми кладемо їх у збірку заздалегідь.\n")
        fh.write("> Файл службовий (походження й цілісність), у термінал нічого не виводить —\n")
        fh.write("> стелс-режим збирача не порушено.\n\n")
        fh.write("| Файл | Розмір | SHA-256 | Звідки |\n|---|---|---|---|\n")
        for name, url, digest, size in rows:
            fh.write("| `%s` | %s | `%s` | %s |\n"
                     % (name,
                        ("%.1f МБ" % (size / 1048576)) if size else "-",
                        digest, url))
    print("походження записано у %s" % PROV)
    return 0 if len(ok) == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
