import ctypes
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

# DFIR collector launcher v3 - ask first, extract only what the answer needs.
#
# WHY THIS EXISTS (measured 2026-08-09): with the payload bundled as a PyInstaller data file,
# PyInstaller unpacked 670 MB into %TEMP%\_MEI before this code even started, and only then
# did we extract another 1.09 GB - about 1.76 GB written per run, most of it never used.
# Now the payload is an UNCOMPRESSED zip appended to this exe as an overlay:
#   * PyInstaller bundles only this small script, so its stage is negligible
#   * zipfile reads the overlay straight out of our own file (it handles prepended data,
#     which is exactly how self-extracting zips work) - no intermediate copy, no RAM blow-up
#   * the two questions are asked BEFORE extraction, so only that tier lands on disk
#
# Ukrainian text is printed through the console code page (1251), matching the .bat.

FOOTER_MAGIC = b"DFIRPAY1"
FOOTER_LEN = 16


def _setup_console():
    """Console + stdout on CP1251 so Ukrainian prompts render (the .bat uses 1251 too)."""
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(1251)
        ctypes.windll.kernel32.SetConsoleCP(1251)
    except Exception:
        pass
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="cp1251", errors="replace")
        except Exception:
            pass
    try:
        # a stray click with QuickEdit on freezes output until a key is pressed
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-10)
        mode = ctypes.c_uint()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, (mode.value & ~0x0040) | 0x0080)
    except Exception:
        pass
    try:
        os.system("mode con: cols=120 lines=50 >nul 2>&1")
    except Exception:
        pass


def _overlay():
    """(path_to_self, offset_of_zip) or (None, None) when there is no overlay."""
    me = sys.executable if getattr(sys, "frozen", False) else __file__
    try:
        with open(me, "rb") as fh:
            fh.seek(-FOOTER_LEN, os.SEEK_END)
            tail = fh.read(FOOTER_LEN)
        if tail[8:] != FOOTER_MAGIC:
            return None, None
        return me, struct.unpack("<Q", tail[:8])[0]
    except Exception:
        return None, None


def ask(title, options, default="1"):
    print()
    print("  " + "-" * 108)
    print("   " + title)
    print("  " + "-" * 108)
    for key, text in options:
        print("     [%s] %s" % (key, text))
    print()
    try:
        a = input("   Вибір [%s, за замовч. %s]: " % ("/".join(k for k, _ in options), default))
    except Exception:
        a = ""
    a = (a or "").strip()
    return a if a in [k for k, _ in options] else default


def banner(version):
    print()
    print("  " + "=" * 108)
    print("    db    db  .d8b.   .d88b.        d8888b. d88888b d888888b d8888b.      D F I R   T R I A G E")
    print("    88    88 d8' `8b .8P  Y8.       88  `8D 88'       `88'   88  `8D      C O L L E C T O R")
    print("    Y8    8P 88ooo88 88    88       88   88 88ooo      88    88oobY'")
    print("    `8b  d8' 88~~~88 88    88       88   88 88~~~      88    88`8b        версія   %s" % version)
    print("     `8bd8'  88   88 `8b  d8'       88  .8D 88        .88.   88 `88.      автор    V . A . O")
    print("      `88'   YP   YP  `Y88P'        Y8888D' YP      Y888888P 88   YD      профіль  digital forensics")
    print()
    print("    collect  .  parse  .  hunt                                            пошта    github.com/vao-forensics")
    print("    артефакти -> ZIP -> бот -> звіт від локальної ЛЛМ, без інтернету      бот      t.me/<your_bot>")
    print("  " + "=" * 108)


def extract(zf, names, dest, label):
    """Extract a named subset, showing progress. Uncompressed members copy at disk speed."""
    total = len(names)
    t0 = time.time()
    done = 0
    for n in names:
        try:
            zf.extract(n, dest)
        except Exception:
            pass
        done += 1
        if done % 250 == 0 or done == total:
            pct = int(done * 100 / total) if total else 100
            bar = "#" * (pct // 4) + "." * (25 - pct // 4)
            sys.stdout.write("\r     %-22s [%s] %3d%%  %d/%d" % (label, bar, pct, done, total))
            sys.stdout.flush()
    print("   %.1f c" % (time.time() - t0))


def main():
    _setup_console()
    version = os.environ.get("DFIR_VER", "v3.0")
    banner(version)

    me, off = _overlay()
    if me is None:
        print("\n  [X] Пошкоджений файл: службові дані не знайдено. Завантажте збирач ще раз.")
        input("  Enter для виходу...")
        return 1

    scen = ask("[ 1 ]  РЕЖИМ ЗБОРУ", [
        ("1", "LIVE   - жива система, що працює зараз"),
        ("2", "IMAGE  - змонтований образ диска (офлайн)")])
    mode = ask("[ 2 ]  ГЛИБИНА", [
        ("1", "FAST - швидко (хвилини): артефакти + типовий розбір"),
        ("2", "FULL - глибоко: додатково sigma-полювання, THOR, реєстр")])

    work = os.path.join(tempfile.gettempdir(), "".join(
        __import__("random").choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10)))
    os.makedirs(work, exist_ok=True)
    try:
        ctypes.windll.kernel32.SetFileAttributesW(work, 0x2)
    except Exception:
        pass

    print()
    print("  " + "-" * 108)
    print("   Розпаковується ЛИШЕ те, що потрібно обраному режиму - решта лишається всередині файла.")
    print("  " + "-" * 108)

    with open(me, "rb") as fh:
        fh.seek(off)
        with zipfile.ZipFile(fh) as zf:
            names = zf.namelist()
            tiers = {"core": [], "fast": [], "full": [], "extra": []}
            import json
            try:
                tiers = json.loads(zf.read("_tiers.json").decode("utf-8"))
            except Exception:
                tiers["core"] = [n for n in names if n != "_tiers.json"]
            want = list(tiers.get("core", []))
            want += tiers.get("fast", [])
            if mode == "2":
                want += tiers.get("full", [])
            want = [n for n in want if n in set(names)]
            extract(zf, want, work, "розпакування")

    bat = os.path.join(work, "Run_KAPE_DFIR.bat")
    if not os.path.exists(bat):
        print("\n  [X] Не знайдено керуючий сценарій. Завантажте збирач ще раз.")
        input("  Enter для виходу...")
        shutil.rmtree(work, ignore_errors=True)
        return 1

    env = dict(os.environ)
    env["DFIR_SCEN"] = scen      # the bat skips its own two questions when these are set
    env["DFIR_MODE"] = mode
    subprocess.call(["cmd", "/c", bat], cwd=work, env=env)
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
