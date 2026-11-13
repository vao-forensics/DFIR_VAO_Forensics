import os, sys, subprocess, tempfile, shutil

# Robust stdout/stderr regardless of console code page (a Cyrillic print on a cp1252
# console raises UnicodeEncodeError and the exe dies before extraction). Launcher
# messages are ASCII; Ukrainian UX lives in the bat.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def res(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def _disable_quickedit():
    # QuickEdit ON => a stray click freezes console output until a key is pressed. Clear it
    # so tools never pause on a click. Persists for the bat in this same console.
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-10)  # STD_INPUT_HANDLE
        mode = ctypes.c_uint()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            ENABLE_QUICK_EDIT_MODE = 0x0040
            ENABLE_EXTENDED_FLAGS = 0x0080
            new_mode = (mode.value & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS
            k.SetConsoleMode(h, new_mode)
    except Exception:
        pass


def _pick_workroot():
    """Pick a work dir on a real fixed disk with room. In WinPE (e.g. Sergei Strelec) %TEMP%
    is X: (a RAM disk) — extracting ~700MB there overflows RAM. Prefer the fixed, non-X: drive
    with the most free space; return None to keep the default temp when it's already fine."""
    try:
        import string, ctypes
        need = 3 * 1024 ** 3  # 3 GB headroom
        best, best_free = None, -1
        for d in string.ascii_uppercase:
            if d == "X":  # WinPE RAM disk
                continue
            root = d + ":\\"
            try:
                if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:  # 3 = DRIVE_FIXED only
                    continue
                free = ctypes.c_ulonglong(0)
                if ctypes.windll.kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free), None, None):
                    if free.value > best_free:
                        best_free, best = free.value, root
            except Exception:
                continue
        tmp = tempfile.gettempdir()
        on_x = tmp[:2].upper() == "X:"
        try:
            tmp_free = shutil.disk_usage(tmp).free
        except Exception:
            tmp_free = 0
        if (on_x or tmp_free < need) and best and best_free >= need:
            return best
    except Exception:
        pass
    return None


def _cleanup(work):
    try:
        shutil.rmtree(work, ignore_errors=True)
    except Exception:
        pass


def main():
    _disable_quickedit()
    # sweep leftover PyInstaller temp dirs from prior crashed runs
    try:
        import glob
        _self = getattr(sys, "_MEIPASS", None)
        for _d in glob.glob(os.path.join(tempfile.gettempdir(), "_MEI*")):
            if _d != _self:
                shutil.rmtree(_d, ignore_errors=True)
    except Exception:
        pass
    print("=" * 52)
    print("   DFIR Triage Collector")
    print("=" * 52)
    import random, string, ctypes as _ctypes
    _rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    _wroot = _pick_workroot() or tempfile.gettempdir()
    work = os.path.join(_wroot, _rnd)  # no telltale name
    os.makedirs(work, exist_ok=True)
    try:
        _ctypes.windll.kernel32.SetFileAttributesW(work, 0x2)  # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        pass
    print("\n  preparing, please wait (~1 min)...\n")
    # SILENT extraction: operator never sees the internal toolset scroll by.
    r = subprocess.run([res("7za.exe"), "x", res("payload.7z"), "-o" + work, "-y",
                        "-bso0", "-bse0", "-bsp0"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    bat = os.path.join(work, "Run_KAPE_DFIR.bat")
    if r.returncode != 0 or not os.path.exists(bat):
        print("\n[X] Prep failed. Press Enter to exit...")
        try:
            input()
        except Exception:
            pass
        _cleanup(work)
        return

    import threading, time as _time
    _stop = threading.Event()

    def _auto_enter():
        # Keep a stuck tool moving WITHOUT the old system-wide keybd_event (which leaked Enter
        # into whatever OS window had focus). Write the Enter straight into THIS console's input
        # buffer via WriteConsoleInput, so only our own child cmd/tool ever receives it.
        # QuickEdit is disabled above (the real freeze fix); this is a scoped stdin backup.
        try:
            import ctypes as _c
            from ctypes import wintypes as _w
            k = _c.windll.kernel32
            hin = k.GetStdHandle(-10)  # STD_INPUT_HANDLE

            class KEY_EVENT_RECORD(_c.Structure):
                _fields_ = [("bKeyDown", _w.BOOL), ("wRepeatCount", _w.WORD),
                            ("wVirtualKeyCode", _w.WORD), ("wVirtualScanCode", _w.WORD),
                            ("UnicodeChar", _w.WCHAR), ("dwControlKeyState", _w.DWORD)]

            class _EVU(_c.Union):
                _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]

            class INPUT_RECORD(_c.Structure):
                _fields_ = [("EventType", _w.WORD), ("Event", _EVU)]

            def _enter_once():
                for down in (1, 0):
                    rec = INPUT_RECORD()
                    rec.EventType = 1  # KEY_EVENT
                    ke = rec.Event.KeyEvent
                    ke.bKeyDown = down
                    ke.wRepeatCount = 1
                    ke.wVirtualKeyCode = 0x0D  # VK_RETURN
                    ke.wVirtualScanCode = 0x1C
                    ke.UnicodeChar = "\r"
                    ke.dwControlKeyState = 0
                    written = _w.DWORD(0)
                    k.WriteConsoleInputW(hin, _c.byref(rec), 1, _c.byref(written))

            _time.sleep(150)  # let the operator answer the prompts first
            while not _stop.is_set():
                _enter_once()
                _time.sleep(30)
        except Exception:
            pass

    threading.Thread(target=_auto_enter, daemon=True).start()
    subprocess.call(["cmd", "/c", bat], cwd=work)
    _stop.set()
    _cleanup(work)


if __name__ == "__main__":
    main()
