#!/usr/bin/env python3
"""T3 test: drive the real `dfir menu` (whiptail) through a pseudo-terminal, like a person at a keyboard.

  1 the menu opens in the installation's language (uk) with every item
  2 'c' + Enter runs "check for updates"; its output appears; Enter returns to the menu
  3 'v' + Enter runs the VPN item; answering "n" leaves the settings unchanged; back to the menu
  4 Esc leaves the menu, exit code 0
  5 without a terminal the menu refuses with a clear message (no hang)
A throw-away DESTDIR with its own answers file is used; nothing of the live installation changes.
"""
import os, pty, re, select, shutil, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTL = os.path.join(ROOT, "installer", "dfirctl.sh")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]")
res = []


def ok(name, cond, extra=""):
    res.append(cond)
    print(("PASS " if cond else "FAIL ") + name + (" " + extra if extra and not cond else ""))


d = tempfile.mkdtemp(prefix="dfir_menu_test_")
try:
    os.makedirs(d + "/state")
    open(d + "/state/install_answers.env", "w").write(
        "INSTALL_LANG=uk\nLLM_ENDPOINT=http://127.0.0.1:9\nWG_ENABLE=y\nWG_ENDPOINT=203.0.113.1\nWG_PORT=51820\n")
    env = {**os.environ, "DESTDIR": d, "TERM": "xterm", "LC_ALL": "C.UTF-8",
           "DFIR_UPDATE_SKIP": "sources,owui,ez", "COLUMNS": "100", "LINES": "30"}
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("bash", ["bash", CTL, "menu"], env)
    buf = b""

    def wait_for(pat, t=60):
        global buf
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    return False
                buf += chunk
                if re.search(pat, ANSI.sub(b"", buf)):
                    return True
        return False

    def send(b):
        global buf
        buf = b""
        os.write(fd, b)

    import fcntl, struct, termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    m1 = wait_for("Що зробити".encode())
    plain = ANSI.sub(b"", buf).decode("utf-8", "replace")
    items = all(k in plain for k in ("status", "vpn", "check", "apply", "backup", "quit"))
    ok("1 menu opens in Ukrainian with all items", m1 and items, plain[-600:])

    time.sleep(0.5); send(b"c"); time.sleep(0.3); send(b"\r")
    m2 = wait_for(rb"code\s+n/a") and wait_for("Enter = назад".encode())
    ok("2 'check for updates' ran from the menu and waits for Enter", m2, ANSI.sub(b"", buf).decode("utf-8", "replace")[-600:])
    send(b"\r")
    m2b = wait_for("Що зробити".encode())
    ok("2b Enter returns to the menu", m2b)

    time.sleep(0.5); send(b"v"); time.sleep(0.3); send(b"\r")
    m3 = wait_for("Змінити налаштування VPN".encode())
    send(b"n\r")
    m3b = wait_for("Enter = назад".encode())
    send(b"\r")
    m3c = wait_for("Що зробити".encode())
    after = open(d + "/state/install_answers.env").read()
    ok("3 VPN item shows state, 'n' keeps settings, back to menu", m3 and m3b and m3c and "WG_PORT=51820" in after)

    time.sleep(0.5); send(b"\x1b")
    code = None
    for _ in range(40):
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            code = os.waitstatus_to_exitcode(st); break
        try:
            os.read(fd, 65536)
        except OSError:
            pass
        time.sleep(0.25)
    ok("4 Esc leaves the menu with exit code 0", code == 0, "code=%s" % code)

    p = subprocess.run(["bash", CTL, "menu"], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    ok("5 no terminal -> refuses clearly", p.returncode != 0 and "термінала" in (p.stdout + p.stderr), p.stdout + p.stderr)

    # 6-8 (T9) optional parts: interactive choice by numbers, then on/off from a script; DRY_RUN = answers only
    envm = {**env, "DRY_RUN": "1"}
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("bash", ["bash", CTL, "modules"], envm)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    m6 = wait_for("ВИМКНУТИ".encode())
    listing = ANSI.sub(b"", buf).decode("utf-8", "replace")
    send(b"1 3\r")
    m6b = wait_for("вимкнено: webchat translate".encode())
    os.waitpid(pid, 0)
    after = open(d + "/state/install_answers.env").read()
    ok("6 dfir modules: list with sizes, '1 3' switches off web chat + translation",
       m6 and "6.7 GB" in listing and "Веб-чат" in listing and m6b and "MODULES_OFF=webchat\\ translate" in after,
       listing[-500:] + "|" + after)
    p = subprocess.run(["bash", CTL, "modules", "on", "webchat"], env=envm, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    after = open(d + "/state/install_answers.env").read()
    ok("7 dfir modules on webchat (no terminal) keeps only translation off", p.returncode == 0 and "MODULES_OFF=translate" in after,
       p.stdout + p.stderr + after)
    p = subprocess.run(["bash", CTL, "modules", "off", "nosuch"], env=envm, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    ok("8 unknown module is refused with the list", p.returncode != 0 and "Невідомо: nosuch" in (p.stdout + p.stderr), p.stdout + p.stderr)
finally:
    shutil.rmtree(d, ignore_errors=True)

print("dfir menu test: %d passed, %d failed" % (sum(res), len(res) - sum(res)))
sys.exit(0 if all(res) else 1)
