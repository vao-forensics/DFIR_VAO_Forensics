#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dfir update: one place that knows what can be updated, tells the owner, and updates safely.

Why (T2, 08.11.2026): four separate things went stale with nobody told in one place - the code
(git), the reference databases (dfir sources), Open WebUI and the Zimmerman tools of the collector.
Each had its own checker, or none. This gathers them, messages the owner once per NEW set of
updates (not every week about the same thing), and applies a code update only after a trial on a
separate copy: new code is checked out next to the live one, its changed files compiled, its
compose file validated and the sandbox parser run on the test archive. Only then the live checkout
moves; if the system is not healthy afterwards, it goes back to the previous commit.

    dfir_update.py check [--notify]   what is new (changes nothing); --notify = tell the owner if the set changed
    dfir_update.py apply [--sources] [--owui]   code: trial -> switch -> health -> rollback on failure;
                                      --sources also updates the reference databases (they verify themselves),
                                      --owui also updates Open WebUI (owui_update.sh has its own rollback)
Exit: 0 ok / nothing new, 3 (check) updates available, 1 failure, 2 rolled back.

Overrides (tests): DFIR_UPDATE_INSTALL (re-install command, default 'bash install.sh'),
DFIR_UPDATE_HEALTH (health command, default: every compose container running and not unhealthy),
DFIR_UPDATE_NOTIFY=print (print instead of Telegram), DFIR_UPDATE_SKIP=code,sources,owui,ez,parse.
"""
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from shutil import which

ROOT = Path(os.environ.get("DFIR_ROOT") or Path(__file__).resolve().parents[2])
STATE = ROOT / "state" / "update"
OWNER_CHAT_DEFAULT = "CHANGE_ME_OWNER_CHAT_ID"          # owner only - never broadcast
FIXTURE = Path(os.environ.get("DFIR_UPDATE_FIXTURE") or ROOT / "state/sandbox_testdata/collector_TEST_output.zip")
SKIP = set(filter(None, os.environ.get("DFIR_UPDATE_SKIP", "").split(",")))


def sh(cmd, cwd=None, timeout=1800, env=None):
    p = subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str), capture_output=True, text=True,
                       timeout=timeout, env={**os.environ, **(env or {})})
    return p.returncode, (p.stdout + p.stderr).strip()


def git(*a, cwd=None):
    return sh(["git", "-C", str(cwd or ROOT), *a])


def env_value(name):
    if os.environ.get(name):
        return os.environ[name]
    try:
        for ln in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if ln.startswith(name + "="):
                return ln.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def log(msg):
    STATE.mkdir(parents=True, exist_ok=True)
    with open(STATE / "update.log", "a", encoding="utf-8") as f:
        f.write(time.strftime("%F %T ") + msg + "\n")
    print(msg, flush=True)


# ---------------------------------------------------------------- check
def upstream():
    """'origin/branch', or None when this checkout has no upstream (a source install)."""
    rc, out = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    return out if rc == 0 and out else None


def check_code():
    up = upstream()
    if not up:
        return {"id": "code", "state": "n/a", "text": "no upstream configured (source install)"}
    rc, out = git("fetch", "--quiet", up.split("/")[0])
    if rc:
        return {"id": "code", "state": "error", "text": "git fetch failed: " + out[-200:]}
    _, n = git("rev-list", "--count", "HEAD.." + up)
    _, head = git("rev-parse", "--short", up)
    _, subj = git("log", "--format=%s", "-5", "HEAD.." + up)
    n = int(n or 0)
    return {"id": "code", "state": "new" if n else "current", "key": head if n else "",
            "text": (f"{n} new commit(s) up to {head}: " + "; ".join(subj.splitlines()[:3])) if n else "current"}


def check_sources():
    script = ROOT / "tools/sources/dfir_sources.py"
    if not script.exists():
        return {"id": "sources", "state": "n/a", "text": "no manifest tool"}
    rc, out = sh([sys.executable, str(script), "check"], env={"DFIR_ROOT": str(ROOT)}, timeout=600)
    # one row per source: "<id> <status> installed=... upstream=... detail"; only non-current rows matter
    rows = [ln.split(None, 2) for ln in out.splitlines() if re.match(r"^\S+\s+(current|outdated|needs_key|error)\s", ln)]
    todo = [r for r in rows if r[1] != "current"]
    if rc not in (0, 3) and not todo:
        return {"id": "sources", "state": "error", "text": out[-300:]}
    if not todo:
        return {"id": "sources", "state": "current", "text": f"{len(rows)} sources current"}
    text = "; ".join(f"{r[0]} {r[1]}" + (" (" + r[2].split("upstream=", 1)[-1][:90] + ")" if r[1] == "needs_key" else "")
                     for r in todo)
    # the key is stable while nothing changes, so the owner is not told the same thing every week
    key = hashlib.sha1("|".join(" ".join(r[:2]) + re.sub(r"\(.*?\)", "", r[2] if len(r) > 2 else "")
                                for r in todo).encode()).hexdigest()[:12]
    return {"id": "sources", "state": "new", "key": key, "text": text[:500]}


def owui_versions():
    _, cur = sh(["docker", "exec", "open-webui", "sh", "-c", "grep -m1 '\"version\"' /app/package.json"], timeout=60)
    m = re.search(r'"version":\s*"([^"]+)"', cur or "")
    cur = m.group(1) if m else ""
    latest = ""
    try:
        req = urllib.request.Request("https://api.github.com/repos/open-webui/open-webui/releases/latest",
                                     headers={"User-Agent": "dfir-update/1.0"})
        latest = json.load(urllib.request.urlopen(req, timeout=30)).get("tag_name", "").lstrip("v")
    except Exception:
        pass
    return cur, latest


def check_owui():
    cur, latest = owui_versions()
    if not cur or not latest:
        return {"id": "owui", "state": "error", "text": f"could not read (current={cur or '?'} latest={latest or '?'})"}
    if cur == latest:
        return {"id": "owui", "state": "current", "text": cur}
    return {"id": "owui", "state": "new", "key": latest, "text": f"{cur} -> {latest}"}


def check_ez():
    script = ROOT / "tools/ez_tools_check.py"
    if not script.exists():
        return {"id": "ez", "state": "n/a", "text": "no checker"}
    rc, out = sh([sys.executable, str(script), "--dry-run"], timeout=600)
    if rc:
        return {"id": "ez", "state": "error", "text": out[-300:]}
    if out.startswith("up to date") or "no baseline" in out:
        return {"id": "ez", "state": "current", "text": out.splitlines()[0] if out else ""}
    lines = [ln.strip(" •") for ln in out.splitlines() if ln.strip()]
    return {"id": "ez", "state": "new", "key": hashlib.sha1(out.encode()).hexdigest()[:12],
            "text": "; ".join(lines[:5])[:500] + (f" (+{len(lines) - 5})" if len(lines) > 5 else "")}


CHECKS = {"code": check_code, "sources": check_sources, "owui": check_owui, "ez": check_ez}


def notify(text):
    if os.environ.get("DFIR_UPDATE_NOTIFY") == "print":
        print("NOTIFY: " + text)
        return True
    tok = env_value("DFIR_TG_BOT_TOKEN")
    if not tok and os.path.exists("/root/.dfir_bot_token"):
        tok = open("/root/.dfir_bot_token").read().strip()
    if not tok:
        print("no bot token, not sending")
        return False
    chat = env_value("DFIR_OWNER_CHAT") or OWNER_CHAT_DEFAULT
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data=data, timeout=20)
        return True
    except Exception as e:
        print("send failed: " + str(e)[:120])
        return False


def cmd_check(do_notify):
    res = [CHECKS[k]() for k in CHECKS if k not in SKIP]
    for r in res:
        print(f"{r['id']:8} {r['state']:8} {r['text']}")
    new = [r for r in res if r["state"] == "new"]
    sig = ",".join(f"{r['id']}:{r.get('key', '')}" for r in new)
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "last_check.json").write_text(json.dumps({"time": time.strftime("%F %T"), "results": res},
                                                      ensure_ascii=False, indent=1), encoding="utf-8")
    if do_notify and new:
        last = STATE / "last_notice.txt"
        if last.exists() and last.read_text() == sig:
            print("owner already told about this set of updates")
        else:
            body = "\n".join(f"- {r['id']}: {r['text']}" for r in new)
            if notify("DFIR: є оновлення (нічого не змінено):\n" + body +
                      "\nОновити з пробою і відкатом: sudo dfir update apply [--sources] [--owui]"):
                last.write_text(sig)
    for r in res:
        if r["state"] == "error":
            log(f"check {r['id']}: error {r['text']}")
    if new:
        return 3
    return 1 if any(r["state"] == "error" for r in res) else 0


# ---------------------------------------------------------------- apply
def trial(wt, old, new):
    """Everything that must hold for the NEW tree before the live checkout moves. Returns (ok, why)."""
    _, out = git("diff", "--name-only", "--diff-filter=AMR", old, new, cwd=wt)
    files = [ln for ln in out.splitlines() if ln]
    for f in files:
        p = wt / f
        if f.endswith(".py"):
            rc, out = sh([sys.executable, "-c",
                          "import sys,ast;ast.parse(open(sys.argv[1],'rb').read(),sys.argv[1])", str(p)])
            if rc:
                return False, f"python syntax: {f}: {out.splitlines()[-1] if out else ''}"
        elif f.endswith(".sh"):
            rc, out = sh(["bash", "-n", str(p)])
            if rc:
                return False, f"bash syntax: {f}: {out[-200:]}"
        elif f.endswith(".json"):
            try:
                json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                return False, f"json: {f}: {e}"
    if (wt / "docker-compose.yml").exists() and (ROOT / ".env").exists() and which("docker"):
        rc, out = sh(["docker", "compose", "--project-directory", str(wt), "-f", str(wt / "docker-compose.yml"),
                      "--env-file", str(ROOT / ".env"), "config", "-q"], timeout=120)
        if rc:
            return False, "compose config: " + out[-300:]
    if "parse" not in SKIP and FIXTURE.exists() and (wt / "sandbox/run_sandbox.sh").exists():
        job = "update_trial_" + time.strftime("%Y%m%dT%H%M%S")
        rc, out = sh(["bash", str(wt / "sandbox/run_sandbox.sh"), str(FIXTURE), job],
                     env={"DFIR_ROOT": str(wt)}, timeout=1200)
        outdir = wt / "sandbox/jobs" / job / "out"
        produced = [p for p in outdir.rglob("*") if p.is_file() and p.stat().st_size > 0] if outdir.exists() else []
        if rc or not produced:
            return False, f"trial parse of the test archive failed (rc={rc}, files={len(produced)}): {out[-300:]}"
        log(f"trial parse ok: {len(produced)} output files")
    return True, f"{len(files)} changed files checked"


def default_health():
    """All compose services running, none unhealthy (waits up to 4 min while any is 'starting')."""
    for _ in range(48):
        rc, out = sh(["docker", "compose", "--project-directory", str(ROOT), "ps", "-a",
                      "--format", "{{.Name}} {{.State}} {{.Health}}"], timeout=60)
        if rc:
            return False, out[-200:]
        rows = [ln.split() for ln in out.splitlines() if ln.strip()]
        bad = [r for r in rows if r[1] != "running" or (len(r) > 2 and r[2] == "unhealthy")]
        starting = [r for r in rows if len(r) > 2 and r[2] == "starting"]
        if not bad and not starting:
            return True, f"{len(rows)} containers running"
        if bad and not starting:
            return False, "not healthy: " + ", ".join(r[0] for r in bad)
        time.sleep(5)
    return False, "timeout waiting for health"


def health():
    cmd = os.environ.get("DFIR_UPDATE_HEALTH")
    if cmd:
        rc, out = sh(cmd, cwd=ROOT, timeout=600)
        return rc == 0, out[-300:]
    return default_health()


def reinstall():
    cmd = os.environ.get("DFIR_UPDATE_INSTALL") or f"bash {shlex.quote(str(ROOT / 'install.sh'))} </dev/null"
    return sh(cmd, cwd=ROOT, timeout=3600)


def apply_code():
    up = upstream()
    if not up:
        log("code: no upstream configured - nothing to update")
        return 0
    _, out = git("status", "--porcelain", "--untracked-files=no")
    if out:
        log("code: local changes in tracked files - refusing to update:\n" + out[:500])
        return 1
    rc, out = git("fetch", "--quiet", up.split("/")[0])
    if rc:
        log("code: fetch failed: " + out[-200:])
        return 1
    _, old = git("rev-parse", "HEAD")
    _, new = git("rev-parse", up)
    if old == new:
        log("code: already current " + old[:8])
        return 0
    if git("merge-base", "--is-ancestor", old, new)[0]:
        log("code: upstream is not a fast-forward of the live commit - refusing")
        return 1
    wt = Path(tempfile.mkdtemp(prefix="dfir_update_trial_"))
    try:
        rc, out = git("worktree", "add", "--detach", str(wt), new)
        if rc:
            log("code: worktree failed: " + out)
            return 1
        ok, why = trial(wt, old, new)
        log(f"code: trial {old[:8]}..{new[:8]}: {'OK' if ok else 'FAILED'} - {why}")
        if not ok:
            notify(f"DFIR update {new[:8]}: проба не пройшла ({why[:200]}), нічого не змінено")
            return 1
    finally:
        git("worktree", "remove", "--force", str(wt))
        sh(["rm", "-rf", str(wt)])
    git("merge", "--ff-only", new)
    rc, out = reinstall()
    ok, why = health() if rc == 0 else (False, "installer rc=%d: %s" % (rc, out[-300:]))
    if ok:
        log(f"code: updated {old[:8]} -> {new[:8]}, healthy ({why})")
        return 0
    log(f"code: unhealthy after update ({why}) - rolling back to {old[:8]}")
    git("reset", "--hard", old)
    rc2, out2 = reinstall()
    ok2, why2 = health() if rc2 == 0 else (False, out2[-300:])
    log(f"code: rollback to {old[:8]}: {'healthy' if ok2 else 'STILL UNHEALTHY: ' + why2}")
    notify(f"DFIR update {new[:8]} не прижився ({why[:150]}), повернуто {old[:8]}"
           + ("" if ok2 else " - але система досі нездорова, потрібна увага"))
    return 2


def cmd_apply(args):
    rc = 0 if "code" in SKIP else apply_code()
    if rc == 0 and "--sources" in args:
        r, out = sh([sys.executable, str(ROOT / "tools/sources/dfir_sources.py"), "update"],
                    env={"DFIR_ROOT": str(ROOT)}, timeout=7200)
        log("sources update: rc=%d %s" % (r, out[-300:]))
        rc = 1 if r else 0
    if rc == 0 and "--owui" in args:
        cur, latest = owui_versions()
        if cur and latest and cur != latest:
            r, out = sh(["bash", str(ROOT / "scripts/owui_update.sh"), latest], timeout=3600)
            log("owui update %s -> %s: rc=%d %s" % (cur, latest, r, out[-300:]))
            rc = 2 if r else 0
        else:
            log(f"owui: nothing to do (current={cur} latest={latest})")
    return rc


def main(a):
    if a and a[0] == "check":
        return cmd_check("--notify" in a)
    if a and a[0] == "apply":
        return cmd_apply(a[1:])
    print(__doc__)
    return 0 if (not a or a[0] in ("-h", "--help", "help")) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
