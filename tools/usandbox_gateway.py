#!/usr/bin/env python3
"""Гейтвей персональних пісочниць асистента. OpenAPI tool-server для OWUI.
Кожен користувач має ПОСТІЙНИЙ ізольований контейнер (usandbox-<uid>): інтернет для встановлення
інструментів є, але база справ/хост/інші користувачі — недоступні (окрема мережа + фаєрвол).
Користувач визначається заголовком X-OpenWebUI-User-Id (OWUI форвардить server-side — підробити не можна)."""
import json, os, re, subprocess, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = os.environ.get("DFIR_ROOT", "/srv/dfir")

PORT = 8796
BIND = os.environ.get("USBX_BIND", "172.18.0.1")
IMAGE = "usandbox:0.1"
NET = "usandbox-net"
ENV_ROOT = os.path.join(ROOT, "user_envs")
STATE = os.path.join(ROOT, "state")
TOKEN = open(os.path.join(STATE, "usandbox_token")).read().strip()
MAX_OUT = 20000
DEF_TIMEOUT = 60

os.makedirs(ENV_ROOT, exist_ok=True)


def sh(args, timeout=DEF_TIMEOUT, inp=None):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=inp)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "⏱ перевищено ліміт часу (%ds)" % timeout


def safe_uid(uid):
    return re.sub(r"[^a-zA-Z0-9_-]", "", uid or "")[:64]


def ensure_container(uid):
    name = "usandbox-" + safe_uid(uid)
    if not name or name == "usandbox-":
        return None, "нема user id"
    rc, out, _ = sh(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=15)
    if rc == 0 and out.strip() == "true":
        return name, None
    if rc == 0:  # існує, але не запущений
        sh(["docker", "start", name], timeout=30)
        return name, None
    # створити
    home = os.path.join(ENV_ROOT, safe_uid(uid))
    os.makedirs(home, exist_ok=True)
    rc, _, err = sh(["docker", "run", "-d", "--name", name, "--network", NET,
                     "--memory", "2g", "--cpus", "1", "--pids-limit", "256",
                     "--security-opt", "no-new-privileges", "--restart", "unless-stopped",
                     "-e", "HTTP_PROXY=http://172.30.0.1:3128", "-e", "HTTPS_PROXY=http://172.30.0.1:3128", "-e", "http_proxy=http://172.30.0.1:3128", "-e", "https_proxy=http://172.30.0.1:3128",
                     "-e", "NO_PROXY=localhost,127.0.0.1", "-e", "no_proxy=localhost,127.0.0.1",
                     "-v", "%s:/home/user" % home, "-w", "/home/user", IMAGE], timeout=60)
    if rc != 0:
        return None, "не вдалося створити пісочницю: " + err[:200]
    return name, None


def audit(uid, op, payload, rc):
    try:
        with open(os.path.join(STATE, "usandbox_audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "uid": uid, "op": op,
                                "payload": payload[:300], "rc": rc}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def run_in(uid, args, timeout, inp=None):
    name, err = ensure_container(uid)
    if err:
        return {"error": err}
    to = min(int(timeout or DEF_TIMEOUT), 300)
    rc, out, serr = sh(["docker", "exec", "-i", name] + args, timeout=to + 5, inp=inp)
    return {"exit_code": rc, "stdout": out[:MAX_OUT], "stderr": serr[:MAX_OUT],
            "truncated": len(out) > MAX_OUT}


OPS = {
    "/run_python": ("Виконати Python-код у персональній пісочниці користувача (ізольовано; інтернет є, база справ недоступна). Повертає stdout/stderr.",
                    {"code": {"type": "string", "description": "Python-код"},
                     "timeout": {"type": "integer", "description": "Ліміт секунд (до 300)"}}),
    "/run_shell": ("Виконати команду bash у пісочниці (для встановлення інструментів: apt-get/pip, та роботи з файлами). Ізольовано.",
                   {"command": {"type": "string", "description": "Команда bash"},
                    "timeout": {"type": "integer", "description": "Ліміт секунд (до 300)"}}),
}


def openapi():
    paths = {}
    for p, (desc, props) in OPS.items():
        paths[p] = {"post": {"summary": desc, "operationId": p.strip("/"),
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "properties": props}}}},
                    "responses": {"200": {"description": "OK"}}}}
    return {"openapi": "3.1.0", "info": {"title": "Персональна пісочниця", "version": "0.1.0"},
            "servers": [{"url": "http://%s:%d" % (BIND, PORT)}], "paths": paths}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.split("?")[0] in ("/openapi.json", "/"):
            return self._send(200, openapi())
        self._send(404, {"error": "not found"})

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer " + TOKEN:
            return self._send(401, {"error": "unauthorized"})
        path = self.path.split("?")[0]
        if path not in OPS:
            return self._send(404, {"error": "not found"})
        uid = self.headers.get("X-OpenWebUI-User-Id") or self.headers.get("x-openwebui-user-id")
        if not uid:
            return self._send(400, {"error": "нема X-OpenWebUI-User-Id (увімкніть ENABLE_FORWARD_USER_INFO_HEADERS)"})
        ln = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(ln) or b"{}")
        to = body.get("timeout")
        if path == "/run_python":
            code = body.get("code", "")
            res = run_in(uid, ["python3", "-c", code], to)
            audit(uid, "run_python", code, res.get("exit_code"))
        else:
            cmd = body.get("command", "")
            res = run_in(uid, ["bash", "-lc", cmd], to)
            audit(uid, "run_shell", cmd, res.get("exit_code"))
        self._send(200, res)


if __name__ == "__main__":
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
