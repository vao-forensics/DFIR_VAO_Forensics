#!/usr/bin/env python3
"""dfir-hoststats — tiny VM-host stats helper for the DFIR admin dashboard.

The case-maintainer runs INSIDE a container and cannot see docker/df/host-cpu.
This runs on the VM host (native) and serves the bits the container is blind to:
docker container list (name/ports/mem/cpu/image-size), docker disk usage,
host RAM/CPU/load and root-fs df. Everything is gathered live per request so a
new/removed container or changing disk is always reflected (no hardcoding).

  GET /hoststats  -> JSON   (optional header X-DFIR-Token if DFIR_HOSTSTATS_TOKEN set)
  GET /health     -> {"ok": true}

Bound on 0.0.0.0:8096; case-maintainer reaches it at http://172.18.0.1:8096.
"""
import json
import os
import shutil
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("DFIR_HOSTSTATS_HOST", "0.0.0.0")
PORT = int(os.getenv("DFIR_HOSTSTATS_PORT", "8096"))
TOKEN = os.getenv("DFIR_HOSTSTATS_TOKEN", "").strip()
CACHE_TTL = float(os.getenv("DFIR_HOSTSTATS_TTL", "8"))

_cache = {"ts": 0.0, "data": None}


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _mem():
    out = {}
    try:
        for ln in open("/proc/meminfo"):
            k, _, v = ln.partition(":")
            out[k.strip()] = int(v.strip().split()[0]) * 1024  # bytes
    except Exception:
        return {}
    total = out.get("MemTotal", 0)
    avail = out.get("MemAvailable", 0)
    return {"total": total, "available": avail, "used": max(0, total - avail)}


def _cpu():
    def snap():
        f = open("/proc/stat").readline().split()[1:]
        v = [int(x) for x in f]
        idle = v[3] + v[4]
        return sum(v), idle
    try:
        t0, i0 = snap(); time.sleep(0.25); t1, i1 = snap()
        dt, di = t1 - t0, i1 - i0
        pct = round(100.0 * (dt - di) / dt, 1) if dt > 0 else 0.0
    except Exception:
        pct = None
    try:
        cores = os.cpu_count() or 0
        load = open("/proc/loadavg").read().split()[:3]
    except Exception:
        cores, load = 0, []
    return {"pct": pct, "cores": cores, "load": load}


def _disk():
    try:
        t, u, f = shutil.disk_usage("/")
        return {"total": t, "used": u, "free": f, "pct": round(100.0 * u / t) if t else 0}
    except Exception:
        return {}


def _docker():
    """Merge name|ports, name|size, name|mem|cpu from three docker calls."""
    ports, size, memcpu = {}, {}, {}
    for ln in _run(["docker", "ps", "--format", "{{.Names}}|{{.Ports}}"], 15).splitlines():
        p = ln.split("|", 1)
        if p[0]:
            ports[p[0]] = p[1] if len(p) > 1 else ""
    for ln in _run(["docker", "ps", "--size", "--format", "{{.Names}}|{{.Size}}"], 25).splitlines():
        p = ln.split("|", 1)
        if p[0]:
            size[p[0]] = p[1] if len(p) > 1 else ""
    for ln in _run(["docker", "stats", "--no-stream", "--format",
                    "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}"], 25).splitlines():
        p = ln.split("|")
        if p[0]:
            memcpu[p[0]] = {"mem": p[1] if len(p) > 1 else "", "cpu": p[2] if len(p) > 2 else ""}
    conts = []
    for name in ports:  # only running containers (docker ps)
        mc = memcpu.get(name, {})
        conts.append({
            "name": name,
            "ports": ports.get(name, ""),
            "size": size.get(name, ""),          # "6MB (virtual 139MB)"
            "mem": mc.get("mem", ""),             # "53.68MiB / 33.51GiB"
            "cpu": mc.get("cpu", ""),             # "0.02%"
        })
    return conts


def _docker_df():
    out = {}
    for ln in _run(["docker", "system", "df", "--format",
                    "{{.Type}}|{{.Size}}|{{.Reclaimable}}"], 20).splitlines():
        p = ln.split("|")
        if len(p) >= 3:
            out[p[0].strip().lower()] = {"size": p[1].strip(), "reclaimable": p[2].strip()}
    return out


CASES_DIR = os.getenv("DFIR_CASES_DIR", "/srv/dfir/cases")


def _cases_disk():
    """Per-directory disk usage under the cases dir (host `du`, fast). Keyed by dir
    name so the dashboard can map to DB cases and flag ghost dirs (dir w/o DB case)."""
    out = {}
    txt = _run(["sh", "-c", "du -sb %s/*/ 2>/dev/null" % CASES_DIR.replace("'", "")], 40)
    for ln in txt.splitlines():
        parts = ln.split("\t", 1)
        if len(parts) == 2 and parts[0].strip().isdigit():
            name = parts[1].rstrip("/").split("/")[-1]
            out[name] = int(parts[0].strip())
    return out


def _collect():
    return {
        "ts": time.time(),
        "mem": _mem(),
        "cpu": _cpu(),
        "disk": _disk(),
        "containers": _docker(),
        "docker_df": _docker_df(),
        "cases_disk": _cases_disk(),
    }


def _get():
    now = time.time()
    if _cache["data"] and (now - _cache["ts"]) < CACHE_TTL:
        return _cache["data"]
    data = _collect()
    _cache["ts"] = now
    _cache["data"] = data
    return data


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            return self._send(200, {"ok": True})
        if self.path.startswith("/hoststats"):
            if TOKEN and self.headers.get("X-DFIR-Token", "") != TOKEN:
                return self._send(403, {"error": "forbidden"})
            try:
                return self._send(200, _get())
            except Exception as e:
                return self._send(500, {"error": str(e)[:200]})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
