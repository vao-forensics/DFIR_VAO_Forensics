#!/usr/bin/env python3
"""Шлюз Silent Push для Open WebUI (OpenAPI tool server).

Токен Silent Push не зберігається тут: його вводить адмін у Web UI
(Адмін-панель -> Налаштування -> Зовнішні інструменти -> ключ Bearer),
і Web UI надсилає його в заголовку Authorization. Шлюз:
  * перевіряє індикатор (лише домен / IPv4 / IPv6, без довільних шляхів),
  * не пускає понад DAILY_LIMIT запитів на добу (спільний лічильник, скидається опівночі),
  * пише журнал хто/що/коли (state/silentpush_audit.jsonl), без ключа,
  * повертає стиснуту відповідь, щоб не забивати контекст моделі.
"""
import ipaddress, json, os, re, threading, time, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.environ.get("SP_STATE", os.path.join(ROOT, "state"))
DAILY_LIMIT = int(os.environ.get("SP_DAILY_LIMIT", "60"))
PER_USER_LIMIT = int(os.environ.get("SP_PER_USER_LIMIT", "0"))  # 0 = без окремого ліміту на людину
BIND = os.environ.get("SP_BIND", "172.18.0.1")
PORT = int(os.environ.get("SP_PORT", "8795"))
BASE = "https://api.silentpush.com/api/v1/merge-api/explore/"
RX_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RECORDS_F = {"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "any"}
RECORDS_R = {"a", "aaaa", "cname", "mx", "ns", "ptr4", "ptr6", "any"}
_lock = threading.Lock()


def _today():
    return time.strftime("%Y-%m-%d")


def _counter_path():
    return os.path.join(STATE, "silentpush_quota.json")


def take_quota(user):
    """True = можна; рахує лише реальні звернення до Silent Push"""
    with _lock:
        try:
            q = json.load(open(_counter_path()))
        except Exception:
            q = {}
        if q.get("day") != _today():
            q = {"day": _today(), "total": 0, "users": {}}
        if q["total"] >= DAILY_LIMIT:
            return False, q
        if PER_USER_LIMIT and q["users"].get(user, 0) >= PER_USER_LIMIT:
            return False, q
        q["total"] += 1
        q["users"][user] = q["users"].get(user, 0) + 1
        tmp = _counter_path() + ".tmp"
        json.dump(q, open(tmp, "w")); os.replace(tmp, _counter_path())
        return True, q


def audit(row):
    try:
        with open(os.path.join(STATE, "silentpush_audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(dict(row, ts=time.strftime("%Y-%m-%dT%H:%M:%S")), ensure_ascii=False) + "\n")
    except Exception:
        pass


def norm_domain(v):
    v = str(v or "").strip().lower().rstrip(".")
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    v = v.encode("idna").decode() if v and not v.isascii() else v
    if not RX_DOMAIN.match(v):
        raise ValueError("це не схоже на домен")
    return v


def norm_ip(v):
    ip = ipaddress.ip_address(str(v or "").strip())
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise ValueError("приватні й службові адреси не перевіряються (вони не мають репутації й не повинні виходити назовні)")
    return ip


def call_sp(key, path, params=None):
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"X-API-KEY": key, "Accept": "application/json", "User-Agent": "dfir-sp-gateway/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": "Silent Push відповів %s" % e.code, "detail": e.read(300).decode("utf-8", "replace")}


def slim(obj, depth=0):
    """стиснути: без довгих списків і вкладеності, щоб влізти в контекст"""
    if depth > 8:
        return "…"
    if isinstance(obj, dict):
        return {k: slim(v, depth + 1) for k, v in list(obj.items())[:60]}
    if isinstance(obj, list):
        out = [slim(v, depth + 1) for v in obj[:25]]
        if len(obj) > 25:
            out.append("… ще %d" % (len(obj) - 25))
        return out
    if isinstance(obj, str) and len(obj) > 400:
        return obj[:400] + "…"
    return obj


OPS = {
    "/enrich_domain": ("Репутація й дані домену в Silent Push (ризик sp_risk_score, реєстрація, хостинг, IP).",
                       {"domain": "домен, напр. example.com"}),
    "/enrich_ip": ("Репутація й дані IP-адреси в Silent Push (ризик, ASN, репутація, пов'язані домени). IPv4 або IPv6.",
                   {"ip": "публічна IP-адреса"}),
    "/padns_forward": ("Пасивний DNS: які записи (A, MX, NS…) мав домен у минулому.",
                       {"domain": "домен", "record": "тип запису: a, aaaa, cname, mx, ns, txt, soa, any (типово a)"}),
    "/padns_reverse": ("Пасивний DNS навпаки: які домени вказували на цю IP-адресу.",
                       {"ip": "публічна IP-адреса", "record": "a або aaaa (типово a)"}),
    "/quota": ("Скільки запитів до Silent Push лишилось сьогодні (не витрачає ліміт).", {}),
}


def openapi():
    paths = {}
    for p, (desc, props) in OPS.items():
        paths[p] = {"post": {
            "operationId": p.strip("/"), "summary": desc, "description": desc,
            "requestBody": {"required": bool(props), "content": {"application/json": {"schema": {
                "type": "object", "properties": {k: {"type": "string", "description": d} for k, d in props.items()},
                "required": [k for k in props if k in ("domain", "ip")]}}}},
            "responses": {"200": {"description": "результат"}}}}
    return {"openapi": "3.1.0", "info": {"title": "Silent Push (через шлюз DFIR, ліміт %d/добу)" % DAILY_LIMIT,
            "version": "1.0", "description": "Зовнішня розвідка загроз. Кожен запит виходить за периметр: не надсилати дані справ без потреби."},
            "paths": paths}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path.split("?")[0] in ("/openapi.json", "/"):
            return self._send(200, openapi())
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path not in OPS:
            return self._send(404, {"error": "not found"})
        auth = self.headers.get("Authorization", "")
        key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        user = self.headers.get("X-OpenWebUI-User-Email") or self.headers.get("X-OpenWebUI-User-Id") or "?"
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 4096)) or b"{}") if n else {}
        except Exception:
            body = {}
        if path == "/quota":
            try:
                q = json.load(open(_counter_path()))
            except Exception:
                q = {}
            used = q.get("total", 0) if q.get("day") == _today() else 0
            return self._send(200, {"day": _today(), "used": used, "limit": DAILY_LIMIT, "left": max(0, DAILY_LIMIT - used)})
        if not key:
            return self._send(401, {"error": "не задано токен Silent Push: адмін має вставити його в налаштуваннях підключення"})
        try:
            if path in ("/enrich_domain", "/padns_forward"):
                ioc = norm_domain(body.get("domain"))
            else:
                ioc = str(norm_ip(body.get("ip")))
        except Exception as e:
            return self._send(400, {"error": "некоректний індикатор: %s" % e})
        ok, q = take_quota(user)
        if not ok:
            audit({"user": user, "op": path, "ioc": ioc, "verdict": "quota"})
            return self._send(429, {"error": "денний ліміт Silent Push (%d) вичерпано, спробуйте завтра" % DAILY_LIMIT})
        if path == "/enrich_domain":
            res = call_sp(key, "enrich/domain/" + ioc, {"explain": 1})
        elif path == "/enrich_ip":
            v = "ipv6" if ":" in ioc else "ipv4"
            res = call_sp(key, "enrich/%s/%s" % (v, ioc), {"explain": 1})
        elif path == "/padns_forward":
            rec = str(body.get("record") or "a").lower()
            rec = rec if rec in RECORDS_F else "a"
            res = call_sp(key, "padns/lookup/query/%s/%s" % (rec, ioc), {"limit": 50})
        else:
            rec = str(body.get("record") or "a").lower()
            rec = rec if rec in RECORDS_R else "a"
            res = call_sp(key, "padns/lookup/answer/%s/%s" % (rec, ioc), {"limit": 50})
        audit({"user": user, "op": path, "ioc": ioc, "verdict": "error" if res.get("error") else "ok"})
        res = slim(res)
        res["_quota"] = {"used_today": q["total"], "limit": DAILY_LIMIT}
        return self._send(200, res)


if __name__ == "__main__":
    os.makedirs(STATE, exist_ok=True)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
