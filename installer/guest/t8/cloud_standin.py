#!/usr/bin/env python3
"""T8 'cloud' stand-in: an OpenAI-compatible endpoint that, like a real provider, REQUIRES an API key
(Authorization: Bearer <key>, 401 otherwise) and forwards to a local llama-swap. Lets the installer's
cloud code path (CLOUD_OK, provider=custom, key, router with key) be tested without a real provider key.
usage: python3 cloud_standin.py BIND PORT UPSTREAM KEY"""
import http.server, sys, urllib.request, urllib.error

BIND, PORT, UP, KEY = sys.argv[1], int(sys.argv[2]), sys.argv[3].rstrip("/"), sys.argv[4]
SEEN = {"ok": 0, "denied": 0}


class H(http.server.BaseHTTPRequestHandler):
    def _go(self, body=None):
        if self.headers.get("Authorization", "") != "Bearer " + KEY:
            SEEN["denied"] += 1
            self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"error":{"message":"invalid api key","type":"invalid_request_error"}}')
            return
        SEEN["ok"] += 1
        path = self.path[3:] if self.path.startswith("/v1") else self.path
        req = urllib.request.Request(UP + "/v1" + path, body, {"Content-Type": "application/json"},
                                     method=self.command)
        try:
            r = urllib.request.urlopen(req, timeout=600); code, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, data = e.code, e.read()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        if self.path == "/_standin_stats":
            b = ("%d %d" % (SEEN["ok"], SEEN["denied"])).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(b); return
        self._go()

    def do_POST(self):
        self._go(self.rfile.read(int(self.headers.get("Content-Length") or 0)))

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer((BIND, PORT), H).serve_forever()
