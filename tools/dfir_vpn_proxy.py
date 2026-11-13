#!/usr/bin/env python3
"""Reverse proxy: WireGuard Portal (reachable only inside the tunnel) -> the LAN the
Windows host sits on.

Why not a plain TCP forward: the portal serves its frontend an ABSOLUTE backend address,
   WGPORTAL_BACKEND_BASE_URL="http://10.8.0.1:8123/api/v0"
so a browser on the host would load the page through the forward and then call the
tunnel address directly, which that machine cannot route. This proxy rewrites that one
string to a relative path, so every API call comes back through here.

Nothing is exposed to the internet: it binds one private address on this VM.
"""
import http.server
import socketserver
import sys
import urllib.error
import urllib.request

UPSTREAM = 'http://10.7.0.1:51821'
BIND = sys.argv[1] if len(sys.argv) > 1 else '192.168.100.128'
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 8123)
REWRITE = [(UPSTREAM, '')]
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx must reach the BROWSER.

    urllib follows redirects by default, and that alone produced a blank page: the portal
    answers /app with 307 -> /app/, the proxy followed it and returned the page under the
    URL /app, so the relative asset links in that HTML resolved to /assets/... instead of
    /app/assets/... - every script 404ed and the app never mounted.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)

HOP = {'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
       'proxy-authenticate', 'proxy-authorization', 'te', 'trailers'}


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'dfir-vpn-proxy'

    def log_message(self, fmt, *a):
        pass

    def _pass(self, method):
        body = None
        n = int(self.headers.get('Content-Length') or 0)
        if n:
            body = self.rfile.read(n)
        req = urllib.request.Request(UPSTREAM + self.path, data=body, method=method)
        for k, v in self.headers.items():
            if k.lower() in HOP or k.lower() == 'host':
                continue
            req.add_header(k, v)
        req.add_header('Host', '10.7.0.1:51821')
        try:
            r = _opener.open(req, timeout=30)
            code, hdrs, data = r.getcode(), r.headers, r.read()
        except urllib.error.HTTPError as e:
            code, hdrs, data = e.code, e.headers, e.read()
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            msg = ('The portal did not answer through the tunnel: %s' % e).encode('utf-8')
            self.send_header('Content-Length', str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        ctype = (hdrs.get('Content-Type') or '').lower()
        if any(t in ctype for t in ('html', 'javascript', 'json', 'text/')):
            try:
                txt = data.decode('utf-8')
                for a, b in REWRITE:
                    txt = txt.replace(a, b)
                data = txt.encode('utf-8')
            except UnicodeDecodeError:
                pass

        self.send_response(code)
        for k, v in hdrs.items():
            lk = k.lower()
            if lk in HOP or lk == 'content-length':
                continue
            if lk == 'location':
                for a, b in REWRITE:
                    v = v.replace(a, b)
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._pass('GET')

    def do_POST(self):
        self._pass('POST')

    def do_PUT(self):
        self._pass('PUT')

    def do_PATCH(self):
        self._pass('PATCH')

    def do_DELETE(self):
        self._pass('DELETE')

    def do_HEAD(self):
        self._pass('HEAD')

    def do_OPTIONS(self):
        self._pass('OPTIONS')


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == '__main__':
    Threaded((BIND, PORT), Proxy).serve_forever()
