#!/usr/bin/env python3
"""Telegram Bot API stub for install tests (usage: test_tg_stub.py PORT [BIND_ADDR], default 127.0.0.1).

Install tests must never hold a real bot's token: a test n8n once took the working bot's webhook
(06.11.2026). install.sh -> telegram.py honours DFIR_TG_API, so the test points it here. Answers
getMe / getWebhookInfo / sendMessage / getUpdates / setWebhook like Telegram does and logs each call
(method only, never the token) to stdout.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    def _go(self):
        method = self.path.rstrip('/').split('/')[-1].split('?')[0]
        n = int(self.headers.get('Content-Length') or 0)
        if n:
            self.rfile.read(n)
        res = {'getMe': {'id': 1, 'is_bot': True, 'username': 'dfir_install_test_stub_bot'},
               'getWebhookInfo': {'url': ''}, 'getUpdates': [], 'setWebhook': True,
               'deleteWebhook': True}.get(method, {'message_id': 1})
        body = json.dumps({'ok': True, 'result': res}).encode()
        print('stub call', method, flush=True)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _go

    def log_message(self, *a):
        pass


ThreadingHTTPServer((sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1', int(sys.argv[1])), H).serve_forever()
