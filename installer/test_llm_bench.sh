#!/usr/bin/env bash
# T4 test: quick LLM benchmark + role check + host discovery (installer/llm_probe.py, sections.sh llm_bench_roles)
#   1) fake OpenAI server: "fast" model slow, "reasoner" fast, one model without the DFIR fact
#      -> table rows, "roles swapped" warning, "weak forensic answers" warning (en + uk)
#   2) real AI server, if one answers (find-host or $LLM_REAL): one model, must pass the DFIR check
set -u
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd); export ROOT
PASS=0; FAIL=0
ok() { echo "PASS $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL+1)); }
W=$(mktemp -d); trap 'kill $SRV 2>/dev/null; rm -rf "$W"' EXIT
PORT=18797
cat > "$W/fake.py" <<'PY'
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
SPEC = {'slow-fast': (1.0, 20, '4624\nok'), 'quick-reasoner': (0.2, 100, '4624\nok'), 'dumb-big': (0.2, 40, 'no idea')}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, d):
        b = json.dumps(d).encode(); self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send({'data': [{'id': k} for k in SPEC]})
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        sec, toks, txt = SPEC[req['model']]
        time.sleep(sec)
        self._send({'choices': [{'message': {'content': txt}}], 'usage': {'completion_tokens': toks}})
HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
python3 "$W/fake.py" $PORT & SRV=$!
for i in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/v1/models" >/dev/null && break; sleep 0.2; done

run_bench() {  # $1 = language
  LANGC=$1 bash -c '
    . "$ROOT/installer/lib.sh"; . "$ROOT/installer/sections.sh"; load_lang "$LANGC"
    LLM_BASE_URL='"http://127.0.0.1:$PORT/v1"' LLM_MODEL_FAST=slow-fast LLM_MODEL_REASONER=quick-reasoner \
    LLM_MODEL_BIG=dumb-big LLM_BENCH=y llm_bench_roles' </dev/null 2>&1
}
out=$(run_bench en)
echo "$out" | sed 's/^/    /'
echo "$out" | grep -q 'slow-fast: [0-9.]* s, [0-9]* tokens/s, DFIR check: pass' && ok "row fast" || bad "row fast"
echo "$out" | grep -q 'quick-reasoner: .* DFIR check: pass' && ok "row reasoner" || bad "row reasoner"
echo "$out" | grep -q 'dumb-big did not name event 4624' && ok "weak model warned" || bad "weak model warned"
echo "$out" | grep -q 'slower than the "reasoner" quick-reasoner' && ok "swapped roles warned" || bad "swapped roles warned"
out=$(run_bench uk)
echo "$out" | grep -q 'варто поміняти місцями' && ok "uk strings" || bad "uk strings"
# no warning when roles are in the right order
out=$(LANGC=en bash -c '. "$ROOT/installer/lib.sh"; . "$ROOT/installer/sections.sh"; load_lang en
  LLM_BASE_URL='"http://127.0.0.1:$PORT/v1"' LLM_MODEL_FAST=quick-reasoner LLM_MODEL_REASONER=slow-fast \
  LLM_MODEL_BIG=slow-fast LLM_BENCH=y llm_bench_roles' </dev/null 2>&1)
echo "$out" | grep -q 'slower than' && bad "no false swap warning" || ok "no false swap warning"
echo "$out" | grep -c 'tokens/s' | grep -qx 2 && ok "duplicate models benched once" || bad "duplicate models benched once"

real=${LLM_REAL:-$(python3 "$ROOT/installer/llm_probe.py" find-host 2>/dev/null)}
if [ -n "$real" ]; then
  r=$(LLM_PROBE_TIMEOUT=180 python3 "$ROOT/installer/llm_probe.py" bench "$real" "${LLM_REAL_MODEL:-gpt-small-20b}")
  echo "    real $real: $r"
  [[ "$r" == *"|pass|"* ]] && ok "real model bench ($real)" || bad "real model bench ($real)"
else
  echo "SKIP real model (no AI server found)"
fi
echo "result: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
