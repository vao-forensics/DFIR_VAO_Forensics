#!/usr/bin/env bash
# Orchestrator (runs on the VM host): take ANY uploaded file, decrypt it in the
# trusted zone if it is an encrypted collector archive (bot's key stays there),
# then analyze it in the disposable sandbox. Prints the report dir.
# Usage: analyze_file.sh <input_file> [job_id]
set -euo pipefail
DFIR_ROOT="${DFIR_ROOT:-$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)}"
BASE=$DFIR_ROOT/sandbox
STATE=$DFIR_ROOT/state/sandbox_work        # shared with case-maintainer as /data/state/sandbox_work
CM_STATE=/data/state/sandbox_work         # same dir seen inside case-maintainer
inp="${1:?need input file}"
job="${2:-job_$(date -u +%Y%m%dT%H%M%SZ)_$$}"
[ -f "$inp" ] || { echo "no such file: $inp" >&2; exit 2; }

mkdir -p "$STATE/$job"
cp -- "$inp" "$STATE/$job/src"
cp -f "$BASE/decrypt_helper.py" "$STATE/decrypt_helper.py"

# 1) trusted decrypt (case-maintainer has the key); prints plaintext path or PLAIN
dec=$(docker exec case-maintainer python3 "$CM_STATE/decrypt_helper.py" \
        "$CM_STATE/$job/src" "$CM_STATE/$job/dec" 2>/dev/null | tail -1 || echo PLAIN)

if [ "$dec" = "PLAIN" ] || [ -z "$dec" ]; then
  target="$STATE/$job/src"        # plain upload: analyze as-is
else
  target="${dec/#$CM_STATE/$STATE}"   # translate container path -> VM path
fi
echo "[orchestrator] job=$job encrypted=$([ "$dec" = PLAIN ] && echo no || echo yes) target=$(basename "$target")"

# 2) disposable sandbox analysis (no network, non-root, isolated)
"$BASE/run_sandbox.sh" "$target" "$job" >/dev/null

# 3) cleanup the trusted decrypted copy (keep only the report)
rm -rf "$STATE/$job"
echo "[orchestrator] report: $BASE/jobs/$job/out"
