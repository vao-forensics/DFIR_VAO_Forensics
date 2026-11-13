#!/usr/bin/env bash
# Disposable, isolated analysis sandbox for one archive.
# Usage: run_sandbox.sh <archive_path> [job_id]
# Launches a locked-down python:3.12-slim container with NO network, non-root,
# all caps dropped, read-only rootfs, size-capped tmpfs workdir, cpu/mem/pids
# limits and a wall-clock timeout. Evidence is mounted read-only; only /out is
# writable. Container is --rm (self-destructs); the ephemeral tmpfs vanishes.
set -euo pipefail

DFIR_ROOT="${DFIR_ROOT:-$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)}"
BASE=$DFIR_ROOT/sandbox
IMG=dfir-sandbox:0.1
MEM=4g                    # tmpfs pages count against it: > WORK_TMPFS + tools
CPUS=2
PIDS=256
WORK_TMPFS=2560m          # ephemeral unpack area (> MAX_TOTAL in analyze.py)
FSIZE_KB=$((600*1024))    # ulimit per-file write cap (anti-bomb), ~600 MiB
TIMEOUT=900               # wall-clock seconds

archive="${1:?need archive path}"
job="${2:-job_$(date -u +%Y%m%dT%H%M%SZ)_$$}"
pwfile="${3:-}"   # optional: file holding a one-time archive password (AES zip)
[ -f "$archive" ] || { echo "no such archive: $archive" >&2; exit 2; }

jobdir="$BASE/jobs/$job"
out="$jobdir/out"
mkdir -p "$out"
# sandbox runs as uid 65534 (nobody); only /out is writable, so grant it
chown 65534:65534 "$out"
chmod 700 "$out"
# copy the archive into the job dir so the container mounts an isolated, ro copy
cp -- "$archive" "$jobdir/input.bin"
cname="dfir_sbx_${job}"

echo "[sandbox] job=$job image=$IMG net=none user=65534 caps=none"
set +e
timeout --signal=SIGKILL "$TIMEOUT" \
  docker run --rm --name "$cname" \
    --network none \
    --user 65534:65534 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --security-opt label=disable \
    --read-only \
    --tmpfs /work:rw,size=${WORK_TMPFS},mode=1777 \
    --tmpfs /tmp:rw,size=64m,mode=1777 \
    --memory "$MEM" --memory-swap "$MEM" \
    --cpus "$CPUS" --pids-limit "$PIDS" \
    --ulimit fsize=$((FSIZE_KB*1024)):$((FSIZE_KB*1024)) \
    --ulimit nofile=1024:1024 \
    -e PYTHONDONTWRITEBYTECODE=1 \
    ${pwfile:+-v "$pwfile":/run/sbx_pw:ro} \
    -v "$BASE/analyze.py":/opt/analyze.py:ro \
    -v "$BASE/deep.py":/opt/deep.py:ro \
    -v "$jobdir/input.bin":/in/archive:ro \
    -v "$out":/out:rw \
    "$IMG" \
    python3 /opt/analyze.py --in /in/archive --out /out --work /work
code=$?
set -e

# self-destruct: remove the raw input copy; keep only the report dir
rm -f "$jobdir/input.bin"
# belt-and-braces: force-remove the container if timeout left it
docker rm -f "$cname" >/dev/null 2>&1 || true

echo "[sandbox] exit=$code report=$out"
echo "[sandbox] job dir will be purged by retention after 24h: $jobdir"
exit $code
