#!/usr/bin/env bash
# T8 matrix runner: runs the cells one after another (one container at a time: RAM/disk), on the test host.
# usage: bash t8_matrix.sh [cell ...]      default = all cells below
# Cells:   OS image  x  LLM mode (answers file)
#   server = own LLM server / DFIR Host Agent on Windows (llama-swap on the host, LLM_MODE=server)
#   cloud  = cloud provider path (key required) via cloud_standin.py on the incus bridge -> host llama-swap
# 'local' (GPUs inside the guest) is NOT a cell here: an incus container has no GPU; see docs/TEST_MATRIX.md.
# Summary: var/t8/summary.txt (one "T8 CELL ..." line per cell).
set -u
D=$(cd "$(dirname "$0")" && pwd); ROOT=/srv/dfir; LOGD=$ROOT/var/t8; mkdir -p "$LOGD"
declare -A IMG=([jammy-server]=t8-jammy [noble-server]=t8-noble [bookworm-server]=t8-bookworm [noble-cloud]=t8-noble)
declare -A ANS=([jammy-server]=answers_server.env [noble-server]=answers_server.env [bookworm-server]=answers_server.env [noble-cloud]=answers_cloud.env)
CELLS=${*:-"jammy-server bookworm-server noble-server noble-cloud"}
SB=$(ip -4 -o addr show incusbr0 | awk '{print $4}' | cut -d/ -f1)
echo "== T8 matrix $(date -Is) cells: $CELLS" | tee -a "$LOGD/summary.txt"
for c in $CELLS; do
  # the host GPUs are shared: a model benchmark (state/bench_active) holds llama-swap -> every LLM call
  # here would time out (13.11: jammy/noble FAIL with TimeoutError while cand-bolt74 was benchmarked)
  w=0; while [ -e $ROOT/state/bench_active ] && [ $w -lt 240 ]; do [ $w = 0 ] && echo "waiting: bench_active"; sleep 30; w=$((w+1)); done
  sp=
  if [ "${ANS[$c]}" = answers_cloud.env ]; then
    python3 "$D/cloud_standin.py" "$SB" 18300 http://192.168.100.1:1234 t8-standin-key-not-secret & sp=$!
    sleep 1
  fi
  bash "$D/t8_cell.sh" "$c" "${IMG[$c]}" "$D/${ANS[$c]}"
  line=$(grep -a '^T8 CELL' "$LOGD/$c.log" | tail -1); [ -n "$line" ] || line="T8 CELL $c => FAIL (no result line)"
  if [ -n "$sp" ]; then
    st=$(curl -s -m5 "http://$SB:18300/_standin_stats"); kill $sp 2>/dev/null
    line="$line standin(ok denied)=$st"
  fi
  echo "$line $(date -Is)" | tee -a "$LOGD/summary.txt"
done
echo "== T8 matrix done $(date -Is)" | tee -a "$LOGD/summary.txt"
