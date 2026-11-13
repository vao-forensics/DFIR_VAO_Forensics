#!/usr/bin/env bash
# gpu_clocks.sh lock|reset|status - hold GPU clocks up for big-120b.
#
# Why: with --split-mode layer each card works ~1/N of the time, the driver drops it to an idle
# P-state between its turns (memory clock 5 GHz instead of ~11 GHz) and generation falls to 6-7 tok/s.
# Locking the graphics floor and the memory clock brought 6x RTX 4080 SUPER to 65-67 tok/s.
# Cost: higher idle power while locked. Installed as dfir-gpu-clocks.service for the large profile.
set -u
command -v nvidia-smi >/dev/null || { echo "nvidia-smi not found"; exit 0; }
FLOOR=${GPU_CLOCK_FLOOR:-1500}   # MHz; the floor, not the ceiling, is what keeps the card awake

case "${1:-status}" in
  lock)
    for i in $(nvidia-smi --query-gpu=index --format=csv,noheader); do
      # highest supported pair for this card: first line = max memory clock, max graphics clock at it
      read -r mem gr < <(nvidia-smi -i "$i" --query-supported-clocks=memory,graphics --format=csv,noheader,nounits \
                         | tr -d ' ' | tr ',' ' ' | sort -k1,1nr -k2,2nr | head -1)
      [ -n "${mem:-}" ] || continue
      lo=$FLOOR; [ "$lo" -gt "$gr" ] && lo=$gr
      nvidia-smi -i "$i" -lgc "$lo,$gr" >/dev/null && nvidia-smi -i "$i" -lmc "$mem,$mem" >/dev/null \
        && echo "GPU $i: graphics $lo-$gr MHz, memory $mem MHz" || echo "GPU $i: lock refused (needs root; some boards forbid -lmc)"
    done ;;
  reset)
    nvidia-smi -rgc >/dev/null; nvidia-smi -rmc >/dev/null; echo "GPU clocks back to driver control" ;;
  status)
    nvidia-smi --query-gpu=index,pstate,clocks.gr,clocks.mem --format=csv ;;
  *) echo "usage: $0 lock|reset|status"; exit 2 ;;
esac
