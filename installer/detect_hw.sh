# Hardware detection -> CPU_*, RAM_GB, GPU_COUNT, GPU_LIST[], GPU_VRAM_*, REC_PROFILE, VIRT, NV_PRESENT.
# NVIDIA only (llama.cpp CUDA build). FAKE_NVSMI=file feeds a saved `nvidia-smi` CSV for tests.

CPU_MODEL=$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)
CPU_CORES=$(nproc 2>/dev/null || echo 1)
RAM_GB=$(awk '/MemTotal/{printf "%d", $2/1048576}' /proc/meminfo 2>/dev/null || echo 0)
VIRT=$(systemd-detect-virt 2>/dev/null || true); VIRT=${VIRT:-none}
NV_PRESENT=n
NVSMI=nvidia-smi
{ [ -n "${FAKE_NVSMI:-}" ] || lspci 2>/dev/null | grep -iE 'vga|3d controller' | grep -qi nvidia; } && NV_PRESENT=y
# WSL2: no PCI device and no Linux driver; the Windows NVIDIA driver lends its libraries and nvidia-smi
# through /usr/lib/wsl/lib (not on PATH). Installing a Linux driver here would break CUDA.
if [ "$VIRT" = wsl ] || grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  VIRT=wsl
  [ -x /usr/lib/wsl/lib/nvidia-smi ] && { NVSMI=/usr/lib/wsl/lib/nvidia-smi; NV_PRESENT=y; }
fi

GPU_LIST=(); GPU_COUNT=0; GPU_VRAM_TOTAL_GB=0; GPU_VRAM_MIN_GB=0
_nv=""
if [ -n "${FAKE_NVSMI:-}" ]; then _nv=$(cat "$FAKE_NVSMI")
elif command -v "$NVSMI" >/dev/null 2>&1; then
  _nv=$("$NVSMI" --query-gpu=index,name,memory.total --format=csv,noheader,nounits 2>/dev/null || true)
fi
while IFS=, read -r idx name mem; do
  [ -n "$idx" ] || continue
  mem=${mem// /}; gb=$(( (mem + 512) / 1024 ))
  GPU_LIST+=("#${idx// /}: ${name# } ${gb} GB")
  GPU_COUNT=$((GPU_COUNT + 1)); GPU_VRAM_TOTAL_GB=$((GPU_VRAM_TOTAL_GB + gb))
  if [ "$GPU_VRAM_MIN_GB" = 0 ] || [ "$gb" -lt "$GPU_VRAM_MIN_GB" ]; then GPU_VRAM_MIN_GB=$gb; fi
done <<< "$_nv"

# Profiles = what the bot's model roles need (measured on 16 GB RTX 4080 SUPER cards):
#   small : gpt-oss-20b MXFP4 (~13 GB)                       -> 1 card >= 16 GB
#   medium: + gemma-4-31B Q4_K_S as reasoner (~19 GB + ctx)   -> 2 cards, >= 40 GB total
#   large : + gpt-oss-120b MXFP4 (~63 GB, 5 cards measured)   -> >= 80 GB total
if   [ "$GPU_COUNT" -eq 0 ] || [ "$GPU_VRAM_MIN_GB" -lt 12 ]; then REC_PROFILE=cpu-remote
elif [ "$GPU_VRAM_TOTAL_GB" -ge 80 ]; then REC_PROFILE=large
elif [ "$GPU_VRAM_TOTAL_GB" -ge 40 ] && [ "$GPU_COUNT" -ge 2 ]; then REC_PROFILE=medium
else REC_PROFILE=small; fi
if [ "$RAM_GB" -lt 32 ]; then wmsg low_ram "$RAM_GB"; fi
true
