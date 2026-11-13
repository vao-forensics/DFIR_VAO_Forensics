#!/usr/bin/env bash
# DFIR Bot guided installer (Ubuntu 22.04 / 24.04, Debian 12).
#
#   sudo ./install.sh                 interactive: language, hardware, AI, Telegram, VPN, then installs
#   sudo ./install.sh --answers FILE  non-interactive (same keys as state/install_answers.env)
#   sudo ./install.sh --reconfigure   ask everything again
#   DRY_RUN=1 ./install.sh ...        show what would be done, change nothing outside $DESTDIR
#
# At any question type ? for an explanation and a block to paste into ChatGPT / Gemini.
# Answers are saved in state/install_answers.env, so a re-run (e.g. after the driver reboot) only
# asks what is missing. Afterwards `dfir` manages the install: dfir llm, dfir lang, dfir status ...
set -Eeuo pipefail
GENERATED_PW=()
export LC_ALL=C.UTF-8   # character-aware lengths and output in every language
ROOT="$(cd "$(dirname "$0")" && pwd)"
export ROOT DRY_RUN="${DRY_RUN:-0}" DESTDIR="${DESTDIR:-$ROOT}"
. "$ROOT/installer/lib.sh"
need_root "$@"

ANSWERS="$DESTDIR/state/install_answers.env"
while [ $# -gt 0 ]; do
  case "$1" in
    --answers) ANSWERS_IN="$2"; shift 2 ;;
    --reconfigure) rm -f "$ANSWERS"; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done
mkdir -p "$DESTDIR/state"; chmod 700 "$DESTDIR/state"
[ -n "${ANSWERS_IN:-}" ] && cp "$ANSWERS_IN" "$ANSWERS"
[ -f "$ANSWERS" ] && . "$ANSWERS"
# answers from installers before 24.10.2026
if [ "${PROFILE:-}" = cpu-remote ] && [ -z "${LLM_MODE:-}" ] && [ -n "${LLM_REMOTE_URL:-}" ]; then
  LLM_MODE=server; LLM_BASE_URL=${LLM_REMOTE_URL%/}; LLM_BASE_URL=${LLM_BASE_URL%/v1}/v1
fi

. "$ROOT/installer/sections.sh"
. "$ROOT/installer/modules.sh"

# ---- language first: everything after it, and the bot itself, speaks it ----------------------------
sec_lang
LOG="$DESTDIR/state/install.log"
exec > >(tee -a "$LOG") 2>&1
on_error() {
  local rc=$? line=$1
  trap - ERR
  echo
  warn "$(t err_failed "$(t "step_${STEP_NAME:-start}")" "$line" "$rc")"
  t err_help "$LOG"; echo
  ai_block "${STEP_NAME:-start}" "The installer failed (exit code $rc, install.sh line $line). Last lines of its log:
$(scrub "$(tail -n 25 "$LOG" 2>/dev/null | grep -v -- '-----')")"
  exit "$rc"
}
trap 'on_error $LINENO' ERR

banner "$(t title)"
t intro; echo
sec_consent
step check
preflight
. "$ROOT/installer/detect_hw.sh"
show_hw

# ---- questions ---------------------------------------------------------------------------------
sec_llm
sec_telegram
sec_vpn
sec_modules
sec_botlang
sec_accounts
sec_secrets
save_answers "$ANSWERS"

# ---- review: change any part before anything is installed ---------------------------------------
review_loop
save_answers "$ANSWERS"
msg answers_saved "$ANSWERS"

# ---- do it -------------------------------------------------------------------------------------
. "$ROOT/installer/apply.sh"
apply_all
banner "$(t done_title)"
summary
