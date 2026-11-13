#!/usr/bin/env bash
# dfir: manage an installed DFIR Bot (installed by install.sh as /usr/local/bin/dfir).
#
#   dfir status          containers, LLM, Telegram webhook, disk
#   dfir llm             change the AI: local GPUs / own server / cloud provider, or other models
#   dfir llm bench       speed + a DFIR check of the models the bot uses now (changes nothing)
#   dfir lang            change the bot's default language (each user can still pick their own)
#   dfir ui-lang         change the language of this tool and the installer
#   dfir logs [NAME]     last log lines of a container (default: case-maintainer)
#   dfir restart         restart all containers
#   dfir update [check]  what is new (code, databases, Open WebUI, collector tools); changes nothing
#   dfir update apply [--sources] [--owui]  trial on a separate copy -> switch -> health -> rollback
#   dfir help-ai         a block to paste into ChatGPT / Gemini when something is wrong
#   dfir password        new password for the browser-chat (Open WebUI) admin; saved like at install
#   dfir sources [check|update [--only ID] [--force]|log [N]]  reference databases: official source, verified, logged
#   dfir vpn             WireGuard: state, owner QR, change address/port
#   dfir modules [on|off ID...]  optional parts (web chat, hash databases, translation...): list, switch, apply
#   dfir backup          database backup now + list of backups
#   dfir menu            all of the above in a menu (arrows + Enter)
set -Eeuo pipefail
export LC_ALL=C.UTF-8
SELF=$(readlink -f "$0")
ROOT=$(cd "$(dirname "$SELF")/.." && pwd)
export ROOT DRY_RUN="${DRY_RUN:-0}" DESTDIR="${DESTDIR:-$ROOT}"
. "$ROOT/installer/lib.sh"
need_root "$@"
ANSWERS="$DESTDIR/state/install_answers.env"
[ -f "$ANSWERS" ] || { echo "No $ANSWERS: run install.sh first"; exit 1; }
. "$ANSWERS"
. "$ROOT/installer/sections.sh"
. "$ROOT/installer/modules.sh"
load_lang "${INSTALL_LANG:-en}"
for v in $(grep -oE '^[A-Z_][A-Z0-9_]*=' "$ANSWERS" | tr -d =); do _remember "$v"; done
for v in DFIR_TG_BOT_TOKEN NGROK_AUTHTOKEN LLM_API_KEY POSTGRES_PASSWORD PGADMIN_DEFAULT_PASSWORD MCP_PG_PASSWORD \
         DFIR_LLM_CTRL_TOKEN DFIR_WINDOWS_AGENT_TOKEN COLLECTOR_SEAL_KEY; do SECRET_VARS+=("$v"); done

cmd_password() {  # reset the Open WebUI admin password: typed (twice) or generated
  local pw="" a b
  if [ -t 0 ]; then
    read -r -s -p "  $(t q_webui_password) $(t pw_enter_gen): " a; echo
    if [ -n "$a" ]; then
      read -r -s -p "  $(t pw_again): " b; echo
      [ "$a" = "$b" ] || { wmsg pw_mismatch; exit 1; }
      [ ${#a} -ge 10 ] || { wmsg pw_short; exit 1; }
      pw=$a
    fi
  fi
  [ -n "$pw" ] || pw=$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 20)
  docker cp "$ROOT/installer/owui_reset_pw.py" open-webui:/tmp/owui_reset_pw.py
  local email
  email=$(docker exec -e NEW_PW="$pw" open-webui python3 /tmp/owui_reset_pw.py 2>/dev/null | tail -1) || { wmsg pw_reset_failed; exit 1; }
  docker exec open-webui rm -f /tmp/owui_reset_pw.py
  local home_user=${SUDO_USER:-root} home_dir copy
  home_dir=$(getent passwd "$home_user" | cut -d: -f6); copy="${home_dir:-/root}/DFIR_VAO_credentials.txt"
  ( umask 077; printf '%s  Open WebUI  %s  %s\n' "$(date '+%F %T')" "$email" "$pw" >> "$DESTDIR/state/credentials.txt" )
  install -m 600 -o "$home_user" "$DESTDIR/state/credentials.txt" "$copy" 2>/dev/null || true
  msg pw_reset_done "$email" "$copy"
}

compose() { docker compose --project-directory "$DESTDIR" "$@"; }

set_env() {  # set_env KEY VALUE in .env (added if missing)
  local f="$DESTDIR/.env"
  if grep -q "^$1=" "$f"; then sed -i "s|^$1=.*|$1=$2|" "$f"; else echo "$1=$2" >> "$f"; fi
}

cmd_status() {
  banner "DFIR Bot"
  local bad
  bad=$(docker ps -a --format '{{.Names}} {{.Status}}' | grep -vE 'Up ' || true)
  msg st_containers "$(docker ps -q | wc -l)"
  [ -n "$bad" ] && warn "$bad"
  docker ps --format '{{.Names}} {{.Status}}' | grep -i unhealthy | while read -r l; do warn "$l"; done
  . "$ROOT/installer/apply.sh"
  if curl -fs --max-time 5 "$LLM_ENDPOINT/v1/models" >/dev/null; then msg st_llm_ok "$(llm_describe)"
  else wmsg st_llm_bad "$LLM_ENDPOINT" "$(llm_describe)"; fi
  local wh
  wh=$(curl -fs --max-time 10 "https://api.telegram.org/bot$DFIR_TG_BOT_TOKEN/getWebhookInfo" 2>/dev/null \
       | python3 -c 'import json,sys; d=json.load(sys.stdin)["result"]; print(d.get("url","") or "-", d.get("pending_update_count",0), d.get("last_error_message",""))' 2>/dev/null || echo "? ? ?")
  msg st_webhook "$wh"
  msg st_disk "$(df -h --output=avail "$DESTDIR" | tail -1 | tr -d ' ')"
}

cmd_llm() {
  . "$ROOT/installer/detect_hw.sh"
  show_hw
  local old_mode=${LLM_MODE:-}
  forget LLM_MODE PROFILE LLM_PROVIDER LLM_BASE_URL LLM_API_KEY LLM_NEEDS_KEY LLM_MODEL_FAST LLM_MODEL_REASONER \
         LLM_MODEL_BIG CLOUD_OK LLM_DIRECT DRIVER_INSTALL LLM_KIND
  sec_llm
  save_answers "$ANSWERS"
  . "$ROOT/installer/apply.sh"
  [ "$LLM_MODE" = local ] && [ "$old_mode" != local ] && apply_prereqs
  apply_models
  apply_llm
  msg llm_switched "$(llm_describe)"
}

cmd_llm_bench() {
  local base=${LLM_BASE_URL:-$LLM_ENDPOINT/v1}
  [ "${LLM_MODE:-local}" = local ] && base=$LLM_ENDPOINT/v1
  export LLM_API_KEY=${LLM_API_KEY:-}
  LLM_MODEL_FAST=${LLM_MODEL_FAST:-gpt-small-20b}
  LLM_MODEL_REASONER=${LLM_MODEL_REASONER:-reasoner-31b}
  LLM_MODEL_BIG=${LLM_MODEL_BIG:-big-120b}
  LLM_BASE_URL=$base LLM_BENCH=y llm_bench_roles
}

cmd_lang() {
  forget BOT_LANG; sec_botlang; save_answers "$ANSWERS"
  set_env DFIR_BOT_LANG "$BOT_LANG"
  compose up -d >/dev/null
  msg lang_switched "${BOT_LANG_NATIVE[$BOT_LANG]:-$BOT_LANG}"
}

cmd_ui_lang() { forget INSTALL_LANG; sec_lang; save_answers "$ANSWERS"; msg answers_saved "$ANSWERS"; }

cmd_help_ai() {
  STEP_NAME=status
  local st
  st=$(cmd_status 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
  ai_block status "Output of 'dfir status':
$(scrub "$st")
Last log lines of case-maintainer:
$(scrub "$(docker logs --tail 15 case-maintainer 2>&1)")"
}

cmd_vpn() {  # state + owner QR; on request re-ask the VPN questions and apply them
  local cdir="$DESTDIR/state/wireguard"
  banner "$(t step_vpn)"
  if command -v wg >/dev/null && wg show wgbot >/dev/null 2>&1; then
    msg vpn_state "$(wg show wgbot peers | wc -l)" "${WG_ENDPOINT:-?}:${WG_PORT:-?}"
  else wmsg vpn_off; fi
  [ -f "$cdir/owner.conf" ] && command -v qrencode >/dev/null && { msg vpn_owner_conf "$cdir/owner.conf"; qrencode -t ansiutf8 < "$cdir/owner.conf"; }
  [ -t 0 ] || return 0
  local a; read -r -p "  $(t vpn_change_q) [y/N] " a
  [[ "$a" =~ ^[yYтТ] ]] || return 0
  forget VPN_KIND ZT_NETWORK WG_ENABLE WG_ENDPOINT WG_PORT WG_SUBNET; sec_vpn; save_answers "$ANSWERS"
  . "$ROOT/installer/apply.sh"; apply_env; apply_wireguard
}

cmd_modules() {  # T9: list; interactive choice, or `dfir modules off translate media` / `on translate`
  local act=${1:-} was=" ${MODULES_OFF:-} " new id
  banner "$(t step_modules)"
  if [ -n "$act" ]; then
    shift
    case "$act" in on|off) ;; *) dmsg bad_module "$act" "on off" ;; esac
    new=" ${MODULES_OFF:-} "
    for id in "$@"; do
      case " $(mod_ids) " in *" $id "*) ;; *) dmsg bad_module "$id" "$(mod_ids)" ;; esac
      if [ "$act" = off ]; then new+=" $id "; else new=${new// $id / }; fi
    done
    MODULES_OFF=$(printf '%s\n' $new | awk 'NF && !s[$0]++' | tr '\n' ' ' | sed 's/ $//')
  else
    msg modules_now "$(modules_summary)"
    [ -t 0 ] || return 0
    forget MODULES_OFF; sec_modules
  fi
  _remember MODULES_OFF; save_answers "$ANSWERS"
  [ "$DRY_RUN" = 1 ] && { msg modules_now "$(modules_summary)"; return 0; }   # answers only, no containers
  . "$ROOT/installer/apply.sh"
  apply_modules
  compose up -d
  # switched back on: the parts that live outside the containers
  if mod_on webchat && [[ "$was" == *" webchat "* ]]; then apply_webui; apply_sandbox; fi
  if mod_on hashdb && [[ "$was" == *" hashdb "* ]]; then apply_sources; fi
  compose up -d --force-recreate tg-i18n >/dev/null 2>&1   # reads DFIR_MODULES_OFF at start
  msg modules_now "$(modules_summary)"
}

cmd_backup() {  # database dump now (same script as the nightly one) + what is kept
  bash "$ROOT/tools/pg_backup.sh" --force && msg backup_done || wmsg backup_failed
  ls -lh "$DESTDIR/backups/pg" 2>/dev/null | tail -n +2
}

pause() { [ -t 0 ] && { read -r -p "  $(t menu_enter) " _ || true; }; }

cmd_menu() {  # whiptail menu over the commands above; Esc / Cancel leaves
  command -v whiptail >/dev/null || { apt-get install -y -qq whiptail >/dev/null 2>&1 || dmsg menu_no_whiptail; }
  [ -t 0 ] || dmsg menu_no_tty
  local c
  while :; do
    c=$(whiptail --title "DFIR Bot" --menu "$(t menu_title)" 23 76 14 \
      status "$(t menu_status)" ai "$(t menu_llm)" lang "$(t menu_lang)" ui-lang "$(t menu_ui_lang)" \
      password "$(t menu_password)" vpn "$(t menu_vpn)" modules "$(t menu_modules)" check "$(t menu_update_check)" \
      apply "$(t menu_update_apply)" sources "$(t menu_sources)" backup "$(t menu_backup)" \
      logs "$(t menu_logs)" restart "$(t menu_restart)" quit "$(t menu_quit)" 3>&1 1>&2 2>&3) || break
    clear
    case "$c" in
      status) cmd_status ;;  ai) cmd_llm ;;  lang) cmd_lang ;;  ui-lang) cmd_ui_lang ;;
      password) cmd_password ;;  vpn) cmd_vpn ;;  modules) cmd_modules ;;
      check) DFIR_ROOT="$DESTDIR" python3 "$ROOT/tools/update/dfir_update.py" check ;;
      apply) whiptail --yesno "$(t menu_update_apply_q)" 10 70 && DFIR_ROOT="$DESTDIR" python3 "$ROOT/tools/update/dfir_update.py" apply ;;
      sources) DFIR_ROOT="$DESTDIR" python3 "$ROOT/tools/sources/dfir_sources.py" check ;;
      backup) cmd_backup ;;  logs) docker logs --tail 80 case-maintainer ;;
      restart) whiptail --yesno "$(t menu_restart_q)" 8 60 && compose restart ;;
      quit) break ;;
    esac
    pause
  done
}

case "${1:-status}" in
  status) cmd_status ;;
  llm) if [ "${2:-}" = bench ]; then cmd_llm_bench; else cmd_llm; fi ;;
  lang) cmd_lang ;;
  ui-lang) cmd_ui_lang ;;
  logs) docker logs --tail "${3:-80}" "${2:-case-maintainer}" ;;
  restart) compose restart ;;
  update) shift; DFIR_ROOT="$DESTDIR" exec python3 "$ROOT/tools/update/dfir_update.py" "${@:-check}" ;;
  help-ai) cmd_help_ai ;;
  password) cmd_password ;;
  vpn) cmd_vpn ;;
  modules) shift; cmd_modules "$@" ;;
  backup) cmd_backup ;;
  menu) cmd_menu ;;
  sources) shift; DFIR_ROOT="$ROOT" exec python3 "$ROOT/tools/sources/dfir_sources.py" "${@:-check}" ;;
  -h|--help|help) sed -n '2,19p' "$SELF" ;;
  *) sed -n '2,18p' "$SELF"; exit 1 ;;
esac
