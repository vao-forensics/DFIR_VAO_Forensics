# Helpers for install.sh and `dfir`: translated messages, prompts with built-in help, answer
# persistence, secrets, dry-run wrapper.
# Prompt rule: if the variable is already set (answers file or environment), it is not asked again.
# At any prompt "?" prints an explanation plus a ready-to-paste block for ChatGPT / Gemini.

C_B=$'\e[1m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_C=$'\e[36m'; C_0=$'\e[0m'
[ -t 1 ] || { C_B=; C_G=; C_Y=; C_R=; C_C=; C_0=; }
SAVED_VARS=()
SECRET_VARS=()
declare -A CHOICE_LABELS=()
STEP_NAME=""

# ---- translations ------------------------------------------------------------------------------
# installer/i18n/<code>.sh fills T[key]; English is loaded first, so a missing key falls back to it.
INSTALL_LANGS=()   # offered only when installer/i18n/<code>.sh exists
for _l in en uk pl de es fr pt it; do [ -f "$ROOT/installer/i18n/$_l.sh" ] && INSTALL_LANGS+=("$_l"); done
# languages generated on this server by its own AI (installer/i18n/<code>.sh), after the built-in ones
for _f in "$ROOT"/installer/i18n/*.sh; do
  _l=$(basename "$_f" .sh)
  case " ${INSTALL_LANGS[*]} " in *" $_l "*) ;; *) [[ "$_l" =~ ^[a-z]{2,3}$ ]] && INSTALL_LANGS+=("$_l") ;; esac
done
declare -A LANG_NATIVE=([en]="English" [uk]="Українська" [pl]="Polski" [de]="Deutsch" [es]="Español" [fr]="Français" [pt]="Português" [it]="Italiano")
declare -A LANG_ENGLISH=([en]="English" [uk]="Ukrainian" [pl]="Polish" [de]="German" [es]="Spanish" [fr]="French" [pt]="Portuguese" [it]="Italian")
declare -A T=() TEN=()
load_lang() {
  local code=$1 k
  T=(); . "$ROOT/installer/i18n/en.sh"
  for k in "${!T[@]}"; do TEN[$k]=${T[$k]}; done
  if [ "$code" != en ] && [ -f "$ROOT/installer/i18n/$code.sh" ]; then . "$ROOT/installer/i18n/$code.sh"; fi
  UI_LANG=$code
}
# t KEY [ARGS...]: translated printf format; unknown key prints the key itself
t() { local k=$1; shift; local f=${T[$k]:-${TEN[$k]:-$k}}; printf -- "$f" "$@"; }
ten() { local k=$1; shift; local f=${TEN[$k]:-$k}; printf -- "$f" "$@"; }
has_t() { [ -n "${T[$1]:-${TEN[$1]:-}}" ]; }

banner() { printf '\n%s== %s ==%s\n' "$C_B" "$1" "$C_0"; }
say()    { printf '%s•%s %s\n' "$C_G" "$C_0" "$*"; }
warn()   { printf '%s! %s%s\n' "$C_Y" "$*" "$C_0" >&2; }
die()    { printf '%s%s: %s%s\n' "$C_R" "$(t error)" "$*" "$C_0" >&2; exit 1; }
msg()    { say "$(t "$@")"; }
wmsg()   { warn "$(t "$@")"; }
dmsg()   { die "$(t "$@")"; }
step()   { STEP_NAME=$1; banner "$(t "step_$1")"; }

# run CMD...: executes, or only prints it in DRY_RUN
run() {
  if [ "$DRY_RUN" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

interactive() { [ -t 0 ] && [ -z "${ANSWERS_IN:-}" ]; }

_remember() { local v; for v in "${SAVED_VARS[@]}"; do [ "$v" = "$1" ] && return; done; SAVED_VARS+=("$1"); }

# ---- help for a person who is stuck --------------------------------------------------------------
sys_facts() {
  local os virt gpu drv dock disk
  os=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
  virt=$(systemd-detect-virt 2>/dev/null || echo none)
  gpu=$(lspci 2>/dev/null | grep -iE 'vga|3d controller' | sed 's/^[^ ]* //' | paste -sd';' -)
  drv=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
  dock=$(docker --version 2>/dev/null | cut -d, -f1)
  disk=$(df -BG --output=avail "$DESTDIR" 2>/dev/null | tail -1 | tr -d ' ')
  printf 'OS: %s | virtualization: %s | CPU: %s cores | RAM: %s GB | free disk: %s\n' \
    "$os" "$virt" "$(nproc 2>/dev/null)" "$(awk '/MemTotal/{printf "%d", $2/1048576}' /proc/meminfo)" "$disk"
  printf 'GPU (lspci): %s | NVIDIA driver: %s | Docker: %s\n' "${gpu:-none}" "${drv:-not installed}" "${dock:-not installed}"
  local v shown=""
  for v in LLM_MODE PROFILE LLM_PROVIDER TUNNEL VPN_KIND WG_ENABLE BOT_LANG; do
    [ -n "${!v:-}" ] && shown+="$v=${!v} "
  done
  [ -n "$shown" ] && printf 'Answers so far: %s\n' "$shown"
}

# ai_block KEY [EXTRA]: a self-contained question for any chat AI, in English (every AI reads it),
# asking it to answer in the person's language. Never contains secrets.
ai_block() {
  local key=$1 extra=${2:-} f="$DESTDIR/state/ai_help.txt"
  local q h
  q=$(ten "q_$key"); h=$(ten "h_$key")
  {
    echo "----- $(t ai_copy_start) -----"
    echo "I am installing DFIR Bot: an open-source Telegram bot for Windows forensic triage (a KAPE-based"
    echo "collector EXE uploads evidence, the server parses it in Docker containers and writes an incident"
    echo "report with a local or cloud LLM). Installer: install.sh on Linux, project README on GitHub."
    echo "Installer step: $(ten "step_${STEP_NAME:-start}")"
    [ "$q" != "q_$key" ] && echo "The installer asks: $q"
    [ "$h" != "h_$key" ] && echo "Installer's explanation: $h"
    [ -n "$extra" ] && printf '%s\n' "$extra"
    sys_facts
    echo "Please explain in ${LANG_ENGLISH[$UI_LANG]:-English}, simply and step by step, what I should answer"
    echo "and where to find this value. Never ask me to paste passwords or tokens into the chat."
    echo "----- $(t ai_copy_end) -----"
  } | tee "$f" 2>/dev/null || true
}

show_help() {
  local key=$1
  printf '%s' "$C_C"
  if has_t "h_$key"; then printf '%s\n' "$(t "h_$key")" | sed 's/^/  /'; fi
  printf '%s\n' "$C_0"
  t help_ai_intro; echo
  ai_block "$key"
  echo
}

# _read VAR PROMPT KEY [-s]: read with "?" -> help, loops until something else is typed
_read() {
  local __v=$1 p=$2 key=$3 flag=${4:-} __a
  while :; do
    if [ "$flag" = -s ]; then read -r -s -p "$p" __a || true; echo; else read -r -p "$p" __a || true; fi
    if [ "$__a" = "?" ]; then show_help "$key"; continue; fi
    printf -v "$__v" '%s' "$__a"; return 0
  done
}

# ask VAR KEY default
ask() {
  local var=$1 key=$2 def=${3:-} ans
  _remember "$var"
  [ -n "${!var+x}" ] && return 0
  if interactive; then
    _read ans "  $(t "q_$key")${def:+ [$def]} $(t help_hint): " "$key"
    printf -v "$var" '%s' "${ans:-$def}"
  else
    printf -v "$var" '%s' "$def"
  fi
}

ask_secret() {
  local var=$1 key=$2 ans
  _remember "$var"; SECRET_VARS+=("$var")
  [ -n "${!var:-}" ] && return 0
  interactive || dmsg missing_answer "$var"
  while :; do
    _read ans "  $(t "q_$key") $(t help_hint) $(t hidden_input): " "$key" -s
    [ -n "$ans" ] && break
    wmsg empty_value
  done
  printf -v "$var" '%s' "$ans"
}

is_yes() { case "${1,,}" in y|yes|т|так|t|tak|j|ja|s|si|sí|sim|o|oui|д|да|da|evet|ano|igen|kyllä|ναι|はい|是|네|ja|yo|ndiyo) return 0 ;; *) return 1 ;; esac; }
is_no()  { case "${1,,}" in n|no|н|ні|nie|nein|non|não|не|нет|nu|hayır|ne|nem|ei|όχι|いいえ|否|아니요) return 0 ;; *) return 1 ;; esac; }

# ask_yesno VAR KEY y|n
ask_yesno() {
  local var=$1 key=$2 def=$3 ans
  _remember "$var"
  [ -n "${!var+x}" ] && return 0
  if interactive; then
    _read ans "  $(t "q_$key") [$( [ "$def" = y ] && t yes_no_Y || t yes_no_N)] $(t help_hint): " "$key"
    if is_yes "$ans"; then ans=y; elif is_no "$ans"; then ans=n; else ans=$def; fi
  else ans=$def; fi
  printf -v "$var" '%s' "$ans"
}

# ask_choice VAR KEY default opt1 opt2 ...   (labels: o_KEY_opt, descriptions: d_KEY_opt)
ask_choice() {
  local var=$1 key=$2 def=$3; shift 3
  local opts=("$@") i ans lbl
  _remember "$var"
  if [ -n "${!var+x}" ]; then
    for i in "${opts[@]}"; do [ "$i" = "${!var}" ] && return 0; done
    dmsg bad_answer "$var" "${!var}" "${opts[*]}"
  fi
  if interactive; then
    echo "  $(t "q_$key")"
    for i in "${!opts[@]}"; do
      lbl=$(t "o_${key}_${opts[$i]}"); [ "$lbl" = "o_${key}_${opts[$i]}" ] && lbl=${CHOICE_LABELS[${opts[$i]}]:-${opts[$i]}}
      printf '    %s%d)%s %s%s\n' "$C_B" $((i+1)) "$C_0" "$lbl" "$( [ "${opts[$i]}" = "$def" ] && printf '  %s(%s)%s' "$C_G" "$(t recommended)" "$C_0")"
      if has_t "d_${key}_${opts[$i]}"; then printf '       %s\n' "$(t "d_${key}_${opts[$i]}")"; fi
    done
    while :; do
      _read ans "  $(t choice) [$(( $(_idx "$def" "${opts[@]}") + 1 ))] $(t help_hint): " "$key"
      [ -z "$ans" ] && { ans=$def; break; }
      if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le ${#opts[@]} ]; then ans=${opts[$((ans-1))]}; break; fi
      for i in "${opts[@]}"; do [ "$i" = "$ans" ] && break 2; done
      wmsg unknown_choice "$ans"
    done
    printf -v "$var" '%s' "$ans"
    return 0
  fi
  printf -v "$var" '%s' "$def"
}
_idx() { local x=$1 i=0; shift; for o in "$@"; do [ "$o" = "$x" ] && { echo $i; return; }; i=$((i+1)); done; echo 0; }

# forget VAR...: so the next ask_* asks again (review screen, `dfir llm`)
forget() { local v; for v in "$@"; do unset "$v"; done; }

# gen_secret VAR LEN: random URL-safe value unless already set
gen_secret() {
  local var=$1 len=$2
  _remember "$var"; SECRET_VARS+=("$var")
  [ -n "${!var:-}" ] && return 0
  printf -v "$var" '%s' "$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$len")"
}

save_answers() {
  local f=$1 v
  ( umask 077
    { echo "# install.sh answers $(date -Is). Contains secrets: keep it private, never commit."
      for v in "${SAVED_VARS[@]}"; do [ -n "${!v+x}" ] && printf '%s=%q\n' "$v" "${!v}"; done; } > "$f" )
}

# scrub TEXT: replace every secret value with ***
scrub() {
  local s=$1 v
  for v in "${SECRET_VARS[@]}"; do [ -n "${!v:-}" ] && [ ${#v} -gt 0 ] && s=${s//"${!v}"/***}; done
  printf '%s' "$s"
}

public_ip_guess() { curl -fs --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}'; }

need_root() {
  if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" != 0 ]; then
    if command -v sudo >/dev/null; then
      echo "Administrator rights are needed (drivers, Docker, VPN). Restarting with sudo..."
      exec sudo -E bash "$0" "$@"
    fi
    echo "Run as root: su -c 'bash $0'"; exit 1
  fi
}

# apt_get ARGS...: update + run, with retries; when the plain-HTTP Ubuntu mirror does not answer (seen
# 10.11.2026: port 80 of archive.ubuntu.com timed out while HTTPS worked) the sources move to HTTPS
apt_get() {
  [ "$DRY_RUN" = 1 ] && { echo "+ apt-get $*"; return 0; }
  printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80dfir-retries
  apt-get update -qq && apt-get "$@" && return 0
  local f changed=n
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] && grep -qE 'http://([a-z.]*archive\.ubuntu\.com|security\.ubuntu\.com|deb\.debian\.org)' "$f" || continue
    sed -i -E 's#http://([a-z.]*archive\.ubuntu\.com|security\.ubuntu\.com|deb\.debian\.org)#https://\1#g' "$f"; changed=y
  done
  [ $changed = y ] && wmsg apt_https
  apt-get update -qq && apt-get "$@"
}

preflight() {
  [ -f /etc/os-release ] && . /etc/os-release
  [ "${ID:-}" = ubuntu ] || [ "${ID:-}" = debian ] || wmsg os_untested "${PRETTY_NAME:-?}"
  local miss=() c free
  # every later apt-get (Docker's script too) retries a mirror that drops a connection
  [ "$DRY_RUN" = 1 ] || printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80dfir-retries
  for c in curl python3 unzip openssl lspci git; do command -v "$c" >/dev/null || miss+=("$c"); done
  if [ ${#miss[@]} -gt 0 ]; then
    msg installing_pkgs "${miss[*]}"
    miss=("${miss[@]/lspci/pciutils}")
    apt_get install -y -qq "${miss[@]}"
  fi
  free=$(df -BG --output=avail "$DESTDIR" | tail -1 | tr -dc 0-9)
  [ "${free:-0}" -lt 60 ] && wmsg low_disk "$free"
  return 0
}
