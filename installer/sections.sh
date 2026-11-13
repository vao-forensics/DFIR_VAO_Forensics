# install.sh question sections. Each one can be re-run from the review screen or by `dfir`
# (forget its variables first). Nothing here changes the machine except the optional driver install.

# languages the bot answers in (any other ISO code also works: the bot translates with the LLM)
BOT_LANGS=(en uk pl de es fr pt it nl cs ro tr ar hi zh ja)
declare -A BOT_LANG_NATIVE=([en]="English" [uk]="Українська" [pl]="Polski" [de]="Deutsch" [es]="Español"
  [fr]="Français" [pt]="Português" [it]="Italiano" [nl]="Nederlands" [cs]="Čeština" [ro]="Română" [tr]="Türkçe"
  [ar]="العربية" [hi]="हिन्दी" [zh]="中文" [ja]="日本語")
declare -A CHOICE_LABELS=()

sec_lang() {
  _remember INSTALL_LANG
  if [ -z "${INSTALL_LANG:-}" ]; then
    if interactive; then
      local i ans
      printf '\n%sDFIR Bot%s\n  Choose the language / Оберіть мову / Wybierz język / Sprache wählen / Elige idioma / Choisissez la langue\n' "$C_B" "$C_0"
      for i in "${!INSTALL_LANGS[@]}"; do printf '    %d) %s\n' $((i+1)) "${LANG_NATIVE[${INSTALL_LANGS[$i]}]:-${INSTALL_LANGS[$i]}}"; done
      printf '    %d) Other language (your AI translates it at the end)\n' $(( ${#INSTALL_LANGS[@]} + 1 ))
      read -r -p "  [1]: " ans || true
      if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le ${#INSTALL_LANGS[@]} ]; then INSTALL_LANG=${INSTALL_LANGS[$((ans-1))]}
      elif [ "$ans" = "$(( ${#INSTALL_LANGS[@]} + 1 ))" ]; then
        local code=""
        while ! [[ "$code" =~ ^[a-z]{2,3}$ ]]; do
          read -r -p "  Language code (ISO 639, e.g. tr, ja, ro, nl, ar): " code || true
          code=$(echo "$code" | tr 'A-Z' 'a-z' | tr -d ' ')
        done
        INSTALL_LANG=en; INSTALL_LANG_GEN=$code; _remember INSTALL_LANG_GEN
        printf '  OK: the installer continues in English; at the end your AI makes the "%s" version for dfir and the bot.\n' "$code"
      else INSTALL_LANG=en; fi
    else INSTALL_LANG=en; fi
  fi
  load_lang "$INSTALL_LANG"
}

show_hw() {
  msg hw_line "$CPU_MODEL" "$CPU_CORES" "$RAM_GB" "$GPU_COUNT" "$GPU_VRAM_TOTAL_GB"
  [ "$GPU_COUNT" -gt 0 ] && printf '      %s\n' "${GPU_LIST[@]}"
  [ "$VIRT" != none ] && msg hw_virt "$VIRT"
  if [ "$NV_PRESENT" = y ] && [ "$GPU_COUNT" = 0 ]; then wmsg hw_no_driver; fi
  return 0
}

# ---- AI / LLM ---------------------------------------------------------------------------------
sec_llm() {
  step llm
  local def=local
  if [ "$GPU_COUNT" -eq 0 ] && [ "$NV_PRESENT" != y ]; then def=server; fi
  [ "$GPU_COUNT" -gt 0 ] && [ "$REC_PROFILE" = cpu-remote ] && def=server
  if [ "$def" = server ] && [ "$VIRT" != none ]; then msg hint_vm_gpu; fi
  ask_choice LLM_MODE llm_mode "$def" local server cloud
  case "$LLM_MODE" in
    local)  llm_local ;;
    server) llm_remote server ;;
    cloud)  llm_remote cloud ;;
  esac
}

llm_local() {
  if [ "$GPU_COUNT" = 0 ] && [ "$NV_PRESENT" = y ] && [ "$VIRT" = wsl ]; then
    wmsg wsl_gpu_driver   # the driver is the Windows one: nothing to install inside WSL
  elif [ "$GPU_COUNT" = 0 ] && [ "$NV_PRESENT" = y ]; then
    ask_yesno DRIVER_INSTALL driver_install y
    if [ "$DRIVER_INSTALL" = y ]; then install_driver_and_reboot; fi
  fi
  if [ "$GPU_COUNT" = 0 ]; then
    wmsg no_gpu_local
    forget LLM_MODE DRIVER_INSTALL; sec_llm; return
  fi
  msg rec_profile "$REC_PROFILE" "$(t "d_profile_$REC_PROFILE")"
  local opts=(small)
  [ "$GPU_COUNT" -ge 2 ] && opts+=(medium)
  [ "$GPU_COUNT" -ge 2 ] && [ "$GPU_VRAM_TOTAL_GB" -ge 64 ] && opts+=(large)
  local def=$REC_PROFILE; [ "$def" = cpu-remote ] && def=small
  ask_choice PROFILE profile "$def" "${opts[@]}"
}

# NVIDIA driver from Ubuntu's own repository; a reboot is unavoidable, the answers survive it
install_driver_and_reboot() {
  save_answers "$ANSWERS"
  msg driver_installing
  run apt-get install -y -qq ubuntu-drivers-common
  run ubuntu-drivers install
  msg driver_done
  local now=n
  interactive && ask_yesno REBOOT_NOW reboot_now y && now=$REBOOT_NOW
  _forget_saved REBOOT_NOW
  save_answers "$ANSWERS"
  if [ "$now" = y ]; then run reboot; fi
  exit 0
}
_forget_saved() { local v n=(); for v in "${SAVED_VARS[@]}"; do [ "$v" != "$1" ] && n+=("$v"); done; SAVED_VARS=("${n[@]}"); unset "$1"; }

# server: own OpenAI-compatible server (Windows host, another PC over VPN, LM Studio, vLLM, Ollama)
# cloud : a provider with an API key
llm_remote() {
  local kind=$1 row
  if [ "$kind" = cloud ]; then
    wmsg cloud_privacy
    ask_yesno CLOUD_OK cloud_ok n
    if [ "$CLOUD_OK" != y ]; then forget LLM_MODE CLOUD_OK; sec_llm; return; fi
    ask_choice LLM_PROVIDER provider openrouter openrouter openai anthropic gemini groq mistral deepseek custom
    row=$(python3 "$ROOT/installer/llm_probe.py" providers | grep "^$LLM_PROVIDER|" || true)
    if [ -n "$row" ]; then
      IFS='|' read -r _ P_BASE P_KIND P_FAST P_REA P_BIG P_KEYS <<< "$row"
      _remember LLM_BASE_URL; LLM_BASE_URL=${LLM_BASE_URL:-$P_BASE}
      msg key_page "$P_KEYS"
    else
      P_KIND=openai; P_FAST=""; P_REA=""; P_BIG=""
      ask LLM_BASE_URL llm_url ""
    fi
    ask_secret LLM_API_KEY cloud_key
    LLM_KIND=$P_KIND
  else
    local hostu=""
    if [ -z "${LLM_BASE_URL:-}" ] && hostu=$(python3 "$ROOT/installer/llm_probe.py" find-host 2>/dev/null); then
      msg llm_host_found "$hostu"
    else
      hostu=""; [ "$VIRT" != none ] && msg hint_windows_host
    fi
    ask LLM_BASE_URL llm_url "${hostu:-http://192.168.1.10:1234/v1}"
    local keydef=n
    # DFIR VAO Host Agent: answers only with its token (shown in its window, button Copy)
    if python3 "$ROOT/installer/llm_probe.py" is-agent "$LLM_BASE_URL" 2>/dev/null; then msg llm_host_agent; keydef=y; LLM_NEEDS_KEY=y; fi
    ask_yesno LLM_NEEDS_KEY llm_needs_key $keydef
    if [ "$LLM_NEEDS_KEY" = y ]; then ask_secret LLM_API_KEY cloud_key; else LLM_API_KEY=""; fi
    LLM_KIND=openai; P_FAST=gpt-small-20b; P_REA=reasoner-31b; P_BIG=big-120b
  fi
  _remember LLM_KIND
  LLM_BASE_URL=${LLM_BASE_URL%/}; [[ "$LLM_BASE_URL" == */v1* ]] || LLM_BASE_URL="$LLM_BASE_URL/v1"
  [[ "$LLM_BASE_URL" =~ ^https?:// ]] || { wmsg bad_url; forget LLM_BASE_URL; llm_remote "$kind"; return; }
  export LLM_API_KEY
  local probe="python3 $ROOT/installer/llm_probe.py" list miss
  msg llm_connecting "$LLM_BASE_URL"
  if ! list=$($probe models "$LLM_BASE_URL" 2>&1); then
    wmsg llm_unreachable "$(scrub "$list")"
    # unattended (answers file): nobody can re-type a key, so 'change' (the interactive default) would
    # wipe the given answers and die with a misleading "LLM_API_KEY is not set" (T8 13.11: the LLM was
    # only busy). Keep the answers and go on; verify_install.sh re-checks the LLM after the install.
    if interactive; then forget LLM_FIX; ask_choice LLM_FIX llm_fix change change retry ignore; _forget_saved_quiet LLM_FIX
    else LLM_FIX=ignore; fi
    case "$LLM_FIX" in
      change) forget LLM_BASE_URL LLM_API_KEY LLM_PROVIDER LLM_NEEDS_KEY; llm_remote "$kind"; return ;;
      retry) llm_remote "$kind"; return ;;
    esac
    list=""
  fi
  [ -n "$list" ] && msg llm_models_found "$(echo "$list" | grep -c .)" "$(echo "$list" | head -12 | paste -sd' ' -)"
  _remember LLM_DIRECT
  if [ "$kind" = server ] && [ -n "$list" ] && miss=$($probe has-all "$LLM_BASE_URL" 2>/dev/null); then
    LLM_DIRECT=y; msg llm_direct
    return 0
  fi
  LLM_DIRECT=n
  [ "$kind" = server ] && [ -n "$list" ] && msg llm_router_needed
  local f r b
  f=$($probe pick "$LLM_BASE_URL" fast "${P_FAST:-}" 2>/dev/null || echo "$P_FAST")
  r=$($probe pick "$LLM_BASE_URL" reasoner "${P_REA:-}" 2>/dev/null || echo "$P_REA")
  b=$($probe pick "$LLM_BASE_URL" big "${P_BIG:-}" 2>/dev/null || echo "$P_BIG")
  ask LLM_MODEL_FAST llm_model_fast "$f"
  ask LLM_MODEL_REASONER llm_model_reasoner "$r"
  ask LLM_MODEL_BIG llm_model_big "$b"
  local res
  if res=$($probe test "$LLM_BASE_URL" "$LLM_MODEL_FAST" 2>&1); then msg llm_test_ok "$LLM_MODEL_FAST" "$res"
    llm_bench_roles
  else
    wmsg llm_test_fail "$LLM_MODEL_FAST" "$(scrub "$res")"
    # unattended (answers file): nobody can re-type a key, so 'change' (the interactive default) would
    # wipe the given answers and die with a misleading "LLM_API_KEY is not set" (T8 13.11: the LLM was
    # only busy). Keep the answers and go on; verify_install.sh re-checks the LLM after the install.
    if interactive; then forget LLM_FIX; ask_choice LLM_FIX llm_fix change change retry ignore; _forget_saved_quiet LLM_FIX
    else LLM_FIX=ignore; fi
    case "$LLM_FIX" in
      change) forget LLM_MODEL_FAST LLM_MODEL_REASONER LLM_MODEL_BIG LLM_BASE_URL LLM_API_KEY LLM_PROVIDER; llm_remote "$kind"; return ;;
      retry) forget LLM_MODEL_FAST LLM_MODEL_REASONER LLM_MODEL_BIG; llm_remote "$kind"; return ;;
    esac
  fi
}
# quick benchmark of the three role models: speed + one DFIR fact; warns when the roles look swapped
llm_bench_roles() {
  [ "${DRY_RUN:-0}" = 1 ] && return 0
  interactive || [ "${LLM_BENCH:-n}" = y ] || return 0
  local probe="python3 $ROOT/installer/llm_probe.py" ms=() m s tps ok name fast_tps="" rea_tps=""
  for m in "$LLM_MODEL_FAST" "$LLM_MODEL_REASONER" "$LLM_MODEL_BIG"; do
    [ -n "$m" ] || continue
    [[ " ${ms[*]} " == *" $m "* ]] || ms+=("$m")
  done
  msg llm_bench_run "${#ms[@]}"
  while IFS='|' read -r s tps ok name; do
    [ -z "$name" ] && continue
    msg llm_bench_row "$name" "$s" "$tps" "$ok"
    [ "$name" = "$LLM_MODEL_FAST" ] && fast_tps=$tps
    [ "$name" = "$LLM_MODEL_REASONER" ] && rea_tps=$tps
    [ "$ok" = miss ] && wmsg llm_bench_miss "$name"
  done < <(LLM_PROBE_TIMEOUT=180 $probe bench "$LLM_BASE_URL" "${ms[@]}" 2>/dev/null)
  if [[ "$fast_tps" =~ ^[0-9]+$ && "$rea_tps" =~ ^[0-9]+$ ]] && [ "$LLM_MODEL_FAST" != "$LLM_MODEL_REASONER" ] && [ "$fast_tps" -lt "$rea_tps" ]; then
    wmsg llm_bench_swapped "$LLM_MODEL_FAST" "$fast_tps" "$LLM_MODEL_REASONER" "$rea_tps"
  fi
  return 0
}
_forget_saved_quiet() { local v n=(); for v in "${SAVED_VARS[@]}"; do [ "$v" != "$1" ] && n+=("$v"); done; SAVED_VARS=("${n[@]}"); }

# ---- Telegram ----------------------------------------------------------------------------------
sec_telegram() {
  step telegram
  t tg_intro; echo
  ask_secret DFIR_TG_BOT_TOKEN tg_token
  if [ "$DRY_RUN" != 1 ]; then
    local name
    while ! name=$(python3 "$ROOT/installer/telegram.py" me "$DFIR_TG_BOT_TOKEN" 2>/dev/null); do
      interactive || dmsg tg_bad_token
      wmsg tg_bad_token; forget DFIR_TG_BOT_TOKEN; ask_secret DFIR_TG_BOT_TOKEN tg_token
    done
    TG_BOT_NAME=$name; _remember TG_BOT_NAME
    msg tg_bot "$TG_BOT_NAME"
    # the bot already delivers to another server: taking the token here would cut that server off
    local hook
    hook=$(python3 "$ROOT/installer/telegram.py" webhook "$DFIR_TG_BOT_TOKEN" 2>/dev/null || true)
    if [ -n "$hook" ] && [ "$hook" != "${NGROK_URL#https://}" ]; then
      wmsg tg_in_use "$TG_BOT_NAME" "$hook"
      if interactive; then
        forget TG_TAKEOVER; ask_yesno TG_TAKEOVER tg_takeover n
        if [ "$TG_TAKEOVER" != y ]; then forget DFIR_TG_BOT_TOKEN TG_BOT_NAME TG_TAKEOVER; sec_telegram; return; fi
      else
        [ "${TG_TAKEOVER:-n}" = y ] || dmsg tg_in_use_stop
      fi
    fi
    if [ -z "${OWNER_CHAT_ID:-}" ] && interactive; then
      msg tg_wait_start "$TG_BOT_NAME"
      OWNER_CHAT_ID=$(python3 "$ROOT/installer/telegram.py" wait-start "$DFIR_TG_BOT_TOKEN" 180) && msg tg_chat_found "$OWNER_CHAT_ID" || unset OWNER_CHAT_ID
    fi
  fi
  ask OWNER_CHAT_ID chat_id ""
  until [[ "$OWNER_CHAT_ID" =~ ^-?[0-9]{5,15}$ ]]; do
    interactive || dmsg bad_chat_id
    wmsg bad_chat_id; forget OWNER_CHAT_ID; ask OWNER_CHAT_ID chat_id ""
  done

  t tunnel_intro; echo
  ask_choice TUNNEL tunnel ngrok ngrok url
  if [ "$TUNNEL" = ngrok ]; then
    [ -n "${NGROK_AUTHTOKEN:-}" ] || { echo; t ngrok_steps; echo; echo; }
    ask_secret NGROK_AUTHTOKEN ngrok_token
    ask NGROK_URL ngrok_url ""
  else
    ask NGROK_URL proxy_url ""
  fi
  NGROK_URL=${NGROK_URL%/}; [[ "$NGROK_URL" =~ ^https?:// ]] || NGROK_URL="https://$NGROK_URL"
  until [[ "$NGROK_URL" =~ ^https://[A-Za-z0-9.-]+$ ]]; do
    interactive || dmsg bad_https
    wmsg bad_https; forget NGROK_URL; ask NGROK_URL "$([ "$TUNNEL" = ngrok ] && echo ngrok_url || echo proxy_url)" ""
    NGROK_URL=${NGROK_URL%/}
  done
}

# ---- VPN ---------------------------------------------------------------------------------------
sec_vpn() {
  step vpn
  # old answer files: WG_ENABLE=y/n without VPN_KIND
  if [ -z "${VPN_KIND:-}" ] && [ -n "${WG_ENABLE:-}" ]; then
    VPN_KIND=$([ "$WG_ENABLE" = y ] && echo wireguard || echo none)
  fi
  ask_choice VPN_KIND vpn_kind wireguard wireguard zerotier none
  WG_ENABLE=$([ "$VPN_KIND" = wireguard ] && echo y || echo n)
  if [ "$VPN_KIND" = zerotier ]; then
    until [[ "${ZT_NETWORK:-}" =~ ^[0-9a-f]{16}$ ]]; do
      [ -n "${ZT_NETWORK:-}" ] && wmsg zt_bad_id
      forget ZT_NETWORK; ask ZT_NETWORK zt_network ""
      ZT_NETWORK=$(echo "$ZT_NETWORK" | tr 'A-F' 'a-f' | tr -d ' ')
    done
  fi
  if [ "$WG_ENABLE" = y ]; then
    ask WG_ENDPOINT wg_endpoint "$(public_ip_guess)"
    ask WG_PORT wg_port 51820
    ask WG_SUBNET wg_subnet 10.8.0.0/24
  fi
}

# ---- bot language ------------------------------------------------------------------------------
sec_botlang() {
  step botlang
  local c def=${INSTALL_LANG_GEN:-$INSTALL_LANG} opts=("${BOT_LANGS[@]}")
  CHOICE_LABELS=()
  # a generated language is offered first (the bot translates any language with the AI)
  case " ${opts[*]} " in *" $def "*) ;; *) opts=("$def" "${opts[@]}") ;; esac
  for c in "${opts[@]}"; do CHOICE_LABELS[$c]="${BOT_LANG_NATIVE[$c]:-$c} ($c)"; done
  ask_choice BOT_LANG bot_lang "$def" "${opts[@]}"
  CHOICE_LABELS=()
}

# ---- passwords nobody has to type ----------------------------------------------------------------
# ---- accounts: the person's own logins/passwords; Enter = a strong generated one ----------------
ask_password() {   # ask_password VAR KEY   (>= 10 characters, typed twice; empty = generate)
  local var=$1 key=$2 a b
  _remember "$var"; SECRET_VARS+=("$var")
  [ -n "${!var:-}" ] && return 0
  if ! interactive; then gen_secret "$var" 20; GENERATED_PW+=("$var"); return 0; fi
  while :; do
    _read a "  $(t "q_$key") $(t pw_enter_gen) $(t hidden_input): " "$key" -s
    if [ -z "$a" ]; then gen_secret "$var" 20; GENERATED_PW+=("$var"); msg pw_generated; return 0; fi
    if [ ${#a} -lt 10 ]; then wmsg pw_short; continue; fi
    _read b "  $(t pw_again) $(t hidden_input): " "$key" -s
    [ "$a" = "$b" ] && break
    wmsg pw_mismatch
  done
  printf -v "$var" '%s' "$a"
}

sec_accounts() {
  step accounts
  msg accounts_intro
  ask WEBUI_ADMIN_EMAIL webui_email "admin@dfirbot.com"
  ask_password WEBUI_ADMIN_PASSWORD webui_password
  ask PGADMIN_DEFAULT_EMAIL pgadmin_email "${WEBUI_ADMIN_EMAIL:-admin@dfirbot.com}"
  until [[ "$PGADMIN_DEFAULT_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[A-Za-z]{2,}$ ]] && \
        ! [[ "${PGADMIN_DEFAULT_EMAIL##*.}" =~ ^(local|localhost|test|example|invalid|internal|lan|home)$ ]]; do
    interactive || PGADMIN_DEFAULT_EMAIL=admin@dfirbot.com
    interactive || break
    wmsg pgadmin_bad_email; forget PGADMIN_DEFAULT_EMAIL; ask PGADMIN_DEFAULT_EMAIL pgadmin_email "admin@dfirbot.com"
  done
  ask_password PGADMIN_DEFAULT_PASSWORD pgadmin_password
  ask_password POSTGRES_PASSWORD pg_password
}

# machine-to-machine keys: nobody types them
sec_secrets() {
  gen_secret MCP_PG_PASSWORD 24
  gen_secret DFIR_LLM_CTRL_TOKEN 32
  gen_secret DFIR_WINDOWS_AGENT_TOKEN 32
  gen_secret COLLECTOR_SEAL_KEY 40
  gen_secret WEBUI_SECRET_KEY 48
  gen_secret SANDBOX_API_TOKEN 40
}

# ---- review ------------------------------------------------------------------------------------
# pads by characters, not bytes (Cyrillic, CJK)
_row() { printf '  %s%*s %s\n' "$1" $(( ${#1} < 22 ? 22 - ${#1} : 0 )) '' "$2"; }

review_loop() {
  interactive || return 0
  while :; do
    step review
    local llm
    case "$LLM_MODE" in
      local) llm="$(t o_llm_mode_local): $PROFILE" ;;
      server) llm="$(t o_llm_mode_server): $LLM_BASE_URL"
              [ "${LLM_DIRECT:-n}" = y ] || llm+=" ($LLM_MODEL_FAST / $LLM_MODEL_REASONER / $LLM_MODEL_BIG)" ;;
      cloud) llm="$LLM_PROVIDER: $LLM_MODEL_FAST / $LLM_MODEL_REASONER / $LLM_MODEL_BIG" ;;
    esac
    _row "$(t r_lang)" "${LANG_NATIVE[$INSTALL_LANG]}"
    _row "$(t r_llm)" "$llm"
    _row "$(t r_telegram)" "@${TG_BOT_NAME:-?}, chat_id ${OWNER_CHAT_ID}"
    _row "$(t r_webhook)" "$TUNNEL: $NGROK_URL"
    _row "$(t r_vpn)" "$(case "${VPN_KIND:-}" in zerotier) echo "ZeroTier $ZT_NETWORK" ;; *) [ "$WG_ENABLE" = y ] && echo "WireGuard $WG_ENDPOINT:$WG_PORT $WG_SUBNET" || t no ;; esac)"
    _row "$(t r_modules)" "$(modules_summary)"
    _row "$(t r_botlang)" "${BOT_LANG_NATIVE[$BOT_LANG]:-$BOT_LANG}"
    _row "$(t r_accounts)" "Open WebUI: $WEBUI_ADMIN_EMAIL, pgAdmin: $PGADMIN_DEFAULT_EMAIL"
    echo
    forget REVIEW
    ask_choice REVIEW review install install llm telegram vpn modules botlang accounts lang quit
    _forget_saved_quiet REVIEW
    case "$REVIEW" in
      install) return 0 ;;
      llm) forget LLM_MODE PROFILE LLM_PROVIDER LLM_BASE_URL LLM_API_KEY LLM_NEEDS_KEY LLM_MODEL_FAST LLM_MODEL_REASONER LLM_MODEL_BIG CLOUD_OK LLM_DIRECT DRIVER_INSTALL; sec_llm ;;
      telegram) forget DFIR_TG_BOT_TOKEN OWNER_CHAT_ID TUNNEL NGROK_AUTHTOKEN NGROK_URL; sec_telegram ;;
      vpn) forget VPN_KIND ZT_NETWORK WG_ENABLE WG_ENDPOINT WG_PORT WG_SUBNET; sec_vpn ;;
      modules) forget MODULES_OFF; sec_modules ;;
      botlang) forget BOT_LANG; sec_botlang ;;
      accounts) forget WEBUI_ADMIN_EMAIL WEBUI_ADMIN_PASSWORD PGADMIN_DEFAULT_EMAIL PGADMIN_DEFAULT_PASSWORD POSTGRES_PASSWORD; GENERATED_PW=(); sec_accounts ;;
      lang) forget INSTALL_LANG; sec_lang ;;
      quit) save_answers "$ANSWERS"; msg answers_saved "$ANSWERS"; exit 0 ;;
    esac
    save_answers "$ANSWERS"
  done
}

# ---- consent: the person installs third-party software themselves and accepts the terms --------------
sec_consent() {
  _remember ACCEPT_TERMS
  if [ "${ACCEPT_TERMS:-}" = yes ]; then return 0; fi
  step consent
  t consent_software; echo; echo
  t consent_agreement; echo; echo
  if ! interactive; then dmsg consent_needed; fi
  local ans
  while :; do
    read -r -p "  $(t consent_q) " ans || true
    if is_yes "$ans"; then break; fi
    if is_no "$ans"; then msg consent_declined; exit 0; fi
  done
  ACCEPT_TERMS=yes
  mkdir -p "$DESTDIR/state"
  ( umask 077; printf 'accepted=%s\nuser=%s\nhost=%s\nlang=%s\nlicence=AGPL-3.0\n' \
      "$(date -Is)" "${SUDO_USER:-root}" "$(hostname)" "${INSTALL_LANG:-en}" > "$DESTDIR/state/consent.txt" )
}
