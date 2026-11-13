# install.sh: everything that changes the machine. Sourced after all answers are known; `dfir`
# re-uses single steps (apply_llm after `dfir llm`, apply_env after `dfir lang`).
#
# The bot always talks to the LLM at http://172.17.0.1:1234 (docker0). Behind that address sits either
# llama-swap (local GPUs) or llm-router (own server / cloud provider), so switching models later never
# touches the bot's own configuration. The CPU embedder (:5899) always runs here.

# The Windows collector is assembled by DFIR Collector Builder (src/collector_builder): it downloads
# its own tools on the Windows machine, so nothing for it is fetched here.
MODELS="${MODELS_DIR:-/opt/dfir-models}"
HF=https://huggingface.co
LLM_BIND=172.17.0.1
LLM_ENDPOINT="http://$LLM_BIND:1234"

# role -> "repo|file" (checked against the HuggingFace API on 2026-10-22)
declare -A MODEL_SRC=(
  [fast]="ggml-org/gpt-oss-20b-GGUF|gpt-oss-20b-MXFP4.gguf"
  [reasoner]="unsloth/gemma-4-31B-it-GGUF|gemma-4-31B-it-Q4_K_S.gguf"
  [big]="ggml-org/gpt-oss-120b-GGUF|gpt-oss-120b-MXFP4.gguf"
  [embed]="Qwen/Qwen3-Embedding-8B-GGUF|Qwen3-Embedding-8B-Q8_0.gguf"
)
declare -A PROFILE_ROLES=([small]="fast embed" [medium]="fast reasoner embed" [large]="fast reasoner big embed")

fetch() {  # fetch URL DEST: resumable, refuses an empty or HTML answer
  local url=$1 dst=$2
  [ -s "$dst" ] && { msg already_have "$(basename "$dst")"; return 0; }
  run mkdir -p "$(dirname "$dst")"
  msg downloading "$(basename "$dst")"
  run curl -fL --retry 3 -C - -o "$dst.part" "$url" || dmsg download_failed "$url"
  if [ "$DRY_RUN" != 1 ]; then
    head -c 512 "$dst.part" | grep -qi '<html' && dmsg download_html "$url"
    mv "$dst.part" "$dst"
    printf '%s  %s  %s\n' "$(sha256sum "$dst" | cut -d' ' -f1)" "$(basename "$dst")" "$url" >> "$MODELS/SOURCES.txt"
  fi
}

# ---- 1. Docker, and for local GPUs the NVIDIA container runtime -------------------------------
# The project keeps one layout: /srv/dfir. A clone elsewhere gets a link, so every path in compose,
# scripts and units works unchanged. An unrelated /srv/dfir is never touched.
apply_pathlink() {
  [ "$ROOT" = /srv/dfir ] && return 0
  if [ -L /srv/dfir ] && [ "$(readlink -f /srv/dfir)" = "$(readlink -f "$ROOT")" ]; then return 0; fi
  [ -e /srv/dfir ] && dmsg pathlink_busy "$ROOT"
  run mkdir -p /srv
  run ln -s "$ROOT" /srv/dfir
  msg pathlink_done "$ROOT"
}

default_host_ip() { ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}'; }

apply_prereqs() {
  if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    msg installing_docker
    # download first: "curl | sh" hides a failed download (sh runs an empty script and returns 0)
    local i
    for i in 1 2 3; do
      [ "$DRY_RUN" = 1 ] && break
      if curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && env -u DRY_RUN sh /tmp/get-docker.sh >/dev/null && command -v docker >/dev/null; then break; fi
      wmsg docker_retry "$i"; dpkg --configure -a >/dev/null 2>&1 || true; apt-get -qq update >/dev/null 2>&1 || true; sleep 10
    done
    [ "$DRY_RUN" = 1 ] || command -v docker >/dev/null || dmsg docker_install_failed
  fi
  run systemctl enable --now docker >/dev/null 2>&1 || true
  if [ "$LLM_MODE" = local ] && ! docker info 2>/dev/null | grep -qi 'runtimes:.*nvidia'; then
    msg installing_nvidia_ctk
    run install -d -m 0755 /etc/apt/keyrings
    run sh -c 'curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor --yes -o /etc/apt/keyrings/nvidia-ctk.gpg'
    run sh -c "curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/etc/apt/keyrings/nvidia-ctk.gpg] https://#' > /etc/apt/sources.list.d/nvidia-container-toolkit.list"
    run apt-get update -qq
    run apt-get install -y -qq nvidia-container-toolkit
    run nvidia-ctk runtime configure --runtime=docker
    run systemctl restart docker
  fi
}

# ---- 2. collector archive key: without the keypair no archive opens ----------------------------
apply_seal_keys() {
  local keys="$DESTDIR/state/keys"
  if [ "$DRY_RUN" = 1 ]; then msg dry_seal "$keys"; return 0; fi
  SEAL_LINE=$(python3 "$ROOT/installer/seal_key.py" "$keys") || dmsg seal_failed
  export SEAL_LINE
}

# ---- 3. model files ----------------------------------------------------------------------------
apply_models() {
  local r roles="embed"
  [ "$LLM_MODE" = local ] && roles=${PROFILE_ROLES[$PROFILE]}
  for r in $roles; do
    IFS='|' read -r repo file <<< "${MODEL_SRC[$r]}"
    fetch "$HF/$repo/resolve/main/$file" "$MODELS/$file"
  done
}

# ---- 4. the LLM behind 172.17.0.1:1234 ---------------------------------------------------------
apply_llm() {
  local out="$DESTDIR/state/llm" prof=${PROFILE:-small} kind
  run mkdir -p "$out"
  if [ "$LLM_MODE" != local ]; then
    prof=router
    kind=${LLM_KIND:-openai}; [ "$LLM_MODE" = server ] && [ "${LLM_DIRECT:-n}" = y ] && kind=llama-swap
    export LLM_API_KEY="${LLM_API_KEY:-}"
    run python3 "$ROOT/installer/llm_probe.py" router "$out/router.json" "$LLM_BASE_URL" "$kind" \
      "${LLM_MODEL_FAST:-}" "${LLM_MODEL_REASONER:-}" "${LLM_MODEL_BIG:-}" "$LLM_BIND:1234" >/dev/null
  fi
  run python3 "$ROOT/installer/gen_llm_stack.py" "$prof" "$GPU_COUNT" "$GPU_VRAM_MIN_GB" "$MODELS" "$out" "$ROOT/installer/llm_router" >/dev/null
  run docker compose -f "$out/docker-compose.yml" up -d --remove-orphans
  if [ "$LLM_MODE" = local ] && [ "$PROFILE" = large ]; then apply_gpu_clocks
  else run systemctl disable --now dfir-gpu-clocks.service >/dev/null 2>&1 || true; fi
  # containers on compose networks reach docker0's address through the host firewall
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    run ufw allow from 172.16.0.0/12 to any port 1234 proto tcp >/dev/null
    run ufw allow from 172.16.0.0/12 to any port 5899 proto tcp >/dev/null
  fi
  if [ "$DRY_RUN" != 1 ]; then
    local i
    for i in $(seq 1 60); do curl -fs --max-time 3 "$LLM_ENDPOINT/v1/models" >/dev/null && break; sleep 3; done
    curl -fs --max-time 3 "$LLM_ENDPOINT/v1/models" >/dev/null || wmsg llm_not_up "$LLM_ENDPOINT"
  fi
  msg llm_ready "$(llm_describe)"
}

llm_describe() {
  case "$LLM_MODE" in
    local) echo "llama-swap, $PROFILE ($GPU_COUNT GPU)" ;;
    server) echo "$LLM_BASE_URL$([ "${LLM_DIRECT:-n}" = y ] || echo " → $LLM_MODEL_FAST / $LLM_MODEL_REASONER / $LLM_MODEL_BIG")" ;;
    cloud) echo "$LLM_PROVIDER → $LLM_MODEL_FAST / $LLM_MODEL_REASONER / $LLM_MODEL_BIG" ;;
  esac
}

# big-120b splits layers over all cards; without fixed clocks they idle between turns (6-7 tok/s
# instead of 65). A boot-time unit holds them up; `systemctl stop dfir-gpu-clocks` gives them back.
apply_gpu_clocks() {
  local unit=/etc/systemd/system/dfir-gpu-clocks.service
  if [ "$DRY_RUN" = 1 ]; then printf '  [dry-run] %s\n' "$unit"; return 0; fi
  cat > "$unit" <<EOF
[Unit]
Description=DFIR: hold GPU clocks for big-120b (installer/gpu_clocks.sh)
After=nvidia-persistenced.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $DESTDIR/installer/gpu_clocks.sh lock
ExecStop=/bin/bash $DESTDIR/installer/gpu_clocks.sh reset

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now dfir-gpu-clocks.service || wmsg clocks_failed
}

# ---- ZeroTier (no public IP / port forwarding needed; traffic may go through ZeroTier relays = slower)
apply_zerotier() {
  [ "${VPN_KIND:-}" = zerotier ] || return 0
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: zerotier join $ZT_NETWORK"; return 0; }
  if ! command -v zerotier-cli >/dev/null; then
    # official installer: adds ZeroTier's signed apt repository
    curl -fsSL https://install.zerotier.com -o /tmp/zt_install.sh && bash /tmp/zt_install.sh >/dev/null 2>&1 \
      || { wmsg zt_failed; return 0; }
    rm -f /tmp/zt_install.sh
  fi
  systemctl enable --now zerotier-one >/dev/null 2>&1 || true
  zerotier-cli join "$ZT_NETWORK" >/dev/null 2>&1 || { wmsg zt_failed; return 0; }
  msg zt_authorize "$ZT_NETWORK" "$(zerotier-cli info 2>/dev/null | awk '{print $3}')"
  local i
  for i in $(seq 1 60); do   # up to 10 minutes for the owner to tick "Auth" in my.zerotier.com
    ZT_IP=$(zerotier-cli -j listnetworks 2>/dev/null | python3 -c "import json,sys
for n in json.load(sys.stdin):
    if n.get('nwid')==sys.argv[1]:
        a=[x.split('/')[0] for x in n.get('assignedAddresses',[]) if ':' not in x]
        print(a[0] if a else '')" "$ZT_NETWORK" 2>/dev/null)
    [ -n "$ZT_IP" ] && break; sleep 10
  done
  if [ -n "$ZT_IP" ]; then msg zt_up "$ZT_IP"; else wmsg zt_no_ip; fi
  export ZT_IP
}

# ---- 5. .env + placeholders --------------------------------------------------------------------
apply_env() {
  local env="$DESTDIR/.env" vpn_ip
  vpn_ip=$(python3 -c "import ipaddress,sys; print(next(ipaddress.ip_network(sys.argv[1],strict=False).hosts()))" "${WG_SUBNET:-10.8.0.0/24}")
  export DFIR_LLM_HOST=$LLM_BIND DFIR_VPN_BOT_IP=$vpn_ip DFIR_LLM_URL=$LLM_ENDPOINT DFIR_LLM_CTRL_URL="http://$LLM_BIND:8790"
  # llm-gw (LLM door for VPN users) is on the host network: 1234 belongs to llama-swap / llm-router
  export LLMGW_PORT=1240
  export DFIR_VPN_IFACE=wgbot DFIR_VPN_SUBNET=${WG_SUBNET:-10.8.0.0/24} DFIR_VPN_PREFIX="${vpn_ip%.*}."
  local link_ip=$vpn_ip
  [ "${WG_ENABLE:-n}" = y ] || link_ip=$(default_host_ip)
  [ -n "${ZT_IP:-}" ] && link_ip=$ZT_IP
  export DFIR_LINK_IP=$link_ip DFIR_PUBLIC_BASE="http://$link_ip:8080"
  export DFIR_VIEW_BASE="http://$link_ip:8080/view" DFIR_UPLOAD_BASE="http://$link_ip:8080/upload"
  export DFIR_CHAT_BASE="http://$link_ip:8080/chat/" DFIR_WEBUI_BASE="http://$link_ip:8080/"
  export DFIR_AUDIO_BASE_URL="http://$link_ip:8080/audio"
  export DFIR_COLLECTOR_URL="http://$link_ip:8080/collector.exe" DFIR_ADMIN_CHAT_ID=$OWNER_CHAT_ID
  export WEBUI_SECRET_KEY WEBUI_ADMIN_EMAIL WEBUI_ADMIN_PASSWORD PGADMIN_DEFAULT_EMAIL
  export DFIR_BOT_LANG=${BOT_LANG:-en}
  # T9: .env is rewritten here (also by `dfir vpn` / `dfir lang`): keep the switched-off modules for tg-i18n
  export DFIR_MODULES_OFF=${MODULES_OFF:-}
  export POSTGRES_PASSWORD PGADMIN_DEFAULT_PASSWORD MCP_PG_PASSWORD DFIR_LLM_CTRL_TOKEN DFIR_WINDOWS_AGENT_TOKEN DFIR_TG_BOT_TOKEN
  export NGROK_URL NGROK_AUTHTOKEN="${NGROK_AUTHTOKEN:-}" NGROK_HOST="${NGROK_URL#https://}"
  if [ "$DRY_RUN" = 1 ]; then msg dry_env "$(grep -c '=' "$ROOT/.env.example" 2>/dev/null || echo 0)"; return; fi
  ( umask 077
  python3 - "$ROOT/.env.example" "$env" <<'PY'
import os, sys
out, have = [], set()
src = sys.argv[1] if os.path.exists(sys.argv[1]) else None
for line in (open(src, encoding='utf-8') if src else []):
    k = line.split('=', 1)[0].strip()
    if line.startswith('#') or '=' not in line:
        out.append(line.rstrip('\n')); continue
    have.add(k)
    out.append('%s=%s' % (k, os.environ.get(k, '')))
for k in ('DFIR_ADMIN_CHAT_ID', 'DFIR_LLM_HOST', 'DFIR_LLM_URL', 'LLMGW_PORT', 'DFIR_BOT_LANG', 'DFIR_MODULES_OFF',
          'WEBUI_SECRET_KEY', 'WEBUI_ADMIN_EMAIL', 'WEBUI_ADMIN_PASSWORD', 'PGADMIN_DEFAULT_EMAIL',
          'DFIR_VIEW_BASE', 'DFIR_UPLOAD_BASE', 'DFIR_WEBUI_BASE', 'DFIR_AUDIO_BASE_URL', 'DFIR_COLLECTOR_URL'):
    if k not in have:
        out.append('%s=%s' % (k, os.environ[k]))
open(sys.argv[2], 'w', encoding='utf-8').write('\n'.join(out) + '\n')
PY
  )
  msg env_written "$(grep -c '=.' "$env")"
  fill_placeholders
}

# CHANGE_ME_<NAME> in the files listed in CHANGE_ME_FILES.txt -> value; also the original author's
# LLM host address (192.168.100.1) in docker-compose.yml -> docker0, where llama-swap/llm-router listen
fill_placeholders() {
  export CHANGE_ME_COLLECTOR=$COLLECTOR_SEAL_KEY CHANGE_ME_OWNER_CHAT_ID=$OWNER_CHAT_ID CHANGE_ME_OPENAI_API_KEY=sk-local
  [ -f "$DESTDIR/CHANGE_ME_FILES.txt" ] || return 0
  python3 - "$DESTDIR" <<'PY'
import os, re, sys
root = sys.argv[1]
files = [l.strip() for l in open(os.path.join(root, 'CHANGE_ME_FILES.txt'), encoding='utf-8') if l.strip() and not l.startswith('Files')]
files += ['docker-compose.yml']
missing = set()
def val(m):
    # the placeholder can be glued to the following text (e.g. <chat_id>_COURSE in a file name):
    # try the longest known name first, keep the unmatched tail as it was
    name = m.group(0)
    parts = name.split('_')
    for n in range(len(parts), 2, -1):
        cand, tail = '_'.join(parts[:n]), name[len('_'.join(parts[:n])):]
        v = os.environ.get(cand) or os.environ.get(cand[len('CHANGE_ME_'):])
        if v:
            return v + tail
    if name != 'CHANGE_ME_FILES':
        missing.add(name)
    return name
for f in sorted(set(files)):
    p = os.path.join(root, f)
    if not os.path.exists(p):
        continue
    t = open(p, encoding='utf-8').read()
    t2 = re.sub(r'CHANGE_ME_[A-Za-z0-9_]+', val, t)
    if f == 'docker-compose.yml':
        t2 = t2.replace('192.168.100.1', os.environ['DFIR_LLM_HOST'])
        t2 = re.sub(r'(DFIR_EMBED_URL=http://)\S+?(:5899)', r'\g<1>172.17.0.1\2', t2)
    if t2 != t:
        open(p, 'w', encoding='utf-8').write(t2)
if missing:
    print('  ! no value for: ' + ', '.join(sorted(missing)))
PY
}

# ---- 6. WireGuard ------------------------------------------------------------------------------
apply_wireguard() {
  [ "$WG_ENABLE" = y ] || return 0
  run apt-get install -y -qq wireguard qrencode
  local conf=/etc/wireguard/wgbot.conf cdir="$DESTDIR/state/wireguard"
  [ "$DRY_RUN" = 1 ] && { printf '  [dry-run] %s + owner.conf\n' "$conf"; return; }
  mkdir -p "$cdir"; chmod 700 "$cdir"
  if [ ! -f "$conf" ]; then
    local spriv spub cpriv cpub net srv cli
    spriv=$(wg genkey); spub=$(echo "$spriv" | wg pubkey); cpriv=$(wg genkey); cpub=$(echo "$cpriv" | wg pubkey)
    net=${WG_SUBNET%/*}; srv=$DFIR_VPN_BOT_IP; cli="${net%.*}.2"
    ( umask 077
    printf '[Interface]\nAddress = %s/24\nListenPort = %s\nPrivateKey = %s\n\n[Peer]\n# owner\nPublicKey = %s\nAllowedIPs = %s/32\n' \
      "$srv" "$WG_PORT" "$spriv" "$cpub" "$cli" > "$conf"
    printf '[Interface]\nAddress = %s/24\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = %s\nPersistentKeepalive = 25\n' \
      "$cli" "$cpriv" "$spub" "$WG_ENDPOINT" "$WG_PORT" "$WG_SUBNET" > "$cdir/owner.conf" )
  fi
  systemctl enable --now wg-quick@wgbot
  command -v ufw >/dev/null && ufw allow "$WG_PORT"/udp >/dev/null || true
  msg wg_up "$cdir/owner.conf"
  qrencode -t ansiutf8 < "$cdir/owner.conf" || true
}

# ---- 7. the bot's containers -------------------------------------------------------------------
apply_docker() {
  # own reverse proxy instead of ngrok (TUNNEL=url) and switched-off modules (T9): installer/modules.sh
  [ "$DRY_RUN" != 1 ] && write_override
  # data folders the containers write to: Docker would create them as root, and n8n / qdrant /
  # pgadmin run as uid 1000 (n8n then crash-loops on "EACCES /home/node/.n8n/config")
  local d
  for d in services/n8n services/pgadmin services/qdrant var/files var/uploads; do
    run install -d -o 1000 -g 1000 "$ROOT/$d"
  done
  run docker volume create open-webui >/dev/null
  # build our own images first: some services reuse them and must not be pulled from a registry
  run docker compose --project-directory "$DESTDIR" build case-maintainer tools-sidecar
  run docker compose --project-directory "$DESTDIR" build
  # registries drop out now and then (docker.n8n.io refused connections for minutes on 10.11 and
  # one failed image aborted the whole parallel pull): pull first, retry with growing pauses
  local try
  for try in 1 2 3 4 5; do
    run docker compose --project-directory "$DESTDIR" pull --ignore-buildable --quiet && break
    [ "$try" = 5 ] && return 1
    printf '  image download failed (attempt %s of 5), retrying in %s s\n' "$try" $((try * 30))
    sleep $((try * 30))
  done
  run docker compose --project-directory "$DESTDIR" up -d --remove-orphans
}

# n8n starts empty on a new server: create the Telegram credential with the id the workflows
# reference, import the active workflows, switch them on. An existing install is left alone.
apply_n8n() {
  local wf="$ROOT/infra/n8n/workflows.json" ids creds i
  [ -f "$wf" ] || { wmsg n8n_no_workflows; return 0; }
  if [ "$DRY_RUN" = 1 ]; then printf '  [dry-run] n8n: credentials + %s workflows\n' "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$wf")"; return 0; fi
  # wait for the server itself: a CLI call during the first-start migrations knocked n8n over in tests
  for i in $(seq 1 90); do docker exec n8n wget -qO- http://localhost:5678/healthz 2>/dev/null | grep -q ok && break; sleep 5; done
  # an empty n8n still prints a notice line, so look for "id|name" rows, not for any output
  if docker exec n8n n8n list:workflow 2>/dev/null | grep -qE '^[A-Za-z0-9]{16}\|'; then msg n8n_exists; return 0; fi
  creds=$(mktemp); chmod 600 "$creds"
  ids=$(python3 "$ROOT/installer/n8n_creds.py" "$wf" 2>&1 >"$creds" | tail -1)
  # through stdin, so the files belong to n8n's own user (docker cp kept root:600 and n8n could not read it)
  docker exec -i n8n sh -c 'umask 077; cat > /tmp/dfir_creds.json' < "$creds"
  docker exec -i n8n sh -c 'cat > /tmp/dfir_wf.json' < "$wf"
  rm -f "$creds"
  docker exec n8n n8n import:credentials --input=/tmp/dfir_creds.json >/dev/null || dmsg n8n_creds_failed
  docker exec n8n n8n import:workflow --input=/tmp/dfir_wf.json >/dev/null || dmsg n8n_wf_failed
  docker exec n8n rm -f /tmp/dfir_creds.json /tmp/dfir_wf.json
  for i in $ids; do docker exec n8n n8n update:workflow --id="$i" --active=true >/dev/null; done
  docker restart n8n >/dev/null   # activation takes effect on start; the Telegram trigger then sets the webhook
  msg n8n_done "$ids"
}

# ---- read-only database role for the MCP server and the LLM gateway: SELECT on case data, never on
# the tables with users, access rights, audit or chat logs
DBROLE_PRIVATE="access_audit_v1 portal_upload_audit_v1 access_requests_v1 bot_audit_events bot_free_chat_acl bot_free_chat_log bot_free_chat_mirror bot_free_chat_sessions bot_users case_feedback dfir_model_routing_audit dfir_qa_feedback dfir_user_feedback_v1 local_accounts_v1 study_sessions upload_audit_v1 user_access_v1"
apply_dbroles() {
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: dfir_mcp role"; return 0; }
  local i t sql
  # over TCP, not the socket: on the first start postgres runs its init scripts on a socket-only
  # server and then restarts it - a socket check passed and psql was cut off mid-way (T7 test 10.11)
  for i in $(seq 1 90); do docker exec logdb pg_isready -h 127.0.0.1 -U dfir -d dfir_logs >/dev/null 2>&1 && break; sleep 5; done
  sql="DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dfir_mcp') THEN CREATE ROLE dfir_mcp LOGIN; END IF;
END \$\$;
ALTER ROLE dfir_mcp WITH LOGIN PASSWORD :'pw';
GRANT CONNECT ON DATABASE dfir_logs TO dfir_mcp;
GRANT USAGE ON SCHEMA public TO dfir_mcp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dfir_mcp;
ALTER DEFAULT PRIVILEGES FOR ROLE dfir IN SCHEMA public GRANT SELECT ON TABLES TO dfir_mcp;"
  for t in $DBROLE_PRIVATE; do sql+="
DO \$\$ BEGIN IF to_regclass('public.$t') IS NOT NULL THEN EXECUTE 'REVOKE ALL ON public.$t FROM dfir_mcp'; END IF; END \$\$;"; done
  # the SQL is idempotent: a dropped connection is simply tried again
  for i in 1 2 3 4 5 6; do
    printf '%s\n' "$sql" | docker exec -i logdb psql -q -v ON_ERROR_STOP=1 -v pw="$MCP_PG_PASSWORD" -U dfir -d dfir_logs >/dev/null && break
    [ "$i" = 6 ] && dmsg dbroles_failed
    sleep 10
  done
  docker restart llm-gw dfir-mcp >/dev/null 2>&1 || true
  msg dbroles_done
}

# ---- Open WebUI: the browser chat. The admin account comes from the answers (first start only) -----
apply_webui() {
  mod_on webchat || { msg module_skipped "$(t mod_webchat)"; return 0; }
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: open-webui"; return 0; }
  local i
  for i in $(seq 1 60); do
    curl -fs -m 5 http://127.0.0.1:3000/health >/dev/null 2>&1 && break; sleep 5
  done
  curl -fs -m 5 http://127.0.0.1:3000/health >/dev/null 2>&1 || { wmsg webui_not_up; return 0; }
  # uploads are deleted after 24 h (privacy): the worker runs inside the container, hourly
  docker cp "$ROOT/infra/owui/retention.py" open-webui:/app/backend/data/retention.py
  for i in owui-retention.service owui-retention.timer; do install -m 644 "$ROOT/infra/systemd/$i" /etc/systemd/system/; done
  # weekly update check (T2): code, reference databases, Open WebUI, collector tools in ONE message to the
  # owner, only when the set of updates changed; never updates by itself ("dfir update apply" does, with a
  # trial on a separate checkout and a rollback). Replaces the separate Open WebUI version check.
  systemctl disable --now owui-versioncheck.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/owui-versioncheck.service /etc/systemd/system/owui-versioncheck.timer
  for i in dfir-update-check.service dfir-update-check.timer; do
    sed "s#/srv/dfir#$DESTDIR#g" "$ROOT/infra/systemd/$i" > "/etc/systemd/system/$i"; chmod 644 "/etc/systemd/system/$i"
  done
  systemctl daemon-reload; systemctl enable --now owui-retention.timer dfir-update-check.timer >/dev/null 2>&1 || true
  msg webui_done "$(default_host_ip)"
}

# ---- isolated sandbox: every file attached in Open WebUI is unpacked/parsed in a throw-away container
# without network, as nobody, read-only; the collector key never enters it (decrypted in case-maintainer)
apply_sandbox() {
  mod_on webchat || { msg module_skipped "$(t mod_webchat)"; return 0; }
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: sandbox"; return 0; }
  local net gw
  docker build -q -t dfir-sandbox:0.1 "$ROOT/sandbox/image" >/dev/null || { wmsg sandbox_build_failed; return 0; }
  ( umask 077; printf 'SBX_TOKEN=%s\n' "$SANDBOX_API_TOKEN" > "$ROOT/sandbox/api.env" )
  net=$(docker inspect open-webui -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')
  gw=$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
  [ -n "$gw" ] || { wmsg sandbox_no_bridge; return 0; }
  sed -e "s#@ROOT@#$ROOT#g" -e "s#@BIND@#$gw#g" "$ROOT/infra/systemd/dfir-sandbox-api.service" > /etc/systemd/system/dfir-sandbox-api.service
  systemctl daemon-reload; systemctl enable --now dfir-sandbox-api >/dev/null 2>&1
  systemctl restart dfir-sandbox-api
  # only the containers' bridge may call the API
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow from "$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Subnet}}')" to any port 8791 proto tcp >/dev/null
  fi
  docker cp "$ROOT/sandbox/owui_filter_dfir_files.py" open-webui:/tmp/owui_filter_dfir_files.py
  docker cp "$ROOT/sandbox/install_filter.py" open-webui:/tmp/install_filter.py
  docker exec -e SBX_TOKEN="$SANDBOX_API_TOKEN" -e SBX_URL="http://$gw:8791/analyze" open-webui \
    python3 /tmp/install_filter.py >/dev/null 2>&1 || wmsg sandbox_filter_failed
  # built-in tools (knowledge search, view file) make tool-calling models loop instead of reading the
  # sandbox analysis: switch them off for every model
  docker cp "$ROOT/sandbox/owui_models.py" open-webui:/tmp/owui_models.py
  docker exec open-webui python3 /tmp/owui_models.py >/dev/null 2>&1 || wmsg sandbox_filter_failed
  docker exec open-webui rm -f /tmp/owui_filter_dfir_files.py /tmp/install_filter.py /tmp/owui_models.py
  msg sandbox_done
}

# ---- web portal extras: personal sandboxes (internet only via an allow-list proxy), portal filters
# (model dispatcher, assistant identity, per-user profile, live model status, skills), nightly jobs
# (model sync, skill learning, backup, profiles) and the 12-min self-check with safe self-repair
apply_portal() {
  mod_on webchat || { msg module_skipped "$(t mod_webchat)"; return 0; }
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: portal"; return 0; }
  local net gw llm u f tmp
  net=$(docker inspect open-webui -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')
  gw=$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
  [ -n "$gw" ] || { wmsg portal_failed "network"; return 0; }
  llm=${DFIR_LLM_HOST:-172.17.0.1}
  docker network inspect usandbox-net >/dev/null 2>&1 || \
    docker network create --subnet 172.30.0.0/16 --gateway 172.30.0.1 usandbox-net >/dev/null
  docker build -q -t usandbox:0.1 "$ROOT/infra/sandbox" >/dev/null || { wmsg portal_failed "usandbox image"; return 0; }
  run apt-get install -y -qq tinyproxy
  install -m 644 "$ROOT/infra/sandbox/tinyproxy.conf" /etc/tinyproxy/tinyproxy.conf
  install -m 644 "$ROOT/infra/sandbox/allow.txt" /etc/tinyproxy/allow.txt
  systemctl enable tinyproxy >/dev/null 2>&1 || true; systemctl restart tinyproxy
  mkdir -p "$DESTDIR/state" "$DESTDIR/user_envs" "$DESTDIR/backups/owui"
  [ -s "$DESTDIR/state/usandbox_token" ] || ( umask 077; openssl rand -hex 24 > "$DESTDIR/state/usandbox_token" )
  chmod 755 "$ROOT/infra/sandbox/firewall.sh"
  for u in "$ROOT"/infra/systemd/portal/*; do
    sed -e "s#@ROOT@#$DESTDIR#g" -e "s#@GW@#$gw#g" -e "s#@LLM@#$llm#g" "$u" > "/etc/systemd/system/$(basename "$u")"
    chmod 644 "/etc/systemd/system/$(basename "$u")"
  done
  systemctl daemon-reload
  systemctl enable dfir-usandbox-gw >/dev/null 2>&1; systemctl restart dfir-usandbox-gw || wmsg portal_failed "dfir-usandbox-gw"
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow from "$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Subnet}}')" to any port 8796 proto tcp >/dev/null
  fi
  # Open WebUI: functions (the model server address of THIS install) + the sandbox tool server
  tmp=$(mktemp -d)
  for f in owui_filter_model_router.py owui_filter_identity_guard.py owui_filter_user_profile.py \
           owui_filter_live_status.py owui_filter_skills.py owui_pipe_storage.py; do
    sed "s#192\.168\.100\.1#$llm#g" "$ROOT/sandbox/$f" > "$tmp/$f"
  done
  docker exec open-webui rm -rf /tmp/portal_fn; docker cp "$tmp" open-webui:/tmp/portal_fn; rm -rf "$tmp"
  docker cp "$ROOT/sandbox/owui_provision.py" open-webui:/tmp/owui_provision.py
  docker exec -e USBX_URL="http://$gw:8796" -e USBX_TOKEN="$(cat "$DESTDIR/state/usandbox_token")" open-webui \
    python3 /tmp/owui_provision.py >/dev/null 2>&1 || wmsg portal_failed "Open WebUI functions"
  docker exec open-webui rm -rf /tmp/portal_fn /tmp/owui_provision.py
  python3 "$ROOT/tools/skills_seed.py" >/dev/null 2>&1 || true
  python3 "$ROOT/tools/sync_models.py" >/dev/null 2>&1 || true
  systemctl enable --now dfir-sync-models.timer dfir-skill-miner.timer dfir-owui-backup.timer \
    dfir-profiles.timer dfir-portal-qa.timer >/dev/null 2>&1 || true
  msg portal_done
}

# ---- reference databases (hash/path known-good, known-bad) from their official sources ----------
# infra/sources/sources.json: official URL, how the version is found, how a download is verified.
# Verified before use, logged in state/sources/provenance.jsonl. MalwareBazaar needs a free abuse.ch
# Auth-Key (ABUSECH_AUTH_KEY in .env); without it that one source is skipped, the rest still install.
apply_sources() {
  mod_on hashdb || { msg module_skipped "$(t mod_hashdb)"; return 0; }
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: reference databases"; return 0; }
  msg sources_start
  if DFIR_ROOT="$ROOT" timeout 7200 python3 "$ROOT/tools/sources/dfir_sources.py" update; then msg sources_done
  else wmsg sources_failed; fi
  DFIR_ROOT="$ROOT" python3 "$ROOT/tools/sources/dfir_sources.py" check | grep -q needs_key && wmsg sources_need_key
  return 0
}

# ---- a language picked as "Other": the person's own AI writes installer/i18n/<code>.sh now
apply_genlang() {
  [ -n "${INSTALL_LANG_GEN:-}" ] || return 0
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: translate the installer into $INSTALL_LANG_GEN"; return 0; }
  [ -f "$ROOT/installer/i18n/$INSTALL_LANG_GEN.sh" ] || \
    LLM="${LLM_ENDPOINT%/}" MODEL=gpt-small-20b timeout 3600 python3 "$ROOT/installer/i18n/gen_catalog.py" "$INSTALL_LANG_GEN" \
      || { wmsg genlang_failed "$INSTALL_LANG_GEN" "$INSTALL_LANG_GEN"; return 0; }
  INSTALL_LANG=$INSTALL_LANG_GEN; save_answers "$ANSWERS"
  load_lang "$INSTALL_LANG"
  msg genlang_done "$INSTALL_LANG"
}

# ---- 8. `dfir` command -------------------------------------------------------------------------
apply_cli() {
  run ln -sf "$ROOT/installer/dfirctl.sh" /usr/local/bin/dfir
  run chmod +x "$ROOT/installer/dfirctl.sh"
  apply_selfcheck
}

# Self-check after every boot (power cuts: zero-filled files, inactive workflows) and every morning
# at 08:10, silent when green. Reports go to the owner chat only. tools/selfcheck/dfir_selfcheck.py
apply_selfcheck() {
  local u
  [ "$DRY_RUN" = 1 ] && { say "DRY_RUN: selfcheck units"; return 0; }
  install -d -m 700 /etc/dfir
  ( umask 077; printf 'TG_TOKEN=%s\nADMIN_CHAT=%s\nDFIR_ROOT=%s\n' \
      "$DFIR_TG_BOT_TOKEN" "$OWNER_CHAT_ID" "$ROOT" > /etc/dfir/selfcheck.env )
  for u in dfir-selfcheck.service dfir-selfcheck-daily.service dfir-selfcheck-daily.timer; do
    sed "s#/srv/dfir#$ROOT#g" "$ROOT/tools/selfcheck/system/$u" > "/etc/systemd/system/$u"
  done
  systemctl daemon-reload
  systemctl enable dfir-selfcheck.service >/dev/null 2>&1 || true
  systemctl enable --now dfir-selfcheck-daily.timer >/dev/null 2>&1 || wmsg selfcheck_failed
}

# ---- 9. end-to-end proof: the bot's own token reaches the person's own chat --------------------
apply_notify() {
  [ "$DRY_RUN" = 1 ] && return 0
  python3 "$ROOT/installer/telegram.py" send "$DFIR_TG_BOT_TOKEN" "$OWNER_CHAT_ID" "$(t tg_done_msg "$(hostname)")" \
    || wmsg tg_send_failed
}

APPLY_STEPS=(pathlink prereqs seal_keys models llm zerotier env wireguard modules docker dbroles n8n webui sandbox portal sources cli genlang notify)
apply_all() {
  local i=0 s
  for s in "${APPLY_STEPS[@]}"; do
    i=$((i + 1)); STEP_NAME=a_$s
    printf '\n%s[%d/%d] %s%s\n' "$C_B" "$i" "${#APPLY_STEPS[@]}" "$(t "step_a_$s")" "$C_0"
    "apply_$s"
  done
}

summary() {
  msg sum_llm "$(llm_describe)"
  msg sum_owner "$OWNER_CHAT_ID"
  [ "$WG_ENABLE" = y ] && msg sum_vpn "$DFIR_VPN_BOT_IP" "$DESTDIR/state/wireguard/owner.conf"
  msg sum_builder
  if [ -n "${SEAL_LINE:-}" ]; then
    msg sum_seal
    printf '    %s\n' "$SEAL_LINE"
    wmsg sum_backup "$DESTDIR/state/keys/collector_private.pem"
  fi
  local ip; ip=$(default_host_ip)
  ( umask 077; {
      echo "# DFIR Bot logins ($(date '+%F %T')). Keep this file private."
      mod_on webchat && echo "Open WebUI   http://$ip:3000   $WEBUI_ADMIN_EMAIL   $WEBUI_ADMIN_PASSWORD"
      echo "pgAdmin      (see docker-compose.yml)  $PGADMIN_DEFAULT_EMAIL   $PGADMIN_DEFAULT_PASSWORD"
      echo "PostgreSQL   user dfir   $POSTGRES_PASSWORD"
    } > "$DESTDIR/state/credentials.txt" )
  banner "$(t sum_accounts)"
  mod_on webchat && _row "Open WebUI" "http://$ip:3000  —  $WEBUI_ADMIN_EMAIL"
  _row "pgAdmin" "$PGADMIN_DEFAULT_EMAIL"
  local v
  for v in "${GENERATED_PW[@]}"; do _row "$v" "${!v}"; done
  msg sum_creds_file "$DESTDIR/state/credentials.txt"
  # a copy in the home of the person who ran sudo, readable only by them
  local home_user=${SUDO_USER:-root} home_dir copy
  home_dir=$(getent passwd "$home_user" | cut -d: -f6); home_dir=${home_dir:-/root}
  copy="$home_dir/DFIR_VAO_credentials.txt"
  if [ "$DRY_RUN" != 1 ]; then
    install -m 600 -o "$home_user" "$DESTDIR/state/credentials.txt" "$copy" 2>/dev/null || cp "$DESTDIR/state/credentials.txt" "$copy"
  fi
  banner "$(t creds_save_title)"
  msg creds_save_where "$copy"
  wmsg creds_save_hint
  if interactive; then
    local ans
    while :; do
      read -r -p "  $(t creds_save_confirm) " ans || true
      is_yes "$ans" && break
    done
  fi
  msg sum_secrets
  msg sum_cli
}
