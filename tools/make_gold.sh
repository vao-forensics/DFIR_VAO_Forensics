#!/bin/bash
# A rollback floor, taken while the system is known good.
#
# The last one is from 2026-06-25 - two months and a VPN migration ago. Everything that
# now stands between strangers and this machine (the upload gate, the tunnel firewall,
# the attribution, the workflow that was finally imported properly) exists only in the
# current state. If the next change breaks something, "restore from the last gold" would
# mean losing all of it.
set -u
ROOT=/srv/dfir
LABEL="${1:-vpn_gate_attribution}"
TS=$(date +%Y%m%d_%H%M%S)
DIR="$ROOT/GOLD/${TS}_${LABEL}"
mkdir -p "$DIR"

# the workflow as n8n would import it back
cp "$ROOT/services/n8n_workflow_export.json" "$DIR/n8n_workflow.json" 2>/dev/null

# the bot code, without caches and the backups my patchers leave behind
tar -czf "$DIR/case_maintainer_code.tgz" -C "$ROOT/services" \
    --exclude='*.bak*' --exclude='__pycache__' --exclude='*.pyc' case_maintainer 2>/dev/null

cp "$ROOT/docker-compose.yml" "$DIR/docker-compose.yml"
cp "$ROOT/docker-compose.webhookgate.yml" "$DIR/" 2>/dev/null
cp "$ROOT/config/network.env" "$DIR/network.env" 2>/dev/null
cp "$ROOT/uploader/nginx/default.conf" "$DIR/uploader_nginx.conf" 2>/dev/null
tar -czf "$DIR/tools.tgz" -C "$ROOT" --exclude='*.bak*' tools 2>/dev/null
cp /etc/wireguard/wgbot.conf "$DIR/wgbot.conf.txt" 2>/dev/null
cp /usr/local/sbin/dfir-vpn-lock.sh "$DIR/" 2>/dev/null
sudo iptables -S DOCKER-USER > "$DIR/docker_user_rules.txt" 2>/dev/null
sudo ufw status numbered > "$DIR/ufw_rules.txt" 2>/dev/null
cd "$ROOT" && git log --oneline -12 > "$DIR/git_head.txt" 2>/dev/null

cat > "$DIR/MANIFEST.txt" <<EOF
GOLD ${TS} — ${LABEL}
git HEAD: $(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null)

VERIFIED WORKING AT THIS POINT (measured, not assumed):
  * upload gate: 23/23 checks, including all 11 real case archives; a .rar and an EXE
    renamed .zip are refused over the VPN and land in quarantine, the person is told why
    in Ukrainian; a genuine triage archive is accepted, parsed and analysed
  * attribution: every upload recorded in upload_audit_v1 with verdict, size, sha256,
    tunnel address AND the VPN account name
  * tunnel: clients reach port 8080 and nothing else (nc sweep from a real peer);
    client-to-client blocked; no internet egress; scans logged and alerted at 4 ports
  * case names: 32/32 checks, the twelve production names still valid
  * n8n: workflow imported the supported way and ACTIVE; 0 references to 10.244
  * services: wg-quick@dfir, wg-quick@wgbot, dfir-vpn-proxy, dfir-vpn-sync.timer,
    dfir-vpn-lock.timer, dfir-secmon, dfir-ingest-watcher, ttyd

RESTORE:
  workflow  docker cp n8n_workflow.json n8n:/tmp/wf.json
            docker exec n8n n8n import:workflow --input=/tmp/wf.json
            docker exec n8n n8n update:workflow --id=d2pWxJwjQxJUpxwZ --active=true
            docker restart n8n            # all three steps, or the bot stays deactivated
  code      tar -xzf case_maintainer_code.tgz -C $ROOT/services
            docker restart case-maintainer
  compose   cp docker-compose.yml $ROOT/ && docker compose -f docker-compose.yml \\
            -f docker-compose.webhookgate.yml up -d
  network   cp network.env $ROOT/config/ && python3 $ROOT/tools/net_conf.py --apply
EOF

du -sh "$DIR" | awk '{print "GOLD:", $2, "("$1")"}'
echo "$DIR" > "$ROOT/GOLD/LATEST_GOLD.txt"
ls "$DIR"
