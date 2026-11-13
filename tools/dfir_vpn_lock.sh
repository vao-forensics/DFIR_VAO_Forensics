#!/bin/bash
# Keep the VPN users limited to port 8080 even after a Docker daemon restart.
#
# The rules normally come from wgbot.conf PostUp, but Docker rebuilds its chains when the
# daemon restarts and the DOCKER-USER content can be lost with them. Losing them silently
# re-opens the whole container stack (3000, 5678, 1080, 8092) to every VPN client, so the
# invariant is re-asserted here instead of being assumed. Idempotent by -C.
set -u
# The interface and the open port come from config/network.env - the same file
# the bot, the sync job and the monitor read. Fall back to the current values
# so a missing config can never leave the tunnel wide open.
CONF=/srv/dfir/state/config/network.env
IF=$(sed -n "s/^VPN_IFACE=//p" "$CONF" 2>/dev/null | head -1)
PORT=$(sed -n "s/^BOT_PUBLIC_PORT=//p" "$CONF" 2>/dev/null | head -1)
[ -n "$IF" ] || IF=wgbot
[ -n "$PORT" ] || PORT=8080
ip link show "$IF" >/dev/null 2>&1 || exit 0
iptables -C DOCKER-USER -i "$IF" -j DROP 2>/dev/null \
  || iptables -I DOCKER-USER -i "$IF" -j DROP
# Refused packets are evidence: log them (rate-limited so a sweep cannot flood
# the journal) with a prefix secmon can recognise.
iptables -C DOCKER-USER -i "$IF" -m limit --limit 20/min --limit-burst 40 \
  -j LOG --log-prefix "VPN-DROP " --log-level 4 2>/dev/null \
  || iptables -I DOCKER-USER 2 -i "$IF" -m limit --limit 20/min --limit-burst 40 \
     -j LOG --log-prefix "VPN-DROP " --log-level 4
iptables -C DOCKER-USER -i "$IF" -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN 2>/dev/null \
  || iptables -I DOCKER-USER -i "$IF" -p tcp -m conntrack --ctorigdstport "$PORT" -j RETURN
