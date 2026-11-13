#!/bin/bash
# Isolation of the personal sandboxes (network usandbox-net 172.30.0.0/16):
#  - no direct way out: all forwarded traffic from the sandboxes is dropped;
#  - internet only through the allow-list proxy on the host (172.30.0.1:3128, tinyproxy) - INPUT, not FORWARD;
#  - internal networks (cases 172.18/16, VPN 10/8, LAN 192.168/16) are unreachable as well.
# Any iptables failure stops the gateway (systemd ExecStartPre): no rules = no sandboxes.
set -e
SB=172.30.0.0/16
iptables -L DOCKER-USER -n >/dev/null 2>&1 || iptables -N DOCKER-USER
for NET in 172.16.0.0/12 10.0.0.0/8 192.168.0.0/16; do
  iptables -C DOCKER-USER -s $SB -d $NET -j DROP 2>/dev/null || iptables -I DOCKER-USER -s $SB -d $NET -j DROP
done
# -I, not -A: the chain ends with RETURN
iptables -C DOCKER-USER -s $SB -j DROP 2>/dev/null || iptables -I DOCKER-USER -s $SB -j DROP
# the proxy on the host accepts the sandboxes only
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw status | grep -q "3128/tcp.*ALLOW.*172.30.0.0/16" || ufw allow from $SB to any port 3128 proto tcp >/dev/null
fi
exit 0
