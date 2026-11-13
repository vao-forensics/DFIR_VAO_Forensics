#!/bin/bash
# Boot notification. 2026-09-13: ZeroTier is retired as the access path — the message now
# reports the addresses that actually work: the lab-LAN / host route for the owner and the
# WireGuard address users reach the bot on. The web terminal is bound to the lab LAN
# (/etc/default/ttyd), so publishing it on a ZeroTier address was also simply wrong.
TG_TOKEN="CHANGE_ME_DFIR_TG_BOT_TOKEN"
ADMIN_CHAT="CHANGE_ME_OWNER_CHAT_ID"

HOST_IP=$(ip -4 addr show ens33 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)   # VMnet to the Windows host
LAN_IP=$(ip -4 addr show ens32 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)    # lab LAN
WG_USERS=$(ip -4 addr show wgbot 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)  # users' VPN
WG_ADMIN=$(ip -4 addr show dfir 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)   # service tunnel
CONT=$(docker ps -q 2>/dev/null | wc -l)

MSG="🟢 <b>DFIR VM онлайн</b>

🔐 VPN користувачів: <code>${WG_USERS:-немає}</code>  (вхід для людей: http://${WG_USERS:-CHANGE_ME_DFIR_LINK_IP}:8080)
🛠 Службовий тунель: <code>${WG_ADMIN:-немає}</code>
🖥 Хост/лаб: <code>${HOST_IP:-?}</code> / <code>${LAN_IP:-?}</code>

🔗 <b>Веб-термінал:</b>
<code>http://${HOST_IP:-192.168.100.128}:7681</code>
🌐 <b>Панель VPN:</b>
<code>http://${HOST_IP:-192.168.100.128}:8123</code>

Контейнерів піднято: ${CONT}. Решта стартує автоматично."

curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -H "Content-Type: application/json" \
  -d "{\"chat_id\":\"${ADMIN_CHAT}\",\"text\":\"${MSG}\",\"parse_mode\":\"HTML\"}" >/dev/null
