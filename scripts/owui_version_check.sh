#!/usr/bin/env bash
# Checks the latest Open WebUI release vs the running version and NOTIFIES the
# owner (bot chat) when a newer one exists. Does NOT auto-apply. Token is read
# from the VM .env at send time so no secret lives in this file.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # install folder (scripts/..), not a fixed path
set -euo pipefail
cur=$(docker exec open-webui sh -c "grep -m1 '\"version\"' /app/package.json" 2>/dev/null | sed -E 's/.*"version":\s*"([^"]+)".*/\1/')
latest=$(wget -qO- https://api.github.com/repos/open-webui/open-webui/releases/latest 2>/dev/null | sed -nE 's/.*"tag_name":\s*"v?([^"]+)".*/\1/p' | head -1)
[ -n "$cur" ] && [ -n "$latest" ] || { echo "version check: could not read (cur=$cur latest=$latest)"; exit 0; }
if [ "$cur" != "$latest" ]; then
  msg="DFIR Open WebUI: new version $latest is available (you have $cur). Nothing was changed. To update with a backup and automatic rollback: sudo $ROOT/scripts/owui_update.sh $latest"
  tok=$(grep -m1 '^DFIR_TG_BOT_TOKEN=' $ROOT/.env 2>/dev/null | cut -d= -f2-)
  if [ -n "$tok" ]; then
    wget -qO- --post-data="chat_id=CHANGE_ME_OWNER_CHAT_ID&text=$msg" "https://api.telegram.org/bot${tok}/sendMessage" >/dev/null 2>&1 || true
  fi
  echo "NEW: $latest (current $cur) — owner notified"
else
  echo "up to date: $cur"
fi
