#!/bin/bash
# Tell the owner BEFORE the disk fills, and clean up without being asked.
#
# The upload gate refuses a file that would not fit, which protects the case library. It
# does not protect against the slow version: uploads, results, audio and translations
# accumulating until Postgres has nowhere to write. That failure is silent and total -
# every container keeps running and nothing works.
set -u
ROOT=/srv/dfir
WARN_GB=${WARN_GB:-40}
CRIT_GB=${CRIT_GB:-20}
STATE=/var/lib/dfir_disk_watch.last
TOKEN_FILE=/root/.dfir_bot_token
CHAT=CHANGE_ME_OWNER_CHAT_ID

free_gb=$(df --output=avail -BG "$ROOT" | tail -1 | tr -dc '0-9')
used_pct=$(df --output=pcent "$ROOT" | tail -1 | tr -dc '0-9')

send() {
  [ -f "$TOKEN_FILE" ] || return 0
  curl -s -m 15 -o /dev/null \
    "https://api.telegram.org/bot$(cat "$TOKEN_FILE")/sendMessage" \
    --data-urlencode "chat_id=$CHAT" --data-urlencode "text=$1" >/dev/null 2>&1
}

# Do not repeat the same warning every ten minutes; say it once per level per day.
level=ok
[ "$free_gb" -le "$WARN_GB" ] && level=warn
[ "$free_gb" -le "$CRIT_GB" ] && level=crit
last=$(cat "$STATE" 2>/dev/null || echo "ok 0")
last_level=${last%% *}
last_day=${last##* }
today=$(date +%j)

if [ "$level" != "ok" ] && { [ "$level" != "$last_level" ] || [ "$today" != "$last_day" ]; }; then
  if [ "$level" = "crit" ]; then
    # At this point cleaning is not optional: run the existing retention job now rather
    # than waiting for its 03:00 slot, then report what is left.
    "$ROOT/scripts/cleanup_uploads.sh" --apply >> "$ROOT/maintenance.log" 2>&1
    after=$(df --output=avail -BG "$ROOT" | tail -1 | tr -dc '0-9')
    send "🔴 Диск майже заповнений: вільно ${free_gb} ГБ (${used_pct}% зайнято).
Прибирання запущено достроково — після нього вільно ${after} ГБ.
Нові завантаження вже відхиляються з поясненням, щоб база не впала."
  else
    send "🟠 Диск заповнюється: вільно ${free_gb} ГБ (${used_pct}% зайнято).
Поки що все працює. Варто подивитись, що можна прибрати:
  du -sh $ROOT/uploads $ROOT/audio_results $ROOT/translate_output $ROOT/cases"
  fi
  echo "$level $today" > "$STATE"
fi

[ "$level" = "ok" ] && echo "ok $today" > "$STATE"
echo "free=${free_gb}G used=${used_pct}% level=${level}"
