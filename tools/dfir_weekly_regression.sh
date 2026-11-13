#!/bin/bash
# Weekly acceptance regression of the DFIR engine — the owner hears about it ONLY when something is red.
#   1. truth_check --render   : deterministic layer + page 1 on every approved case (no LLM calls)
#   2. llm_compare            : truth/analyst -> detector -> the last LLM report of each case (no LLM calls)
#   3. every *_guard.py       : code-shape guards
# Log: /srv/dfir/state/truth/weekly/<date>.log ; alert -> owner chat on any FAIL, silent when green.
set -u
TOKEN_FILE=/root/.dfir_bot_token
CHAT=CHANGE_ME_OWNER_CHAT_ID
OUT=/srv/dfir/state/truth/weekly
mkdir -p "$OUT"
D=$(date +%F)
LOG="$OUT/$D.log"
: > "$LOG"
X() { docker exec -e PYTHONDONTWRITEBYTECODE=1 case-maintainer "$@"; }
tg() {
  [ -f "$TOKEN_FILE" ] || return 0
  curl -s -m 15 -o /dev/null "https://api.telegram.org/bot$(cat "$TOKEN_FILE")/sendMessage" \
    --data-urlencode "chat_id=$CHAT" --data-urlencode "text=$1" >/dev/null 2>&1
}
# a running DFIR job must not compete with the regression: wait up to 2h
for i in $(seq 240); do
  n=$(docker exec logdb psql -U dfir -d dfir_logs -tAc "select count(*) from dfir_run_jobs_v2 where status in ('running','queued')" 2>/dev/null || echo 0)
  [ "${n:-0}" = "0" ] && break
  sleep 30
done
echo "== truth --render ($D)" >> "$LOG"
X python /app/analysis/truth/truth_check.py --render --out "/data/state/truth/weekly/scores_$D.json" >> "$LOG" 2>&1
TRUTH=$(grep -E '^TRUTH:' "$LOG" | tail -1 | grep -oE '[0-9]+/[0-9]+' | head -1)
echo "== llm_compare" >> "$LOG"
X python /app/analysis/truth/llm_compare.py >> "$LOG" 2>&1
CMP=$(grep -E '^COMPARE:' "$LOG" | tail -1 | grep -oE '[0-9]+/[0-9]+' | head -1)
# Завантаження без жодного рядка доказів: або забутий аналіз, або файл потрапив
# у справу помилково. Дешево, тому перевіряємо щоразу.
echo "== завантаження без аналізу" >> "$LOG"
docker exec case-maintainer python /app/analysis/orphan_uploads.py >> "$LOG" 2>&1

echo "== завантаження, що не доїхали" >> "$LOG"
python3 /srv/dfir/tools/tusd_reconcile.py >> "$LOG" 2>&1

echo "== guards" >> "$LOG"
BAD_GUARDS=""
for g in $(docker exec case-maintainer sh -c 'ls /app/analysis/guards/*_guard.py' 2>/dev/null); do
  name=$(basename "$g" .py)
  line=$(X python "$g" 2>&1 | grep -E 'passed|failed' | tail -1)
  echo "$name :: $line" >> "$LOG"
  echo "$line" | grep -qE ' 0 failed' || BAD_GUARDS="$BAD_GUARDS $name"
done
ok=1
[ -n "$TRUTH" ] && [ "${TRUTH%/*}" = "${TRUTH#*/}" ] || ok=0
[ -n "$CMP" ] && [ "${CMP%/*}" = "${CMP#*/}" ] || ok=0
[ -z "$BAD_GUARDS" ] || ok=0
echo "== RESULT truth=$TRUTH compare=$CMP bad_guards=[$BAD_GUARDS] ok=$ok" >> "$LOG"
if [ "$ok" != "1" ]; then
  tg "🔴 Тижнева регресія DFIR ($D): еталон $TRUTH, LLM-compare $CMP, червоні гарди:${BAD_GUARDS:- немає}. Лог: state/truth/weekly/$D.log"
fi
# keep 12 weeks
ls -1t "$OUT"/*.log 2>/dev/null | tail -n +13 | xargs -r rm -f
