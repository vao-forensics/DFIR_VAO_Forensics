#!/bin/bash
# Runs unattended after the 120B batch finishes:
#   1. waits for BATCH120-DONE
#   2. recreates case-maintainer so the chat fast path actually switches to the 120B
#      (a plain restart keeps the OLD env - compose env is baked in at container creation)
#   3. re-runs the comparison over all 15 reports
#   4. messages the owner with the result
# Safe to run twice; safe to kill (it only reads until the batch is done).
LOG=/tmp/finalize_120b.log
: > "$LOG"
say() { echo "$(date +%H:%M) $*" >> "$LOG"; }

say "waiting for the batch to finish"
for i in $(seq 720); do
  grep -q "BATCH120-DONE" /tmp/llm_120b.log 2>/dev/null && break
  sleep 30
done
grep -q "BATCH120-DONE" /tmp/llm_120b.log 2>/dev/null || { say "batch did not finish in 6h, stopping"; exit 1; }
say "batch done, reports: $(ls /srv/dfir/state/truth/llm_120b/*.txt 2>/dev/null | wc -l)/15"

# no DFIR job may be running when we recreate the container
for i in $(seq 60); do
  r=$(docker exec logdb psql -U dfir -d dfir_logs -tAc "select count(*) from dfir_run_jobs_v2 where status='running'" 2>/dev/null)
  [ "$r" = "0" ] && break
  sleep 20
done

cd /srv/dfir || exit 1
say "recreating case-maintainer to apply DFIR_FAST_MODEL=big-120b"
docker compose up -d case-maintainer >> "$LOG" 2>&1
sleep 20
say "models now: $(docker exec case-maintainer env | grep -E 'DFIR_(FAST|LLM|EMBED)_MODEL=' | sort | tr '\n' ' ')"

say "running the final comparison"
docker exec -e PYTHONDONTWRITEBYTECODE=1 case-maintainer python /app/analysis/truth/llm_compare_120b.py >> "$LOG" 2>&1
RES=$(grep -E "^COMPARE:" "$LOG" | tail -1)
say "RESULT: $RES"

TOK=$(grep -o 'TG_TOKEN="[^"]*' /usr/local/bin/dfir-boot-notify.sh | cut -d'"' -f2)
MSG=$(printf '🧪 Прогін 120b завершено.\n\n%s\n\nЗвіти: state/truth/llm_120b/\nЧат переведено на 120b.\nВідкат: python3 /srv/dfir/tools/switch_llm.py revert' "$RES")
curl -s -X POST "https://api.telegram.org/bot${TOK}/sendMessage" -H 'Content-Type: application/json' \
     -d "$(python3 -c "import json,sys; print(json.dumps({'chat_id':'CHANGE_ME_OWNER_CHAT_ID','text':sys.argv[1]}))" "$MSG")" >/dev/null
say "FINALIZE-DONE"
