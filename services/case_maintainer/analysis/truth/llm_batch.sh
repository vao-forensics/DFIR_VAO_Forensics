#!/bin/bash
# Full LLM regression: run the production DFIR job (chat_id=None -> no delivery) for every
# approved case, one at a time, and keep the final report as the baseline.
# Logs: /tmp/llm_batch.log ; reports: /srv/dfir/state/truth/llm_baseline/<case>.txt
OUT=/srv/dfir/state/truth/llm_baseline
mkdir -p "$OUT"
Q() { docker exec logdb psql -U dfir -d dfir_logs -tA -F'|' -c "$1" 2>/dev/null; }
CASES="case_02 case_07 case_29 case_04 case_36 case_30 case_23 case_34 case_32 case_31 case_33 case_38 case_08 case_25 case_27"
for K in $CASES; do
  s=$(date +%s)
  resp=$(docker exec case-maintainer python -c "
import os, json, urllib.request
tok = os.environ.get('MAINTAINER_TOKEN') or os.environ.get('TOKEN') or ''
req = urllib.request.Request('http://127.0.0.1:8787/dfir-start', data=json.dumps({'case_key':'$K','chat_id':None}).encode(), headers={'Content-Type':'application/json','X-Maintainer-Token':tok}, method='POST')
try:
    print(urllib.request.urlopen(req, timeout=60).read().decode()[:200])
except Exception as e:
    print('ERR', e)
" 2>&1 | tail -1)
  jid=$(echo "$resp" | grep -oE '"job_id":"[^"]+"' | cut -d'"' -f4)
  echo "$(date +%H:%M) START $K job=$jid :: $(echo "$resp" | cut -c1-120)" >> /tmp/llm_batch.log
  if [ -z "$jid" ]; then continue; fi
  for i in $(seq 480); do
    st=$(Q "select status from dfir_run_jobs_v2 where job_id='$jid'")
    case "$st" in completed|failed|error) break;; esac
    sleep 15
  done
  f=$(Q "select coalesce(txt_report_path,'') from dfir_run_jobs_v2 where job_id='$jid'")
  err=$(Q "select coalesce(error_short,'') from dfir_run_jobs_v2 where job_id='$jid'")
  [ -n "$f" ] && docker exec case-maintainer cat "$f" > "$OUT/$K.txt" 2>/dev/null
  echo "$(date +%H:%M) END   $K status=$st secs=$(( $(date +%s)-s )) lines=$(wc -l < "$OUT/$K.txt" 2>/dev/null) err=$err" >> /tmp/llm_batch.log
done
echo BATCHDONE >> /tmp/llm_batch.log
