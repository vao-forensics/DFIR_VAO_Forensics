#!/bin/bash
# Night run: the SAME production DFIR job as the baseline, but with the pipeline pointed at the
# 120B MoE (tools/switch_llm.py big). Reports land in a SEPARATE folder so the reasoner-31b
# baseline in llm_baseline/ stays intact for the comparison.
# Logs: /tmp/llm_120b.log ; reports: /srv/dfir/state/truth/llm_120b/<case>.txt
# case_45 is skipped if it already ran as the smoke test (its report is picked up instead).
OUT=/srv/dfir/state/truth/llm_120b
mkdir -p "$OUT"
LOG=/tmp/llm_120b.log
Q() { docker exec logdb psql -U dfir -d dfir_logs -tA -F'|' -c "$1" 2>/dev/null; }
CASES="case_02 case_07 case_29 case_04 case_36 case_30 case_23 case_34 case_32 case_31 case_33 case_38 case_08 case_25 case_27"

echo "$(date +%H:%M) BATCH START model=120b" >> "$LOG"

# if a job is still running from the smoke test, wait it out first
for i in $(seq 240); do
  run=$(Q "select count(*) from dfir_run_jobs_v2 where status='running'")
  [ "$run" = "0" ] && break
  sleep 15
done

for K in $CASES; do
  # already have a good report from this run? skip (covers the smoke-tested case)
  if [ -s "$OUT/$K.txt" ]; then
    echo "$(date +%H:%M) SKIP  $K (report already present)" >> "$LOG"
    continue
  fi
  s=$(date +%s)
  resp=$(docker exec case-maintainer python -c "
import os, json, urllib.request
tok = os.environ.get('MAINTAINER_TOKEN') or os.environ.get('TOKEN') or ''
req = urllib.request.Request('http://127.0.0.1:8787/dfir-start', data=json.dumps({'case_key':'$K','chat_id':None}).encode(), headers={'Content-Type':'application/json','X-Maintainer-Token':tok}, method='POST')
try:
    print(urllib.request.urlopen(req, timeout=90).read().decode()[:200])
except Exception as e:
    print('ERR', e)
" 2>&1 | tail -1)
  jid=$(echo "$resp" | grep -oE '"job_id":"[^"]+"' | cut -d'"' -f4)
  echo "$(date +%H:%M) START $K job=$jid :: $(echo "$resp" | cut -c1-100)" >> "$LOG"
  if [ -z "$jid" ]; then echo "$(date +%H:%M) NOJOB $K" >> "$LOG"; continue; fi
  # 120B generates at ~79 t/s, so a case can take noticeably longer than with the 31B: 2h ceiling
  for i in $(seq 480); do
    st=$(Q "select status from dfir_run_jobs_v2 where job_id='$jid'")
    case "$st" in completed|failed|error) break;; esac
    sleep 15
  done
  f=$(Q "select coalesce(txt_report_path,'') from dfir_run_jobs_v2 where job_id='$jid'")
  err=$(Q "select coalesce(error_short,'') from dfir_run_jobs_v2 where job_id='$jid'")
  [ -n "$f" ] && docker exec case-maintainer cat "$f" > "$OUT/$K.txt" 2>/dev/null
  echo "$(date +%H:%M) END   $K status=$st secs=$(( $(date +%s)-s )) lines=$(wc -l < "$OUT/$K.txt" 2>/dev/null) err=$err" >> "$LOG"
done
echo "$(date +%H:%M) BATCH120-DONE" >> "$LOG"
