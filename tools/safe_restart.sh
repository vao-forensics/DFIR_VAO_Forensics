#!/bin/bash
# Restart case-maintainer ONLY when nothing is in flight.
#
# Why this exists: on 2026-09-16 a restart during a test killed the owner's log import
# one minute after it started. Everything the container does - log parsing, trigger scans,
# DFIR analysis - runs in daemon threads, which die instantly with the process and leave
# the job row sitting at "running 5%" forever. Checking "is an analysis running?" was not
# enough; an import was running too.
#
# Usage:  safe_restart.sh            refuse if busy (default)
#         safe_restart.sh --wait     wait until idle, then restart
#         safe_restart.sh --force    restart anyway (say why out loud)
set -u
MODE="${1:-check}"
Q() { docker exec logdb psql -U dfir -d dfir_logs -tAc "$1" 2>/dev/null | tr -d ' '; }

busy_report() {
  local n_dfir n_trig n_ing
  n_dfir=$(Q "SELECT count(*) FROM public.dfir_run_jobs_v2 WHERE status IN ('running','queued')")
  n_trig=$(Q "SELECT count(*) FROM public.trigger_scan_jobs_v2 WHERE status IN ('running','queued') AND updated_at > now() - interval '15 minutes'")
  n_ing=$(Q "SELECT count(*) FROM public.ingest_jobs WHERE status='running' AND started_at > now() - interval '2 hours'")
  echo "${n_dfir:-0} ${n_trig:-0} ${n_ing:-0}"
}

show() {
  read -r d t i <<< "$(busy_report)"
  echo "  аналіз справ (dfir_run_jobs_v2):      $d"
  echo "  сканування тригерів / парсинг логів:  $t"
  echo "  імпорт архівів (ingest_jobs):         $i"
  TOTAL=$((d + t + i))
}

echo "=== що зараз у роботі ==="
show

if [ "$MODE" = "--force" ]; then
  echo "!! примусовий перезапис при $TOTAL активних завданнях"
elif [ "$TOTAL" -gt 0 ]; then
  if [ "$MODE" = "--wait" ]; then
    echo "чекаю, доки звільниться (перевірка кожні 30 с, максимум 2 год)..."
    for i in $(seq 1 240); do
      sleep 30
      show >/dev/null
      [ "$TOTAL" -eq 0 ] && break
    done
    show
    if [ "$TOTAL" -gt 0 ]; then
      echo "ВІДМОВА: усе ще зайнято після 2 год"
      exit 2
    fi
  else
    echo
    echo "ВІДМОВА: перезапуск уб'є ці завдання без сліду (вони живуть у daemon-потоках)."
    echo "         safe_restart.sh --wait   щоб дочекатися"
    echo "         safe_restart.sh --force  якщо це справді треба зараз"
    exit 1
  fi
fi

echo "=== перезапускаю ==="
cd /srv/dfir && docker compose restart case-maintainer >/dev/null 2>&1
for i in $(seq 1 40); do
  sleep 5
  if docker exec case-maintainer python3 -c "pass" 2>/dev/null; then
    echo "готовий"
    exit 0
  fi
done
echo "УВАГА: контейнер не піднявся за 200 с"
exit 3
