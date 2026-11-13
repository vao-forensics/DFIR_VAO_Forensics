#!/bin/bash
# Nightly DB anti-clutter: prune old failed jobs + orphaned ioc_overlap/iocs.
#
# 24.10.2026: the job DELETE had failed every night - a failed job that a later retry points to
# (retry_of_job_id) blocks the whole statement, so nothing was ever pruned. Now: unreferenced
# failed jobs only, and their rows (+ steps) are copied to backups/failed_jobs/ first, so the
# failure history (power cuts, orphaned runners) stays available for statistics.
P="docker exec -i logdb psql -U dfir -d dfir_logs -v ON_ERROR_STOP=1"
SEL="SELECT j.job_id FROM dfir_run_jobs_v2 j WHERE j.status='failed' AND j.created_at < now()-interval '3 days'
     AND NOT EXISTS (SELECT 1 FROM dfir_run_jobs_v2 r WHERE r.retry_of_job_id = j.job_id)"
OUT=/srv/dfir/backups/failed_jobs
mkdir -p "$OUT"
D=$(date +%F)
if $P -c "\copy (SELECT * FROM dfir_run_jobs_v2 WHERE job_id IN ($SEL)) TO STDOUT WITH CSV HEADER" > "$OUT/jobs_$D.csv" \
   && $P -c "\copy (SELECT * FROM dfir_run_steps_v2 WHERE job_id IN ($SEL)) TO STDOUT WITH CSV HEADER" > "$OUT/steps_$D.csv"; then
  $P -c "DELETE FROM dfir_run_jobs_v2 WHERE job_id IN ($SEL);"
else
  echo "failed-jobs backup did not complete - nothing deleted"
fi
find "$OUT" -name '*.csv' -size -200c -delete    # header-only files of quiet nights
$P -c "DELETE FROM ioc_overlap WHERE case_a NOT IN (SELECT case_key FROM cases) OR case_b NOT IN (SELECT case_key FROM cases);"
$P -c "DELETE FROM case_iocs WHERE case_key NOT IN (SELECT case_key FROM cases);"
