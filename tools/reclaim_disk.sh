#!/bin/bash
# Reclaim the disk the backups ate by backing up each other.
#
# MEASURED: services/n8n holds TWELVE database.sqlite.bak_* copies, 1.5 GB each = 18 GB,
# left behind by past sessions before editing the workflow. The nightly job then tars the
# WHOLE n8n directory - including those copies - which is why each nightly archive is
# 4.6 GB rather than the 1.4 GB the database actually is, and why six of them come to
# 27 GB. The live database is itself mostly empty space: 174 executions in 1.43 GB,
# because SQLite does not return freed pages without a VACUUM.
#
# Nothing here touches case data. It runs in stages and prints what it frees.
set -u
ROOT=/srv/dfir
DRY=${DRY:-1}
say() { echo "  $*"; }
free_now() { df --output=avail -BG "$ROOT" | tail -1 | tr -dc '0-9'; }

BEFORE=$(free_now)
echo "вільно на початку: ${BEFORE} ГБ"

# --- 1. the stale sqlite copies, keeping the two newest --------------------------
echo "[1] копії бази n8n"
mapfile -t OLD < <(ls -t "$ROOT"/services/n8n/database.sqlite.bak_* 2>/dev/null | tail -n +3)
say "знайдено $(ls -1 "$ROOT"/services/n8n/database.sqlite.bak_* 2>/dev/null | wc -l), видаляю ${#OLD[@]} (дві найновіші лишаю)"
for f in "${OLD[@]:-}"; do
  [ -n "$f" ] || continue
  if [ "$DRY" = "1" ]; then say "  [dry] $f"; else rm -f "$f"; fi
done

# --- 2. the nightly archives, keeping the two newest -----------------------------
echo "[2] нічні архіви"
mapfile -t OLDT < <(ls -t "$ROOT"/backups/n8n_*.tar.gz 2>/dev/null | tail -n +3)
say "знайдено $(ls -1 "$ROOT"/backups/n8n_*.tar.gz 2>/dev/null | wc -l), видаляю ${#OLDT[@]} (дві найновіші лишаю)"
for f in "${OLDT[@]:-}"; do
  [ -n "$f" ] || continue
  if [ "$DRY" = "1" ]; then say "  [dry] $f"; else rm -f "$f"; fi
done

# --- 3. loose sqlite copies in backups/ ------------------------------------------
echo "[3] окремі копії бази у backups/"
mapfile -t OLDS < <(ls -t "$ROOT"/backups/n8n_db.bak_* "$ROOT"/backups/n8n_database_*.sqlite 2>/dev/null | tail -n +2)
say "видаляю ${#OLDS[@]} (найновішу лишаю)"
for f in "${OLDS[@]:-}"; do
  [ -n "$f" ] || continue
  if [ "$DRY" = "1" ]; then say "  [dry] $f"; else rm -f "$f"; fi
done

AFTER=$(free_now)
echo "вільно тепер: ${AFTER} ГБ (звільнено $((AFTER-BEFORE)) ГБ)"
[ "$DRY" = "1" ] && echo "це був сухий прогін; запусти з DRY=0 щоб виконати"
exit 0
