#!/bin/bash
# The home directory the owner suspected. He was right.
#
# MEASURED before touching anything: /home is 24 GB, and 16 of them are
# .openclaw/workspace - which holds ANOTHER copy of the project: a 3.5 GB Postgres data
# directory and 12 GB of model backups, neither touched since April. The gateway service
# uses that workspace as its working directory, so the folder itself stays; the two dead
# subfolders inside it do not.
#
# Nothing is deleted. Everything moves to var/attic with a note saying what it was, so the
# owner decides - the same rule as the rest of the tidy-up.
set -u
ATTIC=/srv/dfir/var/attic/home_2026-08-22
DRY=${DRY:-1}
mkdir -p "$ATTIC" 2>/dev/null

free_gb() { df --output=avail -BG / | tail -1 | tr -dc '0-9'; }
BEFORE=$(free_gb)

move() {
  local src="$1" why="$2"
  [ -e "$src" ] || return 0
  local sz; sz=$(du -sh "$src" 2>/dev/null | cut -f1)
  if [ "$DRY" = "1" ]; then
    printf "  [dry] %-52s %-7s %s\n" "$src" "$sz" "$why"
  else
    mkdir -p "$ATTIC/$(dirname "${src#/home/dfir-bot/}")" 2>/dev/null
    if mv "$src" "$ATTIC/${src#/home/dfir-bot/}" 2>/dev/null; then
      printf "  %-52s %-7s %s\n" "${src#/home/dfir-bot/}" "$sz" "$why"
      echo "${src}|${sz}|${why}" >> "$ATTIC/WHAT_IS_THIS.txt"
    else
      printf "  НЕ ВДАЛОСЯ: %s\n" "$src"
    fi
  fi
}

echo "=== мертві копії проєкту (квітень, нічого не посилається) ==="
move /home/dfir-bot/.openclaw/workspace/backups "бекапи моделей, квітень 2026"
move /home/dfir-bot/.openclaw/workspace/services "стара копія Postgres/сервісів, квітень 2026"

echo "=== старі бекапи й знімки проєкту поза /srv ==="
move /home/dfir-bot/backups        "бекапи проєкту до переїзду (липень)"
move /home/dfir-bot/dfir_clean     "робоча копія часів чистки"
move /home/dfir-bot/bb_backup      "стара копія"
move /home/dfir-bot/dfir_tmp       "тимчасове"
move /home/dfir-bot/dfir_snap_before "знімок стану 16.08"
move /home/dfir-bot/dfir_snap_after2 "знімок стану 16.08"
move /home/dfir-bot/reingest_20260815 "разовий переінгест"

echo "=== демо й проби, які ніде не підключені ==="
move /home/dfir-bot/pdf2zh-demo   "демо перекладача, не підключене"
move /home/dfir-bot/poc_cpu_tools "проба CPU-інструментів"

echo "=== кеші, які самі відновлюються ==="
for c in /root/.cache /root/.npm /home/dfir-bot/.cache; do
  [ -d "$c" ] || continue
  sz=$(du -sh "$c" 2>/dev/null | cut -f1)
  if [ "$DRY" = "1" ]; then echo "  [dry] очистити $c ($sz)"; else rm -rf "${c:?}"/* 2>/dev/null; echo "  очищено $c (було $sz)"; fi
done

if [ "$DRY" != "1" ]; then
  cat > "$ATTIC/README.md" <<'EOF'
# Що тут лежить

Перенесено 2026-08-22 під час наведення порядку. **Нічого не видалено** — рішення за
власником. Кожен рядок у `WHAT_IS_THIS.txt` каже, звідки файл і чим був.

Перевірено ПЕРЕД перенесенням: жодна з цих тек не згадується в systemd-юнітах, у cron і не
змонтована в жоден контейнер. `.openclaw/workspace` сама лишилась на місці — у ній працює
gateway; переїхали лише її квітневі `backups/` і `services/`.

Коли скажеш «видаляй» — `rm -rf` цієї теки поверне місце.
EOF
  echo; echo "вільно було: ${BEFORE} ГБ, стало: $(free_gb) ГБ"
  du -sh "$ATTIC" 2>/dev/null | awk '{print "у attic: " $1}'
fi
[ "$DRY" = "1" ] && echo && echo "сухий прогін; DRY=0 щоб виконати"
exit 0
