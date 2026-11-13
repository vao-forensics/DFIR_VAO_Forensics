#!/usr/bin/env bash
# Щоденний бекап бази справ (dfir_logs) з контейнера logdb. Пишемо у тимчасовий файл і
# перейменовуємо лише після успіху, щоб обірваний дамп (вимкнули світло) не вважався бекапом.
# Тримаємо 3 останні. Самоперевірка вважає бекап старшим за 30 год червоним.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/backups/pg"
KEEP=3
mkdir -p "$DIR"
# запуск щогодини: якщо свіжий бекап (<20 год) уже є — нічого не робимо; так пропущений через
# вимкнення світла нічний бекап надолужується після старту ВМ
if [ "${1:-}" != "--force" ] && [ -n "$(find "$DIR" -maxdepth 1 -name logdb_*.dump -mmin -1200 -print -quit)" ]; then exit 0; fi
# мало місця -> не дампимо (дамп ~2 ГБ), щоб не забити диск ВМ
free_gb=$(df -BG --output=avail "$DIR" | tail -1 | tr -dc 0-9)
[ "${free_gb:-0}" -ge 10 ] || { echo "pg_backup: мало місця (${free_gb} ГБ), пропуск" >&2; exit 1; }
out="$DIR/logdb_$(date +%Y%m%d_%H%M%S).dump"
tmp="$out.part"
trap 'rm -f "$tmp"' EXIT
docker exec logdb pg_dump -U dfir -d dfir_logs -Fc > "$tmp"
[ -s "$tmp" ] || { echo "pg_backup: порожній дамп" >&2; exit 1; }
mv "$tmp" "$out"
chmod 600 "$out"
ls -1t "$DIR"/logdb_*.dump | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "pg_backup: $(basename "$out") $(du -h "$out" | cut -f1)"
