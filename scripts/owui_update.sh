#!/usr/bin/env bash
# Controlled Open WebUI update with backup, smoke-test and automatic rollback.
# Usage: owui_update.sh <target_version>   e.g. owui_update.sh 0.12.5
# Never silently leaves a broken service: if any smoke-test fails, it restores
# the previous image and data and exits non-zero.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # install folder (scripts/..), not a fixed path
set -euo pipefail

VER="${1:?need target version, e.g. 0.12.5}"
NEW_IMG="ghcr.io/open-webui/open-webui:${VER}"
VOL=/var/lib/docker/volumes/open-webui/_data
BK="$ROOT/backups/owui"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BK"

log(){ echo "[owui-update $(date -u +%T)] $*"; }

# 0. record current image + digest (rollback anchor)
CUR_IMG="$(docker inspect open-webui --format '{{.Config.Image}}')"
log "current image: $CUR_IMG"
echo "$CUR_IMG" > "$BK/rollback_image_${STAMP}.txt"

# 1. backup the data volume (db + uploads + vectors)
log "backing up data volume -> $BK/owui_data_${STAMP}.tgz"
tar -czf "$BK/owui_data_${STAMP}.tgz" -C "$VOL" . 2>/dev/null
cp "$VOL/webui.db" "$BK/webui_${STAMP}.db"

# 2. pull target
log "pulling $NEW_IMG"
docker pull "$NEW_IMG"

# 3. swap image in compose (keep a copy), recreate
COMPOSE=$ROOT/docker-compose.yml
cp "$COMPOSE" "$BK/compose_${STAMP}.yml"
# replace the open-webui image line only
python3 - "$COMPOSE" "$NEW_IMG" <<'PY'
import sys,re
f,newimg=sys.argv[1],sys.argv[2]
s=open(f).read().splitlines()
out=[];inblk=False
for ln in s:
    if re.match(r'^\s{2}open-webui:',ln): inblk=True
    elif re.match(r'^\s{2}\S',ln): inblk=False
    if inblk and re.match(r'^\s+image:\s',ln):
        ln=re.sub(r'(image:\s*).*',r'\1'+newimg,ln)
    out.append(ln)
open(f,'w').write('\n'.join(out)+'\n')
PY
log "recreating container"
cd $ROOT && docker compose up -d open-webui

# 4. smoke tests
fail=""
log "waiting for Docker health (container's own healthcheck)..."
for i in $(seq 1 40); do
  hs=$(docker inspect open-webui --format '{{.State.Health.Status}}' 2>/dev/null || echo none)
  st=$(docker inspect open-webui --format '{{.State.Status}}' 2>/dev/null || echo none)
  [ "$hs" = healthy ] && break
  [ "$st" = restarting ] && { fail="container is crash-looping (likely DB migration mismatch)"; break; }
  sleep 5
done
[ "$hs" = healthy ] || fail="${fail:-container never became healthy}"

# use python (always present in this image), NOT wget/curl
if [ -z "$fail" ]; then
  docker exec open-webui python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/health',timeout=8)" >/dev/null 2>&1 \
    || fail="health endpoint check failed"
fi
# retention worker must still import + dry-run (its internal hooks may change between versions)
if [ -z "$fail" ]; then
  out=$(docker exec -e DRY_RUN=1 -e PYTHONPATH=/app/backend -e WEBUI_SECRET_KEY=retention-worker-dummy open-webui python /app/backend/data/retention.py 2>&1 | grep -E "total=" || true)
  [ -n "$out" ] || fail="retention worker broke on new version"
fi

if [ -n "$fail" ]; then
  log "SMOKE TEST FAILED: $fail -> ROLLING BACK to $CUR_IMG"
  cd $ROOT && docker compose stop open-webui || true
  # a newer version may have migrated webui.db; the old version cannot read it,
  # so restore the pre-update DB before starting the old image.
  cp "$BK/webui_${STAMP}.db" "$VOL/webui.db"
  rm -f "$VOL/webui.db-shm" "$VOL/webui.db-wal" 2>/dev/null || true
  cp "$BK/compose_${STAMP}.yml" "$COMPOSE"
  docker compose up -d open-webui
  log "rollback done (image + pre-update DB restored). full data backup: $BK/owui_data_${STAMP}.tgz"
  exit 1
fi

log "UPDATE OK -> $VER. retention check: $out"
log "backups: $BK (data_${STAMP}.tgz, webui_${STAMP}.db, compose+rollback_image)"
