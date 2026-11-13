#!/usr/bin/env bash
# P7 checks straight against the sandbox API (same path the OWUI filter uses). Prints no secrets.
set -u
cd "$(dirname "$(readlink -f "$0")")"
set -a; . ./api.env; set +a
UP=/var/lib/docker/volumes/open-webui/_data/uploads
API=http://172.18.0.1:8791/analyze
T=$(mktemp -d)
call() {  # $1 = file name inside uploads
  curl -s -m 1200 -o "$T/r.json" -w "%{http_code}" -H "X-Token: $SBX_TOKEN" -H 'Content-Type: application/json' \
       -d "{\"path\":\"/app/backend/data/uploads/$1\",\"ticket\":\"p7t$RANDOM\"}" "$API"
  echo -n "  "; python3 -c "import json;d=json.load(open('$T/r.json'));print({k:(v if k!='report' else v[:420].replace(chr(10),' ')) for k,v in d.items() if k in ('ok','error','size_mb','limit_mb','report')})"
}

echo "== 1. small log file"
printf '2026-01-14 11:39:47 user01 created\n%.0s' $(seq 1 2000) > "$UP/p7_small.log"
s=$(date +%s); echo -n "  http=$(call p7_small.log)"; echo "  $(( $(date +%s)-s )) s"

echo "== 2. zip bomb (3 GiB of zeros, ~3 MB compressed)"
python3 - "$UP/p7_bomb.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for i in range(6):
        with z.open("evtx/part%d.bin" % i, "w", force_zip64=True) as f:
            blk = b"\0" * (1 << 20)
            for _ in range(512):
                f.write(blk)
PY
ls -la "$UP/p7_bomb.zip" | awk '{print "  compressed bytes:", $5}'
s=$(date +%s); echo -n "  http=$(call p7_bomb.zip)"; echo "  $(( $(date +%s)-s )) s"

echo "== 3. file over the 2 GiB chat limit (sparse 2.2 GiB)"
truncate -s 2200M "$UP/p7_big.bin"
s=$(date +%s); echo -n "  http=$(call p7_big.bin)"; echo "  $(( $(date +%s)-s )) s"

rm -f "$UP"/p7_small.log "$UP"/p7_bomb.zip "$UP"/p7_big.bin; rm -rf "$T"
echo "== leftovers: jobs=$(ls jobs | wc -l) containers=$(docker ps -q --filter name=dfir_sbx_ | wc -l)"
