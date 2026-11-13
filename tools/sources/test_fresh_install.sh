#!/usr/bin/env bash
# test t1_sources_fresh_install: installer step apply_sources on an EMPTY database dir (as on a new server)
set -u
cd /srv/dfir
TT=t1test; rm -rf cases/_hashdb_$TT /tmp/srcstate_$TT; mkdir -p cases/_hashdb_$TT
python3 - <<PY
import json; m=json.load(open("infra/sources/sources.json"))
m["dest_dir"]="cases/_hashdb_$TT"; m["container_dest_dir"]="/data/case_library/_hashdb_$TT"
json.dump(m,open("/tmp/sources_$TT.json","w"))
PY
export DFIR_SOURCES_MANIFEST=/tmp/sources_$TT.json DFIR_SOURCES_STATE=/tmp/srcstate_$TT ABUSECH_AUTH_KEY=
ROOT=/srv/dfir; . installer/lib.sh; load_lang uk
eval "$(sed -n '/^apply_sources()/,/^}/p' installer/apply.sh)"
ROOT=/srv/dfir DRY_RUN=0; apply_sources
echo "--- files"; ls -la cases/_hashdb_$TT
echo "--- check"; python3 tools/sources/dfir_sources.py check
echo "--- vanilla rows / bloom selftest in container"
docker exec -w /app case-maintainer python3 -c "
import sqlite3;print('vpath', sqlite3.connect('/data/case_library/_hashdb_$TT/vanilla_paths.sqlite').execute('select count(*) from vpath').fetchone()[0])
from flor import BloomFilter; from analysis import hash_lookup as h
bf=BloomFilter(); bf.read(open('/data/case_library/_hashdb_$TT/hashlookup-full.bloom','rb')); print('fp', h.bloom_self_test(bf))"
echo "--- provenance outcomes"; python3 -c "import json;[print(json.loads(l)['id'], json.loads(l)['outcome']) for l in open('/tmp/srcstate_$TT/provenance.jsonl')]"
rm -rf cases/_hashdb_$TT /tmp/srcstate_$TT /tmp/sources_$TT.json
