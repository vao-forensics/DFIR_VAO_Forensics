#!/usr/bin/env bash
# T2 test: dfir update on a throw-away clone with its own "upstream" (bare repo in /tmp).
#   1 check --notify tells the owner once about new commits, not again for the same set
#   2 good update: trial (syntax + compose + REAL sandbox parse of the test archive) -> switch -> healthy
#   3 broken Python in the update: trial rejects it, live commit unchanged
#   4 sandbox parser broken in the update: trial parse rejects it, live commit unchanged
#   5 update passes trial but the system is unhealthy after it: rolled back to the previous commit
# Live /srv/dfir is only READ (cloned); nothing in it changes.
set -u
SRC="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
T=$(mktemp -d /tmp/dfir_update_test.XXXX)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

git clone -q --bare "$SRC" "$T/up.git"
git clone -q "$T/up.git" "$T/inst"
install -m 600 "$SRC/.env" "$T/inst/.env"
W="$T/work"; git clone -q "$T/up.git" "$W"
git -C "$W" config user.email test@local; git -C "$W" config user.name test
U() { DFIR_ROOT="$T/inst" DFIR_UPDATE_NOTIFY=print DFIR_UPDATE_INSTALL=true \
      DFIR_UPDATE_HEALTH='test ! -f BREAK_HEALTH' DFIR_UPDATE_FIXTURE="$SRC/state/sandbox_testdata/collector_TEST_output.zip" \
      python3 "$T/inst/tools/update/dfir_update.py" "$@"; }
push() { git -C "$W" add -A && git -C "$W" commit -qm "$1" && git -C "$W" push -q origin HEAD; git -C "$W" rev-parse HEAD; }
head() { git -C "$T/inst" rev-parse HEAD; }

# 1 check + notify dedupe
echo "# t2 test" >> "$W/docs/T2_TEST.md"; G1=$(push "test: harmless doc")
o1=$(DFIR_UPDATE_SKIP=sources,owui,ez U check --notify); r1=$?
o2=$(DFIR_UPDATE_SKIP=sources,owui,ez U check --notify)
[ $r1 = 3 ] && grep -q '^NOTIFY: ' <<<"$o1" && grep -q 'already told' <<<"$o2" && ! grep -q '^NOTIFY' <<<"$o2" \
  && ok "1 check notifies once (rc=3), same set not repeated" || { bad "1 check/notify"; echo "$o1"; echo "$o2"; }

# 2 good update with a real trial parse
echo "# harmless" >> "$W/tools/update/dfir_update.py"; G2=$(push "test: harmless code change")
o=$(DFIR_UPDATE_SKIP=sources,owui,ez U apply); r=$?
[ $r = 0 ] && [ "$(head)" = "$G2" ] && grep -q 'trial parse ok' <<<"$o" \
  && ok "2 good update applied after real sandbox trial parse ($(grep -o 'trial parse ok.*' <<<"$o"))" || { bad "2 good update rc=$r"; echo "$o"; }

# 3 broken python
before=$(head); echo "def broken(:" > "$W/tools/broken_t2.py"; push "test: syntax error" >/dev/null
o=$(DFIR_UPDATE_SKIP=sources,owui,ez U apply); r=$?
[ $r = 1 ] && [ "$(head)" = "$before" ] && grep -q 'python syntax' <<<"$o" \
  && ok "3 broken Python rejected by trial, live unchanged" || { bad "3 rc=$r"; echo "$o"; }
git -C "$W" rm -q tools/broken_t2.py; push "test: fix syntax" >/dev/null

# 4 sandbox parser broken (valid syntax, fails at run time)
before=$(head); sed -i '0,/^from pathlib import Path/s//from pathlib import Path\nraise SystemExit("t2 broken parser")/' "$W/sandbox/analyze.py"
push "test: parser broken" >/dev/null
o=$(DFIR_UPDATE_SKIP=sources,owui,ez U apply); r=$?
[ $r = 1 ] && [ "$(head)" = "$before" ] && grep -q 'trial parse of the test archive failed' <<<"$o" \
  && ok "4 broken parser rejected by trial parse, live unchanged" || { bad "4 rc=$r"; echo "$o"; }
git -C "$W" checkout -q HEAD~1 -- sandbox/analyze.py; push "test: parser fixed" >/dev/null

# 5 passes trial, unhealthy after switch -> rollback
before=$(head); touch "$W/BREAK_HEALTH"; push "test: breaks health" >/dev/null
o=$(DFIR_UPDATE_SKIP=sources,owui,ez,parse U apply); r=$?
[ $r = 2 ] && [ "$(head)" = "$before" ] && [ ! -f "$T/inst/BREAK_HEALTH" ] && grep -q 'rolling back' <<<"$o" && grep -q '^NOTIFY: .*повернуто' <<<"$o" \
  && ok "5 unhealthy after update -> rolled back to ${before:0:8}, owner told" || { bad "5 rc=$r"; echo "$o"; }

echo "dfir_update test: $pass passed, $fail failed"
[ $fail = 0 ]
