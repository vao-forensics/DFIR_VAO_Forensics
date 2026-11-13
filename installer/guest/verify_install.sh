#!/usr/bin/env bash
# Checks a finished install from inside the guest (the checks of the G5 test from scratch, as PASS/FAIL).
# usage: sudo bash verify_install.sh [DEST]      exit 0 = every check passed
DEST=${1:-/srv/dfir}
pass=0; fail=0
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1 ${3:-}"; fail=$((fail+1)); fi; }
# T9: modules switched off at install are checked to be ABSENT, their checks below are skipped
OFF=$( (. "$DEST/state/install_answers.env" >/dev/null 2>&1; echo "${MODULES_OFF:-}") )
on() { case " $OFF " in *" $1 "*) return 1 ;; *) return 0 ;; esac; }
if [ -n "$OFF" ]; then
  echo "modules off: $OFF"
  svcs=$(python3 -c 'import json,sys;off=sys.argv[2].split();print(" ".join(s for m in json.load(open(sys.argv[1]))["modules"] if m["id"] in off for s in m["services"]))' "$DEST/infra/modules.json" "$OFF")
  for s in $svcs; do
    n=$(docker ps -a --filter "label=com.docker.compose.service=$s" -q | wc -l)
    ok "module off: no $s container" "$([ "$n" = 0 ]; echo $?)" "[$n]"
  done
  if ! on webchat; then
    n=$(docker image ls -q ghcr.io/open-webui/open-webui | wc -l)
    ok "module off: Open WebUI image not downloaded" "$([ "$n" = 0 ]; echo $?)" "[$n]"
    ok "module off: no sandbox service" "$(! systemctl is-active --quiet dfir-sandbox-api; echo $?)"
  fi
  if ! on hashdb; then
    n=$(find "$DEST/cases/_hashdb" -type f 2>/dev/null | wc -l)
    ok "module off: no reference databases downloaded" "$([ "$n" = 0 ]; echo $?)" "[$n]"
  fi
  e=$(docker exec tg-i18n printenv DFIR_MODULES_OFF 2>/dev/null)
  ok "bot hides the off modules' buttons (tg-i18n: $e)" "$([ "$e" = "$OFF" ]; echo $?)"
fi
running=$(docker ps -q | wc -l)
ok "containers running ($running >= 15)" "$([ "$running" -ge 15 ]; echo $?)"
r=$(docker ps --filter status=restarting --format '{{.Names}}' | tr '\n' ' ')
ok "none restarting" "$([ -z "$r" ]; echo $?)" "[$r]"
u=$(docker ps --filter health=unhealthy --format '{{.Names}}' | tr '\n' ' ')
ok "none unhealthy" "$([ -z "$u" ]; echo $?)" "[$u]"
x=$(docker ps -a --filter status=exited --format '{{.Names}}' | tr '\n' ' ')
ok "none exited" "$([ -z "$x" ]; echo $?)" "[$x]"
units="dfir-selfcheck-daily.timer"; on webchat && units="dfir-sandbox-api owui-retention.timer dfir-usandbox-gw tinyproxy dfir-sync-models.timer dfir-skill-miner.timer dfir-owui-backup.timer dfir-profiles.timer dfir-portal-qa.timer $units"
for s in $units; do
  ok "service $s active" "$(systemctl is-active --quiet "$s"; echo $?)"
done
if on webchat; then
users=$(docker exec open-webui python3 -c "import sqlite3;print(sqlite3.connect('/app/backend/data/webui.db').execute(\"select count(*) from user where role='admin'\").fetchone()[0])" 2>/dev/null)
ok "Open WebUI admin exists" "$([ "${users:-0}" -ge 1 ]; echo $?)"
fn=$(docker exec open-webui python3 -c "import sqlite3;print(sqlite3.connect('/app/backend/data/webui.db').execute(\"select count(*) from function where id='dfir_files' and is_active=1 and is_global=1\").fetchone()[0])" 2>/dev/null)
ok "file filter dfir_files active+global" "$([ "${fn:-0}" = 1 ]; echo $?)"
ok "Open WebUI health" "$(curl -fs -m5 http://127.0.0.1:3000/health >/dev/null; echo $?)"
fi
wf=$(docker exec n8n n8n list:workflow 2>/dev/null | grep -c '|')
ok "n8n workflows imported ($wf)" "$([ "${wf:-0}" -ge 1 ]; echo $?)"
llm=$(docker exec case-maintainer python3 -c "import urllib.request,os;print(urllib.request.urlopen(os.environ.get('DFIR_LLM_URL','http://172.17.0.1:1234').rstrip('/')+'/v1/models',timeout=20).status)" 2>&1 | tail -1)
ok "LLM reachable from the bot ($llm)" "$([ "$llm" = 200 ]; echo $?)"
if on webchat; then
printf 'ts,user,event\n2026-01-01T00:00:00Z,test,logon\n' > /tmp/vi.csv
if on webchat; then
  nf=$(docker exec open-webui python3 -c "import sqlite3;print(sqlite3.connect('/app/backend/data/webui.db').execute(\"select count(*) from function where is_active=1 and id in ('dfir_model_router','dfir_identity_guard','dfir_user_profile','dfir_live_status','dfir_skills','dfir_storage')\").fetchone()[0])" 2>/dev/null)
  ok "portal functions active (6)" "$([ "$nf" = 6 ]; echo $?)" "[$nf]"
  ts=$(docker exec open-webui python3 -c "import sqlite3,json;v=sqlite3.connect('/app/backend/data/webui.db').execute(\"select value from config where key='tool_server.connections'\").fetchone();print(sum(1 for c in json.loads(v[0]) if (c.get('info') or {}).get('id')=='usandbox') if v else 0)" 2>/dev/null)
  ok "sandbox tool server registered" "$([ "$ts" = 1 ]; echo $?)" "[$ts]"
  gwu=$(systemctl show dfir-usandbox-gw -p Environment --value | tr ' ' '\n' | sed -n 's/^USBX_BIND=//p')
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://$gwu:8796/openapi.json")
  ok "sandbox gateway answers ($gwu:8796)" "$([ "$code" = 200 ]; echo $?)" "[$code]"
  n=$(iptables -S DOCKER-USER 2>/dev/null | grep -c -- '-s 172.30.0.0/16')
  ok "sandbox egress rules in place ($n)" "$([ "$n" -ge 4 ]; echo $?)"
fi
"$DEST/sandbox/analyze_file.sh" /tmp/vi.csv verify >/dev/null 2>&1 && test -s "$DEST/sandbox/jobs/verify/out/report.md"
ok "sandbox analyses a file" $?
rm -rf "$DEST/sandbox/jobs/verify" /tmp/vi.csv
fi
echo "verify: $pass passed, $fail failed"
[ "$fail" = 0 ]
