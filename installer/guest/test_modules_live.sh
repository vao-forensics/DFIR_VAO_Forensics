#!/usr/bin/env bash
# T9 live test, run INSIDE a fresh install made with MODULES_OFF="webchat hashdb translate"
# (incus/VM from scratch, Telegram stub token). Checks the installed system, then switches modules
# with the real `dfir modules`.   usage: sudo bash test_modules_live.sh [DEST]   exit 0 = all PASS
D=${1:-/opt/dfir-vao}; cd "$D" || exit 2
pass=0; fail=0
ok() { if [ "$2" = 0 ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1 ${3:-}"; fail=$((fail+1)); fi; }
verify() { bash installer/guest/verify_install.sh "$D" > /tmp/verify_t9.out 2>&1; local rc=$?
           grep -E 'FAIL|verify:|modules off' /tmp/verify_t9.out | sed 's/^/    /'; return $rc; }
running() { docker ps --filter "label=com.docker.compose.service=$1" -q | wc -l; }
existing() { docker ps -a --filter "label=com.docker.compose.service=$1" -q | wc -l; }

echo "== 1 fresh install, modules off: $(grep '^MODULES_OFF=' state/install_answers.env)"
verify; ok "verify_install green with webchat+hashdb+translate off" $?

echo "== 2 the installed bot hides/refuses the off modules (real tg-i18n container, fake token)"
ip=$(docker inspect tg-i18n -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' | awk '{print $1}')
tok=$(grep '^DFIR_TG_BOT_TOKEN=' .env | cut -d= -f2-)
h0=$(curl -s "http://$ip:8098/health")
curl -s -m 30 -H 'Content-Type: application/json' "http://$ip:8098/bot$tok/sendMessage" -d \
  '{"chat_id":5,"text":"menu","reply_markup":{"inline_keyboard":[[{"text":"PDF","callback_data":"tool:pdf_translate"},{"text":"Info","callback_data":"show_stats"}]]}}' >/dev/null
curl -s -m 30 -H 'Content-Type: application/json' "http://$ip:8098/webhook/t9" -d \
  '{"update_id":1,"callback_query":{"id":"c1","from":{"id":5},"data":"tool:translate","message":{"message_id":1,"chat":{"id":5}}}}' >/dev/null
h1=$(curl -s "http://$ip:8098/health")
st=$(python3 -c 'import json,sys;a,b=json.loads(sys.argv[1]),json.loads(sys.argv[2]);print(b["module_stripped"]-a["module_stripped"],b["module_refused"]-a["module_refused"])' "$h0" "$h1")
ok "off button stripped + off tap refused (stripped/refused: $st)" "$([ "$st" = "1 1" ]; echo $?)"

echo "== 3 .env rewritten by apply_env (dfir vpn / dfir lang do that) keeps DFIR_MODULES_OFF"
off=$(. state/install_answers.env; echo "$MODULES_OFF")
( export ROOT=$D DESTDIR=$D DRY_RUN=0; . installer/lib.sh; ANSWERS=$D/state/install_answers.env; . "$ANSWERS"
  . installer/sections.sh; . installer/modules.sh; load_lang en; . installer/apply.sh; apply_env ) >/tmp/t9_env.out 2>&1
e=$(grep '^DFIR_MODULES_OFF=' .env | cut -d= -f2-)
ok "after apply_env: DFIR_MODULES_OFF=$e" "$([ "$e" = "$off" ]; echo $?)" "$(tail -3 /tmp/t9_env.out)"

echo "== 4 dfir modules on translate webchat"
dfir modules on translate webchat > /tmp/t9_on.out 2>&1; ok "exit 0" $? "$(tail -5 /tmp/t9_on.out)"
ok "translate-watcher running" "$([ "$(running translate-watcher)" = 1 ]; echo $?)"
for i in $(seq 1 60); do curl -fs -m5 http://127.0.0.1:3000/health >/dev/null && break; sleep 5; done
ok "Open WebUI downloaded + healthy" "$(curl -fs -m5 http://127.0.0.1:3000/health >/dev/null; echo $?)"
ok "sandbox service active" "$(systemctl is-active --quiet dfir-sandbox-api; echo $?)"
e=$(docker exec tg-i18n printenv DFIR_MODULES_OFF)
ok "tg-i18n now hides only: $e" "$([ "$e" = hashdb ]; echo $?)"
verify; ok "verify_install green after switching on" $?

echo "== 5 dfir modules off webchat translate (after install)"
dfir modules off webchat translate > /tmp/t9_off.out 2>&1; ok "exit 0" $? "$(tail -5 /tmp/t9_off.out)"
ok "open-webui container removed" "$([ "$(existing open-webui)" = 0 ]; echo $?)"
ok "translate-watcher container removed" "$([ "$(existing translate-watcher)" = 0 ]; echo $?)"
ok "sandbox service + retention timer stopped" "$(! systemctl is-active --quiet dfir-sandbox-api && ! systemctl is-active --quiet owui-retention.timer; echo $?)"
e=$(docker exec tg-i18n printenv DFIR_MODULES_OFF)
ok "tg-i18n hides: $e" "$([ "$e" = "hashdb webchat translate" ]; echo $?)"
verify; ok "verify_install green after switching off" $?
echo "modules live test: $pass passed, $fail failed"
[ "$fail" = 0 ]
