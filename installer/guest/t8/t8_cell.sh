#!/usr/bin/env bash
# T8 matrix: ONE cell = a fresh install from scratch in a new incus container, then checks.
# Runs on the TEST HOST (the machine with incus), not in the guest.
# usage: bash t8_cell.sh CELL IMAGE ANSWERS_FILE [keep]
#   CELL    name, e.g. jammy-server      IMAGE  incus image alias (t8-noble / t8-jammy / t8-bookworm)
#   ANSWERS install answers (KEY=value); the Telegram token MUST be the stub (checked below)
# Pass criterion (all three): install rc=0; verify_install.sh all PASS; one real chat completion
# through the bot's own LLM endpoint (172.17.0.1:1234 router -> the chosen mode) from case-maintainer.
# Result line: "T8 CELL <name> HEAD <sha> OS <..> install_rc=.. verify=.. llm=.. => PASS|FAIL"
set -u
CELL=$1; IMG=$2; ANS=$3; KEEP=${4:-}
N=dfir-t8-$CELL
ROOT=/srv/dfir
LOGD=$ROOT/var/t8; mkdir -p "$LOGD"; LOG=$LOGD/$CELL.log
exec > >(tee "$LOG") 2>&1

# never a real bot token: the 06.11 webhook-hijack trap
grep -q '^DFIR_TG_BOT_TOKEN=100000001:STUB_' "$ANS" || { echo "ABORT: answers must use the stub Telegram token"; exit 2; }

cd $ROOT
HEAD=$(git rev-parse --short HEAD)
echo "== T8 cell $CELL on $IMG, repo HEAD $HEAD, $(date -Is)"
rm -rf /tmp/t8exp; python3 tools/export_github.py --out /tmp/t8exp > /tmp/t8exp.log 2>&1 || { echo "export failed"; tail -5 /tmp/t8exp.log; exit 1; }
tar czf /tmp/t8repo.tgz -C /tmp/t8exp .

incus delete -f $N >/dev/null 2>&1
# Docker 29.x / runc inside a privileged LXC needs writable /proc/sys
incus init $IMG $N -c security.nesting=true -c security.privileged=true \
  -c security.syscalls.intercept.mknod=true -c security.syscalls.intercept.setxattr=true -c limits.memory=20GiB >/dev/null || exit 1
printf 'lxc.apparmor.profile=unconfined\nlxc.mount.auto=proc:rw sys:rw cgroup:rw\n' | incus config set $N raw.lxc -
incus start $N
for i in $(seq 1 60); do timeout 5 incus exec $N -- getent hosts github.com >/dev/null 2>&1 && break; sleep 3; done
OS=$(incus exec $N -- sh -c '. /etc/os-release; echo "$ID-$VERSION_ID"')
echo "guest OS: $OS"
# a minimal image may lack python3/curl/git: that is the installer's job, but its bootstrap needs bash + tar
incus exec $N -- mkdir -p /opt/dfir-vao
incus file push -q /tmp/t8repo.tgz $N/root/repo.tgz
incus exec $N -- tar xzf /root/repo.tgz -C /opt/dfir-vao
incus file push -q "$ANS" $N/root/ans.env
# Telegram stub runs on the TEST HOST (incus bridge), not in the guest: a minimal image (Debian 12)
# has no python3 before install.sh brings it, and the guest must stay exactly as the distro ships it.
BR=$(ip -4 -o addr show incusbr0 | awk '{print $4}' | cut -d/ -f1); TGP=$((18100 + RANDOM % 100))
python3 $ROOT/installer/guest/test_tg_stub.py $TGP $BR > $LOGD/$CELL.stub.log 2>&1 & STUBPID=$!
trap 'kill $STUBPID 2>/dev/null' EXIT; sleep 1
t0=$(date +%s)
incus exec $N --env TGSTUB=$BR:$TGP -- bash -c 'cd /opt/dfir-vao
  DFIR_TG_API=http://$TGSTUB timeout 7000 ./install.sh --answers /root/ans.env < /dev/null > /root/install.out 2>&1; echo $? > /root/install.rc'
RC=$(incus exec $N -- cat /root/install.rc)
echo "install rc=$RC in $(( ($(date +%s)-t0)/60 )) min"
incus exec $N -- bash -c 'grep -aiE "warn|skipped|failed|error" /root/install.out | tail -15'

incus exec $N -- bash /opt/dfir-vao/installer/guest/verify_install.sh /opt/dfir-vao > /tmp/t8verify.out 2>&1; VRC=$?
cat /tmp/t8verify.out; VER=$(tail -2 /tmp/t8verify.out | grep -o 'verify: .*')

# one real completion through the bot's endpoint (whatever mode is behind it)
LLM=$(incus exec $N -- docker exec case-maintainer python3 -c '
import json, os, urllib.request
u = os.environ.get("DFIR_LLM_URL", "http://172.17.0.1:1234").rstrip("/")
ms = [m["id"] for m in json.load(urllib.request.urlopen(u + "/v1/models", timeout=30))["data"]]
m = "gpt-small-20b" if "gpt-small-20b" in ms else ms[0]
b = json.dumps({"model": m, "max_tokens": 400, "messages": [{"role": "user", "content": "Reply with the single word: pong"}]}).encode()
r = json.load(urllib.request.urlopen(urllib.request.Request(u + "/v1/chat/completions", b, {"Content-Type": "application/json"}), timeout=300))
c = (r["choices"][0]["message"].get("content") or "").strip()
print(("ok" if "pong" in c.lower() else "bad") + " model=" + m + " reply=" + c[:40].replace(" ", "_"))
' 2>&1 | tail -1)
echo "llm round-trip: $LLM"

res=PASS
[ "$RC" = 0 ] || res=FAIL; [ "$VRC" = 0 ] || res=FAIL; case "$LLM" in ok*) ;; *) res=FAIL ;; esac
echo "telegram stub calls: $(grep -c 'stub call' $LOGD/$CELL.stub.log)"
echo "T8 CELL $CELL HEAD $HEAD OS $OS install_rc=$RC $VER llm=${LLM%% *} => $res"
if [ "$KEEP" != keep ]; then incus delete -f $N >/dev/null 2>&1 && echo "container $N deleted"; fi
df -h / | tail -1; free -g | sed -n 2p
[ "$res" = PASS ]
