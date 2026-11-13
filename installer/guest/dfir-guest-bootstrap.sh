#!/usr/bin/env bash
# DFIR VAO guest bootstrap: the first start of a Linux made by DFIR VAO VM Wizard (WSL2, VMware,
# Hyper-V, VirtualBox). Fetches the project, then runs install.sh --answers with what the wizard
# collected on Windows (Host Agent address + token, Telegram, accounts). Runs once; a later start
# after success does nothing, a start after a failure tries again (install.sh resumes).
#
#   /etc/dfir-wizard/wizard.env           REPO_SRC  file (.tar.gz / .bundle) or git URL
#                                         REPO_REF  branch or tag for a git URL (optional)
#                                         DEST      install directory (default /opt/dfir-vao)
#                                         TEST_TG_STUB=1  install test only: local Telegram stub
#   /etc/dfir-wizard/install_answers.env  answers; __GATEWAY__ becomes this guest's default gateway
#                                         (under WSL2 NAT that is the Windows host)
# Progress: /var/lib/dfir-wizard/status (fetching | installing | ok | failed:<rc>), log /var/log/dfir-wizard.log
set -uo pipefail
CONF=/etc/dfir-wizard
STATE=/var/lib/dfir-wizard
LOG=/var/log/dfir-wizard.log
mkdir -p "$STATE"; chmod 700 "$CONF" "$STATE" 2>/dev/null
exec >> "$LOG" 2>&1
status() {
  echo "$1" > "$STATE/status"; echo "[$(date -Is)] status: $1"
  # VMware / VirtualBox / Hyper-V: the wizard on Windows reads the serial port log
  [ -w /dev/ttyS0 ] && ! grep -qi microsoft /proc/sys/kernel/osrelease && echo "DFIR-WIZARD-STATUS: $1" > /dev/ttyS0 2>/dev/null || true
}
[ "$(cat "$STATE/status" 2>/dev/null)" = ok ] && { echo "already installed"; exit 0; }
[ -f "$CONF/wizard.env" ] || { status "failed:no-wizard.env"; exit 2; }
. "$CONF/wizard.env"
DEST=${DEST:-/opt/dfir-vao}

# network first: a cloud image may start before DHCP / DNS answer
status waiting-network
for i in $(seq 1 120); do
  getent hosts github.com >/dev/null 2>&1 && break
  sleep 5
done

status fetching
export DEBIAN_FRONTEND=noninteractive
command -v git >/dev/null || { apt-get update -qq && apt-get install -y -qq git ca-certificates curl; }
if [ ! -x "$DEST/install.sh" ]; then
  rm -rf "$DEST.part"; mkdir -p "$DEST.part"
  case "$REPO_SRC" in
    *.tar.gz|*.tgz) tar -xzf "$REPO_SRC" -C "$DEST.part" || { status failed:unpack; exit 3; } ;;
    *.bundle)       rmdir "$DEST.part"; git clone -q "$REPO_SRC" "$DEST.part" || { status failed:clone; exit 3; } ;;
    *)              rmdir "$DEST.part"
                    git clone -q --depth 1 ${REPO_REF:+--branch "$REPO_REF"} "$REPO_SRC" "$DEST.part" || { status failed:clone; exit 3; } ;;
  esac
  # a tarball may hold one top directory
  if [ ! -f "$DEST.part/install.sh" ] && [ "$(ls -A "$DEST.part" | wc -l)" = 1 ]; then
    top="$DEST.part/$(ls -A "$DEST.part")"; mv "$top" "$DEST.next"; rmdir "$DEST.part"; mv "$DEST.next" "$DEST.part"
  fi
  [ -f "$DEST.part/install.sh" ] || { status failed:no-install.sh; exit 3; }
  mv "$DEST.part" "$DEST"
fi

# the gateway placeholder: WSL2 NAT gives the Windows host a new address on every Windows start
gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
ans="$STATE/install_answers.env"
( umask 077; sed "s/__GATEWAY__/${gw:-127.0.0.1}/g" "$CONF/install_answers.env" > "$ans" )

if [ "${TEST_TG_STUB:-0}" = 1 ]; then
  python3 "$DEST/installer/guest/test_tg_stub.py" 18081 >> "$STATE/tg_stub.log" 2>&1 &
  export DFIR_TG_API=http://127.0.0.1:18081
  sleep 1
fi

status installing
cd "$DEST"
./install.sh --answers "$ans" < /dev/null
rc=$?
if [ $rc = 0 ]; then status ok; else status "failed:$rc"; fi
[ "${TEST_TG_STUB:-0}" = 1 ] && kill %1 2>/dev/null
exit $rc
