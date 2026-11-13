#!/bin/bash
# test: sandbox_api retries audit DDL while DB is recovering (simulated via docker shim)
set -u
D=$(mktemp -d); echo 0 > $D/n
cat > $D/docker <<SH
#!/bin/bash
n=\$(cat $D/n); echo \$((n+1)) > $D/n
if [ "\$n" -lt 2 ]; then echo 'FATAL:  the database system is starting up' >&2; exit 2; fi
exec /usr/bin/docker "\$@"
SH
chmod +x $D/docker
PATH=$D:$PATH SBX_BIND=127.0.0.1 SBX_PORT=8792 timeout 35 python3 /srv/dfir/sandbox/sandbox_api.py > $D/log 2>&1
cat $D/log
grep -q 'will retry' $D/log && grep -q 'ready after 2 retries' $D/log && echo "TEST PASS" || echo "TEST FAIL"
rm -rf $D
