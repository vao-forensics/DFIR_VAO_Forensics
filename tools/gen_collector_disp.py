# -*- coding: utf-8 -*-
"""Generate the nginx Content-Disposition include so the collector downloads with a VERSIONED
filename taken from its manifest (vao_collector_v4.3_2026-08-22.exe), and reload nginx. Run at
publish time (path-unit on collector.json) so the download name auto-tracks the latest build."""
import io, json, re, subprocess
try:
    m = json.load(io.open('/srv/dfir/var/dist/collector.json', encoding='utf-8'))
except Exception:
    m = {}
ver = str(m.get('version', '') or '').strip()
safe = re.sub(r'[^A-Za-z0-9._-]+', '_', ver).strip('_')
fname = ('vao_collector_%s.exe' % safe) if safe else 'vao_collector.exe'
inc = ('add_header Content-Disposition \'attachment; filename="%s"\';\n'
       'add_header Cache-Control "no-store";\n' % fname)
io.open('/srv/dfir/src/uploader/nginx/collector_disp.inc', 'w', encoding='utf-8', newline='\n').write(inc)
# validate + reload nginx (keeps running old config if the test fails)
t = subprocess.run(['docker', 'exec', 'dfir-uploader', 'nginx', '-t'], capture_output=True)
if t.returncode == 0:
    subprocess.run(['docker', 'exec', 'dfir-uploader', 'nginx', '-s', 'reload'], capture_output=True)
    print('OK: collector download name ->', fname)
else:
    print('nginx -t FAILED, not reloaded:', (t.stderr or b'').decode('utf-8', 'replace')[:200])
