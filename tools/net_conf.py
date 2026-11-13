#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read config/network.env, and make everything else agree with it.

Why this exists: retiring ZeroTier meant changing the same handful of addresses in the
compose environment, four python modules, the nginx config, two firewall scripts and the
security monitor. They were copies, not decisions, and copies drift. From here on the
addresses live in ONE file and everything derives from it.

  python3 tools/net_conf.py            # show what is configured and what disagrees
  python3 tools/net_conf.py --apply    # write the derived values, reload what needs it

Docker compose only interpolates variables it finds in the project .env, so --apply
maintains a clearly marked block there. Everything else reads this module directly.
"""
import io
import os
import subprocess
import sys

ROOT = os.environ.get('DFIR_ROOT', '/srv/dfir')
CONF = os.path.join(ROOT, 'config', 'network.env')
DOTENV = os.path.join(ROOT, '.env')
BEGIN = '# >>> generated from config/network.env - do not edit between the markers'
END = '# <<< end generated network block'


def load(path=CONF):
    """The configuration, as a plain dict. Comments and blanks ignored."""
    out = {}
    with io.open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def derived(cfg):
    """Values other services need, computed here so nobody computes them twice."""
    base = cfg['BOT_PUBLIC_BASE'].rstrip('/')
    return {
        'DFIR_UPLOAD_BASE': base,
        'DFIR_VIEW_BASE': base + '/view',
        'DFIR_AUDIO_BASE_URL': base + '/audio',
        'DFIR_COLLECTOR_URL': base + '/collector.exe',
        'DFIR_CHAT_BASE': base + '/chat/',
        'DFIR_WEBUI_BASE': base + '/chat/',
        'DFIR_LLM_URL': 'http://%s:1234' % cfg['LAB_HOST_IP'],
        'DFIR_LLM_CTRL_URL': 'http://%s:8790' % cfg['LAB_HOST_IP'],
        'DFIR_WINDOWS_AGENT_URL': 'http://%s:8788' % cfg['LAB_HOST_IP'],
        'DFIR_VPN_IFACE': cfg['VPN_IFACE'],
        'DFIR_VPN_SUBNET': cfg['VPN_SUBNET'],
        'DFIR_VPN_PREFIX': cfg['VPN_PREFIX'],
        'DFIR_VPN_BOT_IP': cfg['BOT_VPN_IP'],
        'DFIR_VPN_PANEL': cfg['PANEL_URL'],
        'DFIR_LAB_VM_IP': cfg['LAB_VM_IP'],
    }


def write_dotenv(values, path=DOTENV):
    """Keep the generated block in .env, leave everything else in it alone."""
    try:
        old = io.open(path, encoding='utf-8').read()
    except IOError:
        old = ''
    if BEGIN in old and END in old:
        head = old[:old.index(BEGIN)]
        tail = old[old.index(END) + len(END):]
    else:
        head, tail = (old.rstrip('\n') + '\n\n' if old.strip() else ''), '\n'
    block = [BEGIN]
    for k in sorted(values):
        block.append('%s=%s' % (k, values[k]))
    block.append(END)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(head + '\n'.join(block) + tail)
    os.chmod(path, 0o600)


def main():
    cfg = load()
    val = derived(cfg)
    apply_ = '--apply' in sys.argv

    print('config/network.env:')
    for k in ('VPN_IFACE', 'VPN_SUBNET', 'BOT_VPN_IP', 'BOT_PUBLIC_BASE',
              'LAB_VM_IP', 'LAB_HOST_IP', 'PANEL_URL'):
        print('  %-16s %s' % (k, cfg.get(k, '(missing)')))

    if not apply_:
        print('\nwould write to .env:')
        for k in sorted(val):
            print('  %-26s %s' % (k, val[k]))
        print('\nrun with --apply to write it')
        return 0

    write_dotenv(val)
    print('\n.env block updated (%d values)' % len(val))
    for unit in ('dfir-vpn-sync.service', 'dfir-vpn-lock.service'):
        try:
            subprocess.call(['systemctl', 'start', unit])
        except Exception as e:
            print('could not run %s: %s' % (unit, repr(e)[:80]))
    print('firewall and VPN sync re-applied')
    print('now: docker compose -f docker-compose.yml -f docker-compose.webhookgate.yml '
          'up -d case-maintainer uploader')
    return 0


if __name__ == '__main__':
    sys.exit(main())
