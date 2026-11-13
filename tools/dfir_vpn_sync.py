#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Keep the VPN honest without anyone remembering to.

Two jobs, both of which were manual and therefore going to be forgotten:

1. A NEW CLIENT IS BORN WITH NO LIMITS. wg-easy creates it with firewallIps unset, and
   with the interface firewall on that means "reaches nothing" - so the owner has to open
   the record and type the bot address every single time. Miss it and the person cannot
   work; type the wrong thing and they can reach more than the bot. This sets it.

2. NOBODY KNOWS WHO UPLOADED. The uploader has no login, so the only identity a file
   carries is the tunnel address it came from. This writes the address -> client-name map
   where the bot can read it, so an upload can be attributed to a named VPN account.

Runs on the VM host, not in a container: only the host can reach the panel through the
service tunnel. Credentials live in /root/.dfir_vpn_admin (root-only, 0600).
"""
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request

def _conf():
    """One source for the addresses; see config/network.env."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import net_conf
        return net_conf.load()
    except Exception:
        return {}


_CONF = _conf()
PANEL = os.environ.get('DFIR_VPN_PANEL') or _CONF.get(
    'PANEL_URL', 'http://192.168.100.128:8123')
CREDS = '/root/.dfir_vpn_admin'
STATE = '/srv/dfir/state/vpn_clients.json'
BOT_IP = os.environ.get('DFIR_VPN_BOT_IP') or _CONF.get('BOT_VPN_IP', 'CHANGE_ME_DFIR_LINK_IP')
CLIENT_LIMIT = [BOT_IP + '/32']


def log(msg):
    print('%s [vpn-sync] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg), flush=True)


def _req(path, method='GET', body=None, cookie=''):
    data = json.dumps(body).encode('utf-8') if body is not None else None
    r = urllib.request.Request(PANEL + path, data=data, method=method)
    r.add_header('Content-Type', 'application/json')
    if cookie:
        r.add_header('Cookie', cookie)
    with urllib.request.urlopen(r, timeout=20) as resp:
        raw = resp.read().decode('utf-8', 'replace')
        try:
            return resp, json.loads(raw)
        except ValueError:
            return resp, raw          # a .conf, not JSON



def login():
    user, password = io.open(CREDS, encoding='utf-8').read().strip().split(':', 1)
    resp, _ = _req('/api/auth/password', 'POST',
                   {'username': user, 'password': password, 'remember': True})
    cookies = resp.headers.get_all('Set-Cookie') or []
    jar = '; '.join(c.split(';')[0] for c in cookies)
    if not jar:
        raise RuntimeError('panel accepted the login but sent no session cookie')
    return jar


def _host_dsn(root='/srv/dfir'):
    """The bot's own database login (user=dfir), as seen from the host.

    24.10.2026: this used to take the FIRST PG_DSN= line of docker-compose.yml. Since 18.10 that
    line belongs to dfir-mcp - the read-only role, with its password written as
    ${MCP_PG_PASSWORD} - so every login failed and VPN access requests / RAM jobs silently
    stopped. Now: the line whose user is dfir, with ${VAR} filled in from .env.
    """
    import re as _re
    env = {}
    try:
        for line in io.open(root + '/.env', encoding='utf-8'):
            if '=' in line and not line.lstrip().startswith('#'):
                k, v = line.rstrip('\n').split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except IOError:
        pass
    cands = []
    if env.get('PG_DSN'):
        cands.append(env['PG_DSN'])
    try:
        for line in io.open(root + '/docker-compose.yml', encoding='utf-8'):
            line = line.strip().lstrip('-').strip()
            if line.startswith('PG_DSN='):
                cands.append(line.split('=', 1)[1].strip())
    except IOError:
        pass
    for d in cands:
        if _re.search(r'\buser=dfir\b', d):
            d = _re.sub(r'\$\{(\w+)(?::-([^}]*))?\}', lambda m: env.get(m.group(1), m.group(2) or ''), d)
            return d.replace('host=logdb', 'host=127.0.0.1').replace('port=5432', 'port=5433')
    return ''


def _dsn():
    d = _host_dsn()
    if not d:
        log('NO DATABASE: no PG_DSN with user=dfir in .env or docker-compose.yml - access requests '
            'cannot be carried out')
    return d


def _client_by_name(clients, name):
    for c in clients:
        if str(c.get('name') or '') == name:
            return c
    return None


OWNER_CHAT = 'CHANGE_ME_OWNER_CHAT_ID'
BOT_TOKEN_FILE = '/root/.dfir_bot_token'


def _deliver(path, label, ip):
    """Send the config to the owner as a file, and remove it once it is gone."""
    try:
        token = io.open(BOT_TOKEN_FILE, encoding='utf-8').read().strip()
    except IOError:
        log('no bot token: the config for %s stays at %s' % (label, path))
        return False
    try:
        body = io.open(path, encoding='utf-8').read()
    except IOError:
        return False

    boundary = '----dfirvpn%d' % int(time.time() * 1000)
    caption = (u'\U0001f510 VPN для: %s\nадреса в тунелі: %s\n\n'
               u'Перешліть цей файл людині. Він містить приватний ключ і більше ніде '
               u'не зберігається - після цього повідомлення файл видалено з сервера.'
               % (label, ip or '-'))
    parts = []
    for k, v in (('chat_id', OWNER_CHAT), ('caption', caption)):
        parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                      % (boundary, k, v)).encode('utf-8'))
    parts.append(('--%s\r\nContent-Disposition: form-data; name="document"; '
                  'filename="%s.conf"\r\nContent-Type: text/plain\r\n\r\n'
                  % (boundary, label.replace(' ', '_')[:40])).encode('utf-8'))
    parts.append(body.encode('utf-8'))
    parts.append(('\r\n--%s--\r\n' % boundary).encode('utf-8'))
    data = b''.join(parts)

    req = urllib.request.Request(
        'https://api.telegram.org/bot%s/sendDocument' % token, data=data,
        headers={'Content-Type': 'multipart/form-data; boundary=%s' % boundary})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            ok = b'"ok":true' in r.read()
    except Exception as e:
        log('could not deliver the config for %s: %s' % (label, repr(e)[:120]))
        return False
    if ok:
        try:
            os.remove(path)
        except OSError:
            pass
        log('config for %s delivered to the owner and removed from disk' % label)
    return ok


def process_requests(jar):
    """Carry out what the bot asked for, and write back what happened."""
    dsn = _dsn()
    if not dsn:
        return
    try:
        import psycopg2
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import access_center as ac
    except Exception as e:
        log('cannot reach the request queue: %s' % repr(e)[:120])
        return

    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    ac.ensure_schema(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT id, action, user_id, label, requested_by "
                    "FROM public.access_requests_v1 WHERE status='pending' "
                    "ORDER BY id LIMIT 20")
        pending = cur.fetchall() or []

    if not pending:
        conn.close()
        return

    _, clients = _req('/api/client', cookie=jar)
    for rid, action, user_id, label, requested_by in pending:
        name = (label or ('user-%s' % user_id))[:60]
        status, result = 'failed', ''
        try:
            if action == 'grant_vpn':
                existing = _client_by_name(clients, name)
                if existing is None:
                    _req('/api/client', 'POST', {'name': name, 'expiresAt': None}, cookie=jar)
                    _, clients = _req('/api/client', cookie=jar)
                    existing = _client_by_name(clients, name)
                if existing is None:
                    raise RuntimeError('panel accepted the client but did not list it')
                cid = existing.get('id')
                body = dict(existing)
                for k in ('id', 'userId', 'interfaceId', 'publicKey', 'createdAt',
                          'updatedAt', 'oneTimeLink', 'latestHandshakeAt', 'endpoint',
                          'transferRx', 'transferTx'):
                    body.pop(k, None)
                body['firewallIps'] = CLIENT_LIMIT
                body['enabled'] = True
                _req('/api/client/%s' % cid, 'POST', body, cookie=jar)
                _, conf = _req('/api/client/%s/configuration' % cid, cookie=jar)
                # The private key exists in this file and nowhere else of ours: it is
                # stashed root-only for one delivery and removed by whoever delivers it.
                path = ac.stash_once('vpn_%s_%s.conf' % (user_id, int(time.time())),
                                     conf if isinstance(conf, str) else str(conf))
                ac.upsert_access(conn, user_id, label=name, vpn_client_id=str(cid),
                                 vpn_ip=str(existing.get('ipv4Address') or ''),
                                 vpn_enabled=True, vpn_created_at='now()' if False else None,
                                 granted_by=str(requested_by))
                with conn.cursor() as cur:
                    cur.execute("UPDATE public.user_access_v1 SET vpn_created_at=now(), "
                                "granted_at=COALESCE(granted_at, now()) WHERE user_id=%s",
                                (str(user_id),))
                if _deliver(path, name, str(existing.get('ipv4Address') or '')):
                    status, result = 'done', 'delivered to the owner'
                else:
                    status, result = 'done', path   # kept for manual pickup

            elif action in ('revoke_vpn', 'reset_vpn'):
                existing = _client_by_name(clients, name)
                if existing is None:
                    status, result = 'done', 'no such client'
                else:
                    body = dict(existing)
                    for k in ('id', 'userId', 'interfaceId', 'publicKey', 'createdAt',
                              'updatedAt', 'oneTimeLink', 'latestHandshakeAt', 'endpoint',
                              'transferRx', 'transferTx'):
                        body.pop(k, None)
                    body['enabled'] = False
                    _req('/api/client/%s' % existing.get('id'), 'POST', body, cookie=jar)
                    ac.upsert_access(conn, user_id, vpn_enabled=False)
                    with conn.cursor() as cur:
                        cur.execute("UPDATE public.user_access_v1 SET revoked_at=now() "
                                    "WHERE user_id=%s", (str(user_id),))
                    status, result = 'done', 'disabled'
            else:
                result = 'unknown action'
        except Exception as e:
            result = repr(e)[:200]
            log('request #%s (%s for %s) failed: %s' % (rid, action, user_id, result))

        with conn.cursor() as cur:
            cur.execute("UPDATE public.access_requests_v1 SET status=%s, result=%s, "
                        "handled_at=now() WHERE id=%s", (status, result[:500], rid))
        ac.audit(conn, 'vpn-sync', '%s:%s' % (action, status), user_id, result[:200])
        log('request #%s %s -> %s' % (rid, action, status))
    conn.close()


def main():
    try:
        jar = login()
    except Exception as e:
        log('LOGIN FAILED: %s' % repr(e)[:160])
        return 1

    _, clients = _req('/api/client', cookie=jar)
    if not isinstance(clients, list):
        log('unexpected client list: %s' % repr(clients)[:120])
        return 1

    fixed, mapping = [], {}
    for c in clients:
        ip = str(c.get('ipv4Address') or '')
        name = str(c.get('name') or '')
        if ip:
            mapping[ip] = {'name': name, 'id': c.get('id'), 'enabled': bool(c.get('enabled')),
                           'created': str(c.get('createdAt') or '')}
        if ip == BOT_IP:
            continue                      # the bot answers everyone; it is not a user
        if c.get('firewallIps'):
            continue
        body = dict(c)
        for k in ('id', 'userId', 'interfaceId', 'publicKey', 'createdAt', 'updatedAt',
                  'oneTimeLink', 'latestHandshakeAt', 'endpoint', 'transferRx', 'transferTx'):
            body.pop(k, None)
        body['firewallIps'] = CLIENT_LIMIT
        try:
            _req('/api/client/%s' % c.get('id'), 'POST', body, cookie=jar)
            fixed.append('%s (%s)' % (name, ip))
        except Exception as e:
            log('could not limit %s (%s): %s' % (name, ip, repr(e)[:120]))

    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    io.open(tmp, 'w', encoding='utf-8').write(json.dumps(
        {'updated': int(time.time()), 'panel': PANEL, 'clients': mapping},
        ensure_ascii=False, indent=1))
    os.replace(tmp, STATE)

    try:
        process_requests(jar)
    except Exception as e:
        log('request queue error: %s' % repr(e)[:160])

    if fixed:
        log('limited to the bot only: %s' % ', '.join(fixed))
    return 0


if __name__ == '__main__':
    sys.exit(main())
