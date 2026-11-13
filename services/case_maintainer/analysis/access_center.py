#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One record per person, across all three doors: Telegram, the browser chat, the VPN.

Today the three live apart. bot_users says who may talk to the bot; wg-easy holds the
tunnel accounts; Open WebUI has its own user table. Granting access means doing three
things by hand in three places and remembering that they belong together - and revoking
means remembering all three under pressure, which is exactly when things get missed.

WHY A QUEUE AND NOT A DIRECT CALL. The bot runs in a container that cannot reach the VPN
panel - only the VM host can, through the service tunnel, and the panel credentials live
on the host at /root/.dfir_vpn_admin, root-only. Having the bot hold those credentials to
make the call itself would put them inside a container that strangers upload files to. So
the bot writes a REQUEST, and the host job that already talks to the panel every two
minutes carries it out. The credentials never move.

WHAT IS DELIBERATELY NOT STORED:
  * the VPN private key - wg-easy generates it, it is delivered once and never kept here;
  * the browser-chat password - only a hash and the moment it was handed over. If someone
    loses it, it is reset, not looked up. A password that can be retrieved is a password
    that can be stolen from us.
"""
import hashlib
import io
import json
import os
import secrets
import string

SCHEMA = """
CREATE TABLE IF NOT EXISTS public.user_access_v1 (
  user_id        text PRIMARY KEY,
  chat_id        text,
  label          text,
  bot_enabled    boolean NOT NULL DEFAULT false,
  vpn_client_id  text,
  vpn_ip         text,
  vpn_enabled    boolean NOT NULL DEFAULT false,
  vpn_created_at timestamptz,
  webui_email    text,
  webui_pw_hash  text,
  webui_given_at timestamptz,
  granted_by     text,
  granted_at     timestamptz,
  revoked_at     timestamptz,
  notes          text,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- What the bot asks the host to do. The host job is the only thing holding panel
-- credentials, so every VPN action arrives here first.
CREATE TABLE IF NOT EXISTS public.access_requests_v1 (
  id          bigserial PRIMARY KEY,
  created_at  timestamptz NOT NULL DEFAULT now(),
  action      text NOT NULL,           -- grant_vpn | revoke_vpn | reset_vpn
  user_id     text NOT NULL,
  label       text,
  requested_by text,
  status      text NOT NULL DEFAULT 'pending',   -- pending | done | failed
  result      text,
  handled_at  timestamptz
);

-- Who changed whose access, when, and from where. Separate from the request queue on
-- purpose: a queue gets cleaned, an audit trail does not.
CREATE TABLE IF NOT EXISTS public.access_audit_v1 (
  id         bigserial PRIMARY KEY,
  ts         timestamptz NOT NULL DEFAULT now(),
  actor      text,
  action     text NOT NULL,
  user_id    text,
  detail     text
);

CREATE INDEX IF NOT EXISTS idx_access_req_status ON public.access_requests_v1 (status, id);
CREATE INDEX IF NOT EXISTS idx_access_audit_ts ON public.access_audit_v1 (ts DESC);
"""

PW_ALPHABET = string.ascii_letters + string.digits + '!@#$%^&*-_=+'


def ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute(SCHEMA)


def new_password(n=20):
    """A password nobody will guess and nobody has to remember - it is delivered once."""
    return ''.join(secrets.choice(PW_ALPHABET) for _ in range(n))


def pw_hash(password, salt=None):
    """Store proof of the password, never the password.

    scrypt from the standard library: no dependency, and slow enough that a stolen table
    is not a list of accounts.
    """
    salt = salt or secrets.token_hex(16)
    dk = hashlib.scrypt(password.encode('utf-8'), salt=salt.encode('utf-8'),
                        n=16384, r=8, p=1, dklen=32)
    return 'scrypt$%s$%s' % (salt, dk.hex())


def pw_verify(password, stored):
    try:
        _, salt, _hex = stored.split('$', 2)
        return secrets.compare_digest(pw_hash(password, salt), stored)
    except Exception:
        return False


def audit(conn, actor, action, user_id='', detail=''):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO public.access_audit_v1 (actor, action, user_id, detail) "
                    "VALUES (%s,%s,%s,%s)", (str(actor), action, str(user_id), detail[:500]))


def request(conn, action, user_id, label='', requested_by=''):
    """Ask the host to do something with the tunnel. Returns the request id."""
    with conn.cursor() as cur:
        cur.execute("INSERT INTO public.access_requests_v1 (action, user_id, label, "
                    "requested_by) VALUES (%s,%s,%s,%s) RETURNING id",
                    (action, str(user_id), label, str(requested_by)))
        rid = cur.fetchone()[0]
    audit(conn, requested_by, 'request:' + action, user_id, 'request #%d' % rid)
    return rid


def upsert_access(conn, user_id, **fields):
    """Create or update the single row that says what this person may reach."""
    cols = [k for k in fields if k in (
        'chat_id', 'label', 'bot_enabled', 'vpn_client_id', 'vpn_ip', 'vpn_enabled',
        'vpn_created_at', 'webui_email', 'webui_pw_hash', 'webui_given_at',
        'granted_by', 'granted_at', 'revoked_at', 'notes')]
    with conn.cursor() as cur:
        cur.execute("INSERT INTO public.user_access_v1 (user_id) VALUES (%s) "
                    "ON CONFLICT (user_id) DO NOTHING", (str(user_id),))
        if cols:
            sets = ', '.join('%s = %%s' % c for c in cols) + ', updated_at = now()'
            cur.execute("UPDATE public.user_access_v1 SET %s WHERE user_id = %%s" % sets,
                        [fields[c] for c in cols] + [str(user_id)])


def one_time_dir():
    """Where a freshly generated config waits to be handed over exactly once."""
    d = os.environ.get('DFIR_ONETIME_DIR', '/srv/dfir/state/onetime')
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def stash_once(name, content):
    """Write a secret to a root-only file and return its path.

    Used for the VPN config: it exists between "the host generated it" and "the owner
    handed it over", and is removed by whoever delivers it.
    """
    path = os.path.join(one_time_dir(), name)
    with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(content)
    os.chmod(path, 0o600)
    return path


def take_once(path):
    """Read a stashed secret and delete it. Never returns the same thing twice."""
    try:
        data = io.open(path, encoding='utf-8').read()
    except IOError:
        return ''
    try:
        os.remove(path)
    except OSError:
        pass
    return data


if __name__ == '__main__':
    import psycopg2
    dsn = os.environ.get('PG_DSN') or (
        'host=127.0.0.1 port=5433 dbname=dfir_logs user=dfir password=%s'
        % os.environ.get('PGPASSWORD', ''))
    with psycopg2.connect(dsn) as c:
        c.autocommit = True
        ensure_schema(c)
    print('access tables ready')
