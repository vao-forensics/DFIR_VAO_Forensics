# -*- coding: utf-8 -*-
"""Create and disable browser-chat accounts, so granting access is one action.

Open WebUI keeps its own user table, which is why giving somebody access used to mean
doing a third thing by hand and inventing a password. It has an admin API - /api/v1/auths/add
answers 401 rather than 404, so the endpoint is there and only wants a key.

The key lives at /root/.dfir_webui_key, root-only, and is read at call time rather than
imported: until the owner creates one, everything else still works and this part reports
that it is not configured instead of failing the whole grant.

The generated password is returned to the caller ONCE and never written down here. What
goes in our database is a hash; what goes to the owner is a message they forward.
"""
import io
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get('DFIR_WEBUI_INTERNAL', 'http://open-webui:8080')
KEY_FILE = os.environ.get('DFIR_WEBUI_KEY_FILE', '/webui_key/key')


class WebuiResult(object):
    def __init__(self, ok, detail='', email='', password=''):
        self.ok = ok
        self.detail = detail
        self.email = email
        self.password = password


def _key():
    try:
        return io.open(KEY_FILE, encoding='utf-8').read().strip()
    except IOError:
        return ''


def configured():
    return bool(_key())


def _call(path, body=None, method='POST', timeout=25):
    key = _key()
    if not key:
        raise RuntimeError('no admin key')
    data = json.dumps(body).encode('utf-8') if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', 'Bearer ' + key)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode('utf-8', 'replace')
        try:
            return json.loads(raw)
        except ValueError:
            return {'raw': raw[:200]}


def create_user(email, name, password, role='user'):
    """Add one account. Returns what the owner needs to pass on, or why it did not work."""
    if not configured():
        return WebuiResult(False, 'admin key not configured')
    try:
        res = _call('/api/v1/auths/add',
                    {'name': name, 'email': email, 'password': password, 'role': role})
        if isinstance(res, dict) and (res.get('id') or res.get('email') or res.get('token')):
            return WebuiResult(True, 'created', email, password)
        return WebuiResult(False, 'unexpected answer: %s' % str(res)[:160])
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:200]
        if e.code == 400 and 'exist' in detail.lower():
            return WebuiResult(False, 'account already exists')
        return WebuiResult(False, 'HTTP %s: %s' % (e.code, detail))
    except Exception as e:
        return WebuiResult(False, repr(e)[:180])


def set_role(email, role):
    """Demote to 'pending' to lock somebody out without deleting their history."""
    if not configured():
        return WebuiResult(False, 'admin key not configured')
    try:
        users = _call('/api/v1/users/', method='GET')
        uid = ''
        for u in (users if isinstance(users, list) else users.get('users', [])):
            if str(u.get('email', '')).lower() == email.lower():
                uid = u.get('id')
                break
        if not uid:
            return WebuiResult(False, 'no such account')
        _call('/api/v1/users/%s/update' % uid, {'role': role})
        return WebuiResult(True, 'role set to %s' % role, email)
    except Exception as e:
        return WebuiResult(False, repr(e)[:180])
