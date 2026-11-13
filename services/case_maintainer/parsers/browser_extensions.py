# -*- coding: utf-8 -*-
"""Which extensions were installed in the victim's browser, and which of them are wrong.

The bot had nothing on this. An extension is the quietest possible foothold: it reads
every page the person opens, survives a password change, needs no process of its own, and
shows up in no execution artefact. The collector now forwards Preferences / Secure
Preferences (Chromium) and extensions.json / addons.json (Firefox), so the question has a
source for the first time.

WHAT IS FLAGGED, and why - these are the two signals that actually separate a normal
browser from a compromised one:

  NOT FROM THE STORE. Chromium records `from_webstore`. An extension that was side-loaded
  - by a dropper, by a policy, by hand - is the single strongest signal here. Ordinary
  users do not side-load.

  PERMISSIONS THAT READ EVERYTHING. `<all_urls>`, `webRequest` + `webRequestBlocking`,
  `cookies`, `nativeMessaging`, `debugger`. Each is legitimate somewhere, so none of them
  is an accusation on its own - they are reported with the extension so an analyst can
  judge, and only the combination raises a flag.

Nothing here decides guilt. It produces rows the report can cite.
"""
import io
import json
import os
import posixpath
import re

FAMILY = 'browser_extensions'

# Permissions that let an extension see or change everything the person does.
LOUD_PERMS = {
    '<all_urls>': 'читає всі сторінки',
    'http://*/*': 'читає всі сторінки',
    'https://*/*': 'читає всі сторінки',
    'webrequest': 'перехоплює запити',
    'webrequestblocking': 'змінює запити на льоту',
    'cookies': 'доступ до сесійних кук',
    'nativemessaging': 'спілкується з програмою поза браузером',
    'debugger': 'керує вкладками як налагоджувач',
    'proxy': 'перенаправляє трафік',
    'downloads': 'керує завантаженнями',
    'management': 'керує іншими розширеннями',
    'history': 'читає історію',
}

_PROFILE = re.compile(r'_raw/browsers/([^/]+)/([^/]+)/(.+)$', re.I)


def _who(rel):
    """user, browser, file - the collector writes _raw/browsers/<user>/<Browser>/<file>."""
    m = _PROFILE.search(rel.replace('\\', '/'))
    if not m:
        return '', '', posixpath.basename(rel.replace('\\', '/'))
    return m.group(1), m.group(2), m.group(3)


def _loud(perms):
    hits = []
    for p in perms or []:
        key = str(p).lower()
        if key in LOUD_PERMS:
            hits.append('%s (%s)' % (p, LOUD_PERMS[key]))
    return hits


# Chromium Manifest::Location - where the extension came from. This, not from_webstore,
# is what separates "the browser shipped it" from "something put it there".
DROPPER_LOCATIONS = {
    2: 'встановлено іншою програмою (файл налаштувань)',
    3: 'встановлено іншою програмою (через реєстр)',
    4: 'завантажено з теки на диску (developer mode)',
}
BUILTIN_LOCATIONS = {1, 5, 6, 8}      # internal / component / external component
POLICY_LOCATIONS = {7, 10}            # put there by an administrator


def _chromium(raw, user, browser, src_name):
    """Preferences / Secure Preferences: extensions.settings is a dict of id -> record.

    Real machines keep a dozen component extensions here with from_webstore absent or
    false; treating that as a finding produces noise on every case, so the flag rests on
    the install location instead.
    """
    out = []
    try:
        data = json.loads(raw)
    except ValueError:
        return out
    settings = (((data.get('extensions') or {}).get('settings')) or {})
    for ext_id, rec in settings.items():
        if not isinstance(rec, dict):
            continue
        manifest = rec.get('manifest') or {}
        if not manifest:
            continue                      # a settings stub, not an installed extension
        name = str(manifest.get('name') or rec.get('path') or '')[:200]
        loc = rec.get('location')
        try:
            loc = int(loc) if loc is not None else None
        except (TypeError, ValueError):
            loc = None
        perms = list(manifest.get('permissions') or []) + \
            list(manifest.get('host_permissions') or [])
        loud = _loud(perms)

        why = []
        if loc in DROPPER_LOCATIONS:
            why.append(DROPPER_LOCATIONS[loc])
        elif loc in POLICY_LOCATIONS:
            why.append('встановлено політикою адміністратора')
        if loud and (loc in DROPPER_LOCATIONS or loc is None):
            why.append('широкі дозволи: ' + '; '.join(loud[:4]))

        out.append({
            'source_file': src_name, 'user': user, 'browser': browser,
            'extension_id': ext_id, 'name': name,
            'version': str(manifest.get('version') or ''),
            'location': loc,
            'builtin': loc in BUILTIN_LOCATIONS,
            'by_policy': loc in POLICY_LOCATIONS,
            'dropped': loc in DROPPER_LOCATIONS,
            'from_webstore': rec.get('from_webstore'),
            'install_time': str(rec.get('install_time') or ''),
            'state': rec.get('state'),
            'path': str(rec.get('path') or '')[:300],
            'permissions': [str(p)[:60] for p in perms][:30],
            'loud_permissions': loud,
            'why': ' · '.join(why),
        })
    return out


def _firefox(raw, user, browser, src_name):
    """extensions.json / addons.json: a list under `addons`."""
    out = []
    try:
        data = json.loads(raw)
    except ValueError:
        return out
    for a in (data.get('addons') or []):
        if not isinstance(a, dict):
            continue
        loc = str(a.get('location') or '')
        perms = list(((a.get('userPermissions') or {}).get('permissions')) or []) + \
            list(((a.get('userPermissions') or {}).get('origins')) or [])
        loud = _loud(perms)
        # app-profile is the normal place; app-system-* are shipped with the browser
        # app-profile is where a user's own add-ons live; app-system-* ship with the
        # browser. Anything else - temporary, external, a directory install - was put
        # there by something.
        sideloaded = loc not in ('app-profile', 'app-system-defaults', 'app-builtin',
                                 'app-system-share', 'app-global', 'app-system-profile',
                                 'app-system-addons', 'app-system-local')
        out.append({
            'source_file': src_name, 'user': user, 'browser': browser,
            'extension_id': str(a.get('id') or ''),
            'name': str(a.get('defaultLocale', {}).get('name') or a.get('id') or '')[:200],
            'version': str(a.get('version') or ''),
            'location': loc,
            'sideloaded': sideloaded,
            'active': a.get('active'),
            'install_time': str(a.get('installDate') or ''),
            'permissions': [str(p)[:60] for p in perms][:30],
            'loud_permissions': loud,
            'why': ('встановлено поза профілем (%s)' % loc if sideloaded else '')
                   + ((' · ' if sideloaded and loud else '')
                      + ('широкі дозволи: ' + '; '.join(loud[:4]) if loud else '')),
        })
    return out


WANTED = ('preferences', 'secure preferences', 'extensions.json', 'addons.json')


def parse_from_zip(zf, all_names):
    """(records, errors) in the shape the ingest already understands."""
    recs, errors = [], []
    for rel in all_names:
        low = rel.replace('\\', '/').lower()
        if '_raw/browsers/' not in low:
            continue
        base = posixpath.basename(low)
        # profiles are written as "<profile>__<file>"
        bare = base.split('__')[-1]
        if bare not in WANTED:
            continue
        user, browser, src_name = _who(rel)
        try:
            raw = zf.read(rel).decode('utf-8', 'replace')
        except Exception as e:
            errors.append('%s: %s' % (base, repr(e)[:80]))
            continue
        try:
            if bare in ('extensions.json', 'addons.json'):
                rows = _firefox(raw, user, browser, src_name)
            else:
                rows = _chromium(raw, user, browser, src_name)
        except Exception as e:
            errors.append('%s: %s' % (base, repr(e)[:80]))
            continue
        for r in rows:
            recs.append((FAMILY, r))
    return recs, errors
