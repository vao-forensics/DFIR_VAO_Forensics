# -*- coding: utf-8 -*-
"""A folder per person, so "what did this one do" is also a place, not only a query.

Everything a user touches today lands in a shared pile: audio results in one directory,
translations in another, uploads inside whichever case they named. Nothing on disk says
whose it is - the answer lives in the database, and only for what we thought to record.

users/<user_id>__<label>/
    README.md    who this is, when access was granted and by whom
    uploads/     what they sent - as LINKS into the case library
    results/     reports and exports produced for them
    audio/       output of the audio tools
    docs/        translations and books they asked for
    access/      the provisioning record: which VPN account, which chat account, no secrets

LINKS, NOT COPIES. Evidence must exist once: two copies of a 97 MB archive is not tidiness,
it is a second thing to keep in sync and a second thing to forget when deleting. A symlink
costs nothing and points at the file in the case library, which stays the single original.
"""
import io
import logging
import os
import re
import time

_log = logging.getLogger('app')

ROOT = os.environ.get('DFIR_USERS_DIR', '/data/users')
KINDS = ('uploads', 'results', 'audio', 'docs', 'access')
_SAFE = re.compile(r'[^A-Za-z0-9_.-]+')


def _slug(text, cap=40):
    from core.case_name import _translit  # same rules as case names, one convention
    s = _translit(str(text or ''))
    s = _SAFE.sub('_', s).strip('._-')
    return s[:cap]


def folder_name(user_id, label=''):
    uid = _SAFE.sub('', str(user_id or 'unknown'))
    lab = _slug(label)
    return '%s__%s' % (uid, lab) if lab else str(uid)


def find(user_id):
    """An existing folder for this id, whatever label it was created with."""
    uid = _SAFE.sub('', str(user_id or ''))
    if not uid or not os.path.isdir(ROOT):
        return ''
    for name in os.listdir(ROOT):
        if name == uid or name.startswith(uid + '__'):
            return os.path.join(ROOT, name)
    return ''


def ensure(user_id, label='', granted_by='', note=''):
    """Create the folder if it is not there. Returns its path; never raises."""
    try:
        existing = find(user_id)
        if existing:
            return existing
        path = os.path.join(ROOT, folder_name(user_id, label))
        for k in KINDS:
            os.makedirs(os.path.join(path, k), exist_ok=True)
        readme = os.path.join(path, 'README.md')
        if not os.path.exists(readme):
            io.open(readme, 'w', encoding='utf-8', newline='\n').write(
                u'# Користувач %s\n\n'
                u'| | |\n|---|---|\n'
                u'| Підпис | %s |\n| Telegram id | %s |\n| Заведено | %s |\n'
                u'| Ким | %s |\n\n%s\n'
                u'## Що тут лежить\n\n'
                u'- `uploads/` — посилання на файли, які ця людина завантажила '
                u'(оригінали лишаються в бібліотеці справ)\n'
                u'- `results/` — звіти й вивантаження, зроблені для неї\n'
                u'- `audio/` — результати аудіоінструментів\n'
                u'- `docs/` — переклади й книги на її запит\n'
                u'- `access/` — запис про доступи: який акаунт VPN, який акаунт чату '
                u'(без паролів і ключів)\n'
                % (user_id, label or u'—', user_id,
                   time.strftime('%Y-%m-%d %H:%M'), granted_by or u'—',
                   (note + '\n\n') if note else ''))
        return path
    except Exception as e:
        # LOUD on purpose: a folder that silently fails to appear is how "everything is
        # tidy" becomes a lie nobody notices for weeks.
        _log.error('[user-space] could not create the folder for %s: %s',
                   user_id, repr(e)[:160])
        return ''


# What the bot calls a path and what a person browsing the disk calls it are not the
# same string. The folders exist to be READ BY PEOPLE, so the links must resolve on the
# host; inside the container nobody opens them.
_HOST_MAP = (('/data/case_library', '/srv/dfir/cases'),
             ('/data/quarantine', '/srv/dfir/var/quarantine'),
             ('/data/users', '/srv/dfir/users'),
             ('/data/state', '/srv/dfir/state'),
             ('/tusd_uploads', '/srv/dfir/var/uploads'),
             ('/audio_results', '/srv/dfir/var/audio_results'),
             ('/translate_output', '/srv/dfir/var/translate_output'))


def host_path(path):
    for a, b in _HOST_MAP:
        if (path or '').startswith(a):
            return b + path[len(a):]
    return path


def link(user_id, kind, src_path, label=''):
    """Point at something of theirs without copying it."""
    if kind not in KINDS:
        return ''
    base = ensure(user_id, label)
    if not base or not src_path:
        return ''
    try:
        name = os.path.basename(src_path)
        dst = os.path.join(base, kind, name)
        if os.path.lexists(dst):
            stem, ext = os.path.splitext(name)
            dst = os.path.join(base, kind, '%s_%s%s' % (stem, time.strftime('%H%M%S'), ext))
        os.symlink(host_path(src_path), dst)
        return dst
    except Exception:
        return ''


def note(user_id, kind, text, label=''):
    """One line in that section's index - what happened, when."""
    base = ensure(user_id, label)
    if not base:
        return ''
    try:
        idx = os.path.join(base, kind if kind in KINDS else 'results', 'index.md')
        with io.open(idx, 'a', encoding='utf-8', newline='\n') as fh:
            fh.write(u'- %s — %s\n' % (time.strftime('%Y-%m-%d %H:%M'), text))
        return idx
    except Exception:
        return ''
