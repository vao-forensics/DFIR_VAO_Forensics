# -*- coding: utf-8 -*-
"""Give the people who are already here the folder that new ones will get automatically.

Thirty-three accounts exist in bot_users, from before there was anywhere to put their
things. Creating the folders now means the structure is true for everyone rather than
only for whoever arrives next.
"""
import sys

sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN
from analysis import user_space as us

conn = psycopg2.connect(PG_DSN)
with conn.cursor() as cur:
    cur.execute("SELECT user_id, COALESCE(username, ''), COALESCE(first_name, ''), enabled "
                "FROM public.bot_users ORDER BY user_id")
    rows = cur.fetchall() or []

made, existed, failed = 0, 0, []
for uid, username, first_name, enabled in rows:
    label = username or first_name or ''
    before = us.find(str(uid))
    path = us.ensure(str(uid), label, granted_by='backfill')
    if not path:
        failed.append(str(uid))
    elif before:
        existed += 1
    else:
        made += 1
        us.note(str(uid), 'access',
                u'тека заведена ретроспективно; стан у боті: %s'
                % (u'увімкнений' if enabled else u'вимкнений'))

print('користувачів у базі: %d' % len(rows))
print('  створено тек: %d' % made)
print('  вже було:     %d' % existed)
if failed:
    print('  НЕ ВДАЛОСЯ:   %s' % ', '.join(failed[:10]))
