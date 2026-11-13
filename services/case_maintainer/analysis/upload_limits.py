# -*- coding: utf-8 -*-
"""What stops one person, or one bad day, from taking the whole machine down.

The realistic way this bot dies is not an attacker - it is load. A tunnel account may
upload 32 GB, and then do it again; the disk holds 315 GB with 94 GB free, so three of
those fill it, and when it fills, Postgres stops and everything else follows. Nothing
counted per person and nothing looked at free space.

Two limits, both measured against what the system actually does:

  * SPACE. An archive is not just stored - it is unpacked and parsed, so the room needed
    is a multiple of its size. Refuse while there is still enough left to work with,
    rather than after the disk is full and the database has already stopped.

  * QUOTA. Per identity, per rolling day. Generous enough that real work never touches it
    (the largest real case archive in the library is 97 MB), tight enough that a script
    cannot run the machine out of disk before anyone notices.

Both refusals name the number and say what to do, because a person who is told "quota
exceeded" and nothing else will simply try again.
"""
import os

RESERVE_BYTES = 25 * 1024 ** 3      # never let an upload eat into the last 25 GB
UNPACK_FACTOR = 3                   # stored + unpacked + parsed artefacts
DAILY_FILES = 25
DAILY_BYTES = 60 * 1024 ** 3
QUARANTINE_MAX = 200 * 1024 ** 2    # above this a refused file is hashed, not copied


class Limit(object):
    def __init__(self, ok, code='', message=''):
        self.ok = ok
        self.code = code
        self.message = message


def _gb(n):
    return n / 1024.0 ** 3


def space_check(path, size_bytes, reserve=RESERVE_BYTES, factor=UNPACK_FACTOR):
    """Is there room to store this AND work with it."""
    try:
        st = os.statvfs(path)
    except OSError:
        return Limit(True)                      # cannot measure: do not block evidence
    free = st.f_bavail * st.f_frsize
    need = int(size_bytes) * factor
    if free - need < reserve:
        return Limit(False, 'no_space',
                     u'На сервері замало місця: вільно %.1f ГБ, а для цього файлу з '
                     u'розпакуванням потрібно близько %.1f ГБ і ще %.0f ГБ запасу. '
                     u'Зверніться до адміністратора - файл не втрачено, його просто не '
                     u'прийнято.' % (_gb(free), _gb(need), _gb(reserve)))
    return Limit(True)


def quota_check(conn, identity, size_bytes, files=DAILY_FILES, cap=DAILY_BYTES):
    """How much this identity has already put in over the last 24 hours.

    identity is whatever names the person - the chat id, or the VPN account when the
    upload came through the tunnel. Counting only ACCEPTED uploads on purpose: a refused
    file cost us nothing but a hash, and refusing someone twice for the same mistake
    would be its own bug.
    """
    if not identity:
        return Limit(True)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT count(*), COALESCE(sum(size_bytes), 0)
                  FROM public.upload_audit_v1
                 WHERE verdict = 'accepted'
                   AND ts > now() - interval '24 hours'
                   AND (chat_id = %s OR vpn_client = %s)""", (str(identity), str(identity)))
            n, total = cur.fetchone() or (0, 0)
    except Exception:
        return Limit(True)                      # bookkeeping must never block evidence
    n, total = int(n or 0), int(total or 0)

    if n + 1 > files:
        return Limit(False, 'quota_files',
                     u'Ліміт на добу вичерпано: %d завантажень із %d. Наступне можна '
                     u'через кілька годин, або попросіть адміністратора підняти ліміт.'
                     % (n, files))
    if total + int(size_bytes) > cap:
        return Limit(False, 'quota_bytes',
                     u'Ліміт обсягу на добу вичерпано: вже %.1f ГБ із %.0f ГБ. '
                     u'Цей файл (%.1f ГБ) не влазить - зачекайте або зверніться до '
                     u'адміністратора.' % (_gb(total), _gb(cap), _gb(size_bytes)))
    return Limit(True)


def should_quarantine(size_bytes):
    """A refused 30 GB archive must not be copied - that is the disk problem twice."""
    try:
        return int(size_bytes) <= QUARANTINE_MAX
    except (TypeError, ValueError):
        return True
