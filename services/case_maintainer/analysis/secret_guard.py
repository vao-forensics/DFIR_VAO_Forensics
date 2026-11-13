# -*- coding: utf-8 -*-
"""Нічого секретного не виходить із бота назовні.

НАВІЩО. Після того, як інструмент-скрипт посадили під безправного користувача, модель уже
не може прочитати приватний ключ. Але залишковий ризик є завжди: у промпт аналізу йде текст
із досліджуваної машини, тобто підкинутий зловмисником рядок може спробувати змусити модель
щось «переказати». Тому на самому виході стоїть остання перевірка: якщо в тексті, який бот
збирається надіслати, трапився наш секрет — він не піде.

Це не фільтр здогадок і не список слів. Він шукає рівно ті рядки, які в нас справді є:
приватний ключ (шматками, щоб спіймати і часткову витікшу копію), токен бота, пароль до бази,
службовий токен. Нічого іншого він не чіпає — доказовий текст має доходити до слідчого
недоторканим.

Спрацювання — це подія безпеки: пишемо гучно в лог, бо означає, що щось у системі спробувало
винести секрет назовні.
"""
import io
import logging
import os
import re

_log = logging.getLogger(__name__)

KEY_DIRS = ('/data/state/keys', '/srv/dfir/state/keys')
PRIV_NAME = 'collector_private.pem'

# Загальний вигляд будь-якого приватного ключа — навіть не нашого: у звіті йому не місце.
_PEM_RX = re.compile(
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
    re.S)

_NEEDLES = None          # [(підрядок, чим замінити)]
_MIN_NEEDLE = 24


def _slices(blob, size=48, step=48):
    """Шматки секрету замість цілого: часткова витік теж має спрацьовувати.

    Кроком 48 при довжині 48 шматки йдуть щільно, без перекриття, тому будь-який суцільний
    уривок ключа завдовжки від ~95 символів обовʼязково містить цілий шматок і буде спіймано.
    З кроком 256 (перша версія) уривок на 100 символів проходив повз - знайдено тестом.
    """
    out = []
    for i in range(0, max(1, len(blob) - size), step):
        piece = blob[i:i + size]
        if len(piece) >= _MIN_NEEDLE:
            out.append(piece)
    return out


def _build():
    needles = []

    # 1. приватний ключ збирача - і як є, і без переносів рядків
    for d in KEY_DIRS:
        p = os.path.join(d, PRIV_NAME)
        if not os.path.isfile(p):
            continue
        try:
            text = io.open(p, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        body = ''.join(l.strip() for l in text.splitlines() if 'PRIVATE KEY' not in l)
        for piece in _slices(body):
            needles.append((piece, u'⟨вилучено: приватний ключ⟩'))
        break

    # 2. секрети з оточення - токен бота, пароль до бази, службовий токен
    for env_name, label in (('TG_BOT_TOKEN', u'⟨вилучено: токен бота⟩'),
                            ('MAINTAINER_TOKEN', u'⟨вилучено: службовий токен⟩'),
                            ('NGROK_AUTHTOKEN', u'⟨вилучено: токен тунелю⟩')):
        v = (os.environ.get(env_name) or '').strip()
        if len(v) >= _MIN_NEEDLE:
            needles.append((v, label))

    dsn = (os.environ.get('PG_DSN') or '').strip()
    m = re.search(r'://[^:/@]+:([^@]+)@', dsn)
    if m and len(m.group(1)) >= 8:
        needles.append((m.group(1), u'⟨вилучено: пароль бази⟩'))
    if len(dsn) >= _MIN_NEEDLE:
        needles.append((dsn, u'⟨вилучено: рядок підключення⟩'))

    return needles


def needles():
    global _NEEDLES
    if _NEEDLES is None:
        try:
            _NEEDLES = _build()
        except Exception as e:
            _log.error('[secret_guard] could not build the list: %r', e)
            _NEEDLES = []
    return _NEEDLES


def scrub(text, where=''):
    """Повертає текст без секретів. Якщо щось знайшлося - голосно в лог."""
    if not text:
        return text
    s = str(text)
    hits = []

    if 'PRIVATE KEY' in s:
        s2 = _PEM_RX.sub(u'⟨вилучено: приватний ключ⟩', s)
        if s2 != s:
            hits.append('pem-block')
            s = s2

    for needle, label in needles():
        if needle and needle in s:
            s = s.replace(needle, label)
            hits.append(label)

    if hits:
        # Це подія безпеки, а не дрібниця: щось намагалося винести секрет назовні.
        _log.error('[secret_guard] BLOCKED %s in outgoing text%s',
                   ', '.join(sorted(set(hits))), (' (%s)' % where) if where else '')
    return s


def has_secret(text):
    """Чи є в тексті секрет - без зміни тексту (для перевірок і гардів)."""
    if not text:
        return False
    s = str(text)
    if _PEM_RX.search(s):
        return True
    return any(n and n in s for n, _ in needles())
