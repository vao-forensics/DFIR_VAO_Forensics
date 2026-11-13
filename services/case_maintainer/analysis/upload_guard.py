# -*- coding: utf-8 -*-
"""What is allowed INTO a case, decided before the file becomes evidence.

Until 2026-08-20 the upload path accepted anything: the page has no file filter, tusd
stores whatever arrives, and /store-tusd copied it into the case library. With the VPN
about to be handed to other people that is the widest hole in the system - a wrong file
type breaks a parser, and a deliberately built one is a probe.

TWO RULES THAT SHAPE THIS MODULE

1. The CONTAINER is validated, never the contents. A case archive is SUPPOSED to hold
   malware, PE files, scripts and registry hives - that is the evidence. Blocking those
   would break the product. So: the outer file must be the declared type, and the archive
   must be structurally sane; what is inside is data, not a threat to us.

2. Refusal must say WHY, in a sentence the person who uploaded can act on. "Invalid file"
   is how a user learns nothing and tries again with the same file.

The allowlist is grounded in what the case library actually holds today (measured
2026-08-20: logs = zip + csv, reports/docs/kb = pdf, docx, md, jpeg), not in a guess.
"""
import io
import os
import zipfile

MAX_BYTES = {
    'logs': 34 * 1024 ** 3,
    'raw': 34 * 1024 ** 3,
    'ram': 34 * 1024 ** 3,
    'email': 2 * 1024 ** 3,
    'reports': 512 * 1024 ** 2,
    'docs': 512 * 1024 ** 2,
    'kb': 2 * 1024 ** 3,
    'misc': 512 * 1024 ** 2,
}
DEFAULT_MAX = 512 * 1024 ** 2

# mode -> extensions the pipeline can actually process
ALLOWED = {
    'logs': {'.zip', '.csv', '.evtx'},
    'raw': {'.zip', '.csv', '.evtx'},
    # A memory capture: either the archive the collector builds, or a raw dump.
    'ram': {'.zip', '.dmp', '.raw', '.mem', '.vmem', '.core', '.bin', '.lime'},
    # 2026-10-08: e-mail evidence uploaded into a case (analysis/case_email.py)
    'email': {'.eml', '.msg', '.zip'},
    'reports': {'.pdf', '.docx', '.doc', '.rtf', '.odt', '.txt', '.md', '.jpg', '.jpeg', '.png'},
    'docs': {'.pdf', '.docx', '.doc', '.rtf', '.odt', '.txt', '.md', '.jpg', '.jpeg', '.png'},
    'kb': {'.pdf', '.docx', '.doc', '.rtf', '.odt', '.txt', '.md', '.epub'},
    'misc': {'.pdf', '.docx', '.doc', '.rtf', '.odt', '.txt', '.md', '.jpg', '.jpeg', '.png', '.zip'},
}

# Формати, яких у ТЕКСТОВОМУ файлі бути не може. Довести, що файл - справжній CSV,
# неможливо; довести, що він ним НЕ є, можна завжди, коли всередині відомий бінарний
# формат. Знайдено 19.09: `kape.csv`, який насправді PDF, пройшов ворота й ліг у справу -
# аналіз не запустився, і дізналися про це випадково, через півроку.
_BINARY_IN_TEXT = (
    (b'%PDF', 'PDF'),
    (b'PK\x03\x04', 'ZIP/DOCX'),
    (b'Rar!\x1a\x07', 'RAR'),
    (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'MZ', 'Windows-EXE/DLL'),
    (b'\x7fELF', 'ELF'),
    (b'\xd0\xcf\x11\xe0', 'документ Office (doc/xls)'),
    (b'\xff\xd8\xff', 'JPEG'),
    (b'\x89PNG\r\n\x1a\n', 'PNG'),
    (b'\x1f\x8b', 'GZIP'),
    (b'SQLite format 3', 'база SQLite'),
)
TEXTY_EXT = ('.csv', '.txt', '.md', '.log', '.json')


def _binary_inside(head):
    """Назва каже «текст», а всередині відомий бінарний формат - повертає його назву."""
    for sig, label in _BINARY_IN_TEXT:
        if head.startswith(sig):
            return label
    return ''


# Signatures used to catch a file whose NAME lies about what it is. Formats without a
# reliable magic (txt, md, csv) are deliberately absent - there is nothing to check.
MAGIC = {
    '.zip': [b'PK\x03\x04', b'PK\x05\x06'],
    '.docx': [b'PK\x03\x04'],
    '.odt': [b'PK\x03\x04'],
    '.epub': [b'PK\x03\x04'],
    '.pdf': [b'%PDF'],
    '.doc': [b'\xd0\xcf\x11\xe0'],
    '.rtf': [b'{\\rt'],
    '.jpg': [b'\xff\xd8\xff'],
    '.jpeg': [b'\xff\xd8\xff'],
    '.png': [b'\x89PNG\r\n\x1a\n'],
    '.evtx': [b'ElfFile\x00'],
}

# A container that is NOT what it claims, named so the message can be specific.
FOREIGN = [
    (b'Rar!\x1a\x07', 'RAR'),
    (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'\x1f\x8b', 'GZIP'),
    (b'MZ', 'Windows-EXE/DLL'),
    (b'\x7fELF', 'ELF'),
    (b'\xfd7zXZ\x00', 'XZ'),
    (b'BZh', 'BZIP2'),
]

# An archive of forensic material looks like something. This is a plausibility check,
# not a whitelist: one hit is enough, and the list is broad on purpose.
FORENSIC_HINTS = (
    '.evtx', '.csv', '.json', '.txt', '.log', '.xml', '.db', '.sqlite', '.jsonl',
    '.pf', '.lnk', '.dat', '.hve', '.reg', '.etl', '.plist',
    'mft', 'usnjrnl', 'amcache', 'shimcache', 'srudb', 'ntuser', 'system', 'software',
    'security', 'sam', 'prefetch', 'registry', 'eventlogs', 'windows', 'users',
    'kape', 'hayabusa', 'timeline', 'triage', 'collector', 'browser', 'history',
)

# What a memory archive looks like. The collector puts the page and hibernation files
# beside the dump, and any of them alone is a legitimate capture.
MEMORY_HINTS = ('pagefile', 'swapfile', 'hiberfil', '.dmp', '.raw', '.mem', '.vmem',
                '.core', '.lime', 'memory', 'dumpit', 'ram')

MAX_MEMBERS = 400000
MAX_RATIO = 250          # uncompressed / compressed, whole archive
MAX_UNCOMPRESSED = 600 * 1024 ** 3


class Verdict(object):
    def __init__(self, ok, code='', message='', detail='', decrypted=None):
        self.ok = ok
        self.code = code
        self.message = message
        self.detail = detail
        # Set only when this upload arrived encrypted and was opened here. The caller
        # needs it because the file on disk is no longer the bytes it received.
        self.decrypted = decrypted

    def as_dict(self):
        return {'ok': self.ok, 'code': self.code, 'message': self.message,
                'detail': self.detail}


def _head(path, n=16):
    try:
        with io.open(path, 'rb') as f:
            return f.read(n)
    except Exception:
        return b''


def _looks_like(head):
    for sig, label in FOREIGN:
        if head.startswith(sig):
            return label
    return ''


def _check_zip(path, mode):
    """Structure only. Contents are evidence and are never judged here."""
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return Verdict(False, 'zip_broken',
                       u'Архів пошкоджений або це не ZIP - розпакувати його не вдалося. '
                       u'Перезберіть архів і завантажте ще раз.')
    with zf:
        try:
            infos = zf.infolist()
        except Exception as e:
            return Verdict(False, 'zip_unreadable',
                           u'Не вдалося прочитати перелік файлів усередині архіву.',
                           repr(e)[:120])
        if not infos:
            return Verdict(False, 'zip_empty',
                           u'Архів порожній - усередині немає жодного файлу.')
        if len(infos) > MAX_MEMBERS:
            return Verdict(False, 'zip_too_many',
                           u'В архіві %d файлів - це більше за межу %d. Схоже на помилку '
                           u'збору, а не на матеріали справи.' % (len(infos), MAX_MEMBERS))

        comp = unc = 0
        names = []
        for i in infos:
            name = i.filename.replace(chr(92), '/')
            names.append(name.lower())
            # zip-slip: a member that escapes the extraction directory
            if name.startswith('/') or name.startswith('../') or '/../' in name:
                return Verdict(False, 'zip_traversal',
                               u'Архів містить шлях, що виходить за межі теки розпакування '
                               u'(%s). Такий архів не приймається.' % name[:60])
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                return Verdict(False, 'zip_symlink',
                               u'Архів містить символьне посилання (%s). У матеріалах справи '
                               u'їх не має бути.' % name[:60])
            comp += i.compress_size
            unc += i.file_size

        if unc > MAX_UNCOMPRESSED:
            return Verdict(False, 'zip_too_big',
                           u'Розпакований вміст - %.1f ГБ, це понад межу %.0f ГБ.'
                           % (unc / 1024.0 ** 3, MAX_UNCOMPRESSED / 1024.0 ** 3))
        if comp > 0 and unc / float(comp) > MAX_RATIO:
            return Verdict(False, 'zip_bomb',
                           u'Стиснення в %.0f разів (%.1f ГБ з %.1f МБ) - так виглядає '
                           u'архів-бомба, а не матеріали справи.'
                           % (unc / float(comp), unc / 1024.0 ** 3, comp / 1024.0 ** 2))

        if mode == 'ram':
            blob = ' '.join(names)
            if not any(h in blob for h in MEMORY_HINTS):
                sample = ', '.join(n.split('/')[-1] for n in names[:5] if n.strip('/'))
                return Verdict(False, 'zip_not_memory',
                               u'В архіві немає нічого схожого на памʼять: очікуються '
                               u'дамп (.dmp/.raw/.mem), pagefile.sys, swapfile.sys або '
                               u'hiberfil.sys.',
                               'members: %s' % sample[:200])
        elif mode == 'email':
            if not any(n.lower().endswith(('.eml', '.msg')) for n in names):
                return Verdict(False, 'zip_not_email',
                               u'В архіві немає листів: очікуються файли .eml або .msg.',
                               'members: %s' % ', '.join(n.split('/')[-1] for n in names[:5])[:200])
        elif mode in ('logs', 'raw'):
            blob = ' '.join(names)
            if not any(h in blob for h in FORENSIC_HINTS):
                sample = ', '.join(n.split('/')[-1] for n in names[:5] if n.strip('/'))
                return Verdict(False, 'zip_not_forensic',
                               u'Усередині архіву немає нічого схожого на матеріали для '
                               u'аналізу (журнали, реєстр, prefetch, CSV/JSON, бази '
                               u'браузера). Перевірте, що завантажуєте архів збирача.',
                               'members: %s' % sample[:200])
    return Verdict(True, 'ok', '')


def validate(path, mode, file_name=''):
    """Decide whether this upload may enter the case library."""
    mode = (mode or 'misc').strip().lower()
    name = (file_name or os.path.basename(path) or '').strip()
    ext = os.path.splitext(name)[1].lower()

    try:
        size = os.path.getsize(path)
    except OSError as e:
        return Verdict(False, 'unreadable', u'Файл не читається на сервері.', repr(e)[:120])
    if size == 0:
        return Verdict(False, 'empty', u'Файл порожній (0 байт).')

    cap = MAX_BYTES.get(mode, DEFAULT_MAX)
    if size > cap:
        return Verdict(False, 'too_large',
                       u'Файл %.1f ГБ перевищує межу %.1f ГБ для цього типу завантаження.'
                       % (size / 1024.0 ** 3, cap / 1024.0 ** 3))

    # The collector may encrypt what it packs. It is opened HERE, before a single
    # structural check, so that everything downstream - extension, magic, archive
    # structure, parsers, ingest - sees exactly the archive it would have seen if
    # encryption had never been added. A plain upload pays for one cheap zip peek.
    decrypted = None
    try:
        from analysis import archive_crypto
    except Exception:
        archive_crypto = None
    if archive_crypto is not None:
        foreign = ''
        try:
            foreign = archive_crypto.detect_foreign(path)
        except Exception:
            foreign = ''
        try:
            if archive_crypto.detect_foreign_pwzip(path):
                return Verdict(
                    False, 'crypto_foreign_password',
                    u'\u0426\u0435\u0439 \u0430\u0440\u0445\u0456\u0432 \u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u0438\u0439 \u0447\u0443\u0436\u0438\u043c \u043f\u0430\u0440\u043e\u043b\u0435\u043c \u2014 \u043c\u0438 \u0439\u043e\u0433\u043e \u043d\u0435 \u0437\u043d\u0430\u0454\u043c\u043e \u0456 '
                    u'\u0432\u0456\u0434\u043a\u0440\u0438\u0442\u0438 \u043d\u0435 \u043c\u043e\u0436\u0435\u043c\u043e. \u0417\u0430\u0432\u0430\u043d\u0442\u0430\u0436 \u0430\u0440\u0445\u0456\u0432 \u0437\u0456 \u0437\u0431\u0438\u0440\u0430\u0447\u0430 \u0430\u0431\u043e \u0431\u0435\u0437 \u043f\u0430\u0440\u043e\u043b\u044f.',
                    'foreign password archive')
        except Exception:
            pass
        if foreign:
            return Verdict(False, 'crypto_unsupported',
                           u'\u0410\u0440\u0445\u0456\u0432 \u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043e \u0441\u0445\u0435\u043c\u043e\u044e %s, \u0430 \u0446\u0435\u0439 \u0441\u0435\u0440\u0432\u0435\u0440 \u0440\u043e\u0437\u0443\u043c\u0456\u0454 %s. '
                           u'\u041e\u043d\u043e\u0432\u0438 \u0431\u043e\u0442\u0430 \u0430\u0431\u043e \u043f\u0435\u0440\u0435\u0437\u0431\u0435\u0440\u0438 \u0430\u0440\u0445\u0456\u0432 \u043f\u043e\u0442\u043e\u0447\u043d\u0438\u043c \u0437\u0431\u0438\u0440\u0430\u0447\u0435\u043c.'
                           % (foreign, archive_crypto.SCHEME), 'unsupported scheme')
        try:
            decrypted = archive_crypto.maybe_decrypt_in_place(path)
        except archive_crypto.CryptoError as e:
            # Deliberately NOT passed through as a broken archive: three steps later
            # nobody could tell a missing key from a corrupt zip.
            return Verdict(False, 'crypto_failed', e.message, e.detail)
        except Exception as e:
            return Verdict(False, 'crypto_failed',
                           u'Не вдалося розшифрувати архів збирача - деталі в журналі сервера.',
                           repr(e)[:200])
    if decrypted:
        # From here on the file IS the inner archive, so every number and name has to
        # be re-read rather than reused.
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        if size > cap:
            return Verdict(False, 'too_large',
                           u'Розшифрований архів %.1f ГБ перевищує межу %.1f ГБ для цього '
                           u'типу завантаження.' % (size / 1024.0 ** 3, cap / 1024.0 ** 3),
                           'after decryption', decrypted)
        # the SANITISED name, not what the container claims: a container can be built by
        # anyone holding the EXE (the public key is in it), and a declared 'payroll.exe'
        # must not turn into a refusal about a file type nobody uploaded
        try:
            inner = archive_crypto.safe_inner_name(decrypted.get('declared_name'), fallback='')
        except Exception:
            inner = ''
        inner_ext = os.path.splitext(inner or decrypted.get('inner_name') or '')[1].lower()
        if inner_ext:
            ext = inner_ext

    allowed = ALLOWED.get(mode)
    if allowed is None:            # a mode this module does not know: let it through
        return Verdict(True, 'ok_unknown_mode', '', '', decrypted)

    head = _head(path)
    if ext not in allowed:
        foreign = _looks_like(head)
        hint = ''
        if foreign == 'RAR':
            hint = u' RAR не підтримується - перезберіть матеріали у ZIP.'
        elif foreign in ('7z', 'XZ', 'BZIP2', 'GZIP'):
            hint = u' Формат %s не підтримується - потрібен ZIP.' % foreign
        elif foreign in ('Windows-EXE/DLL', 'ELF'):
            hint = u' Це виконуваний файл; окремі програми в справу не приймаються.'
        return Verdict(False, 'ext_not_allowed',
                       u'Тип файлу "%s" не приймається для цього завантаження. '
                       u'Дозволені: %s.%s' % (ext or u'(без розширення)',
                                              ', '.join(sorted(allowed)), hint),
                       'magic=%s' % (foreign or repr(head[:8])), decrypted)

    if ext in TEXTY_EXT:
        _bin = _binary_inside(head)
        if _bin:
            return Verdict(False, 'content_mismatch',
                           u'Файл називається "%s", але всередині %s, а не текст. '
                           u'Перейменування не змінює вміст: такий файл не прочитає жоден '
                           u'парсер, і в справі він просто лежатиме без аналізу.'
                           % (name or ext, _bin),
                           'texty ext with %s content' % _bin, decrypted)

    sigs = MAGIC.get(ext)
    if sigs and not any(head.startswith(s) for s in sigs):
        foreign = _looks_like(head)
        return Verdict(False, 'content_mismatch',
                       u'Вміст файлу не відповідає розширенню "%s"%s. Назву файлу можна '
                       u'змінити, вміст - ні, тому такий файл не приймається.'
                       % (ext, (u' - усередині %s' % foreign) if foreign else ''),
                       'magic=%s' % repr(head[:8]), decrypted)

    if ext == '.zip':
        v = _check_zip(path, mode)
        v.decrypted = decrypted
        return v
    return Verdict(True, 'ok', '', '', decrypted)


# A tool job is not a case upload: the file never enters the case library, it feeds one
# tool and is deleted afterwards. So the accepted set follows what that tool can actually
# read, and the size ceiling follows what it can chew through - neither has anything to do
# with the case-mode tables above.
TOOL_ALLOWED = {
    'bookidx': {'.pdf'},                                     # the exam index reads PDFs only
    'translate': {'.pdf'},
    'book': {'.epub', '.pdf', '.fb2', '.docx', '.doc', '.rtf', '.odt', '.txt', '.md'},
    'audiotr': {'.mp3', '.wav', '.m4a', '.ogg', '.opus', '.flac', '.aac', '.wma',
                '.mp4', '.mkv', '.webm', '.mov', '.avi'},
}
TOOL_MAX_BYTES = {
    'bookidx': 2 * 1024 ** 3,          # Study books run past 100 MB; 2 GB is head-room
    'translate': 2 * 1024 ** 3,
    'book': 1 * 1024 ** 3,
    'audiotr': 4 * 1024 ** 3,       # a long recording, possibly still inside a video
}
TOOL_DEFAULT_MAX = 2 * 1024 ** 3


def validate_tool(path, op, file_name=''):
    """Decide whether this upload may be handed to a tool (BOOKIDX, translate, book, audio).

    An op this module has never heard of passes: a tool added tomorrow must not be blocked
    by a table nobody remembered to update - the same rule validate() already applies to an
    unknown mode.
    """
    op = (op or '').strip().lower()
    name = (file_name or os.path.basename(path) or '').strip()
    ext = os.path.splitext(name)[1].lower()

    try:
        size = os.path.getsize(path)
    except OSError as e:
        return Verdict(False, 'unreadable', u'Файл не читається на сервері.', repr(e)[:120])
    if size == 0:
        return Verdict(False, 'empty', u'Файл порожній (0 байт).')

    cap = TOOL_MAX_BYTES.get(op, TOOL_DEFAULT_MAX)
    if size > cap:
        return Verdict(False, 'too_large',
                       u'Файл %.1f ГБ перевищує межу %.1f ГБ для цього інструмента.'
                       % (size / 1024.0 ** 3, cap / 1024.0 ** 3))

    allowed = TOOL_ALLOWED.get(op)
    if allowed is None:
        return Verdict(True, 'ok_unknown_tool', '')

    head = _head(path)
    if ext not in allowed:
        foreign = _looks_like(head)
        return Verdict(False, 'ext_not_allowed',
                       u'Тип файлу "%s" не підходить для цього інструмента. '
                       u'Приймається: %s.%s'
                       % (ext or u'(без розширення)', ', '.join(sorted(allowed)),
                          (u' Усередині схоже на %s.' % foreign) if foreign else ''),
                       'magic=%s' % (foreign or repr(head[:8])))

    sigs = MAGIC.get(ext)
    if sigs and not any(head.startswith(s) for s in sigs):
        # an encrypted PDF still starts with %PDF, so this only catches a real mismatch
        foreign = _looks_like(head)
        return Verdict(False, 'content_mismatch',
                       u'Вміст файлу не відповідає розширенню "%s"%s.'
                       % (ext, (u' - усередині %s' % foreign) if foreign else ''),
                       'magic=%s' % repr(head[:8]))

    return Verdict(True, 'ok', '')
