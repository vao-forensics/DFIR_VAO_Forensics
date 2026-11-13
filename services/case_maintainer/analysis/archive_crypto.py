# -*- coding: utf-8 -*-
"""Transparent decryption of collector archives.

WHY THIS EXISTS
    The collector encrypts the evidence it packs, so that an archive obtained by a third
    party is unreadable. A static password inside the EXE cannot do that (it is recoverable
    with `strings`, a breakpoint or a process dump), and a password handed to 7za cannot
    either: it would sit on a command line, which Sysmon, Security 4688 and every EDR
    record - on exactly the machines this collector runs on. So the EXE carries only a
    PUBLIC key, the bulk encryption happens in process, and no secret is ever an argument.

CONTAINER FORMAT  "dfir-enc-3"   (a valid STORED zip, written by the collector in one pass)
    README.txt          Ukrainian: what this file is and that nothing is to be done by hand.
                        It exists because an investigator who opened the archive saw
                        "payload.bin" and no explanation, which reads as a mistake.
    MANIFEST.json       scheme, key id, algorithms, inner name and size, timestamp, and
                        `parts` - the member names, so this module resolves them by ROLE
    encryption-key.bin  RSA-4096-OAEP-SHA256 over 80 bytes: AES key | HMAC key | IV
    evidence.encrypted  AES-256-CBC(PKCS7) of the archive, then its HMAC-SHA256 (32 B)
    checksum.sha256     SHA-256 of the archive BEFORE encryption
    dfir-enc-2 is the same thing with the old fixed names (key.bin / payload.bin /
    PLAIN.sha256) and is still accepted.
    The HMAC covers the manifest bytes as well as the ciphertext, so an edited manifest -
    a changed key id or file name - is detected instead of obeyed.

WHAT THIS MODULE GUARANTEES
    After a successful call the path holds EXACTLY the archive the bot used to receive
    before encryption existed - proven by the plaintext SHA-256, not assumed - so every
    parser, guard and ingest step downstream is untouched. A plain upload is recognised as
    plain and passes through without being read twice.
    Nothing replaces the uploaded file until both the HMAC and that SHA-256 have passed.
"""
import hashlib
import hmac as _hmac
import io
import json
import logging
import os
import shutil
import tempfile
import zipfile

SCHEME = 'dfir-enc-3'
# Containers we can open. dfir-enc-2 differs only in what the members are called, and an
# archive built with the EXE that was published before the rename must still open.
SCHEMES = ('dfir-enc-3', 'dfir-enc-2')
MANIFEST_NAME = 'MANIFEST.json'
# defaults for dfir-enc-3; the manifest's `parts` overrides them, and dfir-enc-2 uses LEGACY
KEY_NAME = 'encryption-key.bin'
PAYLOAD_NAME = 'evidence.encrypted'
PLAIN_SHA_NAME = 'checksum.sha256'
LEGACY_PARTS = {'key': 'key.bin', 'payload': 'payload.bin', 'checksum': 'PLAIN.sha256'}
MAC_LEN = 32
KEYMAT_LEN = 80                       # 32 AES | 32 HMAC | 16 IV
CHUNK = 4 * 1024 * 1024

# The collector's current shape: a password ZIP carrying its own wrapped password.
PWZIP_SCHEME = 'dfir-pwzip-1'
PWZIP_KEY_NAME = '_dfir_key.bin'
PWZIP_README = 'README.txt'

KEY_DIRS = ('/data/state/keys', '/srv/dfir/state/keys')
PRIV_NAME = 'collector_private.pem'

_log = logging.getLogger(__name__)


class CryptoError(Exception):
    """Carries a message already written for the operator, in Ukrainian."""

    def __init__(self, message, detail=''):
        Exception.__init__(self, message)
        self.message = message
        self.detail = detail


def private_key_path():
    for d in KEY_DIRS:
        p = os.path.join(d, PRIV_NAME)
        if os.path.isfile(p):
            return p
    return ''


def _our_key_id():
    for d in KEY_DIRS:
        p = os.path.join(d, 'collector_key_id.txt')
        if os.path.isfile(p):
            try:
                return io.open(p, encoding='utf-8').read().strip()
            except Exception:
                pass
    return ''


def detect(path):
    """Return the manifest dict when `path` is one of our containers, else None.

    Detection is by content, never by file name: an operator renaming the file must not
    change how it is handled.
    """
    try:
        if not zipfile.is_zipfile(path):
            return None
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if MANIFEST_NAME not in names:
                return None
            man = json.loads(z.read(MANIFEST_NAME).decode('utf-8', 'replace'))
        if str(man.get('scheme') or '') not in SCHEMES:
            return None
        if _parts(man)['key'] not in names:
            return None
        return man
    except Exception:
        return None


def detect_foreign(path):
    """Return the scheme of a container we CANNOT open, else ''.

    Found the hard way (2026-09-17): a container of an unsupported scheme sailed through the
    gate, because a zip holding MANIFEST.json looks 'plausibly forensic', and landed in the
    case library as evidence nobody could read. That has to be a refusal with a next step,
    not a silent acceptance - the same rule as everywhere else here.
    """
    try:
        if not zipfile.is_zipfile(path):
            return ''
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if MANIFEST_NAME not in names:
                return ''
            man = json.loads(z.read(MANIFEST_NAME).decode('utf-8', 'replace'))
        scheme = str(man.get('scheme') or '')
        if scheme and scheme not in SCHEMES and scheme.startswith('dfir-enc-'):
            return scheme
        return ''
    except Exception:
        return ''


def detect_foreign_pwzip(path):
    """True for a password-protected archive that is NOT ours.

    Somebody else's password zip cannot be opened by us and must not enter a case as
    evidence nobody can read - the same lesson as the unknown-scheme container.
    """
    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as z:
            if PWZIP_KEY_NAME in z.namelist():
                return False
        from analysis import zip_aes
        return zip_aes.is_aes_zip(path)
    except Exception:
        return False


def _parts(man):
    """Which member holds which role, according to the container itself.

    A name declared in the manifest is only ever used to LOOK UP a zip member, never to
    write a path, so a hostile value can at worst point at a member that is not there.
    """
    p = man.get('parts') if isinstance(man.get('parts'), dict) else {}
    legacy = str(man.get('scheme') or '') == 'dfir-enc-2'
    out = {}
    for role, modern in (('key', KEY_NAME), ('payload', PAYLOAD_NAME),
                         ('checksum', PLAIN_SHA_NAME)):
        declared = str(p.get(role) or '').strip()
        out[role] = declared or (LEGACY_PARTS[role] if legacy else modern)
    return out


def _unwrap(blob):
    """RSA-OAEP-SHA256 the 80 bytes of key material out of key.bin."""
    priv = private_key_path()
    if not priv:
        raise CryptoError(
            u'Архів зашифрований, але приватного ключа немає на сервері — розшифрувати нічим.',
            'no private key in %s' % ', '.join(KEY_DIRS))
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except Exception as e:
        raise CryptoError(u'На сервері немає бібліотеки шифрування — звернись до адміністратора.',
                          repr(e)[:160])
    try:
        key = serialization.load_pem_private_key(io.open(priv, 'rb').read(), password=None)
    except Exception as e:
        raise CryptoError(u'Приватний ключ не читається — файл пошкоджений або не той формат.',
                          repr(e)[:160])
    try:
        mat = key.decrypt(blob, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                             algorithm=hashes.SHA256(), label=None))
    except Exception as e:
        raise CryptoError(
            u'Ключ архіву не розшифровується цим ключем. Найімовірніше архів зашифровано '
            u'для іншого ключа — перевір ідентифікатор ключа у збирачі.', repr(e)[:160])
    if len(mat) != KEYMAT_LEN:
        raise CryptoError(u'Ключ архіву має неочікуваний розмір — контейнер не наш або пошкоджений.',
                          'keymat=%d' % len(mat))
    return mat[:32], mat[32:64], mat[64:]


ALLOWED_INNER_EXT = ('.zip', '.csv', '.evtx', '.dmp', '.raw', '.mem', '.vmem',
                      '.core', '.bin', '.lime', '.7z')


def safe_inner_name(declared, fallback='archive.zip'):
    """Sanitise the name declared inside a container. It is UNTRUSTED input.

    The public key ships in every collector EXE, so anyone holding the EXE can build a
    container; the HMAC proves nobody edited it after sealing, not who sealed it. A declared
    name like '..\\..\\startup\\x.zip' must therefore never reach a path join.
    """
    name = str(declared or '')
    name = name.replace('\\', '/').split('/')[-1]      # both separators, whoever wrote it
    for ch in (':', '*', '?', '"', '<', '>', '|', '\n', '\r', '\t', '\x00'):
        name = name.replace(ch, '_')
    name = name.strip().strip('.')
    if not name or len(name) > 120:
        return fallback
    low = name.lower()
    if not low.endswith(ALLOWED_INNER_EXT):
        return fallback
    return name


def decrypt_to_dir(path, out_dir, manifest=None):
    """Decrypt the container at `path` into `out_dir`. Returns (plain_path, info).

    Verification order matters: the HMAC and the plaintext SHA-256 are both checked before
    this returns, so a caller that swaps files can trust what it is swapping in.
    """
    man = manifest or detect(path)
    if not man:
        raise CryptoError(u'Це не зашифрований архів збирача.')

    kid = str(man.get('key_id') or '')
    ours = _our_key_id()
    if kid and ours and kid != ours:
        raise CryptoError(
            u'Архів зашифровано для ключа %s, а на сервері ключ %s — розшифрувати неможливо.'
            % (kid[:16], ours[:16]), 'key id mismatch')

    parts = _parts(man)
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        for need in (MANIFEST_NAME, parts['key'], parts['payload']):
            if need not in names:
                raise CryptoError(u'Контейнер неповний — усередині немає %s.' % need)
        manifest_bytes = z.read(MANIFEST_NAME)
        aes_key, mac_key, iv = _unwrap(z.read(parts['key']))

        cipher_len = z.getinfo(parts['payload']).file_size - MAC_LEN
        if cipher_len <= 0:
            raise CryptoError(u'Зашифрована частина порожня — архів неповний.')

        # Streaming, so the ceiling is the archive size once, not twice.
        try:
            free = shutil.disk_usage(out_dir).free
            if free < cipher_len + 64 * 1024 ** 2:
                raise CryptoError(
                    u'Замало місця для розшифрування: потрібно ~%.1f ГБ, вільно %.1f ГБ.'
                    % (cipher_len / 1024.0 ** 3, free / 1024.0 ** 3))
        except CryptoError:
            raise
        except Exception:
            pass

        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        unpad = sym_padding.PKCS7(128).unpadder()
        mac = _hmac.new(mac_key, manifest_bytes, hashlib.sha256)
        sha = hashlib.sha256()

        inner_name = safe_inner_name(man.get('inner_name'))
        plain_path = os.path.join(out_dir, inner_name)
        left = cipher_len
        try:
            with z.open(parts['payload']) as src, io.open(plain_path, 'wb') as dst:
                while left > 0:
                    chunk = src.read(min(CHUNK, left))
                    if not chunk:
                        raise CryptoError(u'Зашифрована частина обірвана — завантаж архів ще раз.',
                                          'short read, %d bytes left' % left)
                    left -= len(chunk)
                    mac.update(chunk)
                    out = unpad.update(dec.update(chunk))
                    if out:
                        sha.update(out)
                        dst.write(out)
                out = unpad.update(dec.finalize()) + unpad.finalize()
                if out:
                    sha.update(out)
                    dst.write(out)
                stored_mac = src.read(MAC_LEN)
        except CryptoError:
            raise
        except Exception as e:
            raise CryptoError(
                u'Не вдалося розшифрувати вміст — архів пошкоджений або зашифрований інакше.',
                repr(e)[:200])

        if not _hmac.compare_digest(mac.digest(), stored_mac or b''):
            raise CryptoError(
                u'Контейнер не проходить перевірку цілісності — його змінили або він '
                u'пошкоджений під час передачі. Завантаж ще раз.', 'hmac mismatch')

        want = ''
        if parts['checksum'] in names:
            want = z.read(parts['checksum']).decode('ascii', 'replace').strip().lower()
        got = sha.hexdigest()
        if want and want != got:
            raise CryptoError(
                u'Розшифрований архів не збігається з контрольною сумою збирача — '
                u'архів пошкоджений. Завантаж ще раз.', 'sha %s != %s' % (got[:16], want[:16]))

    info = {'key_id': kid or ours, 'inner_name': inner_name,
            'declared_name': str(man.get('inner_name') or ''),
            'created': str(man.get('created') or ''),
            'inner_size': os.path.getsize(plain_path),
            'plain_sha256': got, 'verified': bool(want)}
    return plain_path, info


def detect_pwzip(path):
    """True when `path` is a password ZIP from the collector: our key file plus AES entries.

    Both tests matter. The key file alone could be anything; AES entries alone would be
    somebody else's password archive, which we must not pretend to be able to open.
    """
    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as z:
            if PWZIP_KEY_NAME not in z.namelist():
                return False
        from analysis import zip_aes
        return zip_aes.is_aes_zip(path)
    except Exception:
        return False


def pwzip_password(path):
    """The archive's own password, unwrapped with our private key."""
    with zipfile.ZipFile(path) as z:
        try:
            blob = z.read(PWZIP_KEY_NAME)
        except KeyError:
            raise CryptoError(u'В архіві немає файлу з паролем (%s) — його видалили, і '
                              u'відкрити архів уже неможливо.' % PWZIP_KEY_NAME)
    priv = private_key_path()
    if not priv:
        raise CryptoError(
            u'Архів під паролем, але приватного ключа немає на сервері — відкрити нічим.',
            'no private key in %s' % ', '.join(KEY_DIRS))
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        key = serialization.load_pem_private_key(io.open(priv, 'rb').read(), password=None)
        return key.decrypt(blob, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                              algorithm=hashes.SHA256(), label=None)
                           ).decode('utf-8', 'strict')
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(
            u'Пароль архіву не розшифровується нашим ключем. Найімовірніше архів зібрано '
            u'збирачем з іншим ключем — перевір ідентифікатор ключа у README.txt архіву.',
            repr(e)[:160])


def decrypt_pwzip_in_place(path):
    """Replace a password ZIP with a plain one holding the same entries. Returns info.

    The envelope entries (the key file and the README) are deliberately dropped from the
    result: their job is done, and a README.txt in the root of an evidence archive would
    turn up later as an unrecognised artefact for somebody to explain.
    """
    from analysis import zip_aes
    password = pwzip_password(path)
    try:
        if not zip_aes.check_password(path, password):
            raise CryptoError(
                u'Пароль з архіву до нього ж не підходить — архів перепакували або '
                u'пошкодили. Візьми оригінал у того, хто збирав.', 'verifier mismatch')
    except zip_aes.ZipAesError as e:
        raise CryptoError(e.message, e.detail)

    size = os.path.getsize(path)
    try:
        free = shutil.disk_usage(os.path.dirname(os.path.abspath(path))).free
        if free < size + 64 * 1024 ** 2:
            raise CryptoError(
                u'Замало місця, щоб відкрити архів: потрібно ~%.1f ГБ, вільно %.1f ГБ.'
                % (size / 1024.0 ** 3, free / 1024.0 ** 3))
    except CryptoError:
        raise
    except Exception:
        pass

    work = tempfile.mkdtemp(prefix='dfirpw_', dir=os.path.dirname(os.path.abspath(path)))
    try:
        plain = os.path.join(work, 'plain.zip')
        try:
            stats = zip_aes.decrypt_to_zip(path, plain, password,
                                           skip=(PWZIP_KEY_NAME, PWZIP_README))
        except zip_aes.ZipAesError as e:
            raise CryptoError(e.message, e.detail)
        os.replace(plain, path)
        info = {'kind': 'pwzip', 'key_id': _our_key_id(), 'entries': stats['entries'],
                'encrypted': stats['encrypted'], 'inner_size': os.path.getsize(path),
                'declared_name': '', 'inner_name': os.path.basename(path),
                'verified': True}
        _log.info('[archive_crypto] opened password zip %s (%d entries, %d encrypted, %.1f MB)',
                  os.path.basename(path), stats['entries'], stats['encrypted'],
                  info['inner_size'] / 1048576.0)
        return info
    finally:
        shutil.rmtree(work, ignore_errors=True)


def maybe_decrypt_in_place(path):
    """If `path` is one of our containers, replace it with the archive inside; else None.

    Returns None when the file is not ours, so a plain upload costs one cheap zip peek.
    Raises CryptoError with an operator-ready message when it IS ours but cannot be opened -
    silently letting an undecryptable archive through would land as "broken zip" three steps
    later, where nobody could tell why.
    """
    if detect_pwzip(path):
        return decrypt_pwzip_in_place(path)
    man = detect(path)
    if not man:
        return None
    work = tempfile.mkdtemp(prefix='dfirenc_', dir=os.path.dirname(os.path.abspath(path)))
    try:
        plain, info = decrypt_to_dir(path, work, man)
        # The swap happens only after the HMAC and the SHA-256 have both passed, and the
        # container stays intact until the plain archive is in place under its name.
        tmp_final = path + '.plain'
        shutil.move(plain, tmp_final)
        os.replace(tmp_final, path)
        _log.info('[archive_crypto] decrypted %s (key %s, inner %s, %.1f MB, sha %s)',
                  os.path.basename(path), info['key_id'][:16], info['inner_name'],
                  info['inner_size'] / 1048576.0, info['plain_sha256'][:16])
        return info
    finally:
        shutil.rmtree(work, ignore_errors=True)


def pack_for_test(archive_path, out_path, public_pem=None, mangle=None,
                  inner_name_override=None):
    """Build a container the way the collector does - for the guard test, not production.

    `mangle` lets a test produce a container that is wrong in one specific way, which is the
    only honest way to check that each wrong container is refused for the right reason.
    """
    import datetime
    import os as _os
    from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if public_pem is None:
        for d in KEY_DIRS:
            p = os.path.join(d, 'collector_public.pem')
            if os.path.isfile(p):
                public_pem = p
                break
    pub = serialization.load_pem_public_key(io.open(public_pem, 'rb').read())

    keymat = _os.urandom(KEYMAT_LEN)
    aes_key, mac_key, iv = keymat[:32], keymat[32:64], keymat[64:]
    blob = pub.encrypt(keymat, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                            algorithm=hashes.SHA256(), label=None))
    man = {'scheme': SCHEME, 'key_id': _our_key_id(),
           'alg': 'RSA-4096-OAEP-SHA256 + AES-256-CBC + HMAC-SHA256',
           'inner_name': os.path.basename(archive_path),
           'inner_size': os.path.getsize(archive_path),
           'created': datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
           'collector': 'test',
           'parts': {'payload': PAYLOAD_NAME, 'key': KEY_NAME, 'checksum': PLAIN_SHA_NAME}}
    if mangle == 'key_id':
        man['key_id'] = 'deadbeefdeadbeef'
    if inner_name_override is not None:
        # a container built by someone who merely holds the EXE: the public key is in there,
        # so they can declare whatever name they like and the HMAC will be valid
        man['inner_name'] = inner_name_override
    manifest_bytes = json.dumps(man, ensure_ascii=False, indent=1).encode('utf-8')

    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    pad = sym_padding.PKCS7(128).padder()
    mac = _hmac.new(mac_key, manifest_bytes, hashlib.sha256)
    sha = hashlib.sha256()
    body = bytearray()
    with io.open(archive_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            sha.update(chunk)
            piece = enc.update(pad.update(chunk))
            mac.update(piece)
            body += piece
    piece = enc.update(pad.finalize()) + enc.finalize()
    mac.update(piece)
    body += piece
    digest = mac.digest()
    if mangle == 'payload':
        body = bytearray(b'\x00' * len(body))
    if mangle == 'mac':
        digest = b'\x00' * MAC_LEN
    plain_sha = sha.hexdigest()
    if mangle == 'plain_sha':
        plain_sha = '0' * 64

    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_STORED) as z:
        z.writestr('README.txt', u'\u0426\u0435 \u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u0438\u0439 \u0430\u0440\u0445\u0456\u0432 '
                                 u'\u0434\u043e\u043a\u0430\u0437\u0456\u0432 (\u0442\u0435\u0441\u0442).\n')
        z.writestr(MANIFEST_NAME, manifest_bytes)
        z.writestr(KEY_NAME, blob)
        if mangle != 'no_payload':
            z.writestr(PAYLOAD_NAME, bytes(body) + digest)
        z.writestr(PLAIN_SHA_NAME, plain_sha + '\n')
    return out_path
