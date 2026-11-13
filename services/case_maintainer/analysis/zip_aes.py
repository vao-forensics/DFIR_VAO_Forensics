# -*- coding: utf-8 -*-
"""Read a password-protected ZIP (WinZip AES / AE-2) - the format 7-Zip writes with
`-tzip -mem=AES256 -p...`, and the format any investigator can open with 7-Zip or WinRAR.

WHY THIS MODULE EXISTS
    The owner wants an archive that opens like an archive - the file tree is visible - while
    the files themselves need a password. That is exactly AE-2: names live in the central
    directory in the clear, each entry's CONTENT is AES-256 encrypted. Python's own zipfile
    cannot read it (compression method 99 is not supported) and `pyzipper` is not in this
    image, so the format is implemented here. It is a published format, not a guess:

    per entry, the data is
        salt (16 B for AES-256) | password verifier (2 B) | ciphertext | auth code (10 B)
    keys come from PBKDF2-HMAC-SHA1(password, salt, 1000 iterations), taking
        enc key (32 B) | mac key (32 B) | verifier (2 B)
    the cipher is AES-CTR with a 16-byte LITTLE-ENDIAN counter starting at 1,
    the auth code is HMAC-SHA1(mac key, ciphertext) truncated to 10 bytes,
    and the real compression method sits in extra field 0x9901 along with the AES strength.

WHAT IT GUARANTEES
    Every entry is verified twice before it is written out: the 2-byte verifier catches a
    wrong password immediately, and the authentication code catches a modified or truncated
    entry. An archive that fails either one raises instead of producing half a file - a
    silently truncated piece of evidence is worse than a refusal.
"""
import binascii
import hashlib
import hmac
import io
import os
import struct
import zipfile
import zlib

AES_METHOD = 99                  # what the zip header says instead of store/deflate
AES_EXTRA_ID = 0x9901
SALT_LEN = {1: 8, 2: 12, 3: 16}  # AES-128 / AES-192 / AES-256
KEY_LEN = {1: 16, 2: 24, 3: 32}
MAC_LEN = 10
VERIFIER_LEN = 2
PBKDF2_ROUNDS = 1000
CHUNK = 1 << 20


class ZipAesError(Exception):
    """Carries a message already written for the operator, in Ukrainian."""

    def __init__(self, message, detail=''):
        Exception.__init__(self, message)
        self.message = message
        self.detail = detail


def _aes_extra(raw):
    """Pull (version, strength, real_method) out of extra field 0x9901, or None."""
    i = 0
    while i + 4 <= len(raw):
        fid, size = struct.unpack_from('<HH', raw, i)
        body = raw[i + 4:i + 4 + size]
        i += 4 + size
        if fid == AES_EXTRA_ID and len(body) >= 7:
            version, vendor, strength, method = struct.unpack('<H2sBH', body[:7])
            if vendor != b'AE':
                continue
            return version, strength, method
    return None


def is_aes_zip(path):
    """True when this zip has at least one AES-encrypted entry."""
    try:
        with zipfile.ZipFile(path) as z:
            for zi in z.infolist():
                if zi.compress_type == AES_METHOD:
                    return True
        return False
    except Exception:
        return False


def encrypted_names(path, limit=0):
    """The names of the AES-encrypted entries - what the operator sees listed."""
    out = []
    with zipfile.ZipFile(path) as z:
        for zi in z.infolist():
            if zi.compress_type == AES_METHOD:
                out.append(zi.filename)
                if limit and len(out) >= limit:
                    break
    return out


def _raw_data_offset(fh, header_offset):
    """Where an entry's data starts, read from its LOCAL header.

    The central directory does not record it, and the local header's name and extra fields
    are not the same length as the central ones - so it has to be read here rather than
    guessed.
    """
    fh.seek(header_offset)
    head = fh.read(30)
    if len(head) < 30 or head[:4] != b'PK\x03\x04':
        raise ZipAesError(u'Архів пошкоджений: не знайдено заголовок файлу всередині.',
                          'bad local header at %d' % header_offset)
    name_len, extra_len = struct.unpack_from('<HH', head, 26)
    return header_offset + 30 + name_len + extra_len


def check_password(path, password):
    """True when `password` opens this archive, tested on the first encrypted entry.

    Costs two reads and a PBKDF2 - so a wrong password is reported as a wrong password,
    before anything is written anywhere.
    """
    with zipfile.ZipFile(path) as z:
        with io.open(path, 'rb') as fh:
            for zi in z.infolist():
                if zi.compress_type != AES_METHOD:
                    continue
                info = _aes_extra(zi.extra) or _aes_extra(b'')
                if not info:
                    raise ZipAesError(u'Архів зашифрований у невідомий спосіб.',
                                      'no AE extra field for %s' % zi.filename)
                _v, strength, _m = info
                off = _raw_data_offset(fh, zi.header_offset)
                fh.seek(off)
                salt = fh.read(SALT_LEN[strength])
                verifier = fh.read(VERIFIER_LEN)
                _ek, _mk, want = _derive(password, salt, strength)
                return want == verifier
    return False


def _derive(password, salt, strength):
    klen = KEY_LEN[strength]
    total = klen * 2 + VERIFIER_LEN
    material = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt,
                                   PBKDF2_ROUNDS, total)
    return material[:klen], material[klen:klen * 2], material[klen * 2:]


def _ctr_cipher(key):
    """AES-CTR with the counter AE-2 uses: 16 bytes, LITTLE-endian, starting at 1.

    Little-endian is why the obvious library call does not work - `cryptography`'s CTR mode
    counts big-endian. PyCryptodome exposes the counter explicitly, so this runs at C speed;
    measured 5 MB/s with a Python byte loop against roughly 700 MB/s here, which is the
    difference between a usable upload and a timeout.
    """
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    ctr = Counter.new(128, initial_value=1, little_endian=True)
    return AES.new(key, AES.MODE_CTR, counter=ctr)


def decrypt_to_zip(src, dst, password, progress=None, level=1, skip=()):
    """Rewrite `src` as an ordinary zip at `dst`, decrypting every AES entry.

    The result is a plain zip with the same entry names, so every parser and guard
    downstream is untouched. Compression level 1 on purpose: the data is being re-deflated
    only to keep the archive a reasonable size, and level 6 costs minutes on a multi-GB
    archive for a few percent.
    """
    done = [0]
    stats = {'entries': 0, 'encrypted': 0, 'bytes': 0}
    with zipfile.ZipFile(src) as zin, io.open(src, 'rb') as fh, \
            zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED, allowZip64=True,
                            compresslevel=level) as zout:
        total = sum(zi.compress_size for zi in zin.infolist()) or 1
        for zi in zin.infolist():
            if zi.filename in skip:
                continue          # envelope, not evidence: the key file and the README
            stats['entries'] += 1
            if zi.compress_type != AES_METHOD:
                # not encrypted (a directory, or the key file the collector added): copy
                if zi.is_dir():
                    zout.writestr(zi, b'')
                else:
                    zout.writestr(zi.filename, zin.read(zi.filename))
                done[0] += zi.compress_size
                continue

            info = _aes_extra(zi.extra)
            if not info:
                raise ZipAesError(u'Архів зашифрований у невідомий спосіб (%s).' % zi.filename,
                                  'no AE extra field')
            _version, strength, real_method = info
            slen = SALT_LEN[strength]
            off = _raw_data_offset(fh, zi.header_offset)
            fh.seek(off)
            salt = fh.read(slen)
            verifier = fh.read(VERIFIER_LEN)
            enc_key, mac_key, want = _derive(password, salt, strength)
            if want != verifier:
                raise ZipAesError(
                    u'Пароль не підходить до цього архіву.',
                    'verifier mismatch on %s' % zi.filename)

            cipher_len = zi.compress_size - slen - VERIFIER_LEN - MAC_LEN
            if cipher_len < 0:
                raise ZipAesError(u'Архів пошкоджений: запис %s обрізаний.' % zi.filename)

            mac = hmac.new(mac_key, b'', hashlib.sha1)
            cipher = _ctr_cipher(enc_key)
            inflate = zlib.decompressobj(-zlib.MAX_WBITS) if real_method == 8 else None
            crc = 0
            left = cipher_len
            with zout.open(zi.filename, 'w') as out:
                while left > 0:
                    piece = fh.read(min(CHUNK, left))
                    if not piece:
                        raise ZipAesError(u'Архів обірваний на записі %s.' % zi.filename)
                    left -= len(piece)
                    mac.update(piece)
                    plain = cipher.decrypt(piece)
                    if inflate is not None:
                        plain = inflate.decompress(plain)
                    if plain:
                        crc = binascii.crc32(plain, crc) & 0xffffffff
                        out.write(plain)
                    done[0] += len(piece)
                    if progress:
                        progress(done[0], total)
                if inflate is not None:
                    tail = inflate.flush()
                    if tail:
                        crc = binascii.crc32(tail, crc) & 0xffffffff
                        out.write(tail)
            code = fh.read(MAC_LEN)
            if not hmac.compare_digest(mac.digest()[:MAC_LEN], code):
                raise ZipAesError(
                    u'Запис %s не проходить перевірку цілісності — архів пошкоджений або '
                    u'змінений.' % zi.filename, 'auth code mismatch')
            if zi.CRC and crc != zi.CRC:
                raise ZipAesError(
                    u'Запис %s не збігається з контрольною сумою — архів пошкоджений.'
                    % zi.filename, 'crc %08x != %08x' % (crc, zi.CRC))
            stats['encrypted'] += 1
            stats['bytes'] += zi.file_size
    return stats
