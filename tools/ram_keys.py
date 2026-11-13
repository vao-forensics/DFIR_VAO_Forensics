# -*- coding: utf-8 -*-
"""Recover keys and secrets from a memory image - the ransomware/BitLocker/VeraCrypt case.

The owner asked whether we can pull decryption keys out of RAM: a server encrypted by a
ransomware, a BitLocker/LUKS/VeraCrypt volume. The honest answer: a key is recoverable only
if it was RESIDENT in memory at capture time - but that is exactly the common case for a
machine that was live and unlocked, and the tools to try are these:

  * AES KEYS - aeskeyfind scans the raw image for scheduled AES-128/256 keys. Ransomware,
    BitLocker (FVEK), LUKS and VeraCrypt all use AES, so a resident key schedule shows up
    here. Each hit is a candidate key in hex.
  * VERACRYPT / TRUECRYPT passphrase - Volatility windows.truecrypt.Passphrase reads the
    cached passphrase straight out of the driver's memory.
  * WINDOWS CREDENTIALS - hashdump (NTLM), lsadump (LSA secrets), cachedump (domain cache):
    what an attacker would have grabbed, recovered for the investigator instead.

Everything lands in a keys/ folder and as findings. Nothing is invented: aeskeyfind either
prints a key or it does not, and "no key found" is reported honestly, not as emptiness.
"""
import io
import os
import re
import subprocess

AESKEYFIND = os.environ.get('DFIR_AESKEYFIND', '/usr/local/bin/aeskeyfind')
VOL = os.environ.get('DFIR_VOL_BIN', '/opt/vol3/bin/vol')
AES_TIMEOUT = int(os.environ.get('DFIR_AESKEYFIND_TIMEOUT', '3600'))
VOL_TIMEOUT = int(os.environ.get('DFIR_KEYS_VOL_TIMEOUT', '300'))
SECRETSDUMP = os.environ.get('DFIR_SECRETSDUMP', '/opt/impacket/bin/secretsdump.py')
SECRETS_PY = os.environ.get('DFIR_SECRETSDUMP_PY', '/opt/impacket/bin/python')


def log(m):
    import time
    print('%s [ram-keys] %s' % (time.strftime('%H:%M:%S'), m), flush=True)


def _aeskeyfind(dump, keys_dir):
    """Scan the raw image for AES key schedules. One candidate key per hit."""
    if not os.path.exists(AESKEYFIND):
        return [], u'aeskeyfind не встановлено'
    try:
        _sz = os.path.getsize(dump)
    except OSError:
        _sz = 0
    _maxgb = float(os.environ.get('DFIR_AESKEYFIND_MAXGB', '6'))
    _force = str(os.environ.get('DFIR_FORCE_AESKEYFIND', '')).lower() in ('1', 'true', 'yes', 'on')
    if _sz > _maxgb * 1024 ** 3 and not _force:
        return [], (u'пропущено: образ %.1f ГБ > %.0f ГБ — aeskeyfind надто довгий на великому '
                    u'образі (DFIR_FORCE_AESKEYFIND=1 щоб примусити)' % (_sz / 1024.0 ** 3, _maxgb))
    try:
        r = subprocess.run([AESKEYFIND, dump], capture_output=True, timeout=AES_TIMEOUT)
    except subprocess.TimeoutExpired:
        return [], u'aeskeyfind не вклався в ліміт'
    except Exception as e:
        return [], repr(e)[:120]
    out = (r.stdout or b'').decode('utf-8', 'replace')
    io.open(os.path.join(keys_dir, 'aes_keys.txt'), 'w', encoding='utf-8').write(out)
    findings = []
    # aeskeyfind prints the bare key hex lines; keep the plausible ones
    for line in out.splitlines():
        line = line.strip()
        # a key line is hex, 32 or 64 hex chars (possibly space-separated)
        compact = line.replace(' ', '')
        if re.fullmatch(r'[0-9a-fA-F]{32}', compact) or re.fullmatch(r'[0-9a-fA-F]{64}', compact):
            bits = len(compact) * 4
            findings.append({'severity': 'high', 'kind': 'aes_key',
                             'name': 'AES-%d' % bits, 'detail': compact,
                             'why': u'знайдено кандидат AES-%d ключа в памʼяті — можливий '
                                    u'ключ шифрувальника / BitLocker / LUKS / VeraCrypt' % bits})
    return findings, ''


def _vol(dump, plugin, keys_dir, label):
    """One Volatility credential plugin, best-effort."""
    try:
        r = subprocess.run([VOL, '-q', '-f', dump, plugin],
                           capture_output=True, timeout=VOL_TIMEOUT)
    except Exception:
        return [], ''
    out = (r.stdout or b'').decode('utf-8', 'replace').strip()
    if not out or 'Unsatisfied' in out:
        return [], ''
    io.open(os.path.join(keys_dir, label + '.txt'), 'w', encoding='utf-8').write(out)
    # the banner comes first and the column header second - both are not data
    lines = [l for l in out.splitlines()
             if l.strip() and not l.startswith('Volatility')]
    rows = lines[1:]
    return rows, out


def _secretsdump(out_dir, keys_dir):
    """Local secrets from the registry hives MemProcFS recovered: NTLM hashes, LSA secrets,
    cached domain creds, DPAPI machine keys. This is the professional path - the same
    hives EZTools/RECmd read on Windows, read here by impacket on Linux.
    """
    hdir = os.path.join(out_dir, 'hives')
    if not os.path.isdir(hdir) or not os.path.exists(SECRETSDUMP):
        return []
    def _pick(*needles):
        cands = [f for f in os.listdir(hdir)
                 if all(n in f.upper() for n in needles)]
        # MemProcFS writes both the raw memory range (.hivemem) and the registry file
        # (.reghive); only the second one is something secretsdump can read
        cands.sort(key=lambda f: (not f.lower().endswith('.reghive'), len(f)))
        return os.path.join(hdir, cands[0]) if cands else ''
    sam = _pick('SAM')
    security = _pick('SECURITY')
    system = _pick('SYSTEM')
    if not system or not (sam or security):
        return []
    cmd = [SECRETS_PY, SECRETSDUMP, '-system', system]
    if sam:
        cmd += ['-sam', sam]
    if security:
        cmd += ['-security', security]
    cmd += ['LOCAL', '-outputfile', os.path.join(keys_dir, 'secrets')]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=VOL_TIMEOUT)
    except Exception as e:
        return [{'severity': 'low', 'kind': 'secretsdump_err',
                 'name': 'secretsdump', 'detail': repr(e)[:120], 'why': u'secretsdump не запустився'}]
    out = (r.stdout or b'').decode('utf-8', 'replace')
    io.open(os.path.join(keys_dir, 'secretsdump.txt'), 'w', encoding='utf-8').write(out)
    findings = []
    for line in out.splitlines():
        t = line.strip()
        if not t:
            continue
        # NTLM hash rows look like user:rid:lm:nt:::
        if t.count(':') >= 5 and ':::' in t:
            findings.append({'severity': 'medium', 'kind': 'ntlm_hash', 'name': t.split(':')[0],
                             'detail': t[:200], 'why': u'NTLM-хеш облікового запису (з вуликів памʼяті)'})
        elif 'dpapi_' in t.lower() or 'DPAPI' in t:
            findings.append({'severity': 'high', 'kind': 'dpapi_key', 'name': 'DPAPI',
                             'detail': t[:200], 'why': u'DPAPI-ключ машини — розшифровує збережені паролі/секрети'})
        elif t.startswith('$MACHINE.ACC') or 'aad3b435' in t.lower():
            findings.append({'severity': 'medium', 'kind': 'lsa_secret', 'name': 'LSA',
                             'detail': t[:200], 'why': u'LSA-секрет із памʼяті'})
    return findings


def extract(dump, out_dir):
    """All key/secret recovery. Returns findings; writes a keys/ folder. Never raises."""
    keys_dir = os.path.join(out_dir, 'keys')
    os.makedirs(keys_dir, exist_ok=True)
    findings = []
    summary_lines = []

    log('aeskeyfind по %s' % os.path.basename(dump))
    aes, err = _aeskeyfind(dump, keys_dir)
    findings += aes
    summary_lines.append('AES-ключі: %d%s' % (len(aes), (' (%s)' % err) if err else ''))

    # secretsdump on the recovered registry hives (hashes/LSA/DPAPI)
    sd = _secretsdump(out_dir, keys_dir)
    findings += sd
    summary_lines.append('secretsdump (хеші/LSA/DPAPI): %d' % len(sd))

    # VeraCrypt / TrueCrypt cached passphrase
    tc_rows, tc_out = _vol(dump, 'windows.truecrypt.Passphrase', keys_dir, 'veracrypt_passphrase')
    if tc_rows:
        for r in tc_rows[:10]:
            findings.append({'severity': 'high', 'kind': 'veracrypt_passphrase',
                             'name': 'VeraCrypt/TrueCrypt', 'detail': r[:200],
                             'why': u'знайдено кешований пароль VeraCrypt/TrueCrypt у памʼяті'})
    summary_lines.append('VeraCrypt-пароль: %d' % len(tc_rows))

    # Windows credentials
    for plugin, label, kind, why in (
        ('windows.hashdump.Hashdump', 'ntlm_hashes', 'ntlm_hash',
         u'витягнуто NTLM-хеш облікового запису з памʼяті'),
        ('windows.lsadump.Lsadump', 'lsa_secrets', 'lsa_secret',
         u'витягнуто LSA-секрет із памʼяті'),
        ('windows.cachedump.Cachedump', 'cached_domain', 'cached_cred',
         u'витягнуто кешовані доменні облікові дані'),
    ):
        rows, _ = _vol(dump, plugin, keys_dir, label)
        for r in rows[:20]:
            findings.append({'severity': 'medium', 'kind': kind,
                             'name': label, 'detail': r[:200], 'why': why})
        if rows:
            summary_lines.append('%s: %d' % (label, len(rows)))

    io.open(os.path.join(keys_dir, 'README.txt'), 'w', encoding='utf-8').write(
        u'Витяг ключів і секретів з памʼяті\n' + '\n'.join(summary_lines) +
        u'\n\nУВАГА: ключ у RAM існує лише якщо був резидентним у мить зняття дампа. '
        u'Порожній результат НЕ означає, що диск неможливо розшифрувати іншими способами.\n')
    log('ключів/секретів знайдено: %d' % len(findings))
    return findings


if __name__ == '__main__':
    import json
    import sys
    d = sys.argv[1]
    o = sys.argv[2] if len(sys.argv) > 2 else '/tmp/keys_out'
    print(json.dumps(extract(d, o), ensure_ascii=False, indent=1))
