#!/usr/bin/env python3
"""Make (once) the collector archive keypair and print the public "seal line".

  seal_key.py KEYS_DIR            create the keypair if missing, write collector_seal.txt, print the line
  seal_key.py KEYS_DIR --show     print the line only

The collector encrypts every archive to the PUBLIC key; only this bot, holding the private one,
can open it. An existing private key is never touched: replacing it would make every archive
already collected unreadable.

Seal line format (one line, safe to paste into a chat or the collector builder):
  dfir-seal-1:<key id, 16 hex>:<RSA modulus, base64>
"""
import base64
import hashlib
import os
import subprocess
import sys

PRIV, PUB, KID, LINE = ('collector_private.pem', 'collector_public.pem', 'collector_key_id.txt',
                        'collector_seal.txt')


def _tlv(buf, i):
    tag, n = buf[i], buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], 'big')
        i += k
    return tag, buf[i:i + n], i + n


def modulus(pub_pem):
    der = base64.b64decode(''.join(l.strip() for l in open(pub_pem) if l.strip() and not l.startswith('-----')))
    _, spki, _ = _tlv(der, 0)
    _, _alg, i = _tlv(spki, 0)
    _, bits, _ = _tlv(spki, i)
    _, rsa, _ = _tlv(bits[1:], 0)
    _, mod, j = _tlv(rsa, 0)
    _, exp, _ = _tlv(rsa, j)
    if exp.lstrip(b'\x00') != b'\x01\x00\x01':
        sys.exit('collector_public.pem: exponent is not 65537, the collector expects AQAB')
    return der, mod.lstrip(b'\x00')


def main():
    d = sys.argv[1]
    priv, pub, kid = (os.path.join(d, n) for n in (PRIV, PUB, KID))
    if '--show' not in sys.argv:
        os.makedirs(d, mode=0o700, exist_ok=True)
        if not os.path.isfile(priv):
            old = os.umask(0o077)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096',
                            '-out', priv], check=True, stderr=subprocess.DEVNULL)
            os.umask(old)
            print('new collector key created: %s (back it up offline: lose it and no archive opens)' % priv,
                  file=sys.stderr)
        if not os.path.isfile(pub):
            subprocess.run(['openssl', 'pkey', '-in', priv, '-pubout', '-out', pub], check=True)
    der, mod = modulus(pub)
    if len(mod) * 8 < 3072:
        sys.exit('collector key is only %d bits' % (len(mod) * 8))
    if not os.path.isfile(kid):
        open(kid, 'w').write(hashlib.sha256(der).hexdigest()[:16] + '\n')
    key_id = open(kid).read().strip()
    line = 'dfir-seal-1:%s:%s' % (key_id, base64.b64encode(mod).decode())
    if '--show' not in sys.argv:
        open(os.path.join(d, LINE), 'w').write(line + '\n')
    print(line)


if __name__ == '__main__':
    main()
