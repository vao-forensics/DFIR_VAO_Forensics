#!/usr/bin/env python3
"""Runs INSIDE case-maintainer (trusted zone: has the RSA key + crypto libs).
Decrypts the crypto layer of a collector archive using the bot's own proven
routine, writing a PLAINTEXT archive the sandbox can open without any key.
Prints the plaintext path, or 'PLAIN' if the input is not our encrypted archive.
The private key is used only here and never leaves this container."""
import os, sys, shutil
sys.path.insert(0, "/app")
from analysis import archive_crypto as ac

src, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)


def _is_custom(p):
    try:
        return bool(ac.detect(p))
    except Exception:
        return False


try:
    if ac.detect_pwzip(src):
        # current collector format: a password ZIP; make a plain copy in place
        dst = os.path.join(outdir, "plain_" + os.path.basename(src))
        shutil.copy(src, dst)
        ac.maybe_decrypt_in_place(dst)
        print(dst)
    elif _is_custom(src):
        # older container format: decrypt_to_dir yields the inner archive
        ac.decrypt_to_dir(src, outdir)
        inner = [os.path.join(r, f) for r, _, fs in os.walk(outdir) for f in fs]
        print(inner[0] if inner else "PLAIN")
    else:
        print("PLAIN")
except Exception as e:
    sys.stderr.write("decrypt error: %s\n" % e)
    print("PLAIN")
