#!/usr/bin/env python3
"""Offline NTLM hash extraction from raw SAM + SYSTEM registry hives (Win7..Win11,
incl. AES-encrypted SAM on Win10 1607+). Uses impacket (isolated in /opt/impacket).
Returns list of dicts: {user, rid, lm, ntlm}."""
import sys
sys.path.insert(0, '/opt/impacket')
from impacket.examples.secretsdump import LocalOperations, SAMHashes


def extract_ntlm(system_path, sam_path):
    rows = []
    lo = LocalOperations(system_path)
    bootkey = lo.getBootKey()

    def _cb(secret):
        # secret like "Administrator:500:<lm>:<ntlm>:::"
        parts = str(secret).split(':')
        if len(parts) >= 4:
            rows.append({'user': parts[0], 'rid': parts[1], 'lm': parts[2], 'ntlm': parts[3]})

    sam = SAMHashes(sam_path, bootkey, isRemote=False, perSecretCallback=_cb)
    sam.dump()
    sam.finish()
    return rows


if __name__ == '__main__':
    import json
    sysh, samh = sys.argv[1], sys.argv[2]
    r = extract_ntlm(sysh, samh)
    print(json.dumps(r, ensure_ascii=False, indent=2))
