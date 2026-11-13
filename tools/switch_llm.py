# -*- coding: utf-8 -*-
"""Switch the DFIR pipeline between the current model set and the 120B MoE.

    python3 switch_llm.py big     -> synthesis/react/general = big-120b, embeddings = CPU
    python3 switch_llm.py revert  -> restore whatever was there before the first switch

Why the embedding model has to move to the CPU: the 120B fills all five cards (13.8-15.9 GB each,
measured), so a GPU embedding request would evict it and pay ~100 s to reload it. Served from system
RAM the same embedding costs 0.79 s and the 120B never leaves the cards.
"""
import io
import re
import shutil
import subprocess
import sys

COMPOSE = '/srv/dfir/docker-compose.yml'
BACKUP = '/srv/dfir/var/attic/docker-compose.yml.bak.llm120'

BIG = {
    'DFIR_LLM_MODEL': 'big-120b',
    'DFIR_SYNTH_MODEL': 'big-120b',
    'DFIR_AGENT_JSON_MODEL': 'big-120b',
    'DFIR_EML_MODEL': 'big-120b',
    'DFIR_GENERAL_MODEL': 'big-120b',
    'DFIR_REACT_MODEL': 'big-120b',
    'DFIR_EMBED_MODEL': 'text-embedding-qwen3-embedding-8b-cpu',
    'DFIR_FAST_MODEL': 'big-120b',
}


def current(s):
    out = {}
    for k in BIG:
        m = re.search(r'^(\s*-\s*)' + k + r'=(.*)$', s, re.M)
        if m:
            out[k] = m.group(2).strip()
    return out


def main():
    mode = (sys.argv[1] if len(sys.argv) > 1 else '').lower()
    s = io.open(COMPOSE, encoding='utf-8').read()

    if mode == 'big':
        import os
        if not os.path.exists(BACKUP):
            shutil.copy2(COMPOSE, BACKUP)
            print('backup ->', BACKUP)
        print('before:', current(s))
        n = 0
        for k, v in BIG.items():
            s, c = re.subn(r'^(\s*-\s*)' + k + r'=.*$', lambda m: m.group(1) + k + '=' + v, s, flags=re.M)
            n += c
        io.open(COMPOSE, 'w', encoding='utf-8').write(s)
        print('replacements:', n)
        print('after:', current(io.open(COMPOSE, encoding='utf-8').read()))
    elif mode == 'revert':
        shutil.copy2(BACKUP, COMPOSE)
        print('restored from', BACKUP)
        print('now:', current(io.open(COMPOSE, encoding='utf-8').read()))
    else:
        print(__doc__)
        print('current:', current(s))
        return

    print(subprocess.run(['docker', 'compose', 'config', '--quiet'], cwd='/srv/dfir',
                         capture_output=True, text=True).stderr.strip() or 'compose valid')


if __name__ == '__main__':
    main()
