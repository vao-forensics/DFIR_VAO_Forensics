# -*- coding: utf-8 -*-
"""Prefetch rescue: when an archive carries raw .pf files but no PECmd output (PECmd < 2026.5 refuses
Prefetch v31 on Windows 11 24H2+), parse the .pf natively and feed the same program_exec_v2 /
prefetch_timeline shape the PECmd mapper produces.

Sources searched, in order: members of the ingested zip; a nested *input*.zip inside it; sibling
*input*.zip / *.zip files next to it in uploads/logs (the v4 collector ships input and output as two
archives, sometimes wrapped in one outer zip).
"""
import io, os, zipfile, glob

from parsers.prefetch_py import parse_prefetch, rows_from_prefetch


def _iter_pf_in_zip(zf, depth=0):
    for n in zf.namelist():
        nl = n.lower()
        if nl.endswith('.pf'):
            try:
                yield n, zf.read(n)
            except Exception:
                continue
        elif depth < 1 and nl.endswith('.zip') and 'input' in nl:
            try:
                inner = zipfile.ZipFile(io.BytesIO(zf.read(n)))
            except Exception:
                continue
            for x in _iter_pf_in_zip(inner, depth + 1):
                yield x


def find_pf_sources(zip_path, zf=None):
    """Yield (source_label, name, bytes) for every raw prefetch file reachable from zip_path."""
    if zf is not None:
        for n, b in _iter_pf_in_zip(zf):
            yield os.path.basename(zip_path), n, b
    d = os.path.dirname(zip_path)
    for sib in sorted(glob.glob(os.path.join(d, '*.zip'))):
        if os.path.abspath(sib) == os.path.abspath(zip_path):
            continue
        try:
            with zipfile.ZipFile(sib) as z2:
                for n, b in _iter_pf_in_zip(z2):
                    yield os.path.basename(sib), n, b
        except Exception:
            continue


def rescue_rows(zip_path, zf=None, limit=6000):
    """(pecmd_like_rows, timeline_rows, source_label, n_failed)"""
    pe, tl, src_used, failed, seen = [], [], '', 0, set()
    for src, name, data in find_pf_sources(zip_path, zf):
        base = os.path.basename(name)
        if base.lower() in seen:
            continue
        seen.add(base.lower())
        r = rows_from_prefetch(base, data)
        if not r:
            failed += 1
            continue
        src_used = src_used or src
        pe.append(r)
        p = parse_prefetch(data)
        for t in (p or {}).get('run_times') or []:
            tl.append({'RunTime': t.strftime('%Y-%m-%d %H:%M:%S'), 'ExecutableName': r['ExecutableName'], 'SourceFilename': base})
        if len(pe) >= limit:
            break
    return pe, tl, src_used, failed
