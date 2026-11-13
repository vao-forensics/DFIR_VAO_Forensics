"""Backfill MFTECmd flag fields into MFT rows ingested before 18.10.2026.

map_fs_mft started keeping SI<FN (with the $FILE_NAME times), uSecZeros, Copied, HasAds and IsAds
on 18.10; older cases have none of them. Only FLAGGED rows are touched (a few thousand per case),
not all ~1 M MFT rows of a case: a full payload rewrite would double filesystem_v2 on disk for
fields that are false on almost every row.

Source: the KAPE zip kept in cases/<case>/uploads/logs (already decrypted at ingest).
Match: case_key + action 'MFT' + file_name + parent_path + payload last_modified (raw string,
exactly as the old ingest stored it). Idempotent: rows that already carry the flag are skipped.

  python3 workers/mft_flags_backfill.py [--apply] [case_key ...]     (default: count only)
"""
import csv
import glob
import io
import json
import os
import sys
import zipfile

import psycopg2
from psycopg2.extras import execute_values

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config import PG_DSN  # noqa: E402

CASES = os.environ.get('DFIR_CASES_DIR', '/data/case_library')
# Copied is true on ~40% of rows (any file that arrived by copy): stored only on rows patched anyway
FLAGS = (('SI<FN', 'si_lt_fn'), ('HasAds', 'has_ads'), ('IsAds', 'is_ads'))
csv.field_size_limit(10 * 1024 * 1024)


def _true(v):
    return str(v or '').strip().lower() == 'true'


def flagged_rows(case_key):
    """(file_name, parent_path, last_modified, payload_patch) for every flagged MFT row in the case zip."""
    zips = sorted(glob.glob(os.path.join(CASES, case_key, 'uploads', '**', '*.zip'), recursive=True))
    out, seen_member = [], None
    for zp in zips:
        try:
            zf = zipfile.ZipFile(zp)
        except zipfile.BadZipFile:
            continue
        for m in zf.namelist():
            low = m.lower()
            if not (low.endswith('.csv') and 'mftecmd' in low and '$mft_output' in low):
                continue
            seen_member = '%s:%s' % (os.path.basename(zp), m)
            with zf.open(m) as fh:
                for row in csv.DictReader(io.TextIOWrapper(fh, encoding='utf-8-sig', errors='replace')):
                    patch = {k: True for col, k in FLAGS if _true(row.get(col))}
                    if not patch:
                        continue
                    if patch.get('si_lt_fn'):
                        if row.get('Created0x30'):
                            patch['created_fn'] = row['Created0x30']
                        if row.get('LastModified0x30'):
                            patch['modified_fn'] = row['LastModified0x30']
                    if _true(row.get('Copied')):
                        patch['copied'] = True
                    if _true(row.get('uSecZeros')):
                        patch['usec_zeros'] = True
                    if row.get('EntryNumber'):
                        patch['entry'] = row['EntryNumber']
                    out.append((row.get('FileName') or None, row.get('ParentPath') or None,
                                row.get('LastModified0x10') or '', json.dumps(patch)))
    return out, seen_member


def backfill(cur, case_key, apply):
    rows, member = flagged_rows(case_key)
    if member is None:
        return 'no MFT csv in uploads'
    cur.execute('CREATE TEMP TABLE IF NOT EXISTS _mft_patch (fn text, pp text, lm text, patch jsonb)')
    cur.execute('TRUNCATE _mft_patch')
    execute_values(cur, 'INSERT INTO _mft_patch VALUES %s', rows, page_size=5000)
    match_sql = """FROM _mft_patch p
        WHERE f.case_key = %s AND f.action = 'MFT'
          AND f.file_name IS NOT DISTINCT FROM p.fn AND f.parent_path IS NOT DISTINCT FROM p.pp
          AND coalesce(f.payload->>'last_modified', '') = p.lm
          AND NOT (coalesce(f.payload, '{}'::jsonb) @> p.patch)"""
    if apply:
        cur.execute('UPDATE filesystem_v2 f SET payload = coalesce(f.payload, \'{}\'::jsonb) || p.patch ' + match_sql,
                    (case_key,))
        n = cur.rowcount
    else:
        cur.execute('SELECT count(*) FROM filesystem_v2 f, _mft_patch p WHERE ' + match_sql.split('WHERE', 1)[1],
                    (case_key,))
        n = cur.fetchone()[0]
    by = {}
    for r in rows:
        for k in json.loads(r[3]):
            if k in ('si_lt_fn', 'has_ads', 'is_ads'):
                by[k] = by.get(k, 0) + 1
    return 'flagged in csv %d %s -> db rows %s %d' % (len(rows), by, 'updated' if apply else 'to update', n)


def main():
    apply = '--apply' in sys.argv
    want = [a for a in sys.argv[1:] if not a.startswith('--')]
    cn = psycopg2.connect(PG_DSN)
    cur = cn.cursor()
    if not want:
        cur.execute("SELECT DISTINCT case_key FROM filesystem_v2 WHERE action = 'MFT' ORDER BY 1")
        want = [r[0] for r in cur.fetchall()]
    for ck in want:
        try:
            print('%-55s %s' % (ck, backfill(cur, ck, apply)), flush=True)
            cn.commit()
        except Exception as e:  # one broken archive must not stop the rest
            cn.rollback()
            print('%-55s ERROR %s' % (ck, e), flush=True)
    cn.close()


if __name__ == '__main__':
    main()
