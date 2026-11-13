# -*- coding: utf-8 -*-
"""Real-ingest smoke test for parsers/forensic changes (header sniff + logon_type_of).
Builds a small archive from REAL EZ output (case_45) under FOREIGN file names, ingests it under a
throwaway case_key, checks the DB, then deletes every row of that key. Run inside case-maintainer."""
import sys, os, zipfile, shutil
sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN

CK = 'zz_smoke_sniff'
SRC = '/data/case_library/case_36/uploads/logs/27_07_2026_case_45_kape.zip'
DST_DIR = '/data/case_library/%s/uploads/logs' % CK
dst = DST_DIR + '/smoke.zip'


def cleanup():
    n = 0
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        cur = c.cursor()
        cur.execute("""SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t
                       ON t.table_name=c.table_name AND t.table_schema=c.table_schema
                       WHERE c.table_schema='public' AND c.column_name='case_key' AND t.table_type='BASE TABLE'""")
        for (t,) in cur.fetchall():
            try:
                cur.execute('DELETE FROM public."%s" WHERE case_key=%%s' % t, (CK,))
                if cur.rowcount > 0:
                    n += cur.rowcount
            except Exception as e:
                print('  del-err', t, str(e)[:80])
    shutil.rmtree('/data/case_library/%s' % CK, ignore_errors=True)
    return n


def slice_of(zf, name, n, must_eid=None):
    if isinstance(must_eid, str) and ',' in must_eid:
        must_eid = set(must_eid.split(','))
    elif isinstance(must_eid, str):
        must_eid = {must_eid}
    import csv, io as _io
    f = zf.open(name)
    rd = csv.reader(_io.TextIOWrapper(f, encoding='utf-8-sig', errors='ignore', newline=''))
    hdr = next(rd)
    col = hdr.index('EventId') if 'EventId' in hdr else None
    buf = _io.StringIO()
    wr = csv.writer(buf, lineterminator='\n')
    wr.writerow(hdr)
    k = 0
    for row in rd:
        if must_eid is not None and (col is None or len(row) <= col or row[col] not in must_eid):
            continue
        wr.writerow(row)
        k += 1
        if k >= n:
            break
    return buf.getvalue()


if '--cleanup-only' in sys.argv:
    print('cleanup rows deleted:', cleanup())
    sys.exit(0)

print('pre-clean rows deleted:', cleanup())
os.makedirs(DST_DIR, exist_ok=True)
with zipfile.ZipFile(SRC) as z:
    names = z.namelist()
    ev = [n for n in names if n.lower().endswith('evtxecmd_output.csv')][0]
    pe = [n for n in names if 'pecmd_output.csv' in n.lower() and 'timeline' not in n.lower()][0]
    with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as out:
        out.writestr('Odd/renamed_events_by_new_kape.csv', slice_of(z, ev, 1500, must_eid=(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '--cleanup-only' else '4624')))
        out.writestr('Odd/renamed_prefetch.csv', slice_of(z, pe, 300))
print('archive built:', os.path.getsize(dst), 'bytes')

from parsers.forensic import _ensure_minimal_ingest_from_zip
try:
    r = _ensure_minimal_ingest_from_zip(CK)
    print('ingest returned:', str(r)[:200])
except Exception as e:
    print('INGEST-ERR', repr(e)[:300])

with psycopg2.connect(PG_DSN) as c:
    cur = c.cursor()
    cur.execute("SELECT count(*), count(*) FILTER (WHERE event_id=4624), count(*) FILTER (WHERE event_id=4624 AND logon_type IS NOT NULL), count(*) FILTER (WHERE event_id=4624 AND logon_type='10') FROM event_logs_v2 WHERE case_key=%s", (CK,))
    print('event_logs rows / 4624 / 4624 with logon_type / type10:', cur.fetchone())
    cur.execute("SELECT event_id, count(*), count(remote_host), count(target_user), count(*) FILTER (WHERE payload::text ILIKE '%%TaskName%%' OR payload::text ILIKE '%%Address%%') FROM event_logs_v2 WHERE case_key=%s GROUP BY 1 ORDER BY 1", (CK,))
    print('per-eid rows/remote_host/target_user/lifted:', cur.fetchall())
    cur.execute("SELECT count(*) FROM program_exec_v2 WHERE case_key=%s", (CK,))
    print('program_exec rows:', cur.fetchone()[0])
    cur.execute("SELECT rel_path, family, status, rows FROM dfir_ingest_coverage_v1 WHERE case_key=%s", (CK,))
    print('coverage:', cur.fetchall())
print('cleanup rows deleted:', cleanup())
