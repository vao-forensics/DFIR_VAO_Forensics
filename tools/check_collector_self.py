"""E2E proof for INTEGRATION_CONTRACT.md §2 п.1: _collector_self.txt is read and the
paths it names are subtracted from tampering evidence — and nothing else is."""
import os
import sys
import zipfile

sys.path.insert(0, '/app')
CASE = 'ZZ_NIGHT_SELFDECL'
LIB = '/data/case_library'
d = os.path.join(LIB, CASE, 'uploads', 'logs')
os.makedirs(d, exist_ok=True)
zp = os.path.join(d, CASE + '.zip')

BS = chr(92)
WORK = 'D:' + BS + 'Zbir_2026'                                     # declared, NOT matched by _OWN_PATH_RE
TOOL = 'C:' + BS + 'Users' + BS + 'op' + BS + 'AppData' + BS + 'Local' + BS + 'Temp' + BS + 'Zbir_tk_9f2a'
ATT = 'C:' + BS + 'Users' + BS + 'buh' + BS + 'AppData' + BS + 'Roaming' + BS + 'evil'
NEAR = 'D:' + BS + 'Zbir_2026_backup'                              # looks like ours, NOT declared

self_txt = ('# paths THIS collector added to Defender exclusions (not attacker activity)'
            + chr(13) + chr(10) + WORK + chr(13) + chr(10) + TOOL + chr(13) + chr(10))

excl_csv = ('kind,value,exists' + chr(10)
            + 'ExclusionPath,"' + WORK + '",yes' + chr(10)
            + 'ExclusionPath,"' + TOOL + '",no' + chr(10)
            + 'ExclusionPath,"' + ATT + '",yes' + chr(10)
            + 'ExclusionPath,"' + NEAR + '",yes' + chr(10))

env_csv = 'check,status,detail' + chr(10) + 'admin,ok,' + chr(10)

with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('_collector_self.txt', self_txt.encode('utf-8'))
    z.writestr('live/defender_exclusions.csv', excl_csv.encode('utf-8'))
    z.writestr('environment_restrictions.csv', env_csv.encode('utf-8'))

from parsers.forensic import _ensure_minimal_ingest_from_zip
print('INGEST:', _ensure_minimal_ingest_from_zip(CASE))

import psycopg2
c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
k = c.cursor()
k.execute("""SELECT parser_family, payload FROM raw_fallback_v2
             WHERE case_key=%s AND parser_family IN ('collector_self','defender_exclusions')
             ORDER BY parser_family, row_id""", (CASE,))
rows = k.fetchall()
print('DB ROWS:')
for f, p in rows:
    print('  ', f, p)

from analysis.collector_self import declared_self_paths, contains_declared
decl = declared_self_paths(CASE)
print('DECLARED:', sorted(decl))

sys.path.insert(0, '/app/reports')
import reports.reshape as RS
sec = RS._collection_conditions_section(CASE)
txt = chr(10).join(sec)
print('--- SECTION ---')
print(txt)
print('--- ASSERTIONS ---')
ok = True


def chk(name, cond):
    global ok
    print(('  PASS ' if cond else '  FAIL ') + name)
    ok = ok and bool(cond)


chk('declared set has exactly 2 paths', len(decl) == 2)
chk('attacker path RENDERED as tampering', ATT.lower() in txt.lower())
chk('near-miss path (not declared) RENDERED', NEAR.lower() in txt.lower())
chk('declared work root NOT rendered as tampering',
    (WORK.lower() + '`') not in txt.lower())
chk('declared toolkit path NOT rendered as tampering', TOOL.lower() not in txt.lower())
chk('own counter says 2 and credits the file', ('ще 2' in txt) and ('самодекларації' in txt))
chk('cmdline containing a declared path is recognised as ours',
    contains_declared('powershell.exe add-mppreference -exclusionpath ' + WORK.lower(), decl))
chk('cmdline with an undeclared path is NOT ours',
    not contains_declared('powershell.exe add-mppreference -exclusionpath ' + ATT.lower(), decl))
chk('a bare system root is refused even if declared',
    not contains_declared('c:' + BS + 'windows' + BS + 'system32' + BS + 'svchost.exe',
                          declared_self_paths(CASE) | set()))
print('RESULT:', 'ALL PASS' if ok else 'FAILED')
