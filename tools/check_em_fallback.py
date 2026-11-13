"""Guard for parsers/forensic.py::_em fallback branch.

_em rewrites simple 'INSERT ... VALUES(%s,...)' into a multi-row execute_values call.
Any other SQL shape (ON CONFLICT / RETURNING / UPDATE / DELETE) must fall back to
cur.executemany. A previous version called _em(cur, sql, rows) there -> infinite
recursion (RecursionError) for every non-simple statement.

Imports the REAL _em from the production module - no copy of production code here.
"""
import sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
for p in ('/app', os.path.join(os.path.dirname(HERE), 'services', 'case_maintainer')):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import parsers.forensic as F


class FakeCur(object):
    def __init__(self):
        self.many = []      # (sql, rows) seen by executemany
        self.single = []    # (sql, args) seen by execute

    def executemany(self, sql, rows):
        self.many.append((sql, list(rows)))

    def execute(self, sql, args=None):
        self.single.append((sql, args))


ok = 0
fail = 0


def check(name, cond, detail=''):
    global ok, fail
    if cond:
        ok += 1
        print('PASS ' + name)
    else:
        fail += 1
        print('FAIL ' + name + '  ' + str(detail))


def run(sql, rows):
    """Call the real _em with execute_values recorded instead of executed."""
    calls = []
    orig = F.execute_values
    F.execute_values = lambda cur, s, r, page_size=None: calls.append((s, list(r)))
    cur = FakeCur()
    try:
        F._em(cur, sql, rows)
        err = None
    except RecursionError as e:
        err = e
    finally:
        F.execute_values = orig
    return cur, calls, err


SIMPLE = 'INSERT INTO t (a,b) VALUES(%s,%s)'
CONFL = 'INSERT INTO t (a,b) VALUES(%s,%s) ON CONFLICT DO NOTHING'
RET = 'INSERT INTO t (a,b) VALUES(%s,%s) RETURNING id'
UPD = 'UPDATE t SET a=%s WHERE b=%s'
DEL = 'DELETE FROM t WHERE case_key=%s'

R2 = [('r1', 'x'), ('r2', 'y')]

# 1) simple INSERT keeps the fast path
cur, calls, err = run(SIMPLE, R2)
check('simple INSERT -> execute_values', err is None and len(calls) == 1 and cur.many == [], (calls, cur.many, err))
check('simple INSERT rows intact', calls and calls[0][1] == R2, calls)
check('simple INSERT sql rewritten to VALUES %s', calls and 'VALUES %s' in calls[0][0], calls)

# 2) the branch that used to recurse
for name, sql, rows in (('ON CONFLICT', CONFL, R2), ('RETURNING', RET, R2),
                        ('UPDATE', UPD, R2), ('DELETE', DEL, [('ZZ_CASE',)])):
    cur, calls, err = run(sql, rows)
    check(name + ' -> no RecursionError', err is None, err)
    check(name + ' -> executemany once', len(cur.many) == 1 and calls == [], (cur.many, calls))
    check(name + ' -> exact sql+rows reach the cursor',
          cur.many == [(sql, rows)], cur.many)

# 3) empty rows are a no-op on every shape
for name, sql in (('simple', SIMPLE), ('conflict', CONFL)):
    cur, calls, err = run(sql, [])
    check('empty rows no-op (' + name + ')', err is None and cur.many == [] and calls == [], (cur.many, calls, err))

print('ПІДСУМОК: ' + str(ok) + ' PASS, ' + str(fail) + ' FAIL')
sys.exit(1 if fail else 0)
