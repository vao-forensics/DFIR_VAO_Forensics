# -*- coding: utf-8 -*-
"""Truth-based regression: run the deterministic layer (and optionally the page-1 render) per case
and score it against /app/analysis/truth/cases.json. Prints one line per case; details go to a JSON file.
Usage (inside case-maintainer):
  python /app/analysis/truth/truth_check.py [--cases substr,substr] [--render] [--out path]"""
import sys, json, re, io, time, datetime
sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN
from analysis.threat_detect import detect_threats

SEV = {'critical': 4, 'crit': 4, 'high': 3, 'medium': 2, 'med': 2, 'low': 1, 'info': 0}


def rank(s):
    return SEV.get(str(s or '').lower(), 0)


args = sys.argv[1:]
only = None
render = False
out = None
i = 0
while i < len(args):
    a = args[i]
    if a == '--cases':
        only = set(args[i + 1].split(','))
        i += 1
    elif a == '--render':
        render = True
    elif a == '--out':
        out = args[i + 1]
        i += 1
    i += 1

truth = json.load(io.open('/app/analysis/truth/cases.json', encoding='utf-8'))['cases']
ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
out = out or '/data/state/truth/scores_%s.json' % ts
res = {}


def _connect():
    c = psycopg2.connect(PG_DSN)
    c.autocommit = True
    c.cursor().execute("SET statement_timeout='300000'")
    return c


# 2026-10-17: one connection for the whole run meant a single dropped connection (server closed it
# while case 2 ran, 27.09 and 11.10) turned every later case into 'connection already closed' and the
# weekly regression into an empty score. Now: a fresh connection per case + one retry on a dropped one.
if True:
    for ck, T in truth.items():
        if only and ck not in only and not any(o in ck for o in only):
            continue
        t0 = time.time()
        F, err = None, None
        for attempt in (1, 2):
            c = None
            try:
                c = _connect()
                F = detect_threats(ck, c) or []
                err = None
                break
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                err = e
                print('RETRY %s attempt %d: %s' % (ck[:30], attempt, str(e).strip()[:200]), flush=True)
                time.sleep(10)
            except Exception as e:
                err = e
                break
            finally:
                try:
                    c and c.close()
                except Exception:
                    pass
        if err is not None:
            print('ERR %s detect: %s' % (ck[:30], err))
            res[ck] = {'error': str(err)}
            continue
        texts = [(rank(f.get('severity')), json.dumps(f, ensure_ascii=False, default=str).lower()) for f in F]
        maxsev = max([r for r, _ in texts] or [0])
        missing, forbidden = [], []
        for m in T.get('must', []):
            need = rank(m.get('min_sev', 'low'))
            rx = re.compile(m['re'])
            if not any(r >= need and rx.search(t) for r, t in texts):
                missing.append(m['label'])
        for m in T.get('must_not', []):
            cap = rank(m.get('max_sev', 'info'))
            rx = re.compile(m['re'])
            if [t for r, t in texts if r > cap and rx.search(t)]:
                forbidden.append(m['label'])
        want = T['verdict']
        verdict_ok = (maxsev >= 3) if want == 'compromised' else (maxsev <= 2)
        p1_bad, p1_missing = [], []
        if render:
            try:
                from reports import reshape as RS
                txt = RS.reshape_client_report(ck, '## 📊 АВТОМАТИЧНІ ДЕТЕКЦІЇ ЗАГРОЗ\n(placeholder)\n')
                cut = txt.find('## 7.')
                page1 = (txt[:cut] if cut > 0 else txt).lower()
                try:
                    io.open('/data/state/truth/p1_%s.txt' % ck[:40], 'w', encoding='utf-8').write(txt[:cut] if cut > 0 else txt)
                except Exception:
                    pass
                p1_bad = [rx for rx in T.get('page1_must_not', []) if re.search(rx, page1)]
                p1_missing = [rx for rx in T.get('page1_must', []) if not re.search(rx, page1)]
            except Exception as e:
                p1_bad = ['RENDER-ERROR: %s' % e]
        ok = verdict_ok and not missing and not forbidden and not p1_bad and not p1_missing
        res[ck] = {'ok': ok, 'want': want, 'maxsev': maxsev, 'verdict_ok': verdict_ok, 'missing': missing,
                   'forbidden': forbidden, 'page1_bad': p1_bad, 'page1_missing': p1_missing,
                   'findings': ['%s|%s' % (f.get('severity'), f.get('title')) for f in F],
                   'secs': round(time.time() - t0)}
        extra = ''
        if missing:
            extra += ' MISSING=%s' % missing
        if forbidden:
            extra += ' FORBIDDEN=%s' % forbidden
        if p1_bad:
            extra += ' PAGE1_BAD=%s' % p1_bad
        if p1_missing:
            extra += ' PAGE1_MISSING=%s' % p1_missing
        if not verdict_ok:
            extra += ' VERDICT-MISMATCH'
        print('%s %-40s max=%d want=%s%s  %ds' % ('PASS' if ok else 'FAIL', ck[:40], maxsev, want, extra,
                                                  res[ck]['secs']), flush=True)
json.dump(res, io.open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
n = sum(1 for v in res.values() if v.get('ok'))
print('TRUTH: %d/%d pass -> %s' % (n, len(res), out))
