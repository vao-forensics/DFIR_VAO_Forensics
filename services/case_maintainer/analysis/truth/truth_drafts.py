# -*- coding: utf-8 -*-
"""Truth DRAFTS — never ground truth.

Two sources, both produce a draft file under /data/state/truth/drafts/ and NOTHING else:
  --scaffold <case_key>   from the detector's current output. The detector cannot approve its own
                          result: the draft has verdict=null, its findings are listed as
                          «candidates», and status says the owner must confirm every line.
  --from-feedback         from case_feedback / dfir_case_verified_findings, but ONLY rows the owner
                          set explicitly (verdict correct/wrong by the owner's user id; approved
                          findings with a human approver). «unknown», «pending» and anything
                          produced by the bot itself are ignored.
Promotion into analysis/truth/cases.json is a manual step after the owner confirms.
"""
import sys, io, os, json, re, datetime
sys.path.insert(0, '/app')

DRAFT_DIR = '/data/state/truth/drafts'
OWNER_ID = 'CHANGE_ME_OWNER_CHAT_ID'
CASES = '/app/analysis/truth/cases.json'


def _write_draft(name, obj):
    os.makedirs(DRAFT_DIR, exist_ok=True)
    p = os.path.join(DRAFT_DIR, name)
    io.open(p, 'w', encoding='utf-8').write(json.dumps(obj, ensure_ascii=False, indent=1))
    return p


def _rx(title):
    words = [w for w in re.findall(r'[a-zA-Zа-яА-ЯіїєґІЇЄҐ0-9]{4,}', str(title or '').lower())][:3]
    return '|'.join(re.escape(w) for w in words) or re.escape(str(title or '')[:20].lower())


def scaffold(case_key):
    import psycopg2
    from core.config import PG_DSN
    from analysis.threat_detect import detect_threats
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        F = detect_threats(case_key, c) or []
    cands = [{'label': f.get('title'), 're': _rx(f.get('title')), 'detector_severity': f.get('severity'),
              'category': f.get('category'), 'owner_confirmed': False} for f in F]
    draft = {
        'status': 'DRAFT — NOT ground truth. Detector output only; the owner must confirm the verdict '
                  'and every candidate before this enters cases.json.',
        'case_key': case_key, 'created': datetime.datetime.now().isoformat(timespec='seconds'),
        'verdict': None, 'source': 'detector-scaffold',
        'candidates': cands, 'must': [], 'must_not': [], 'page1_must_not': [],
    }
    return _write_draft('%s.scaffold.json' % case_key, draft)


def from_feedback():
    import psycopg2
    from core.config import PG_DSN
    out = {}
    with psycopg2.connect(PG_DSN) as c:
        cur = c.cursor()
        cur.execute("""SELECT case_key, claim_type, claim_text, verdict FROM case_feedback
                       WHERE user_id::text=%s AND verdict IN ('correct','wrong')""", (OWNER_ID,))
        for ck, ctype, text, verdict in cur.fetchall():
            d = out.setdefault(ck, {'must': [], 'must_not': [], 'ignored': []})
            item = {'label': '%s: %s' % (ctype, str(text)[:80]), 're': _rx(text), 'min_sev': 'low',
                    'owner_confirmed': True, 'from': 'case_feedback'}
            (d['must'] if verdict == 'correct' else d['must_not']).append(item)
        cur.execute("""SELECT case_key, title, value, approval_status, coalesce(approved_by::text,'')
                       FROM dfir_case_verified_findings WHERE approval_status='approved'""")
        for ck, title, value, st, by in cur.fetchall():
            d = out.setdefault(ck, {'must': [], 'must_not': [], 'ignored': []})
            if not by or 'bot' in by.lower() or by.lower() in ('auto', 'system'):
                d['ignored'].append('approved without a human approver: %s' % str(title)[:60])
                continue
            d['must'].append({'label': 'verified: %s' % str(title)[:80], 're': _rx(title or value),
                              'min_sev': 'low', 'owner_confirmed': True, 'from': 'dfir_case_verified_findings',
                              'approved_by': by})
    paths = []
    for ck, d in out.items():
        draft = {'status': 'DRAFT from owner feedback — promote manually after reading; '
                           'unknown/pending/bot-made rows were ignored.',
                 'case_key': ck, 'created': datetime.datetime.now().isoformat(timespec='seconds'),
                 'verdict': None, 'source': 'owner-feedback', **d}
        paths.append(_write_draft('%s.feedback.json' % ck, draft))
    return paths


if __name__ == '__main__':
    before = io.open(CASES, 'rb').read() if os.path.exists(CASES) else b''
    a = sys.argv[1:]
    if a[:1] == ['--scaffold'] and len(a) > 1:
        print('draft:', scaffold(a[1]))
    elif a[:1] == ['--from-feedback']:
        for p in from_feedback():
            print('draft:', p)
    else:
        print(__doc__)
    after = io.open(CASES, 'rb').read() if os.path.exists(CASES) else b''
    assert before == after, 'cases.json must never be touched by drafts'
