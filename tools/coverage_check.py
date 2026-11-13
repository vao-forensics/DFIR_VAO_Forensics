# -*- coding: utf-8 -*-
"""Measure the bot against the expert reports, honestly.

The number this produces was, until now, computed by a script that lived in /tmp and is
gone, so it could not be reproduced - which is why it lives in tools/ now.

Method (unchanged from docs/NIGHT_WORKLOG.md):
  * golden facts come from dfir_golden_facts_v1 (LLM extraction of the expert PDF);
  * every fact is broken into concrete artefact tokens - hashes, IPv4, domains, file
    names, SIDs. A fact with no token is NOT MEASURABLE: there is nothing to look for;
  * a fact counts as FOUND only if one of its tokens is BOTH in the bot's finished
    report AND in the artefact tables.

The correction this file exists for: "the artefact tables" used to include case_iocs rows
whose source_table is 'report' - i.e. indicators lifted out of the expert PDF itself. On
20_05 that is 44 of 111 rows, the single largest source in the case. Counting them makes
the bot's own crib sheet look like evidence it recovered. Both filters are reported side
by side so the size of the correction is visible instead of asserted.

    docker cp tools/coverage_check.py case-maintainer:/tmp/cov.py
    docker exec case-maintainer python3 -u /tmp/cov.py
"""
import os
import re
import sys

if '/app' not in sys.path:
    sys.path.insert(0, '/app')

import psycopg2

from analysis.output_guardrails import guard_client_output
from reports import reshape as _reshape_mod

LLM_TEXT = ('Аналіз показує ознаки компрометації робочої станції. '
            'Деталі наведено нижче у службових даних.')

# The filter as it was written when 30/42 was published: it names two report sources and
# any document extension, and lets the plain 'report' source through.
OLD_EXCL = ('report_llm', 'report_pdf')
# ...and as it must be: 'report' is the expert document parsed into rows, and
# 'report_reclassified' is the same rows relabelled.
NEW_EXCL = ('report_llm', 'report_pdf', 'report', 'report_reclassified')

_HASH = re.compile(r'\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b')
_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_SID = re.compile(r'\bS-1-5-21-[0-9\-]+\b')
_FILE = re.compile(r'\b[\w\-. ]{1,60}\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|scr|sys|msi|'
                   r'lnk|zip|rar|7z|docx?|xlsx?|pdf|tmp|dat|reg)\b', re.I)
_DOM = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+'
                  r'(?:com|net|org|ua|ru|io|info|biz|xyz|top|site|online|cc|me|su|pw|app|dev)\b',
                  re.I)
# tokens that name no particular artefact
_STOP = {'file.exe', 'malware.exe', 'unknown.exe', 'setup.exe', 'install.exe'}


def _ip_ok(tok):
    p = tok.split('.')
    return len(p) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in p) and not tok.startswith('0')


def tokens(text):
    """Concrete artefact tokens inside one golden fact value."""
    t = str(text or '')
    out = []
    for m in _HASH.findall(t):
        out.append(m.lower())
    for m in _IPV4.findall(t):
        if _ip_ok(m):
            out.append(m)
    for m in _SID.findall(t):
        # the report is lower-cased before the comparison, so a SID kept in its original
        # case could never match: both golden SID facts on 20_05 were counted as misses
        # while the report printed the SID on its accounts line all along.
        out.append(m.lower())
    for m in _FILE.findall(t):
        v = m.strip().lower()
        if len(v) > 4 and v not in _STOP:
            out.append(v)
    for m in _DOM.findall(t):
        v = m.strip('.').lower()
        if not _FILE.fullmatch(v) and len(v) > 4:
            out.append(v)
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


ART_Q = [
    # cheapest first - the loop stops at the first table that holds the token
    ('case_iocs', "SELECT 1 FROM case_iocs WHERE case_key=%s AND ioc_value ILIKE %s "
                  "AND coalesce(source_table,'') NOT IN %s "
                  "AND coalesce(source_table,'') !~* '[.](pdf|docx|doc|md)$' LIMIT 1"),
    ('program_exec_v2', "SELECT 1 FROM program_exec_v2 WHERE case_key=%s AND "
                        "(coalesce(executable_name,'')||' '||coalesce(full_path,'')||' '"
                        "||coalesce(hash_sha1,'')) ILIKE %s LIMIT 1"),
    ('filesystem_v2', "SELECT 1 FROM filesystem_v2 WHERE case_key=%s AND "
                      "(file_name ILIKE %s OR coalesce(parent_path,'') ILIKE %s) LIMIT 1"),
    ('event_logs_v2', "SELECT 1 FROM event_logs_v2 WHERE case_key=%s AND "
                      "(coalesce(command_line,'')||' '||coalesce(process_name,'')||' '"
                      "||coalesce(target_user,'')||' '||coalesce(remote_host,'')) ILIKE %s LIMIT 1"),
    ('event_logs_v2/payload', "SELECT 1 FROM event_logs_v2 WHERE case_key=%s AND "
                              "payload::text ILIKE %s LIMIT 1"),
    ('raw_fallback_v2', "SELECT 1 FROM raw_fallback_v2 WHERE case_key=%s AND "
                        "payload::text ILIKE %s LIMIT 1"),
]


_CACHE = {}


def in_artifacts(cur, case_key, tok, excl):
    """Which table holds this token, or None.

    Memoised, and split in two: only the case_iocs probe depends on the exclusion
    list, so the expensive raw-artefact scans (filesystem_v2 is 4.7M rows, the
    event/raw payload probes are unindexed text scans) run ONCE per token instead of
    once per token per filter. Without this the run does not finish in a night.
    """
    like = '%' + tok + '%'
    k_ioc = ('ioc', case_key, tok, excl)
    if k_ioc not in _CACHE:
        _CACHE[k_ioc] = _probe(cur, ART_Q[0], case_key, like, excl, tok)
    if _CACHE[k_ioc]:
        return _CACHE[k_ioc]
    k_raw = ('raw', case_key, tok)
    if k_raw not in _CACHE:
        got = None
        for q in ART_Q[1:]:
            got = _probe(cur, q, case_key, like, excl, tok)
            if got:
                break
        _CACHE[k_raw] = got
    return _CACHE[k_raw]


def _probe(cur, entry, case_key, like, excl, tok):
    name, q = entry
    args = (case_key, like, excl) if name == 'case_iocs' else (
        (case_key, like, like) if name == 'filesystem_v2' else (case_key, like))
    try:
        cur.execute("SET statement_timeout = '150s'")
        cur.execute(q, args)
        return name if cur.fetchone() else None
    except Exception as e:
        print('        [timeout/err %s %s: %s]' % (name, tok[:24], str(e)[:50]))
        return None
    finally:
        try:
            cur.execute("SET statement_timeout = 0")
        except Exception:
            pass


def main():
    c = psycopg2.connect(os.environ['PG_DSN'])
    c.autocommit = True
    cur = c.cursor()
    cur.execute("""SELECT DISTINCT g.case_key FROM dfir_golden_facts_v1 g
                   WHERE EXISTS (SELECT 1 FROM event_logs_v2 e WHERE e.case_key=g.case_key)
                   ORDER BY 1""")
    cases = [r[0] for r in cur.fetchall()]
    print('справ з еталоном і даними: %d\n' % len(cases))

    tot = {'facts': 0, 'meas': 0}
    per_filter = {'OLD': {'found': 0, 'A': 0, 'B': 0}, 'NEW': {'found': 0, 'A': 0, 'B': 0}}
    moved = []

    import time as _t
    for ck in cases:
        _t0 = _t.time()
        print('рендерю %s ...' % ck)
        guarded, _ = guard_client_output(ck, LLM_TEXT, kind='txt_report')
        report = (_reshape_mod.reshape_client_report(ck, guarded) or '').lower()
        print('   готово за %.0f с' % (_t.time() - _t0))
        cur.execute("""SELECT category, fact_key, fact_value FROM dfir_golden_facts_v1
                       WHERE case_key=%s ORDER BY category, fact_key""", (ck,))
        facts = cur.fetchall()
        c_meas = c_old = c_new = 0
        print('=== %s   (звіт %d символів, фактів %d)' % (ck, len(report), len(facts)))
        for cat, fk, fv in facts:
            tot['facts'] += 1
            toks = tokens(fv)
            if not toks:
                continue
            tot['meas'] += 1
            c_meas += 1
            hit_rep = [t for t in toks if t in report]
            res = {}
            for lbl, excl in (('OLD', OLD_EXCL), ('NEW', NEW_EXCL)):
                where = {t: in_artifacts(cur, ck, t, excl) for t in toks}
                art = [t for t, w in where.items() if w]
                if not art:
                    res[lbl] = ('A', None)
                elif set(hit_rep) & set(art):
                    t = sorted(set(hit_rep) & set(art))[0]
                    res[lbl] = ('found', where[t])
                else:
                    res[lbl] = ('B', where[art[0]])
            for lbl in ('OLD', 'NEW'):
                per_filter[lbl][res[lbl][0]] += 1
            # per-fact verdict under the honest filter: without it the log names only the
            # facts that CHANGED status, so the misses themselves stay invisible.
            print('   [%2d] %-16s %-26s %-5s %-18s %s'
                  % (c_meas, cat[:16], fk[:26], res['NEW'][0],
                     res['NEW'][1] or '-', toks[:3]))
            c_old += res['OLD'][0] == 'found'
            c_new += res['NEW'][0] == 'found'
            if res['OLD'][0] != res['NEW'][0]:
                moved.append((ck, cat, fk, res['OLD'], res['NEW'], toks[:3]))
                print('   ЗМІНА %-22s %-26s %s -> %s  (%s)  токени %s'
                      % (cat[:22], fk[:26], res['OLD'][0], res['NEW'][0],
                         res['OLD'][1], toks[:3]))
        print('   вимірних %d, знайдено старим фільтром %d, новим %d\n' % (c_meas, c_old, c_new))

    print('=' * 72)
    print('золотих фактів усього      : %d' % tot['facts'])
    print('вимірних (є токен)         : %d' % tot['meas'])
    for lbl in ('OLD', 'NEW'):
        d = per_filter[lbl]
        pct = (100.0 * d['found'] / tot['meas']) if tot['meas'] else 0
        print('%-4s фільтр: знайдено %d (%.0f%%), A даних нема %d, B у звіт не дійшло %d'
              % (lbl, d['found'], pct, d['A'], d['B']))
    print('фактів, що змінили статус  : %d' % len(moved))
    print('ПІДСУМОК покриття %d з %d вимірних (чесний фільтр)'
          % (per_filter['NEW']['found'], tot['meas']))


if __name__ == '__main__':
    main()
