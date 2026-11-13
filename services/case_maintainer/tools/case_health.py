# -*- coding: utf-8 -*-
"""
DFIR case health / self-test. Runs data-completeness + anomaly checks on every case so
broken/empty/regressed cases (like an empty 20_05, or a delete that left orphans) are
visible immediately. Run standalone (python3 case_health.py) or after each ingest.
Exit code 0 = all healthy, 1 = warnings/errors found.
"""
import sys, os
sys.path.insert(0, '/app')
import psycopg2

PG = os.getenv('PG_DSN')

# per-case data expectations (minimum sane thresholds)
def check():
    conn = psycopg2.connect(PG); conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT case_key FROM cases ORDER BY 1")
    cases = [r[0] for r in cur.fetchall()]
    report = []
    global_issues = []

    # ---- global integrity (not per-case) ----
    for tbl, keycol in [('event_logs_v2', 'case_key'), ('filesystem_v2', 'case_key'),
                        ('program_exec_v2', 'case_key'), ('raw_fallback_v2', 'case_key'),
                        ('case_iocs', 'case_key'), ('tool_alerts_v2', 'case_key')]:
        cur.execute(f"SELECT count(*) FROM {tbl} WHERE {keycol} NOT IN (SELECT case_key FROM cases)")
        n = cur.fetchone()[0]
        if n:
            global_issues.append(f"ORPHAN: {n} rows in {tbl} with no matching case")
    cur.execute("""SELECT count(*) FROM ioc_overlap WHERE case_a NOT IN (SELECT case_key FROM cases)
                   OR case_b NOT IN (SELECT case_key FROM cases)""")
    if cur.fetchone()[0]:
        global_issues.append("ORPHAN: ioc_overlap references deleted case")
    # duplicate-ish case keys (underscore/space variants)
    cur.execute("""SELECT lower(replace(replace(case_key,'_',''),' ','')) norm, count(*), string_agg(case_key,' | ')
                   FROM cases GROUP BY 1 HAVING count(*) > 1""")
    for norm, n, keys in cur.fetchall():
        global_issues.append(f"DUP CASES: {keys}")

    # ---- per-case ----
    for ck in cases:
        counts = {}
        for tbl in ['event_logs_v2', 'filesystem_v2', 'program_exec_v2', 'raw_fallback_v2',
                    'case_iocs', 'tool_alerts_v2']:
            cur.execute(f"SELECT count(*) FROM {tbl} WHERE case_key=%s", (ck,))
            counts[tbl] = cur.fetchone()[0]
        cur.execute("SELECT count(DISTINCT ioc_type) FROM case_iocs WHERE case_key=%s", (ck,))
        ioc_types = cur.fetchone()[0]

        issues = []
        sev = 'ok'
        if counts['event_logs_v2'] == 0 and counts['filesystem_v2'] == 0:
            issues.append('EMPTY: no log data at all'); sev = 'broken'
        else:
            if counts['event_logs_v2'] == 0:
                issues.append('no event_logs'); sev = 'warn'
            if counts['filesystem_v2'] == 0:
                issues.append('no filesystem'); sev = 'warn'
            if counts['case_iocs'] == 0:
                issues.append('no IOCs extracted'); sev = max(sev, 'warn', key=_rank)
            if counts['program_exec_v2'] == 0:
                issues.append('no program execution data'); sev = max(sev, 'warn', key=_rank)
        report.append((ck, sev, counts, ioc_types, issues))

    return report, global_issues

def _rank(s):
    return {'ok': 0, 'warn': 1, 'broken': 2}.get(s, 0)

def main():
    report, gi = check()
    bad = 0
    print("=" * 68)
    print("DFIR CASE HEALTH / SELF-TEST")
    print("=" * 68)
    if gi:
        print("\n[!] GLOBAL INTEGRITY ISSUES:")
        for g in gi:
            print("   -", g); bad += 1
    else:
        print("\n[OK] Global integrity: 0 orphans, no duplicate cases.")
    print("\nPER-CASE:")
    icon = {'ok': '[OK]  ', 'warn': '[WARN]', 'broken': '[BROK]'}
    for ck, sev, c, it, issues in report:
        print(f"  {icon[sev]} {ck[:42]:42s} ev={c['event_logs_v2']:>8} fs={c['filesystem_v2']:>8} "
              f"exec={c['program_exec_v2']:>5} ioc={c['case_iocs']:>4}({it}t) alert={c['tool_alerts_v2']:>5}")
        if issues:
            print(f"          -> {'; '.join(issues)}")
        if sev != 'ok':
            bad += 1
    print("\n" + "=" * 68)
    print(f"RESULT: {'ALL HEALTHY' if bad == 0 else str(bad) + ' issue(s) found'}")
    sys.exit(0 if bad == 0 else 1)

if __name__ == '__main__':
    main()
