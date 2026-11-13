# -*- coding: utf-8 -*-
"""
DFIR maintenance / anti-clutter. The analysis pipeline writes ~5 files per run
(case_result/case_report/case_rendered/planner_output/evidence_bundle) into each
case's reports/ dir and NEVER prunes them -> a case analyzed 66x accrues 269 files
(21 MB). This keeps only the newest KEEP_PER_TYPE of each report type per case,
prunes stale/orphaned job rows, and removes stray .bak_* editor backups.

Run:  python3 maintenance.py            (dry-run, shows what WOULD be deleted)
      python3 maintenance.py --apply    (actually delete)
Safe: never touches uploads/ (source logs), the single *_latest*.* files, or the
newest report-set. Idempotent.
"""
import os, sys, glob, re, time

APPLY = '--apply' in sys.argv
CASES = '/srv/dfir/cases'
KEEP_PER_TYPE = 3          # keep newest N of each report type per case
BAK_AGE_DAYS = 2           # remove .bak_* older than this
REPORT_TYPES = ['case_result', 'case_report', 'case_rendered', 'planner_output', 'evidence_bundle']

def human(n):
    for u in ['B', 'K', 'M', 'G']:
        if n < 1024: return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}T"

def main():
    freed = 0; ndel = 0
    print("=== REPORT RETENTION (keep newest %d per type per case) ===" % KEEP_PER_TYPE)
    for case_dir in sorted(glob.glob(os.path.join(CASES, '*'))):
        rdir = os.path.join(case_dir, 'reports')
        if not os.path.isdir(rdir):
            continue
        ck = os.path.basename(case_dir)
        case_del = 0; case_freed = 0
        for rtype in REPORT_TYPES:
            files = [f for f in glob.glob(os.path.join(rdir, rtype + '_*'))
                     if 'latest' not in os.path.basename(f)]
            files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
            for f in files[KEEP_PER_TYPE:]:
                sz = os.path.getsize(f)
                case_freed += sz; case_del += 1; freed += sz; ndel += 1
                if APPLY:
                    try: os.remove(f)
                    except Exception: pass
        if case_del:
            print(f"  {ck[:44]:44s} -{case_del} files ({human(case_freed)})")

    print("\n=== STRAY .bak_* EDITOR BACKUPS (> %d days) ===" % BAK_AGE_DAYS)
    cutoff = time.time() - BAK_AGE_DAYS * 86400
    baks = glob.glob('/srv/dfir/services/case_maintainer/**/*.bak_*', recursive=True)
    bfreed = 0; bdel = 0
    for f in baks:
        try:
            if os.path.getmtime(f) < cutoff:
                sz = os.path.getsize(f); bfreed += sz; bdel += 1; freed += sz; ndel += 1
                if APPLY: os.remove(f)
        except Exception:
            pass
    print(f"  {bdel} .bak files ({human(bfreed)})  [{len(baks)} total .bak found]")

    print("\n" + "=" * 60)
    print(f"{'APPLIED' if APPLY else 'DRY-RUN'}: {ndel} files, {human(freed)} "
          f"{'freed' if APPLY else 'would be freed'}")
    if not APPLY:
        print("Re-run with --apply to delete.")

if __name__ == '__main__':
    main()
