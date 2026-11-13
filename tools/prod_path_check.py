# -*- coding: utf-8 -*-
"""Run the production report chain, not just the renderer.

core/jobs.py delivers a report as: guard_client_output(...) -> reshape_client_report(...).
A check that calls the renderer directly never exercises the guardrail step, so this runs
both, in production order, and reports whether the guardrail removes anything the renderer
produced.

Run it detached and read the log; a full sweep of the eleven production cases takes about
an hour, which is longer than any interactive pipe survives:

    docker cp tools/prod_path_check.py case-maintainer:/tmp/ppc.py
    docker exec -d case-maintainer sh -c \
        'python3 -u /tmp/ppc.py > /tmp/ppc.log 2>&1; echo EXIT=$? >> /tmp/ppc.log'

/app/tools is baked into the image rather than mounted, so a copy edited on the host is NOT
the copy the container runs - docker cp it in, and note that `docker restart` will not do it
for you.

The last line of a complete run is the sentinel `ПІДСУМОК ok=N fail=M з 11`. Anything else
at the end of the log means the run was cut short - an aborted sweep must never be mistaken
for a clean one. Piping this script into `tail` hides that: the pipeline reports tail's exit
code, not python's, so a killed run still looks like a success.

Optional arguments narrow the sweep to the named cases (substring match), which also lets
the eleven be split across two shards that run at the same time.
"""
import io
import os
import sys
import time
import traceback

# Run from /tmp and /app is not on the path: the module search starts at the SCRIPT's
# directory, not the working one. The guards under analysis/guards do the same thing.
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

import psycopg2
from analysis.output_guardrails import guard_client_output
from reports import reshape as _reshape_mod

SECTIONS = ('УМОВИ ЗБОРУ', 'ДОКУМЕНТИ, НОСІЇ', 'СЛІДИ ЗАПУСКУ', 'Хто власник',
            'ХРОНОЛОГІЯ', 'ІНДИКАТОРИ')

LLM_TEXT = ('Аналіз показує ознаки компрометації робочої станції. '
            'Деталі наведено нижче у службових даних.')

_calls = [0]


def _render(case_key, text):
    _calls[0] += 1
    return _reshape_mod.reshape_client_report(case_key, text)


def main():
    wanted = sys.argv[1:]
    c = psycopg2.connect(os.environ['PG_DSN'])
    c.autocommit = True
    cur = c.cursor()
    cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ_%' ORDER BY 1")
    keys = [r[0] for r in cur.fetchall()]
    if wanted:
        keys = [k for k in keys if any(w in k for w in wanted)]
    total = len(keys)
    ok = fail = 0
    # DUMP_DIR: write each final report to disk so a before/after sweep can be diffed
    # byte for byte. Without it 'the reports did not change' is an opinion, not a fact.
    dump_dir = os.environ.get('DUMP_DIR') or ''
    if dump_dir:
        os.makedirs(dump_dir, exist_ok=True)

    for ck in keys:
        _calls[0] = 0
        t0 = time.time()
        try:
            guarded, _ = guard_client_output(ck, LLM_TEXT, kind='txt_report')
            final = _render(ck, guarded)
            # The unguarded baseline is only needed to tell "the guardrail cut this section"
            # from "the renderer never produced it". Building it inside the comprehension
            # rebuilt the whole report once per MISSING section - nothing on a clean case,
            # up to six times on a broken one, exactly when the run is already in trouble.
            missing = []
            base = None
            for s in SECTIONS:
                if s in final:
                    continue
                if base is None:
                    base = _render(ck, LLM_TEXT)
                if s in base:
                    missing.append(s)
        except Exception as e:
            fail += 1
            print('%-46s ПОМИЛКА %s: %s' % (ck[:46], type(e).__name__, str(e)[:70]),
                  flush=True)
            traceback.print_exc()
            sys.stdout.flush()
            continue
        ok += 1
        if dump_dir:
            with io.open(os.path.join(dump_dir, ck.replace('/', '_') + '.txt'),
                         'w', encoding='utf-8') as fh:
                fh.write(final)
        print('%-46s %6d симв. %5.0fс рендерів=%d%s'
              % (ck[:46], len(final), time.time() - t0, _calls[0],
                 ('  !! ГУБИТЬ: %s' % ','.join(missing)) if missing else ''),
              flush=True)

    print('ПІДСУМОК ok=%d fail=%d з %d' % (ok, fail, total), flush=True)
    return 1 if (fail or not total) else 0


if __name__ == '__main__':
    sys.exit(main())
