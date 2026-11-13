# -*- coding: utf-8 -*-
"""Build an EXPANDED SFT dataset for QLoRA (option Б).

Today only 8 pairs exist (one per case-with-expert-report) — far too few to fine-tune. But we
have a lot of PRESERVED, high-quality supervised data the current builder ignores: grounded
case Q&A (question→answer), approved lessons (situation→advice), playbooks (technique→
procedure). This turns all of that into instruction/response pairs, deduped and quality-
filtered, into a training-ready JSONL — WITHOUT touching the live pipeline (writes a new file).
"""
import io, os, json, re, hashlib
import psycopg2

PG = os.getenv('PG_DSN')
OUT = '/tmp/dfir_sft_expanded.jsonl'
seen = set()
pairs = []
counts = {}

def add(source, system, user, assistant):
    user = (user or '').strip()
    assistant = (assistant or '').strip()
    if len(assistant) < 60 or len(user) < 8:
        return
    low = assistant.lower()
    if any(b in low for b in ('дані відсутні', 'no_data', 'не знайдено даних', 'недостатньо даних для')):
        return
    key = hashlib.md5((source + '|' + user[:80] + '|' + assistant[:120]).encode('utf-8', 'ignore')).hexdigest()
    if key in seen:
        return
    seen.add(key)
    pairs.append({'messages': [
        {'role': 'system', 'content': system},
        {'role': 'user', 'content': user[:2000]},
        {'role': 'assistant', 'content': assistant[:6000]},
    ]})
    counts[source] = counts.get(source, 0) + 1

c = psycopg2.connect(PG); c.autocommit = True
cur = c.cursor()

# 0) existing report pairs (from the current table) — keep them
try:
    cur.execute("SELECT instruction, input_text, output_text FROM dfir_finetune_dataset_v1 ORDER BY id")
    for instr, inp, out in cur.fetchall():
        add('report', instr or 'Ти старший DFIR-аналітик. Напиши експертний звіт за фактами.',
            (inp or '')[:2000], out or '')
except Exception as e:
    print('report source skipped:', repr(e)[:80])

# 1) grounded case Q&A  (question -> answer)
QA_SYS = ('Ти старший DFIR-аналітик. Відповідай на питання по кейсу СТИСЛО, професійно і '
          'ЛИШЕ за фактами з логів/артефактів. Якщо доказів немає — так і кажи.')
try:
    cur.execute("SELECT question, answer FROM dfir_case_qa_v1 "
                "WHERE length(coalesce(answer,''))>80 AND coalesce(status,'') NOT ILIKE '%no_data%' "
                "AND coalesce(review_verdict,'') NOT IN ('wrong','reject') "
                "ORDER BY updated_at DESC LIMIT 4000")
    for qn, an in cur.fetchall():
        add('case_qa', QA_SYS, qn, an)
except Exception as e:
    print('case_qa skipped:', repr(e)[:80])

try:
    cur.execute("SELECT question, answer_markdown FROM dfir_qa_answers "
                "WHERE length(coalesce(answer_markdown,''))>80 "
                "AND coalesce(validation_status,'') NOT IN ('rejected','failed') "
                "ORDER BY created_at DESC LIMIT 4000")
    for qn, an in cur.fetchall():
        add('qa_answers', QA_SYS, qn, an)
except Exception as e:
    print('qa_answers skipped:', repr(e)[:80])

# 2) approved lessons (intent -> lesson)
LS_SYS = 'Ти DFIR-методист. Дай коротку практичну пораду для вказаної фази/типу розслідування.'
try:
    cur.execute("SELECT intent, lesson_type, lesson_text FROM dfir_lessons_learned_v1 "
                "WHERE length(coalesce(lesson_text,''))>60 ORDER BY updated_at DESC LIMIT 3000")
    for intent, lt, txt in cur.fetchall():
        u = 'Порада для фази розслідування: %s%s' % (intent or 'загальна',
             (' (' + lt + ')') if lt else '')
        add('lesson', LS_SYS, u, txt)
except Exception as e:
    print('lessons skipped:', repr(e)[:80])

# 3) playbooks (technique -> checklist)
PB_SYS = 'Ти DFIR-методист. Опиши, як розслідувати вказану техніку: що перевіряти і де.'
try:
    cur.execute("SELECT gap_type, title, checklist::text, evidence_rules::text FROM dfir_playbooks_v1 "
                "WHERE length(coalesce(checklist::text,''))>40 ORDER BY updated_at DESC LIMIT 2000")
    for gt, title, chk, ev in cur.fetchall():
        u = 'Як розслідувати: %s%s?' % (gt or 'техніку', (' — ' + title) if title else '')
        a = (chk or '')
        if ev:
            a += '\n\nДокази/правила:\n' + str(ev)
        add('playbook', PB_SYS, u, a)
except Exception as e:
    print('playbooks skipped:', repr(e)[:80])

# write JSONL
with io.open(OUT, 'w', encoding='utf-8', newline='\n') as fh:
    for p in pairs:
        fh.write(json.dumps(p, ensure_ascii=False) + '\n')

print('=== SFT dataset built ===')
for k in sorted(counts):
    print('  %-12s %d' % (k, counts[k]))
print('  TOTAL       %d pairs -> %s' % (len(pairs), OUT))
