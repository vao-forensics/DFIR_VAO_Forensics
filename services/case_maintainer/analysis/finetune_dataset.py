# -*- coding: utf-8 -*-
"""DFIR fine-tune dataset pipeline.

Turns each (case → expert report) into an SFT training pair:
  INPUT  = the deterministic case FACTS the bot has at inference time
           (threat_detections + key log/artifact stats + IOC roll-up)
  OUTPUT = the analyst's EXPERT REPORT (gold analysis, the target style/depth)
so a fine-tuned model learns: "given grounded case facts → write an expert DFIR report".

This is the FOUNDATION of the fine-tune pipeline. It ACCUMULATES automatically as more
expert reports are uploaded; training only makes sense once the corpus is large enough
(rule of thumb >=100-200 pairs — far above today's 4). Export to JSONL for axolotl /
llama-factory / unsloth.

Privacy: the report text flows programmatically into the dataset table for LOCAL training
only (no egress); no human reads personal content here.
"""
import json
import urllib.request

DDL = """
CREATE TABLE IF NOT EXISTS dfir_finetune_dataset_v1 (
    id            BIGSERIAL PRIMARY KEY,
    case_key      TEXT NOT NULL,
    instruction   TEXT NOT NULL,
    input_text    TEXT NOT NULL,
    output_text   TEXT NOT NULL,
    n_input       INT,
    n_output      INT,
    source        TEXT DEFAULT 'expert_report',
    created_at    TIMESTAMPTZ DEFAULT now(),
    UNIQUE(case_key, source)
);
"""

INSTRUCTION = ("Ти старший DFIR-аналітик. За наданими ФАКТАМИ з логів (детермінований аналіз KAPE/EVTX/MFT) "
               "напиши експертний звіт по інциденту українською: загальний висновок, вектор атаки, хронологія, "
               "IOC, вплив і рекомендації. Спирайся ЛИШЕ на надані факти, не вигадуй.")


def _qdrant_report_text(qdrant_url, case_key, max_chars=12000):
    body = json.dumps({'limit': 400, 'with_payload': True, 'with_vector': False,
                       'filter': {'must': [{'key': 'case_key', 'match': {'value': case_key}}]}}).encode()
    req = urllib.request.Request(qdrant_url.rstrip('/') + '/collections/kb_reports/points/scroll',
                                 data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as r:
        pts = json.loads(r.read()).get('result', {}).get('points', [])
    pts.sort(key=lambda p: (p.get('payload', {}).get('page_num') or 0,
                            p.get('payload', {}).get('chunk_index') or 0))
    return '\n'.join(str(p.get('payload', {}).get('text') or '') for p in pts)[:max_chars]


def _build_input_facts(case_key, conn):
    """Deterministic case facts = what the model gets at inference (threat detections + stats)."""
    from analysis.threat_detect import detect_threats, verdict_line
    cur = conn.cursor()

    def q1(s):
        try:
            cur.execute(s, (case_key,)); r = cur.fetchone(); return r[0] if r else 0
        except Exception:
            conn.rollback(); return 0
    parts = ['# ФАКТИ КЕЙСУ (детермінований аналіз логів)', '']
    # threat detections
    try:
        fnd = detect_threats(case_key, conn)
    except Exception:
        fnd = []
    parts.append('ВЕРДИКТ (сигнатури): ' + verdict_line(fnd))
    parts.append('ДЕТЕКЦІЇ:')
    for f in fnd:
        parts.append('- [%s] %s — %s (MITRE %s, к-сть %s)' %
                     (f['severity'], f['title'], f['detail'], f['mitre'], f['count']))
    # volume stats
    parts.append('')
    parts.append('ОБСЯГИ: event_logs=%d, filesystem=%d, program_exec=%d, srum=%d, tool_alerts=%d' % (
        q1("SELECT count(*) FROM event_logs_v2 WHERE case_key=%s"),
        q1("SELECT count(*) FROM filesystem_v2 WHERE case_key=%s"),
        q1("SELECT count(*) FROM program_exec_v2 WHERE case_key=%s"),
        q1("SELECT count(*) FROM srum_v2 WHERE case_key=%s"),
        q1("SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s")))
    # IOC roll-up
    try:
        cur.execute("""SELECT ioc_type, ioc_value FROM case_iocs WHERE case_key=%s
                       AND ioc_type IN ('public_ip','domain','public_domain','tool_name','anydesk_id')
                       LIMIT 30""", (case_key,))
        iocs = cur.fetchall()
        if iocs:
            parts.append('IOC: ' + '; '.join('%s=%s' % (t, v) for t, v in iocs))
    except Exception:
        conn.rollback()
    return '\n'.join(parts)


def build_dataset(conn, qdrant_url):
    """Build/refresh training pairs for every case that has an expert report. Returns count."""
    cur = conn.cursor()
    cur.execute(DDL); conn.commit()
    # distinct report cases from Qdrant
    body = json.dumps({'limit': 3000, 'with_payload': True, 'with_vector': False}).encode()
    req = urllib.request.Request(qdrant_url.rstrip('/') + '/collections/kb_reports/points/scroll',
                                 data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as r:
        pts = json.loads(r.read()).get('result', {}).get('points', [])
    cases = sorted({p.get('payload', {}).get('case_key') for p in pts if p.get('payload', {}).get('case_key')})
    n = 0
    for ck in cases:
        out = _qdrant_report_text(qdrant_url, ck)
        if not out or len(out) < 400:
            continue
        inp = _build_input_facts(ck, conn)
        cur.execute("""INSERT INTO dfir_finetune_dataset_v1(case_key,instruction,input_text,output_text,n_input,n_output)
                       VALUES(%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (case_key, source) DO UPDATE SET
                         input_text=EXCLUDED.input_text, output_text=EXCLUDED.output_text,
                         n_input=EXCLUDED.n_input, n_output=EXCLUDED.n_output, created_at=now()""",
                    (ck, INSTRUCTION, inp, out, len(inp), len(out)))
        n += 1
    conn.commit()
    return n, cases


def export_jsonl(conn, path):
    """Export to chat-format JSONL (system/user/assistant) for SFT trainers."""
    cur = conn.cursor()
    cur.execute("SELECT instruction, input_text, output_text FROM dfir_finetune_dataset_v1 ORDER BY id")
    rows = cur.fetchall()
    with open(path, 'w', encoding='utf-8') as f:
        for instr, inp, out in rows:
            ex = {'messages': [
                {'role': 'system', 'content': instr},
                {'role': 'user', 'content': inp},
                {'role': 'assistant', 'content': out},
            ]}
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')
    return len(rows)
