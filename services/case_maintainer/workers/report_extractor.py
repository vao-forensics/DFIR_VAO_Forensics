"""Theme B2: report_extractor worker.

Pull a case's finished analyst report chunks from kb_reports (doc_type=report),
windowed-extract findings + lessons via the strong/fast LLM in strict-JSON mode,
GROUND/VALIDATE provenance against the REAL DB (distinct event_ids + a table
whitelist + kb_terms canonical mapping) to block hallucinated provenance, then
write:
  - findings -> dfir_case_verified_findings (approval_status='pending', HUMAN-GATED)
  - lessons  -> dfir_lessons_learned_v1 (lesson_type='from_report',
                approved_by_user=false) via learnings._lesson_dedup_upsert.

Backend context is only ~8192 tokens and the strong model spends budget on
reasoning_content; so we window <=2 chunks (<=3000 chars) per call, cap
max_tokens<=2200, use low temperature, and salvage-parse partial JSON. Per-window
errors degrade (skip that window) rather than abort.
"""
import json
import logging
import os
import re
import urllib.request

try:
    import psycopg2
except ImportError:
    psycopg2 = None

from core.config import PG_DSN, LLM_URL, EMBED_MODEL, QDRANT_URL

try:
    from core.config import LLM_FAST_MODEL
except Exception:
    LLM_FAST_MODEL = os.getenv('DFIR_FAST_MODEL', 'gpt-oss-20b')

from analysis.case_key_norm import norm_case_key, resolve_db_key

_log = logging.getLogger('app')

# Real DB table whitelist — LLM-emitted "tables" not in this set (e.g.
# 'Indicators', 'Timeline', 'OS Info', 'User Accounts') are dropped.
_TABLE_WHITELIST = {
    'event_logs_v2', 'tool_alerts_v2', 'program_exec_v2',
    'filesystem_v2', 'raw_fallback_v2', 'srum_v2',
}

# Extraction model: 20b is fast & survived the dry-run; override via env.
_EXTRACT_MODEL = os.getenv('DFIR_REPORT_EXTRACT_MODEL', LLM_FAST_MODEL or 'gpt-oss-20b')
_MAX_TOKENS = int(os.getenv('DFIR_REPORT_EXTRACT_MAXTOK', '2000'))
_WINDOW_CHARS = int(os.getenv('DFIR_REPORT_WINDOW_CHARS', '3000'))


def _pg():
    if psycopg2 is None:
        raise RuntimeError('psycopg2 not installed')
    return psycopg2.connect(PG_DSN)


def _scroll_report_chunks(report_case_key):
    """Scroll kb_reports for doc_type=report chunks of this case, sorted by
    chunk_index. Returns (chunks[list[str]], source_file)."""
    base = QDRANT_URL.rstrip('/')
    body = json.dumps({
        'limit': 500, 'with_payload': True, 'with_vector': False,
        'filter': {'must': [
            {'key': 'case_key', 'match': {'value': report_case_key}},
            {'key': 'doc_type', 'match': {'value': 'report'}},
        ]}
    }).encode()
    req = urllib.request.Request(f'{base}/collections/kb_reports/points/scroll',
                                 data=body, headers={'Content-Type': 'application/json'},
                                 method='POST')
    with urllib.request.urlopen(req, timeout=30) as r:
        pts = json.loads(r.read().decode()).get('result', {}).get('points', [])
    rows = []
    src = ''
    for p in pts:
        pl = p.get('payload') or {}
        rows.append((pl.get('chunk_index', 0), str(pl.get('text', ''))))
        if not src and pl.get('source_file'):
            src = pl.get('source_file')
    rows.sort(key=lambda x: (x[0] if isinstance(x[0], (int, float)) else 0))
    return [t for _, t in rows if t.strip()], src


def _live_db_case_keys():
    keys = []
    try:
        with _pg() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT case_key FROM event_logs_v2")
                keys = [r[0] for r in cur.fetchall() if r[0]]
    except Exception as e:
        _log.warning(f'[report_extractor] live db keys failed: {e}')
    return keys


def _real_event_ids(db_key):
    ids = set()
    try:
        with _pg() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT event_id FROM event_logs_v2 WHERE case_key=%s", (db_key,))
                for r in cur.fetchall():
                    if r[0] is not None:
                        ids.add(str(r[0]))
    except Exception as e:
        _log.warning(f'[report_extractor] real eids failed: {e}')
    return ids


def _populated_tables(db_key):
    out = set()
    for t in _TABLE_WHITELIST:
        try:
            with _pg() as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT 1 FROM {t} WHERE case_key=%s LIMIT 1", (db_key,))
                    if cur.fetchone():
                        out.add(t)
        except Exception:
            pass
    return out


_KB_TERMS_CACHE = None


def _kb_terms():
    """Load kb_terms canonical->table-ish mapping once (trigger/canonical/intent)."""
    global _KB_TERMS_CACHE
    if _KB_TERMS_CACHE is not None:
        return _KB_TERMS_CACHE
    terms = []
    try:
        base = QDRANT_URL.rstrip('/')
        body = json.dumps({'limit': 2000, 'with_payload': True, 'with_vector': False}).encode()
        req = urllib.request.Request(f'{base}/collections/kb_terms/points/scroll',
                                     data=body, headers={'Content-Type': 'application/json'},
                                     method='POST')
        with urllib.request.urlopen(req, timeout=20) as r:
            pts = json.loads(r.read().decode()).get('result', {}).get('points', [])
        for p in pts:
            pl = p.get('payload') or {}
            terms.append((str(pl.get('trigger', '')).lower(),
                          str(pl.get('canonical', '')).lower(),
                          str(pl.get('intent', ''))))
    except Exception as e:
        _log.warning(f'[report_extractor] kb_terms load failed: {e}')
    _KB_TERMS_CACHE = terms
    return terms


# canonical kb_terms token -> real table
_CANON_TABLE = {
    'event_logs': 'event_logs_v2', 'evtxecmd': 'event_logs_v2',
    'defender': 'event_logs_v2',
    'prefetch': 'program_exec_v2', 'amcache': 'program_exec_v2',
    'shimcache': 'program_exec_v2', 'srum': 'srum_v2',
    'mft': 'filesystem_v2', 'filesystem': 'filesystem_v2',
}


def _enrich_tables_via_terms(text, populated):
    """Match finding text against kb_terms triggers; map canonical->real table
    if that table is actually populated for this case."""
    out = set()
    low = (text or '').lower()
    for trig, canon, _intent in _kb_terms():
        if trig and len(trig) >= 4 and trig in low:
            tbl = _CANON_TABLE.get(canon)
            if tbl and tbl in populated:
                out.add(tbl)
    return out


def _infer_intent_via_terms(text):
    low = (text or '').lower()
    for trig, _canon, intent in _kb_terms():
        if trig and len(trig) >= 4 and trig in low and intent:
            return intent
    return 'phishing'


def _salvage_json(s):
    """Best-effort parse of (possibly truncated) JSON object from LLM content."""
    if not s:
        return None
    s = s.strip()
    # strip code fences
    s = re.sub(r'^```(?:json)?', '', s).strip()
    s = re.sub(r'```$', '', s).strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    # take from first { to last balanced }
    start = s.find('{')
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except Exception:
                    break
    # truncated: try to close arrays/objects greedily
    frag = s[start:]
    for close in (']}', '"}]}', '}]}', '}}', '}'):
        try:
            return json.loads(frag + close)
        except Exception:
            continue
    return None


_SYS_PROMPT = (
    "You are a DFIR report extractor. Given a fragment of a finished analyst "
    "report, output STRICT JSON only (no prose, no markdown) with this shape:\n"
    '{"findings":[{"finding_type":"fact|ioc|host|account|tool|timeline|technique",'
    '"title":"short","value":"the concrete value","evidence_quote":"<=200 chars verbatim",'
    '"tables":[],"event_ids":[]}],'
    '"lessons":[{"lesson_text":"reusable investigative lesson","tables":[],"event_ids":[],"tools":[]}]}\n'
    "Extract concrete facts/IOCs/hosts/accounts/tools/timeline/techniques. "
    "Only include event_ids you literally see as numbers in the text. "
    "Keep it compact. Output ONLY the JSON object."
)


def _llm_extract(window_text):
    body = json.dumps({
        'model': _EXTRACT_MODEL,
        'temperature': 0.05,
        'max_tokens': _MAX_TOKENS,
        'messages': [
            {'role': 'system', 'content': _SYS_PROMPT},
            {'role': 'user', 'content': 'REPORT FRAGMENT:\n' + window_text[:_WINDOW_CHARS]},
        ],
    }).encode('utf-8')
    req = urllib.request.Request(LLM_URL.rstrip('/') + '/v1/chat/completions',
                                 data=body, headers={'Content-Type': 'application/json'},
                                 method='POST')
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read().decode('utf-8', 'ignore'))
    content = (((d.get('choices') or [{}])[0]).get('message') or {}).get('content') or ''
    return _salvage_json(content)


def _snake(s):
    s = re.sub(r'[^a-zA-Z0-9]+', '_', str(s or '').lower()).strip('_')
    return (s or 'finding')[:80]


def extract_case_report(report_case_key, dry_run=False):
    """Main entry. Returns a dict summary with counts + samples."""
    summary = {'report_case_key': report_case_key, 'db_case_key': '',
               'chunks': 0, 'windows': 0, 'findings_parsed': 0,
               'findings_written': 0, 'lessons_parsed': 0, 'lessons_written': 0,
               'dry_run': dry_run, 'errors': []}

    chunks, source_file = _scroll_report_chunks(report_case_key)
    summary['chunks'] = len(chunks)
    summary['source_file'] = source_file
    if not chunks:
        summary['errors'].append('no report chunks')
        return summary

    db_key = resolve_db_key(report_case_key, _live_db_case_keys()) or report_case_key
    summary['db_case_key'] = db_key
    real_eids = _real_event_ids(db_key)
    populated = _populated_tables(db_key)
    summary['real_eid_count'] = len(real_eids)
    summary['populated_tables'] = sorted(populated)

    # window 2 chunks per call
    all_findings = []
    all_lessons = []
    i = 0
    while i < len(chunks):
        window = '\n\n'.join(chunks[i:i + 2])
        i += 2
        summary['windows'] += 1
        try:
            parsed = _llm_extract(window)
        except Exception as e:
            summary['errors'].append(f'window {summary["windows"]}: {str(e)[:120]}')
            continue
        if not isinstance(parsed, dict):
            continue
        for f in (parsed.get('findings') or []):
            if isinstance(f, dict) and (f.get('title') or f.get('value')):
                all_findings.append(f)
        for l in (parsed.get('lessons') or []):
            if isinstance(l, dict) and l.get('lesson_text'):
                all_lessons.append(l)

    summary['findings_parsed'] = len(all_findings)
    summary['lessons_parsed'] = len(all_lessons)

    # dedup findings by (finding_type,title,value)
    seen = set()
    dedup_f = []
    for f in all_findings:
        key = (str(f.get('finding_type', '')), str(f.get('title', '')), str(f.get('value', '')))
        if key in seen:
            continue
        seen.add(key)
        dedup_f.append(f)

    # VALIDATE + WRITE findings
    written_f = 0
    sample_f = []
    for f in dedup_f:
        # validate event_ids against real set
        raw_eids = [str(e).strip() for e in (f.get('event_ids') or [])]
        valid_eids = [e for e in raw_eids if e in real_eids]
        # validate tables: whitelist + enrich via kb_terms
        raw_tabs = [str(t).strip() for t in (f.get('tables') or [])]
        valid_tabs = set(t for t in raw_tabs if t in _TABLE_WHITELIST and t in populated)
        valid_tabs |= _enrich_tables_via_terms(
            (f.get('title', '') + ' ' + f.get('value', '') + ' ' + f.get('evidence_quote', '')),
            populated)
        ftype = str(f.get('finding_type', 'fact')).strip().lower() or 'fact'
        title = str(f.get('title', ''))[:200] or str(f.get('value', ''))[:200]
        value = str(f.get('value', ''))[:2000]
        fkey = _snake((ftype + '_' + title)[:80])
        evidence = {
            'evidence_quote': str(f.get('evidence_quote', ''))[:400],
            'source_file': source_file,
            'report_case_key': report_case_key,
            'validated_tables': sorted(valid_tabs),
            'validated_event_ids': valid_eids,
        }
        rec = {'case_key': db_key, 'finding_key': fkey, 'finding_type': ftype,
               'title': title, 'value': value, 'evidence': evidence}
        if len(sample_f) < 8:
            sample_f.append({'finding_key': fkey, 'finding_type': ftype, 'title': title[:80],
                             'validated_tables': sorted(valid_tabs), 'validated_event_ids': valid_eids})
        if not dry_run:
            try:
                with _pg() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""INSERT INTO dfir_case_verified_findings
                            (case_key, finding_key, finding_type, title, value,
                             evidence_json, source_kind, approval_status)
                            VALUES (%s,%s,%s,%s,%s,%s,'report','pending')
                            ON CONFLICT (case_key, finding_key) DO UPDATE SET
                              finding_type=EXCLUDED.finding_type, title=EXCLUDED.title,
                              value=EXCLUDED.value, evidence_json=EXCLUDED.evidence_json,
                              source_kind='report', approval_status='pending',
                              updated_at=now()""",
                            (db_key, fkey, ftype, title, value, json.dumps(evidence)))
                        conn.commit()
                written_f += 1
            except Exception as e:
                summary['errors'].append(f'finding {fkey}: {str(e)[:120]}')
    summary['findings_written'] = written_f
    summary['sample_findings'] = sample_f

    # WRITE lessons via dedup-upsert
    written_l = 0
    sample_l = []
    from analysis.learnings import _lesson_dedup_upsert
    for l in all_lessons:
        ltext = str(l.get('lesson_text', '')).strip()
        if len(ltext) < 40:
            continue
        intent = _infer_intent_via_terms(ltext)
        tabs = set(str(t).strip() for t in (l.get('tables') or []) if str(t).strip() in _TABLE_WHITELIST)
        tabs |= _enrich_tables_via_terms(ltext, populated)
        eids = [str(e).strip() for e in (l.get('event_ids') or []) if str(e).strip() in real_eids]
        tools = [str(t).strip() for t in (l.get('tools') or []) if str(t).strip()]
        if len(sample_l) < 8:
            sample_l.append({'intent': intent, 'lesson_text': ltext[:120], 'tables': sorted(tabs)})
        if not dry_run:
            try:
                lid = _lesson_dedup_upsert(db_key, intent, 'from_report', ltext,
                                           sorted(tabs), eids, tools, approved_by_user=False)
                if lid is not None:
                    written_l += 1
            except Exception as e:
                summary['errors'].append(f'lesson: {str(e)[:120]}')
    summary['lessons_written'] = written_l
    summary['sample_lessons'] = sample_l
    return summary


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    ck = sys.argv[1] if len(sys.argv) > 1 else 'case_39'
    dr = '--dry-run' in sys.argv
    print(json.dumps(extract_case_report(ck, dry_run=dr), ensure_ascii=False, indent=2))
