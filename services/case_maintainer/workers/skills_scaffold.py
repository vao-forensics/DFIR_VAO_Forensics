"""Theme C3: scaffold forensic methodology skill-cards.

Stands up kb_skills_v1 (Qdrant, 4096-dim Cosine) + dfir_skills_v1 (Postgres
registry), then for ~5 top kb_terms intents does an OFFLINE strong-LLM pass
grounded in books (kb_text_qwen3e8b_v1 search WITH the LESSONS filter) to emit a
methodology skill-card JSON {intent,title,methodology,artifact_hints:{tables,
event_ids,tools}}. Dedup on (intent, cosine>0.92). Writes artifact_hints into the
SAME dfir_reusable_playbooks routing (upsert by intent_name, DISTINCT-unnest merge)
so Theme A's _get_provenance_hint serves them.

Windowed LLM (<=3000 chars in, max_tokens<=2200) for the 8192-token backend.
Skips re-ingesting the 16 truncated books (separate data job).
"""
import json
import logging
import os
import re
import urllib.request
import uuid

try:
    import psycopg2
except ImportError:
    psycopg2 = None

from core.config import (PG_DSN, LLM_URL, EMBED_URL, EMBED_MODEL, QDRANT_URL,
                         TEXT_COLL_PRIMARY)
try:
    from core.config import LLM_FAST_MODEL
except Exception:
    LLM_FAST_MODEL = os.getenv('DFIR_FAST_MODEL', 'gpt-oss-20b')

_log = logging.getLogger('app')
_KB_SKILLS = 'kb_skills_v1'
_BOOK_CK = os.getenv('DFIR_BOOK_CASE_KEY', 'LESSONS')
_EXTRACT_MODEL = os.getenv('DFIR_SKILLS_MODEL', LLM_FAST_MODEL or 'gpt-oss-20b')

# Top kb_terms intents to scaffold + a short query seed for book grounding.
_TARGET_INTENTS = [
    ('windows_logs', 'Windows event log analysis logon 4624 4672 4688 RDP'),
    ('zimmerman_tool', 'Eric Zimmerman tools EvtxECmd MFTECmd prefetch amcache parsing'),
    ('defender', 'Windows Defender detection tampering disabled 1116 5001 5007'),
    ('rdp_lateral', 'RDP lateral movement logon type 10 remote desktop detection'),
    ('phishing', 'phishing email analysis headers SPF attachment malicious link'),
    ('pentest_recon', 'penetration testing reconnaissance enumeration scanning nmap kali linux footprinting'),
    ('exploitation', 'exploitation vulnerability metasploit payload reverse shell gaining initial access'),
    ('privilege_escalation', 'privilege escalation windows linux techniques tokens kernel exploits'),
    ('post_exploitation', 'post exploitation lateral movement pivoting credential dumping mimikatz pass the hash'),
    ('web_pentest', 'web application penetration testing sql injection xss owasp burp'),
]


def _pg():
    if psycopg2 is None:
        raise RuntimeError('psycopg2 not installed')
    return psycopg2.connect(PG_DSN)


def _ensure_kb_skills():
    base = QDRANT_URL.rstrip('/')
    try:
        req = urllib.request.Request(f'{base}/collections/{_KB_SKILLS}', method='GET')
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
        return
    except Exception as e:
        if getattr(e, 'code', None) != 404:
            _log.warning(f'[skills] kb_skills check: {e}')
    try:
        body = json.dumps({'vectors': {'size': 4096, 'distance': 'Cosine'}}).encode()
        req = urllib.request.Request(f'{base}/collections/{_KB_SKILLS}',
                                     data=body, headers={'Content-Type': 'application/json'},
                                     method='PUT')
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        _log.info(f'[skills] created {_KB_SKILLS}')
    except Exception as e:
        _log.error(f'[skills] create {_KB_SKILLS} failed: {e}')


def _ensure_dfir_skills_table():
    with _pg() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_skills_v1 (
                    id bigserial PRIMARY KEY,
                    skill_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
                    intent text,
                    title text,
                    methodology text,
                    artifact_hints jsonb,
                    source_books text[],
                    created_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_skills_intent ON dfir_skills_v1(intent)")
            conn.commit()


def _embed(text):
    body = json.dumps({'model': EMBED_MODEL, 'input': (text or '')[:500]}).encode()
    req = urllib.request.Request(EMBED_URL.rstrip('/') + '/v1/embeddings',
                                 data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))['data'][0]['embedding']


def _book_search(query, vec, limit=4):
    """Book search WITH the LESSONS filter (reuses Theme C1 privacy filter)."""
    base = QDRANT_URL.rstrip('/')
    body = {'vector': vec, 'limit': limit, 'with_payload': True}
    if _BOOK_CK:
        body['filter'] = {'must': [{'key': 'case_key', 'match': {'value': _BOOK_CK}}]}
    req = urllib.request.Request(f'{base}/collections/{TEXT_COLL_PRIMARY}/points/search',
                                 data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=30) as r:
        hits = json.loads(r.read().decode()).get('result', [])
    chunks, books = [], set()
    for h in hits:
        pl = h.get('payload') or {}
        t = str(pl.get('text', pl.get('chunk', '')))
        if t:
            chunks.append(t[:1200])
        sf = pl.get('source_file')
        if sf:
            books.add(str(sf))
    return chunks, sorted(books)


def _salvage_json(s):
    if not s:
        return None
    s = re.sub(r'^```(?:json)?', '', s.strip()).strip()
    s = re.sub(r'```$', '', s).strip()
    try:
        return json.loads(s)
    except Exception:
        pass
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
    for close in ('"}}', '}}', '}'):
        try:
            return json.loads(s[start:] + close)
        except Exception:
            continue
    return None


_SYS = (
    "You are a DFIR methodology author. Given book excerpts for a forensic topic, "
    "output STRICT JSON only (no prose/markdown):\n"
    '{"title":"short skill title","methodology":"3-6 concise numbered steps how to '
    'investigate this, grounded in the excerpts","artifact_hints":{"tables":[],'
    '"event_ids":[],"tools":[]}}\n'
    "tables must be from {event_logs_v2,tool_alerts_v2,program_exec_v2,filesystem_v2,"
    "raw_fallback_v2,srum_v2}. event_ids are Windows EID numbers. tools are forensic "
    "tool names. Output ONLY the JSON object."
)


def _llm_card(intent, query, chunks):
    ctx = '\n---\n'.join(chunks)[:3000]
    body = json.dumps({
        'model': _EXTRACT_MODEL, 'temperature': 0.1, 'max_tokens': 2000,
        'messages': [
            {'role': 'system', 'content': _SYS},
            {'role': 'user', 'content': f'TOPIC (intent={intent}): {query}\n\nBOOK EXCERPTS:\n{ctx}'},
        ],
    }).encode('utf-8')
    req = urllib.request.Request(LLM_URL.rstrip('/') + '/v1/chat/completions',
                                 data=body, headers={'Content-Type': 'application/json'},
                                 method='POST')
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read().decode('utf-8', 'ignore'))
    content = (((d.get('choices') or [{}])[0]).get('message') or {}).get('content') or ''
    return _salvage_json(content)


_WHITELIST = {'event_logs_v2', 'tool_alerts_v2', 'program_exec_v2',
              'filesystem_v2', 'raw_fallback_v2', 'srum_v2'}


def _is_dup(intent, vec):
    """True if an existing kb_skills_v1 point for same intent scores cosine>0.92."""
    base = QDRANT_URL.rstrip('/')
    body = json.dumps({'vector': vec, 'limit': 1, 'with_payload': True,
        'filter': {'must': [{'key': 'intent', 'match': {'value': intent}}]}}).encode()
    try:
        req = urllib.request.Request(f'{base}/collections/{_KB_SKILLS}/points/search',
                                     data=body, headers={'Content-Type': 'application/json'},
                                     method='POST')
        with urllib.request.urlopen(req, timeout=15) as r:
            pts = json.loads(r.read().decode()).get('result', [])
        return bool(pts) and float(pts[0].get('score', 0.0)) > 0.92
    except Exception:
        return False


def _merge_playbook(intent, hints):
    tables = [t for t in (hints.get('tables') or []) if t in _WHITELIST]
    eids = [str(e) for e in (hints.get('event_ids') or []) if str(e).strip()]
    tools = [str(t) for t in (hints.get('tools') or []) if str(t).strip()]
    with _pg() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM dfir_reusable_playbooks WHERE intent_name=%s AND status='active' LIMIT 1", (intent,))
            row = cur.fetchone()
            if row:
                cur.execute("""UPDATE dfir_reusable_playbooks SET
                    preferred_tables=(SELECT array(SELECT DISTINCT unnest(coalesce(preferred_tables,'{}') || %s::text[]))),
                    preferred_event_ids=(SELECT array(SELECT DISTINCT unnest(coalesce(preferred_event_ids,'{}') || %s::text[]))),
                    preferred_tools=(SELECT array(SELECT DISTINCT unnest(coalesce(preferred_tools,'{}') || %s::text[]))),
                    updated_at=now()
                    WHERE id=%s""", (tables, eids, tools, row[0]))
            else:
                cur.execute("""INSERT INTO dfir_reusable_playbooks
                    (intent_name, preferred_tables, preferred_event_ids, preferred_tools, status)
                    VALUES (%s,%s,%s,%s,'active')""", (intent, tables, eids, tools))
            conn.commit()


def build_skill_cards(dry_run=True):
    summary = {'dry_run': dry_run, 'cards_parsed': 0, 'cards_written': 0,
               'dups_skipped': 0, 'errors': [], 'cards': []}
    try:
        _ensure_kb_skills()
        if not dry_run:
            _ensure_dfir_skills_table()
    except Exception as e:
        summary['errors'].append(f'ensure: {str(e)[:120]}')

    for intent, query in _TARGET_INTENTS:
        try:
            qvec = _embed(query)
            chunks, books = _book_search(query, qvec, limit=4)
            if not chunks:
                summary['errors'].append(f'{intent}: no book chunks')
                continue
            card = _llm_card(intent, query, chunks)
        except Exception as e:
            summary['errors'].append(f'{intent}: {str(e)[:120]}')
            continue
        if not isinstance(card, dict) or not card.get('methodology'):
            summary['errors'].append(f'{intent}: bad card')
            continue
        summary['cards_parsed'] += 1
        title = str(card.get('title', intent))[:200]
        methodology = str(card.get('methodology', ''))[:4000]
        hints = card.get('artifact_hints') or {}
        if not isinstance(hints, dict):
            hints = {}
        hints['tables'] = [t for t in (hints.get('tables') or []) if t in _WHITELIST]
        summary['cards'].append({'intent': intent, 'title': title,
                                 'artifact_hints': hints,
                                 'methodology': methodology[:200], 'source_books': books})
        if dry_run:
            continue
        try:
            cvec = _embed(title + ' ' + methodology[:300])
            skill_id = str(uuid.uuid4())
            base = QDRANT_URL.rstrip('/')
            # UPSERT BY INTENT: replace any existing card for this intent so the
            # nightly refresh keeps exactly ONE (latest/best) card per intent and
            # never accumulates near-duplicates (the cosine>0.92 dedup missed
            # reworded dups -> 17 cards for ~5 intents before this fix).
            with _pg() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM dfir_skills_v1 WHERE intent=%s", (intent,))
                    cur.execute("""INSERT INTO dfir_skills_v1
                        (skill_id, intent, title, methodology, artifact_hints, source_books)
                        VALUES (%s,%s,%s,%s,%s,%s)""",
                        (skill_id, intent, title, methodology, json.dumps(hints), books))
                    conn.commit()
            try:
                _dreq = urllib.request.Request(
                    f'{base}/collections/{_KB_SKILLS}/points/delete?wait=true',
                    data=json.dumps({'filter': {'must': [{'key': 'intent',
                        'match': {'value': intent}}]}}).encode(),
                    headers={'Content-Type': 'application/json'}, method='POST')
                urllib.request.urlopen(_dreq, timeout=15).read()
            except Exception:
                pass
            pt = json.dumps({'points': [{'id': skill_id, 'vector': cvec,
                'payload': {'intent': intent, 'title': title,
                            'methodology': methodology[:1000],
                            'artifact_hints': hints, 'source_books': books}}]}).encode()
            req = urllib.request.Request(f'{base}/collections/{_KB_SKILLS}/points',
                                         data=pt, headers={'Content-Type': 'application/json'},
                                         method='PUT')
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
            _merge_playbook(intent, hints)
            summary['cards_written'] += 1
        except Exception as e:
            summary['errors'].append(f'{intent} write: {str(e)[:120]}')
    _log.info(f'[skills] build_skill_cards -> written={summary["cards_written"]}')
    return summary


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    dr = '--apply' not in sys.argv
    print(json.dumps(build_skill_cards(dry_run=dr), ensure_ascii=False, indent=2))
