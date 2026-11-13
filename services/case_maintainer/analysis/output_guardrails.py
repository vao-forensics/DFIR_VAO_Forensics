"""User-facing DFIR output guardrails.

These helpers are intentionally pure and DB-free so they can be regression-tested.
They protect Telegram/report snippets from recurring high-impact mistakes:
- old MOTW/MFT/AppCompatCache artifacts promoted as infection/initial-access time;
- internal tool/model/job details leaking into client-facing text.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from core.config import LLM_MODEL, LLM_FAST_MODEL


def _build_model_leak_pattern() -> str:
    """Build regex alternation from current model names so guardrail stays model-agnostic."""
    names: set[str] = set()
    for m in filter(None, [LLM_MODEL, LLM_FAST_MODEL]):
        names.add(re.escape(m))
        parts = re.split(r'[-./]', m)
        # Add "vendor-family" prefix (first two components, e.g. "gpt-oss")
        base = '-'.join(parts[:2]) if len(parts) >= 2 else parts[0]
        if len(base) > 3:
            names.add(re.escape(base))
    return '|'.join(sorted(names)) if names else 'no-model-configured'


_INTERNAL_LEAK_RE = re.compile(
    r"(?i)(?:\b("
    r"get_[a-z0-9_]+|run_sql|"
    # Static defence-in-depth denylist of UNAMBIGUOUS LLM-serving infra & AI brands that
    # must never surface in a client report. Deliberately EXCLUDES terms that double as
    # malware/product names (mistral, gemini, deepseek) and bare ports (:1234/:8080)
    # — those can be legitimate DFIR IOCs, so redacting them would destroy evidence.
    r"llama\.cpp|llama-swap|lm ?studio|lmstudio|ollama|vllm|text-generation-webui|"
    r"koboldcpp|oobabooga|tabbyapi|exllama\w*|localai|chatgpt|gpt-oss|gpt-4o?|gpt-3\.5|qwen\w*|"
    rf"{_build_model_leak_pattern()}|job_id|run_id|DFIR_RUNNERS|"
    r"PostgreSQL|Qdrant|raw\s+json|localhost"
    r")\b|"
    # Redact RFC1918/Docker-style IPs without naming case IOCs.
    # Redact ONLY the bots OWN infra IPs (docker/zerotier/VM-host) — NOT all RFC1918,
    # so an attackers internal LAN IP (RDP lateral-movement IOC) is NOT hidden.
    r"\b(?:10\.244\.\d{1,3}\.\d{1,3}|192\.168\.(?:100|134)\.\d{1,3}|172\.(?:17|18|19)\.\d{1,3}\.\d{1,3}|127\.0\.0\.\d{1,3})\b)"
)

_CLIENT_HEADING_RE = re.compile(
    r"(?im)^(#\s*FORENSIC\s+ЗВІТ|##\s*ЗАГАЛЬНИЙ\s+ВИСНОВОК|ЗАГАЛЬНИЙ\s+ВИСНОВОК|A\)\s*Загальний\s+висновок|1\)\s*Висновок)\b"
)
_TOOL_DUMP_LINE_RE = re.compile(r"(?im)^\s*\*{0,2}get_[a-z0-9_]+\*{0,2}\s*$")

_ARTIFACT_RE = re.compile(r"(?i)\b(MOTW|ZoneId|Zone\.Identifier|AppCompatCache|ShimCache|\bMFT\b|File/MOTW)\b")
_PROMOTION_RE = re.compile(
    r"(?i)(перша\s+точка\s+заражен|час\s+(?:заражен|компромет)|"
    r"початков(?:ий|а)\s+вектор|initial\s+access|infection\s+time|"
    r"доставка\s+payload|initial\s+payload|старт\s+атаки)"
)
_DATE_RE = re.compile(r"\b((?:19|20)\d{2})[-/]\d{2}[-/]\d{2}\b")
_CASE_YEAR_RE = re.compile(r"^\d{2}_\d{2}_((?:19|20)\d{2})_")
_AI_UNAVAILABLE_HEADING = "# ⚠️ УВАГА: LLM-МОДЕЛЬ НЕ ПРАЦЮЄ"


def ai_unavailable_banner(*, kind: str = "output", reason: str | None = None) -> str:
    """Return a loud client-facing banner for outputs created without LLM synthesis."""
    kind_label = {
        "brief": "короткий висновок",
        "timeline": "хронологія",
        "dfir_report": "звіт",
        "report": "звіт",
        "chat": "AI-відповідь",
        "search": "AI-пошук",
    }.get(str(kind or "").strip(), "результат")
    reason_line = f"\nПричина: {reason.strip()}" if reason else ""
    return (
        f"{_AI_UNAVAILABLE_HEADING}\n\n"
        "LLM-модель не відповідала або повернула порожній/неякісний результат під час генерації.\n"
        "Увімкніть LM Studio, завантажте модель і повторіть запит.\n\n"
        f"Нижче показано лише автоматично зібрані технічні артефакти / evidence-first {kind_label}. "
        "Це НЕ є фінальним AI-висновком і не має подаватися клієнту як повноцінний аналітичний звіт."
        f"{reason_line}"
    )


def prepend_ai_unavailable_banner(text: str | None, *, kind: str = "output", reason: str | None = None) -> str:
    """Prepend the LLM-unavailable banner once, preserving the original body."""
    body = str(text or "").strip()
    if body.startswith(_AI_UNAVAILABLE_HEADING):
        return body
    return (ai_unavailable_banner(kind=kind, reason=reason) + "\n\n" + body).strip()


def has_ai_unavailable_banner(text: str | None) -> bool:
    return str(text or "").lstrip().startswith(_AI_UNAVAILABLE_HEADING)


def incident_year_from_case_key(case_key: str | None) -> int | None:
    m = _CASE_YEAR_RE.match(str(case_key or ""))
    return int(m.group(1)) if m else None


def stale_artifact_promotion_issues(case_key: str | None, text: str | None) -> List[str]:
    """Return lines where an older artifact is promoted as infection/IA time."""
    incident_year = incident_year_from_case_key(case_key)
    if not incident_year:
        return []
    issues: List[str] = []
    for line in str(text or "").splitlines():
        if not (_ARTIFACT_RE.search(line) and _PROMOTION_RE.search(line)):
            continue
        years = [int(m.group(1)) for m in _DATE_RE.finditer(line)]
        if years and min(years) < incident_year:
            issues.append(line.strip()[:260])
    return issues


def demote_stale_artifact_promotions(case_key: str | None, text: str | None) -> Tuple[str, List[str]]:
    """Rewrite risky old-artifact lines as caveats instead of attack-chain claims."""
    original = str(text or "")
    issues = stale_artifact_promotion_issues(case_key, original)
    if not issues:
        return original, []

    incident_year = incident_year_from_case_key(case_key)
    fixed_lines: List[str] = []
    for line in original.splitlines():
        risky = False
        if _ARTIFACT_RE.search(line) and _PROMOTION_RE.search(line):
            years = [int(m.group(1)) for m in _DATE_RE.finditer(line)]
            risky = bool(years and incident_year and min(years) < incident_year)
        if risky:
            line = _PROMOTION_RE.sub("старий артефакт доставки/файлової системи", line)
            if not re.search(r"(?i)caveat|обереж|не\s+час|не\s+старт|не\s+вважати", line):
                line += " — caveat: не вважати часом компрометації без близьких execution/mail/browser доказів."
        fixed_lines.append(line)
    return "\n".join(fixed_lines), issues


def redact_internal_leaks(text: str | None) -> Tuple[str, List[str]]:
    """Redact internal implementation/tool terms from user-facing text."""
    s = str(text or "")
    leaks = sorted(set(m.group(0) for m in _INTERNAL_LEAK_RE.finditer(s)))
    if leaks:
        s = _INTERNAL_LEAK_RE.sub("службові деталі приховано", s)
    return s, leaks


def strip_leading_tool_transcript(text: str | None) -> Tuple[str, List[str]]:
    """Drop raw ReAct/tool prefaces before the first client-facing report heading."""
    s = str(text or "")
    if not _TOOL_DUMP_LINE_RE.search(s[:4000]):
        return s, []
    m = _CLIENT_HEADING_RE.search(s)
    if m and m.start() > 0:
        return s[m.start():].lstrip(), ["leading_tool_transcript"]
    return s, ["tool_transcript_detected"]


def _tables_to_lists(text):
    """Convert markdown tables (| a | b |) to bullet lists — Telegram renders pipe
    tables badly. Model-agnostic (agent-30b keeps emitting tables despite the prompt)."""
    if not text or '|' not in text:
        return text
    lines = text.split(chr(10))
    out = []
    i = 0
    n = len(lines)
    while i < n:
        st = lines[i].strip()
        is_row = st.startswith('|') and st.endswith('|') and st.count('|') >= 3
        sep_next = (i + 1 < n and set(lines[i+1].strip().replace('|','').replace(':','').replace(' ','')) <= set('-') and '-' in lines[i+1])
        if is_row and sep_next:
            hdr = [c.strip() for c in st.strip('|').split('|')]
            i += 2
            while i < n and lines[i].strip().startswith('|') and lines[i].strip().endswith('|'):
                cells = [c.strip() for c in lines[i].strip().strip('|').split('|')]
                parts = [c for c in cells if c and set(c) - set('-: ')]
                if parts:
                    out.append('• ' + '  ·  '.join(parts))
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return chr(10).join(out)


_SQL_LEAK_SIGNALS = re.compile(
    r'(?is)(payload->>|payload::text|SQL\s*помилк|syntax error at or near|\bLINE\s+\d+:'
    r'|\bЗапит:\s*SELECT|\bSELECT\b[\s\S]{0,800}?\bFROM\b\s+[\w".])')


def _strip_sql_statements(text):
    """Remove any raw SQL / DB-internal leak from client output. A ReAct/forced answer can
    echo a SELECT query, a Postgres error report (SQL помилка / syntax error / LINE N: / Запит:),
    or a jsonb accessor (payload->>). Client text must NEVER expose DB queries/schema/errors.
    Strips fenced SQL, PG error blocks, SELECT...FROM runs, and any residual leaking line.
    Returns (cleaned, hit)."""
    if not text or not _SQL_LEAK_SIGNALS.search(text):
        return text, False
    t = re.sub(r'(?is)```[a-z]*\s*\bSELECT\b[\s\S]*?```', '', text)
    # Postgres error-report lines (marker lines + the caret pointer line)
    t = re.sub(r'(?im)^[ \t]*(?:SQL\s*помилк\w*[^\n]*|syntax error[^\n]*|LINE\s+\d+:[^\n]*'
               r'|Запит:[^\n]*|\^[ \t]*)$\n?', '', t)
    # a full SELECT ... FROM statement (possibly multi-line)
    t = re.sub(r'(?is)\bSELECT\b[\s\S]*?\bFROM\b[\s\S]*?(?:;|\n\s*\n|$)', '', t)
    # any residual line still exposing a jsonb accessor / SELECT fragment / query dump
    t = '\n'.join(_ln for _ln in t.split('\n')
                  if 'payload->>' not in _ln and 'payload::text' not in _ln
                  and not re.match(r'(?i)\s*(?:SELECT\b|Запит:|LINE\s+\d+:)', _ln))
    return re.sub(r'\n{3,}', '\n\n', t).strip(), True


# Artifact names the LLM narrative sometimes borrows from a neighbouring case.
# A term counts as SUPPORTED when any of its aliases is present in the case data:
# "Remote Utilities", RMS, rutserv.exe, rfusclient.exe and TektonIT "Remote Manipulator
# System" are all names for the same remote-access product, and the model legitimately
# picks whichever one it likes. Without this, a true finding got masked as foreign.
_CROSS_CASE_TERM_ALIASES = {
    'remote utilities': ('rms', 'rutserv', 'rfusclient', 'tektonit', 'remote manipulator'),
    'rms': ('remote utilities', 'rutserv', 'rfusclient', 'tektonit', 'remote manipulator'),
}


def cross_case_term_aliases(term):
    """Other spellings of the same artifact; any hit means the term is supported."""
    return _CROSS_CASE_TERM_ALIASES.get(str(term or '').strip().lower(), ())


def drop_unsupported_term_sentences(text, terms):
    """Remove the sentences that rest on an artifact absent from THIS case.

    The old behaviour substituted the term with a '[інший кейс]' placeholder and kept the
    sentence. In a forensic report that is the worst of both worlds: the claim stays, and
    the label tells the reader the evidence came from another case. A claim resting on an
    artifact this case does not have is simply unsupported, so the sentence goes.
    Returns (text, dropped_sentence_count).
    """
    if not text or not terms:
        return (text or ''), 0
    pat = re.compile('|'.join(re.escape(str(t)) for t in terms if str(t).strip()), re.I)
    if not pat.search(text):
        return text, 0
    dropped = 0
    out_lines = []
    for line in text.split(chr(10)):
        if not pat.search(line):
            out_lines.append(line)
            continue
        parts = re.split(r'(?<=[.!?])\s+', line)
        kept = [p for p in parts if not pat.search(p)]
        dropped += len(parts) - len(kept)
        rebuilt = ' '.join(kept).strip()
        if not re.sub(r'[\s\-\*•#>`_|]+', '', rebuilt):
            continue
        out_lines.append(rebuilt)
    return re.sub(r'\n{3,}', chr(10)*2, chr(10).join(out_lines)).strip(), dropped


def guard_client_output(case_key: str | None, text: str | None, *, kind: str = "output") -> Tuple[str, List[str]]:
    """Apply conservative final guardrails before returning Telegram/client text.

    Returns (guarded_text, issue_labels). The function does not invent facts; it only
    demotes unsafe wording and removes internal implementation details.
    """
    guarded, transcript_issues = strip_leading_tool_transcript(text)
    guarded = _tables_to_lists(guarded)
    guarded, stale_lines = demote_stale_artifact_promotions(case_key, guarded)
    guarded, leaks = redact_internal_leaks(guarded)
    guarded, _sql_hit = _strip_sql_statements(guarded)
    # Drop lines that leaked the cross-case redaction placeholder — a '[інший кейс]'
    # in an IOC/evidence line is a stray foreign artifact, never a real this-case fact.
    _ph_dropped = False
    if guarded and 'інший кейс' in guarded:
        _kept = []
        for _ln in guarded.split(chr(10)):
            _l = _ln.strip()
            if 'інший кейс' in _l and (_l.startswith('-') or _l.startswith('*') or _l.startswith('•') or 'IOC' in _l.upper() or ':' in _l[:40]):
                _ph_dropped = True
                continue
            _kept.append(_ln)
        guarded = chr(10).join(_kept)
    issues: List[str] = []
    if _ph_dropped:
        issues.append('cross_case_placeholder_dropped')
    # Collapse duplicate bullet lines (LLM IOC sections often repeat the same
    # item dozens of times, e.g. msvcr120.dll ×28). Keep first occurrence with a
    # (×N) count; preserves order and non-list lines untouched.
    _dedup_hit = False
    if guarded:
        _seen = {}
        _order = []
        _out_lines = []
        _norm = lambda t: ' '.join(t.split()).lower()
        for _ln in guarded.split(chr(10)):
            _st = _ln.strip()
            _is_item = _st[:1] in ('-', '*', '•') and len(_st) > 4
            if _is_item:
                _k = _norm(_st)
                if _k in _seen:
                    _seen[_k]['n'] += 1
                    _dedup_hit = True
                    continue
                _seen[_k] = {'idx': len(_out_lines), 'n': 1}
                _order.append(_k)
            _out_lines.append(_ln)
        if _dedup_hit:
            for _k in _order:
                _info = _seen[_k]
                if _info['n'] > 1:
                    _i = _info['idx']
                    if not _out_lines[_i].rstrip().endswith(')'):
                        pass  # dedup collapses duplicates silently; no (×N) marker (was polluting reports)
            guarded = chr(10).join(_out_lines)
            issues.append('duplicate_bullets_collapsed')
    issues.extend(transcript_issues)
    if stale_lines:
        issues.append("stale_artifact_promotion_demoted")
    if leaks:
        issues.append("internal_leak_redacted")
    if _sql_hit:
        issues.append("sql_statement_stripped")
    return guarded.strip(), issues

# ── generic narrative grounding (2026-09-11) ──────────────────────────────────────────────
_GEN_EXE = {'explorer.exe', 'svchost.exe', 'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
            'wscript.exe', 'cscript.exe', 'conhost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'msiexec.exe',
            'taskhostw.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe', 'schtasks.exe', 'net.exe', 'net1.exe',
            'reg.exe', 'sc.exe', 'whoami.exe', 'ntdsutil.exe', 'kernel32.dll', 'ntdll.dll', 'user32.dll'}
_GEN_DOM = re.compile(r'^(www\.)?(microsoft|windows|google|mozilla|adobe|apple|github|python|docs|office|live|bing)\.', re.I)


def narrative_artifact_candidates(text, limit=40):
    """Concrete artefacts a narrative names: domains, IPv4s, executables/scripts. These are the
    terms a case must actually contain — a report may not cite an artefact this case does not have."""
    t = str(text or '')
    ips = {i for i in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', t) if not i.startswith(('127.', '0.', '255.'))}
    doms = {m.lower() for m in re.findall(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|ua|ru|io|dev|info|biz|gov\.ua|edu|cc|xyz|top|online|site|pro)\b', t, re.I)}
    doms = {d for d in doms if not _GEN_DOM.match(d)}
    exes = {m.lower() for m in re.findall(r'\b[\w\-\.]{3,60}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)\b', t, re.I)}
    exes = {e for e in exes if e not in _GEN_EXE}
    out = sorted(ips) + sorted(doms) + sorted(exes)
    return out[:limit]


def artifact_probe_forms(term):
    """Looser probes for grounding: an executable's stem without version digits, a domain
    without its leftmost label (dl-x.swisstransfer.com -> swisstransfer.com)."""
    t = str(term or '').lower()
    forms = [t]
    m = re.match(r'^(.*?)\.(exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)$', t)
    if m:
        stem = re.sub(r'[\d._\-]+$', '', m.group(1))
        if len(stem) >= 4:
            forms.append(stem[:24])
    elif re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', t):
        if t.count('.') >= 2:
            forms.append(t.split('.', 1)[1])
        # the registrable label: a domain of a tool that IS in the case (ngrok.exe -> ngrok.io)
        labels = [x for x in t.split('.') if x not in ('www', 'com', 'net', 'org', 'ua', 'ru', 'io', 'dev', 'gov', 'info', 'biz', 'pro')]
        if labels and len(labels[-1]) >= 5:
            forms.append(labels[-1])
    return forms


UNGROUNDED_MARK = '⟨не в доказах кейсу⟩'


def _case_has_artifact(cur, case_key, term):
    like = '%' + str(term).replace('%', '') + '%'
    try:
        cur.execute("""SELECT EXISTS (
                         SELECT 1 FROM event_logs_v2 WHERE case_key=%s AND (coalesce(command_line,'') ILIKE %s OR coalesce(remote_host,'') ILIKE %s OR payload::text ILIKE %s)
                         UNION ALL SELECT 1 FROM filesystem_v2 WHERE case_key=%s AND (file_name ILIKE %s OR coalesce(parent_path,'') ILIKE %s OR payload::text ILIKE %s)
                         UNION ALL SELECT 1 FROM program_exec_v2 WHERE case_key=%s AND (coalesce(full_path,'') ILIKE %s OR coalesce(executable_name,'') ILIKE %s OR payload::text ILIKE %s)
                         UNION ALL SELECT 1 FROM raw_fallback_v2 WHERE case_key=%s AND payload::text ILIKE %s AND %s=%s
                         UNION ALL SELECT 1 FROM case_iocs WHERE case_key=%s AND ioc_value ILIKE %s AND coalesce(source_table,'') NOT IN ('report_llm','qa_analysis','timeline_analysis','ps_c2','browser_provenance/infra') AND %s=%s
                         LIMIT 1)""", (case_key, like, like, like, case_key, like, like, like, case_key, like, like, like, case_key, like, like, like, case_key, like, like, like))
        return bool((cur.fetchone() or [False])[0])
    except Exception:
        try:
            cur.connection.rollback()
        except Exception:
            pass
        return True


def mark_ungrounded_artifacts(case_key, lines, max_terms=60):
    """Append UNGROUNDED_MARK after every domain/IP/executable in `lines` that the case evidence
    does not contain (looser probe forms included). Cache-agnostic: works on reused Q&A text too."""
    try:
        import psycopg2
        from core.config import PG_DSN
        text = '\n'.join(lines or [])
        cands = [c for c in narrative_artifact_candidates(text, limit=max_terms) if UNGROUNDED_MARK not in text.split(c, 1)[-1][:len(UNGROUNDED_MARK) + 2]]
        if not cands:
            return list(lines or [])
        bad = []
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='15000'")
            for term in cands:
                if not any(_case_has_artifact(cur, case_key, f) for f in artifact_probe_forms(term)):
                    bad.append(term)
        if not bad:
            return list(lines or [])
        out = []
        for ln in (lines or []):
            for term in bad:
                ln = re.sub(r'(?<![\w.-])' + re.escape(term) + r'(?![\w.-])(?!\s*' + re.escape(UNGROUNDED_MARK) + ')',
                            lambda m: m.group(0) + ' ' + UNGROUNDED_MARK, ln, flags=re.I)
            out.append(ln)
        return out
    except Exception:
        return list(lines or [])


_ATTACK_CLAIM_RE = re.compile(r'(атака почалася|зловмисник (отримав|закріпився|встановив|запустив|проник)|'
                              r'систем[аи] (була|є) скомпрометован|скомпрометован[ао]? через|компрометаці[яї] (відбулась|сталась))', re.I)
_NEG_BEFORE_RE = re.compile(r'(\bне\b|\bні\b|без ознак|немає ознак|не підтверджено)[^.\n]{0,25}$', re.I)
CALM_MARK = '⚠ [гіпотеза моделі — детермінований шар НЕ підтверджує] '


def soften_attack_claims(text):
    """On a calm deterministic verdict the model may still write «система була скомпрометована».
    Every such sentence gets an explicit marker instead of being read as a finding. Negated forms
    («не скомпрометована») are left alone. Returns (text, n_marked)."""
    n = 0
    out = []
    for line in str(text or '').split('\n'):
        m = _ATTACK_CLAIM_RE.search(line)
        if m and not _NEG_BEFORE_RE.search(line[:m.start()]) and CALM_MARK not in line:
            lead = re.match(r'^(\s*(?:[-*•]|\d+[.)])?\s*)', line).group(1)
            line = lead + CALM_MARK + line[len(lead):]
            n += 1
        out.append(line)
    return '\n'.join(out), n
