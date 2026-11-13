"""
DFIR model router — routes tasks to fast (Gemma) or strong (120B) model.

Roles:
  fast   = LLM_FAST_MODEL  (Gemma 31B) — QA, routing, brief/timeline formatting
  strong = LLM_STRONG_MODEL (120B)     — full synthesis, conflict resolution, judge
  embed  = EMBED_MODEL                  — semantic search only, never LLM
"""
import logging, time
from core.config import (
    PG_DSN,
    LLM_URL, LLM_MODEL, LLM_FAST_MODEL, LLM_FAST_URL,
    LLM_TIMEOUT, LLM_FAST_TIMEOUT,
    LLM_MAX_TOKENS, LLM_FAST_MAX_TOKENS,
    LLM_TEMPERATURE, LLM_FAST_TEMPERATURE, LLM_STRONG_TEMPERATURE,
    LLM_JSON_TEMPERATURE, LLM_TOP_P,
    LLM_FAST_REASONING_EFFORT, LLM_STRONG_REASONING_EFFORT,
    LLM_JSON_REASONING_EFFORT, LLM_GPT_OSS_SAFETY,
    LLM_REASONING_HEADROOM_LOW, LLM_REASONING_HEADROOM_MEDIUM,
    LLM_REASONING_HEADROOM_HIGH,
)

_log = logging.getLogger('app')

# Reserve added to max_tokens per reasoning effort so the caller's budget funds
# visible content, not the hidden reasoning the gpt-oss model emits first.
_REASONING_HEADROOM = {
    'low':    LLM_REASONING_HEADROOM_LOW,
    'medium': LLM_REASONING_HEADROOM_MEDIUM,
    'high':   LLM_REASONING_HEADROOM_HIGH,
}

# ── Role aliases ─────────────────────────────────────────────────────────────
LLM_STRONG_MODEL = LLM_MODEL       # explicit alias — 120B
LLM_EMBED_MODEL  = None            # resolved from EMBED_MODEL at call time


def generation_profile(role: str = 'fast') -> dict:
    """Return default generation knobs for a role.

    Values are intentionally optional: top_p/reasoning_effort are omitted from
    payloads unless configured/applicable so existing providers stay compatible.
    """
    if role == 'strong':
        reasoning = LLM_STRONG_REASONING_EFFORT
        temperature = LLM_STRONG_TEMPERATURE
    elif role == 'json':
        reasoning = LLM_JSON_REASONING_EFFORT
        temperature = LLM_JSON_TEMPERATURE
    else:
        reasoning = LLM_FAST_REASONING_EFFORT
        temperature = LLM_FAST_TEMPERATURE if LLM_FAST_TEMPERATURE is not None else LLM_TEMPERATURE
    return {
        'temperature': temperature,
        'top_p': LLM_TOP_P,
        'reasoning_effort': reasoning if LLM_GPT_OSS_SAFETY else '',
    }


def build_chat_payload(*, model: str, messages: list, role: str = 'fast',
                       max_tokens=None, temperature=None,
                       stream: bool = False, top_p: float = None,
                       reasoning_effort=None, extra=None) -> dict:
    """Build OpenAI-compatible chat payload with centralized DFIR defaults."""
    prof = generation_profile(role)
    payload = {
        'model': model,
        'messages': messages,
        'stream': bool(stream),
        'temperature': prof['temperature'] if temperature is None else temperature,
        'max_tokens': max_tokens if max_tokens is not None else (LLM_MAX_TOKENS if role == 'strong' else LLM_FAST_MAX_TOKENS),
    }
    effective_top_p = prof.get('top_p') if top_p is None else top_p
    if effective_top_p is not None:
        payload['top_p'] = effective_top_p
    effective_reasoning = prof.get('reasoning_effort') if reasoning_effort is None else reasoning_effort
    if effective_reasoning:
        payload['reasoning_effort'] = effective_reasoning
        # gpt-oss spends part of the completion budget on hidden reasoning before
        # any content. Add headroom so the caller's max_tokens is the content
        # budget. Raising the cap is safe — the model still stops at its natural
        # end; this only prevents reasoning from starving short-budget calls.
        headroom = _REASONING_HEADROOM.get(str(effective_reasoning).strip(),
                                           LLM_REASONING_HEADROOM_LOW)
        payload['max_tokens'] = int(payload['max_tokens']) + headroom
    if extra:
        payload.update(extra)
    return payload

# ── Task → role mapping ──────────────────────────────────────────────────────
# Each task is assigned a default role. Escalation can override to 'strong'.
TASK_ROUTING = {
    # Fast model tasks
    'telegram_qa':              'fast',
    'question_routing':         'fast',
    'playbook_selection':       'fast',
    'sql_plan':                 'fast',
    'brief_formatting':         'fast',
    'timeline_formatting':      'fast',
    'answer_formatting':        'fast',
    'fast_path_qa':             'fast',
    'react_qa':                 'fast',
    'correction_intercept':     'fast',
    'feedback_ack':             'fast',
    'cache_lookup':             'fast',
    # Strong model tasks
    'dfir_synthesis':           'strong',
    'dfir_full_report':         'strong',
    'complex_correlation':      'strong',
    'self_improve_judge':       'strong',
    'self_improve_evaluator':   'strong',
    'needs_review_resolution':  'strong',
    'conflict_validation':      'strong',
    'deep_dfir_analysis':       'strong',
    'report_synthesis':         'strong',
    'agent_report':             'strong',
    'full_report':              'strong',
    'generate_report':          'strong',
    'generate_brief':           'strong',
    'brief_synthesis':          'strong',
    'timeline_synthesis':       'strong',
    'benchmark_compare':        'strong',
    # Embedding — neither fast nor strong
    'semantic_search':          'embed',
    'qdrant_embed':             'embed',
}

# ── Escalation conditions ─────────────────────────────────────────────────────
ESCALATION_CONDITIONS = [
    'confidence_low',
    'conflict_logs_vs_report',
    'missing_evidence',
    'full_analysis_requested',
    'react_exhausted',
    'multi_source_correlation',
    'cross_case_validation',
]


def route(task_name: str, context: dict = None) -> dict:
    """
    Determine model config for a task.

    Returns:
      {
        'model': str,
        'url':   str,
        'role':  'fast'|'strong'|'embed',
        'max_tokens': int,
        'timeout': int,
        'escalated': bool,
        'reason': str,
      }
    """
    context = context or {}
    role = TASK_ROUTING.get(task_name, 'fast')

    # Escalation check
    escalated = False
    escalation_reason = None
    if role == 'fast':
        for cond in ESCALATION_CONDITIONS:
            if context.get(cond):
                role = 'strong'
                escalated = True
                escalation_reason = cond
                break

    if role == 'strong':
        prof = generation_profile('strong')
        return {
            'model':      LLM_STRONG_MODEL,
            'url':        LLM_URL.rstrip('/') + '/v1/chat/completions',
            'role':       'strong',
            'max_tokens': LLM_MAX_TOKENS,
            'timeout':    LLM_TIMEOUT,
            'temperature': prof['temperature'],
            'top_p':      prof['top_p'],
            'reasoning_effort': prof['reasoning_effort'],
            'escalated':  escalated,
            'reason':     escalation_reason or task_name,
        }
    elif role == 'embed':
        return {
            'model':      None,
            'url':        None,
            'role':       'embed',
            'max_tokens': 0,
            'timeout':    0,
            'escalated':  False,
            'reason':     task_name,
        }
    else:
        prof = generation_profile('fast')
        return {
            'model':      LLM_FAST_MODEL,
            'url':        LLM_FAST_URL.rstrip('/') + '/v1/chat/completions',
            'role':       'fast',
            'max_tokens': LLM_FAST_MAX_TOKENS,
            'timeout':    LLM_FAST_TIMEOUT,
            'temperature': prof['temperature'],
            'top_p':      prof['top_p'],
            'reasoning_effort': prof['reasoning_effort'],
            'escalated':  False,
            'reason':     task_name,
        }


def log_routing(task_name: str, case_key: str = None, chat_id: str = None,
                model_used: str = None, role: str = None, reason: str = None,
                escalated: bool = False, escalation_reason: str = None,
                input_tokens: int = None, output_tokens: int = None,
                duration_ms: int = None):
    """Write a routing decision to dfir_model_routing_audit. Best-effort."""
    try:
        import psycopg2
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_model_routing_audit
                        (task_name, case_key, chat_id, model_used, model_role,
                         reason, escalated_to_strong, escalation_reason,
                         input_tokens, output_tokens, duration_ms)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (task_name, case_key, str(chat_id) if chat_id else None,
                      model_used, role or 'fast', reason,
                      escalated, escalation_reason,
                      input_tokens, output_tokens, duration_ms))
    except Exception as e:
        _log.debug(f'[model_router] audit log error: {e}')
