"""Central configuration — all env vars and constants in one place."""
import os

# ── PostgreSQL ─────────────────────────────────────────────────────────────
PG_DSN = os.getenv('PG_DSN', 'host=logdb port=5432 dbname=dfir_logs user=dfir password=CHANGE_ME_POSTGRES_PASSWORD')

# ── LLM (LM Studio) ────────────────────────────────────────────────────────
LLM_URL   = os.getenv('DFIR_LLM_URL',   'http://192.168.100.1:1234')
LLM_MODEL        = os.getenv('DFIR_LLM_MODEL',    'gpt-oss-120b-heretic-v2')
LLM_STRONG_MODEL = LLM_MODEL   # explicit alias: full DFIR synthesis, conflict resolution, judge

# Fast-path model: keep the same GPT OSS model for all chat/analysis functions.
# Embedding models below remain separate because they are not chat LLMs.
LLM_FAST_MODEL = os.getenv('DFIR_FAST_MODEL', LLM_MODEL)
LLM_REACT_MODEL = os.getenv('DFIR_REACT_MODEL', 'gemma-4-31b')  # in-case ReAct: capable dense 31B (20b returned empty on multi-step reasoning)
LLM_FAST_URL   = os.getenv('DFIR_FAST_URL',   LLM_URL)

# Swap authority. 'llamaswap' = the host llama-swap matrix solver owns ALL model
# loading/eviction; the bot must NOT pin/unload GPUs via the lmstudio SDK (that
# collided with llama-swap and caused host freezes). Any other value keeps the
# legacy bot-side SDK pinning (kept only for emergency rollback).
LLM_SWAP_OWNER = os.getenv('DFIR_LLM_SWAP_OWNER', 'llamaswap').strip().lower()
LLM_BOT_OWNS_GPU = (LLM_SWAP_OWNER != 'llamaswap')

# Embeddings — only for Qdrant semantic search, never used as chat LLM
EMBED_URL        = os.getenv('DFIR_EMBED_URL',   LLM_URL)
EMBED_MODEL      = os.getenv('DFIR_EMBED_MODEL', 'text-embedding-qwen3-embedding-8b')
LLM_EMBED_MODEL  = EMBED_MODEL  # explicit alias

# Timeouts (seconds)
LLM_TIMEOUT       = int(os.getenv('DFIR_LLM_TIMEOUT',       '1100'))
LLM_FAST_TIMEOUT  = int(os.getenv('DFIR_FAST_TIMEOUT',       '120'))
LLM_PROBE_TIMEOUT = int(os.getenv('DFIR_LLM_PROBE_TIMEOUT',    '8'))

# Startup warmup: after VM/LM Studio restart, make one tiny chat request so the
# configured model is loaded before the first analyst action hits the bot.
LLM_WARMUP_ENABLED = os.getenv('DFIR_LLM_WARMUP_ENABLED', 'true').lower() == 'true'
LLM_WARMUP_TIMEOUT = int(os.getenv('DFIR_LLM_WARMUP_TIMEOUT', '120'))
LLM_WARMUP_ATTEMPTS = int(os.getenv('DFIR_LLM_WARMUP_ATTEMPTS', '8'))
LLM_WARMUP_RETRY_DELAY = int(os.getenv('DFIR_LLM_WARMUP_RETRY_DELAY', '20'))

# Token budgets
LLM_MAX_TOKENS       = int(os.getenv('DFIR_MAX_TOKENS',       '4000'))
LLM_FAST_MAX_TOKENS  = int(os.getenv('DFIR_FAST_MAX_TOKENS',   '800'))
LLM_SYNTH_MAX_TOKENS = int(os.getenv('DFIR_SYNTH_MAX_TOKENS', '18000'))

# LLM generation profiles. Keep existing call-site defaults unless a profile env
# explicitly overrides them; these knobs let operations tune LM Studio/gpt-oss
# behavior without editing Python code.
LLM_TEMPERATURE = float(os.getenv('DFIR_LLM_TEMPERATURE', '0.1'))
LLM_FAST_TEMPERATURE = float(os.getenv('DFIR_FAST_TEMPERATURE', str(LLM_TEMPERATURE)))
LLM_STRONG_TEMPERATURE = float(os.getenv('DFIR_STRONG_TEMPERATURE', '0.05'))
LLM_JSON_TEMPERATURE = float(os.getenv('DFIR_JSON_TEMPERATURE', '0.0'))
_LLM_TOP_P_RAW = os.getenv('DFIR_LLM_TOP_P', '').strip()
LLM_TOP_P = float(_LLM_TOP_P_RAW) if _LLM_TOP_P_RAW else None

# gpt-oss models can spend completion budget on hidden/visible reasoning. For
# deterministic DFIR output, prefer low reasoning by default on long/json tasks
# while allowing per-endpoint env overrides.
LLM_GPT_OSS_SAFETY = os.getenv('DFIR_LLM_GPT_OSS_SAFETY', 'true').lower() == 'true'
LLM_REASONING_EFFORT = os.getenv('DFIR_LLM_REASONING_EFFORT', '').strip()
LLM_FAST_REASONING_EFFORT = os.getenv('DFIR_FAST_REASONING_EFFORT', LLM_REASONING_EFFORT).strip()
LLM_STRONG_REASONING_EFFORT = os.getenv('DFIR_STRONG_REASONING_EFFORT', LLM_REASONING_EFFORT or 'low').strip()
LLM_JSON_REASONING_EFFORT = os.getenv('DFIR_JSON_REASONING_EFFORT', LLM_REASONING_EFFORT or 'low').strip()

# gpt-oss spends part of the completion budget on hidden reasoning tokens
# BEFORE emitting any visible content. With a small max_tokens the reasoning
# can consume the whole budget and the model returns empty/truncated content
# (observed: max_tokens=32 -> 47 reasoning tokens -> empty content). To keep a
# caller's max_tokens meaning "content budget", build_chat_payload adds this
# reserve on top whenever reasoning_effort is set. Tunable per effort level.
LLM_REASONING_HEADROOM_LOW    = int(os.getenv('DFIR_REASONING_HEADROOM_LOW',    '256'))
LLM_REASONING_HEADROOM_MEDIUM = int(os.getenv('DFIR_REASONING_HEADROOM_MEDIUM', '768'))
LLM_REASONING_HEADROOM_HIGH   = int(os.getenv('DFIR_REASONING_HEADROOM_HIGH',  '1536'))

# Endpoint-specific budgets used by Telegram/user-facing paths.
LLM_REACT_MAX_TOKENS = int(os.getenv('DFIR_REACT_MAX_TOKENS', str(LLM_FAST_MAX_TOKENS)))
LLM_JSON_MAX_TOKENS = int(os.getenv('DFIR_JSON_MAX_TOKENS', '1200'))
LLM_BRIEF_MAX_TOKENS = int(os.getenv('DFIR_BRIEF_MAX_TOKENS', '5000'))
LLM_TIMELINE_MAX_TOKENS = int(os.getenv('DFIR_TIMELINE_MAX_TOKENS', '1800'))
LLM_TIMELINE_STRONG_MAX_TOKENS = int(os.getenv('DFIR_TIMELINE_STRONG_MAX_TOKENS', os.getenv('TIMELINE_STRONG_MAX_TOKENS', '6000')))
LLM_ASK_MAX_TOKENS = int(os.getenv('DFIR_ASK_MAX_TOKENS', '600'))

# ── Windows GPU Agent ───────────────────────────────────────────────────────
WINDOWS_AGENT_URL   = os.getenv('DFIR_WINDOWS_AGENT_URL', 'http://192.168.134.1:8788')
WINDOWS_AGENT_TOKEN = os.getenv('DFIR_WINDOWS_AGENT_TOKEN', '')
GPU_IDLE_THRESHOLD  = int(os.getenv('DFIR_GPU_IDLE_THRESHOLD', '15'))

# ── Qdrant ─────────────────────────────────────────────────────────────────
QDRANT_URL = os.getenv('DFIR_QDRANT_URL', 'http://qdrant:6333')

# ── Telegram ───────────────────────────────────────────────────────────────
TG_TOKEN   = os.getenv('MAINTAINER_TOKEN', 'change-me')
ADMIN_CHAT = os.getenv('DFIR_ADMIN_CHAT', '')

# ── Storage ────────────────────────────────────────────────────────────────
CASE_LIB = os.getenv('CASE_LIBRARY', '/data/case_library')

# ── Job / worker settings ──────────────────────────────────────────────────
STALE_HEARTBEAT_SECONDS = int(os.getenv('DFIR_STALE_HEARTBEAT_SECONDS', '300'))

# ── Idle self-improvement flags (ЕТАП 2) ───────────────────────────────────
# Off by default — enable only explicitly in env
IDLE_LEARNING_ENABLED         = os.getenv('DFIR_IDLE_LEARNING_ENABLED', 'false').lower() == 'true'
IDLE_LEARNING_DRY_RUN         = os.getenv('DFIR_IDLE_LEARNING_DRY_RUN', 'true').lower() == 'true'
IDLE_LEARNING_MAX_CASES       = int(os.getenv('DFIR_IDLE_LEARNING_MAX_CASES', '1'))
IDLE_LEARNING_MAX_QUESTIONS   = int(os.getenv('DFIR_IDLE_LEARNING_MAX_QUESTIONS_PER_CASE', '5'))
IDLE_LEARNING_MIN_IDLE_SECS   = int(os.getenv('DFIR_IDLE_LEARNING_MIN_IDLE_SECONDS', '900'))
IDLE_LEARNING_SLEEP_SECS      = int(os.getenv('DFIR_IDLE_LEARNING_SLEEP_SECONDS', '60'))
IDLE_LEARNING_REQUIRE_APPROVAL = os.getenv('DFIR_IDLE_LEARNING_REQUIRE_APPROVAL', 'true').lower() == 'true'

# ── Telegram ───────────────────────────────────────────────────────────────
TG_BOT_TOKEN = os.getenv('DFIR_TG_BOT_TOKEN', '').strip()
ADMIN_CHAT_ID = os.getenv('DFIR_ADMIN_CHAT_ID', '').strip()

# ── Qdrant collections / embedding ─────────────────────────────────────────
TEXT_COLL_PRIMARY = os.getenv('DFIR_TEXT_COLL_PRIMARY', 'kb_text_qwen3e8b_v1')
EMBED_DIM         = int(os.getenv('DFIR_EMBED_DIM', '4096'))

# ── LLM context sizes ──────────────────────────────────────────────────────
CTX_BUDGET_CHARS  = int(os.getenv('DFIR_CTX_BUDGET_CHARS',  '40000'))
BACKTRACE_SLOT    = int(os.getenv('DFIR_BACKTRACE_SLOT',     '8000'))
TRIAGE_SLICE_CHARS = int(os.getenv('DFIR_TRIAGE_SLICE_CHARS', '50000'))

# ── DFIR pipeline step codes ───────────────────────────────────────────────
DFIR_STEP_CODES = [
    'ingest_check',
    'detection',
    'corroboration',
    'incident_timeline',
    'case_llm_triage_v1',
    'case_drilldown_v1',
    'case_reasoning_v1',
    'detection_timeline',
    'ioc_artifacts',
    'short_conclusion',
    'txt_report',
]

# ── MITRE ATT&CK EID → Technique quick-map ─────────────────────────────────
# Used by timeline_data() to tag events with ATT&CK technique IDs
EID_ATTACK_MAP = {
    # Initial Access
    4624: ('TA0001', 'T1078',  'Valid Accounts'),
    4625: ('TA0001', 'T1110',  'Brute Force'),
    # Execution
    4688: ('TA0002', 'T1059',  'Command & Scripting'),
    4104: ('TA0002', 'T1059.001', 'PowerShell'),
    # Persistence
    4698: ('TA0003', 'T1053.005', 'Scheduled Task'),
    4702: ('TA0003', 'T1053.005', 'Scheduled Task'),
    7045: ('TA0003', 'T1543.003', 'New Service'),
    4720: ('TA0003', 'T1136',  'Create Account'),
    # Privilege Escalation
    4726: ('TA0004', 'T1078',  'Account Manipulation'),
    4728: ('TA0004', 'T1078',  'Account Manipulation'),
    # Defense Evasion
    1116: ('TA0005', 'T1562.001', 'Impair Defenses'),
    1117: ('TA0005', 'T1562.001', 'Impair Defenses'),
    # Credential Access
    4776: ('TA0006', 'T1003',  'Credential Dumping'),
    # Lateral Movement
    4648: ('TA0008', 'T1550',  'Use Alternate Auth Material'),
    # Collection / Exfiltration
    4663: ('TA0009', 'T1074',  'Data Staged'),
    # Defense Evasion — log clearing
    1102: ('TA0005', 'T1070.001', 'Clear Windows Event Logs'),
    104:  ('TA0005', 'T1070.001', 'Clear Windows Event Logs'),
}
