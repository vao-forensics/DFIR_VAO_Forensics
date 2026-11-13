"""HTTP helpers — thin wrappers over urllib."""
import json
import urllib.request
import urllib.error

# Import side effect: installs a global urllib guard so all LM Studio calls made
# by the threaded case-maintainer process are queued with concurrency=1 by default.
from core import llm_queue  # noqa: F401


def http_json(method: str, url: str, body: dict | None = None, timeout: int = 120) -> dict:
    """Make an HTTP request and return parsed JSON response."""
    data = None
    headers = {'Content-Type': 'application/json'}
    if body is not None:
        data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode('utf-8', errors='ignore')
        return json.loads(raw) if raw else {}


def gpu_host_idle(agent_url: str, agent_token: str, threshold: int) -> tuple[bool, dict]:
    """Return (idle, detail) for the Windows GPU host.

    Queries the agent's ``/gpu/json`` endpoint (v4.0+) and derives idle from
    ``totals.avg_util_pct``. The legacy ``/lmstudio/host-idle`` endpoint was
    removed in agent v4.0, so all callers share this single implementation to
    avoid API drift. Fail-open: if the agent is not configured or unreachable,
    returns idle=True so background workers are never permanently blocked.
    """
    if not agent_url or not agent_token:
        return True, {'idle': True, 'reason': 'agent_not_configured'}
    try:
        req = urllib.request.Request(
            f'{agent_url.rstrip("/")}/gpu/json',
            headers={'X-DFIR-Token': agent_token},
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode('utf-8', errors='ignore'))
        totals = (data or {}).get('totals', {}) or {}
        util = totals.get('avg_util_pct')
        # No util reading → treat as idle (fail-open), but report why.
        if util is None:
            return True, {'idle': True, 'util_pct': None, 'threshold': threshold,
                          'reason': 'no_util_data', 'source': 'gpu/json'}
        idle = float(util) <= float(threshold)
        return idle, {'idle': idle, 'util_pct': util, 'threshold': threshold,
                      'vram_free_gb': totals.get('vram_free_gb'), 'source': 'gpu/json'}
    except Exception as ex:
        return True, {'idle': True, 'reason': f'agent_unreachable:{str(ex)[:80]}'}


def llm_chat(llm_url: str, model: str, messages: list, max_tokens: int = 800,
             temperature: float = 0.2, stream: bool = False, timeout: int = 120,
             top_p: float | None = None, reasoning_effort: str | None = None) -> str:
    """Call OpenAI-compatible /v1/chat/completions and return content string."""
    url = llm_url.rstrip('/') + '/v1/chat/completions'
    payload = {
        'model': model,
        'messages': messages,
        'max_tokens': max_tokens,
        'temperature': temperature,
        'stream': stream,
    }
    if top_p is not None:
        payload['top_p'] = top_p
    if reasoning_effort:
        payload['reasoning_effort'] = reasoning_effort
    resp = http_json('POST', url, body=payload, timeout=timeout)
    choices = resp.get('choices', [])
    if not choices:
        return ''
    return choices[0].get('message', {}).get('content', '') or ''
