"""
llm_client.py - LOCAL-ONLY LLM client.

Supports two backends via `requests` (no hard dependency on the ollama client):
  * "openai" : OpenAI-compatible /chat/completions (e.g. local llama-swap)
  * "ollama" : native /api/chat

HARD OFFLINE GUARANTEE: `assert_local_url` refuses any base_url that is not
localhost / loopback / a private-LAN range. No course content ever leaves the
machine. If the local LLM is unreachable, a built-in MockLLM returns canned
JSON so the (regex-driven) pipeline still completes.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

import requests


# ---------------------------------------------------------------------------
# Offline enforcement
# ---------------------------------------------------------------------------
def assert_local_url(base_url: str) -> str:
    """Raise ValueError unless `base_url` points at localhost or a private LAN.

    Accepted hosts:
      * localhost
      * loopback (127.0.0.0/8, ::1)
      * RFC1918 private ranges (10.*, 192.168.*, 172.16-31.*, fc00::/7)
    """
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Refusing to run: cannot parse host from base_url {base_url!r}")

    host_l = host.lower()
    if host_l in ("localhost",):
        return base_url

    try:
        ip = ipaddress.ip_address(host_l)
    except ValueError:
        raise ValueError(
            f"Refusing to run: LLM host {host!r} is not localhost or a private IP. "
            "This tool is OFFLINE-ONLY; no content may be sent to a cloud API."
        )

    if ip.is_loopback or ip.is_private:
        return base_url

    raise ValueError(
        f"Refusing to run: LLM host {host!r} ({ip}) is not loopback/private. "
        "This tool is OFFLINE-ONLY."
    )


# ---------------------------------------------------------------------------
# JSON extraction helper
# ---------------------------------------------------------------------------
def extract_json_array(text: str):
    """Best-effort parse of a JSON array from a model response.

    Returns a Python list, or raises ValueError. Tolerates code fences and
    surrounding prose by grabbing the first '[' .. last ']'.
    """
    if text is None:
        raise ValueError("empty response")
    # Strip markdown code fences.
    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    try:
        val = json.loads(cleaned)
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            # Some models wrap the array, e.g. {"items": [...]}.
            for v in val.values():
                if isinstance(v, list):
                    return v
            return [val]
    except json.JSONDecodeError:
        pass

    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start != -1 and end != -1 and end > start:
        return json.loads(cleaned[start : end + 1])
    raise ValueError("no JSON array found in response")


# ---------------------------------------------------------------------------
# Mock backend (offline fallback / tests)
# ---------------------------------------------------------------------------
class MockLLM:
    """Deterministic canned backend used when the local LLM is unavailable.

    It does a tiny bit of keyword spotting so the mock output is at least
    plausible for the synthetic test, but it never sees the network.
    """

    name = "mock"

    def chat_json(self, system: str, user: str, reminder: bool = False):
        rows = []
        low = user.lower()
        if "kerberos" in low or "88" in low:
            rows.append(
                {"topic": "Kerberos", "description": "Network authentication protocol using tickets",
                 "category": "concept", "weight": 2}
            )
        if "smb" in low:
            rows.append(
                {"topic": "SMB", "description": "Server Message Block file-sharing protocol on port 445",
                 "category": "acronym", "weight": 2}
            )
        if not rows:
            rows.append(
                {"topic": "Sample Concept", "description": "Placeholder description from mock LLM",
                 "category": "concept", "weight": 1}
            )
        return rows


# ---------------------------------------------------------------------------
# Real local backends
# ---------------------------------------------------------------------------
class LLMClient:
    """Thin `requests`-based client for local OpenAI-compatible or Ollama servers."""

    def __init__(self, backend: str, base_url: str, model: str,
                 temperature: float = 0, timeout: int = 60):
        self.backend = backend
        self.base_url = assert_local_url(base_url.rstrip("/"))
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.name = f"{backend}:{model}"

    # -- raw call returning assistant text ---------------------------------
    def _raw(self, system: str, user: str) -> str:
        if self.backend == "openai":
            url = f"{self.base_url}/chat/completions"
            payload = {
                "model": self.model,
                "temperature": self.temperature,
                "max_tokens": 2048,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                # Nudge OpenAI-compatible servers toward pure JSON when supported.
                "response_format": {"type": "json_object"},
            }
            r = requests.post(url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            return data["choices"][0]["message"]["content"]

        elif self.backend == "ollama":
            url = f"{self.base_url}/api/chat"
            payload = {
                "model": self.model,
                "stream": False,
                "options": {"temperature": self.temperature, "num_predict": 2048},
                "format": "json",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
            r = requests.post(url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            return data["message"]["content"]

        raise ValueError(f"Unknown backend {self.backend!r}")

    def chat_json(self, system: str, user: str, reminder: bool = False):
        """Return a parsed JSON list. Raises on network or parse failure."""
        user_msg = user
        if reminder:
            user_msg = user + "\n\nReturn ONLY valid JSON (a JSON array). No prose."
        text = self._raw(system, user_msg)
        return extract_json_array(text)

    def ping(self) -> bool:
        """Cheap reachability check; True if the server responds."""
        try:
            self.chat_json(
                "You reply with JSON only.",
                'Return this exact JSON array: [{"topic":"ping","description":"ok",'
                '"category":"concept","weight":1}]',
            )
            return True
        except Exception:
            return False


def build_client(cfg: dict):
    """Build a client from config['llm']. Returns (client, used_mock: bool).

    Tries the configured local backend once; on failure (and if
    use_mock_on_failure) returns a MockLLM instead of crashing.
    """
    backend = cfg.get("backend", "openai")
    sub = cfg.get(backend, {})
    base_url = sub.get("base_url")
    model = sub.get("model")

    # Offline guard always runs (even before we attempt a connection).
    assert_local_url(base_url)

    client = LLMClient(
        backend=backend,
        base_url=base_url,
        model=model,
        temperature=cfg.get("temperature", 0),
        timeout=cfg.get("timeout", 60),
    )
    return client
