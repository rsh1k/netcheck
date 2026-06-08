"""
netcheck.ai
===========
Pluggable AI analysis layer. Sends the *structured* diagnostic / security /
forensic results to an LLM and gets back an expert narrative: root-cause
ranking, remediation steps, and (for security/IR) triage guidance.

Providers (all via raw HTTP - no third-party SDKs, so it works in locked-down
and air-gapped environments):
  - anthropic : Claude API           (cloud)
  - openai    : OpenAI / compatible  (cloud or self-hosted via base_url)
  - azure     : Azure OpenAI         (cloud, enterprise)
  - ollama    : Ollama               (fully local / on-prem - no data leaves)

API keys are read from environment variables only (see config.get_api_key).
For cloud providers, internal IPs / hostnames / MACs are redacted by default
before any data leaves the machine (config.ai.redact). Use Ollama for zero
data egress.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error

from .config import AIConfig, get_api_key

# --------------------------------------------------------------------------- #
# Redaction (privacy guard for cloud providers)
# --------------------------------------------------------------------------- #

_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")


def redact(text: str, hostname: str = "") -> str:
    """Mask internal IPs, MACs, and the local hostname. Public IPs are kept."""
    text = _PRIVATE_IP_RE.sub("[REDACTED-INTERNAL-IP]", text)
    text = _MAC_RE.sub("[REDACTED-MAC]", text)
    if hostname:
        text = re.sub(re.escape(hostname), "[REDACTED-HOST]", text, flags=re.I)
    return text


# --------------------------------------------------------------------------- #
# Prompt construction
# --------------------------------------------------------------------------- #

SYSTEM_PROMPTS = {
    "triage": (
        "You are a senior network engineer doing incident triage. You are given "
        "structured results from an automated network health check. Identify the "
        "single most likely root cause, explain the reasoning concisely, and give "
        "concrete, ordered remediation steps an on-call engineer can execute now. "
        "Be precise and avoid generic advice. If the data is insufficient, say so."),
    "security": (
        "You are a senior security engineer performing a defensive posture review "
        "of infrastructure the operator is authorised to assess. Given the security "
        "findings, prioritise them by real-world risk, explain the impact of each, "
        "and give specific hardening steps. Map issues to common frameworks (e.g. "
        "CIS, OWASP) where relevant. Do not provide exploitation instructions."),
    "incident": (
        "You are an incident response lead. Given diagnostic, security, and host "
        "forensic data captured during an incident, produce a concise IR analysis: "
        "(1) likely nature and scope, (2) severity, (3) immediate containment steps, "
        "(4) eradication & recovery actions, (5) what additional evidence to collect. "
        "Follow standard IR phases. Be specific and actionable."),
}


def build_user_prompt(env: dict, results, findings, mode: str) -> str:
    payload = {
        "mode": mode,
        "environment": {k: env.get(k) for k in
                        ("os", "target", "timestamp")},  # minimal env, no host/IP
        "checks": [
            {"name": r.name, "status": r.status, "detail": r.detail,
             "category": r.category, "data": r.data}
            for r in results
        ],
        "rule_based_findings": findings,
    }
    return ("Here is the structured output of an automated network assessment. "
            "Analyse it and respond as instructed.\n\n```json\n"
            + json.dumps(payload, indent=2, default=str)
            + "\n```")


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #

def _post_json(url: str, headers: dict, body: dict, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("content-type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #

class AIError(Exception):
    pass


def _provider_anthropic(cfg: AIConfig, system: str, user: str) -> str:
    key = get_api_key("anthropic")
    if not key:
        raise AIError("ANTHROPIC_API_KEY is not set")
    base = cfg.base_url or "https://api.anthropic.com"
    url = base.rstrip("/") + "/v1/messages"
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    body = {
        "model": cfg.resolved_model(),
        "max_tokens": cfg.max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    resp = _post_json(url, headers, body, cfg.timeout)
    parts = [b.get("text", "") for b in resp.get("content", [])
             if b.get("type") == "text"]
    return "\n".join(p for p in parts if p).strip()


def _provider_openai(cfg: AIConfig, system: str, user: str) -> str:
    key = get_api_key("openai")
    base = cfg.base_url or "https://api.openai.com/v1"
    is_official = "api.openai.com" in base
    if is_official and not key:
        raise AIError("OPENAI_API_KEY is not set")
    url = base.rstrip("/") + "/chat/completions"
    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = {
        "model": cfg.resolved_model(),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    }
    if cfg.max_tokens:
        # Official OpenAI uses max_completion_tokens; compat servers use max_tokens.
        body["max_completion_tokens" if is_official else "max_tokens"] = cfg.max_tokens
    resp = _post_json(url, headers, body, cfg.timeout)
    return resp["choices"][0]["message"]["content"].strip()


def _provider_azure(cfg: AIConfig, system: str, user: str) -> str:
    key = get_api_key("azure")
    if not key:
        raise AIError("AZURE_OPENAI_API_KEY is not set")
    endpoint = cfg.base_url or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    if not endpoint:
        raise AIError("Azure endpoint not set (config ai.base_url or AZURE_OPENAI_ENDPOINT)")
    deployment = cfg.deployment or cfg.model
    if not deployment:
        raise AIError("Azure deployment name not set (config ai.deployment)")
    url = (endpoint.rstrip("/") +
           f"/openai/deployments/{deployment}/chat/completions"
           f"?api-version={cfg.api_version}")
    headers = {"api-key": key}
    body = {
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": cfg.max_tokens,
    }
    resp = _post_json(url, headers, body, cfg.timeout)
    return resp["choices"][0]["message"]["content"].strip()


def _provider_ollama(cfg: AIConfig, system: str, user: str) -> str:
    base = (cfg.base_url or os.environ.get("OLLAMA_HOST")
            or "http://localhost:11434")
    if not base.startswith("http"):
        base = "http://" + base
    url = base.rstrip("/") + "/api/chat"
    headers = {}
    key = get_api_key("ollama")
    if key:  # for Ollama behind an authenticating proxy
        headers["Authorization"] = f"Bearer {key}"
    body = {
        "model": cfg.resolved_model(),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "stream": False,
        "options": {"num_predict": cfg.max_tokens},
    }
    resp = _post_json(url, headers, body, cfg.timeout)
    return (resp.get("message", {}) or {}).get("content", "").strip()


_PROVIDERS = {
    "anthropic": _provider_anthropic,
    "openai": _provider_openai,
    "azure": _provider_azure,
    "ollama": _provider_ollama,
}

CLOUD_PROVIDERS = {"anthropic", "openai", "azure"}


def list_providers():
    return sorted(_PROVIDERS)


def analyze(cfg: AIConfig, env: dict, results, findings, mode: str = "triage") -> dict:
    """Run AI analysis. Returns {ok, provider, model, text, error}."""
    out = {"ok": False, "provider": cfg.provider,
           "model": cfg.resolved_model(), "text": "", "error": ""}
    fn = _PROVIDERS.get(cfg.provider)
    if fn is None:
        out["error"] = f"unknown provider '{cfg.provider}'"
        return out

    system = SYSTEM_PROMPTS.get(mode, SYSTEM_PROMPTS["triage"])
    user = build_user_prompt(env, results, findings, mode)

    # Privacy guard: redact internal identifiers before any cloud call.
    if cfg.redact and cfg.provider in CLOUD_PROVIDERS:
        host = env.get("hostname", "")
        user = redact(user, host)

    try:
        text = fn(cfg, system, user)
        if not text:
            out["error"] = "empty response from model"
            return out
        out["ok"] = True
        out["text"] = text
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        out["error"] = f"HTTP {e.code}: {detail or e.reason}"
    except urllib.error.URLError as e:
        out["error"] = f"connection error: {e.reason}"
    except AIError as e:
        out["error"] = str(e)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out
