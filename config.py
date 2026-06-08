"""
netcheck.config
===============
Configuration model and loader. Settings can come from (in order of precedence):
1. CLI flags (handled in cli.py)
2. Environment variables (best for secrets - never commit these)
3. A config file (TOML or JSON)
4. Built-in defaults

Secrets (API keys) are ONLY read from environment variables, never from the
config file, so the config file is safe to commit to version control.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

# Stable, well-known anchors used across checks.
INTERNET_ANCHORS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")]
PUBLIC_RESOLVERS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9")]
DNS_PROBE_NAME = "cloudflare.com"
DEFAULT_TARGET = "cloudflare.com"
DEFAULT_PORTS = [80, 443, 22, 53]

# OS-vendor captive-portal / connectivity probe endpoints.
CAPTIVE_PROBES = [
    ("http://captive.apple.com/hotspot-detect.html", 200, "Success"),
    ("http://www.gstatic.com/generate_204", 204, None),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"),
    ("http://detectportal.firefox.com/canonical.html", 200, "success"),
]

PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "Postgres", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    9200: "Elastic", 27017: "MongoDB",
}

# Risky services that should rarely be exposed to untrusted networks.
RISKY_PORTS = {
    21: "FTP (cleartext credentials)",
    23: "Telnet (cleartext, no encryption)",
    135: "MS-RPC (lateral-movement vector)",
    139: "NetBIOS (legacy SMB)",
    445: "SMB (ransomware/worm vector)",
    1433: "MSSQL (database exposed)",
    1521: "Oracle DB (database exposed)",
    3306: "MySQL (database exposed)",
    3389: "RDP (brute-force/ransomware vector)",
    5432: "PostgreSQL (database exposed)",
    5900: "VNC (often weak/no auth)",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch (often unauthenticated)",
    27017: "MongoDB (often unauthenticated)",
}


@dataclass
class AIConfig:
    enabled: bool = False
    provider: str = "ollama"          # anthropic | openai | azure | ollama
    model: str = ""                   # provider-specific; sensible defaults below
    base_url: str = ""                # override for self-hosted / proxied endpoints
    api_version: str = "2024-10-21"   # azure only
    deployment: str = ""              # azure only
    max_tokens: int = 1500
    timeout: float = 60.0
    redact: bool = True               # redact internal IPs/hostnames before cloud calls
    # API keys are NOT stored here - they are read from env at call time.

    def resolved_model(self) -> str:
        if self.model:
            return self.model
        return {
            "anthropic": "claude-sonnet-4-6",
            "openai": "gpt-5.4-mini",
            "azure": self.deployment or "gpt-4o-mini",
            "ollama": "llama3.1",
        }.get(self.provider, "")


@dataclass
class NotifyConfig:
    webhook_url: str = ""             # generic JSON webhook (also works for Slack)
    on_severity: str = "WARN"         # minimum severity to notify: WARN | FAIL


@dataclass
class AppConfig:
    target: str = DEFAULT_TARGET
    ports: list = field(default_factory=lambda: list(DEFAULT_PORTS))
    timeout: float = 3.0
    full: bool = False
    no_color: bool = False
    output: str = ""
    json: bool = False
    json_only: bool = False
    log_file: str = ""                # JSON-lines audit log
    operator: str = ""                # who ran it (for audit / IR reports)
    ai: AIConfig = field(default_factory=AIConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)

    def to_dict(self) -> dict:
        return asdict(self)


def _load_file(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    if path.endswith((".toml",)):
        try:
            import tomllib  # Python 3.11+
            return tomllib.loads(raw.decode("utf-8"))
        except ModuleNotFoundError:
            try:
                import tomli  # backport
                return tomli.loads(raw.decode("utf-8"))
            except ModuleNotFoundError:
                raise SystemExit(
                    "TOML config requires Python 3.11+ or the 'tomli' package; "
                    "use a .json config instead.")
    return json.loads(raw.decode("utf-8"))


def load_config(path: Optional[str] = None) -> AppConfig:
    """Build an AppConfig from defaults <- file <- environment."""
    cfg = AppConfig()

    data = {}
    if path:
        data = _load_file(path)
    else:
        for candidate in ("netcheck.toml", "netcheck.json",
                          os.path.expanduser("~/.config/netcheck/config.toml")):
            if os.path.exists(candidate):
                data = _load_file(candidate)
                break

    # Apply file values
    for k in ("target", "timeout", "full", "no_color", "output",
              "log_file", "operator"):
        if k in data:
            setattr(cfg, k, data[k])
    if "ports" in data:
        cfg.ports = [int(p) for p in data["ports"]]
    if isinstance(data.get("ai"), dict):
        for k, v in data["ai"].items():
            if hasattr(cfg.ai, k):
                setattr(cfg.ai, k, v)
    if isinstance(data.get("notify"), dict):
        for k, v in data["notify"].items():
            if hasattr(cfg.notify, k):
                setattr(cfg.notify, k, v)

    # Environment overrides (precedence over file for operational settings)
    if os.environ.get("NETCHECK_TARGET"):
        cfg.target = os.environ["NETCHECK_TARGET"]
    if os.environ.get("NETCHECK_OPERATOR"):
        cfg.operator = os.environ["NETCHECK_OPERATOR"]
    if os.environ.get("NETCHECK_AI_PROVIDER"):
        cfg.ai.provider = os.environ["NETCHECK_AI_PROVIDER"]
        cfg.ai.enabled = True
    if os.environ.get("NETCHECK_AI_MODEL"):
        cfg.ai.model = os.environ["NETCHECK_AI_MODEL"]
    if os.environ.get("NETCHECK_WEBHOOK_URL"):
        cfg.notify.webhook_url = os.environ["NETCHECK_WEBHOOK_URL"]

    return cfg


def get_api_key(provider: str) -> Optional[str]:
    """Read the relevant API key from the environment only."""
    return {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY"),
        "openai": os.environ.get("OPENAI_API_KEY"),
        "azure": os.environ.get("AZURE_OPENAI_API_KEY"),
        "ollama": os.environ.get("OLLAMA_API_KEY"),  # usually unset (local)
    }.get(provider)
