"""
netcheck.notify
===============
Send a notification to a generic JSON webhook. The payload also includes a
`text` field, so the same webhook URL works for Slack/Mattermost/Teams-style
incoming webhooks as well as custom endpoints.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from .core import SEVERITY


def should_notify(verdict: str, on_severity: str) -> bool:
    rank = {"HEALTHY": 0, "DEGRADED": 1, "DOWN": 2}
    threshold = {"WARN": 1, "FAIL": 2}.get(on_severity.upper(), 1)
    return rank.get(verdict, 0) >= threshold


def send_webhook(url: str, env: dict, verdict: str, findings, timeout: float = 10.0) -> dict:
    top = findings[0] if findings else None
    summary = top["title"] if top else "No findings"
    text = (f"NetCheck [{verdict}] on {env.get('hostname')} "
            f"(target {env.get('target')}): {summary}")
    payload = {
        "text": text,                       # Slack/Teams compatible
        "verdict": verdict,
        "host": env.get("hostname"),
        "target": env.get("target"),
        "operator": env.get("operator"),
        "timestamp": env.get("timestamp"),
        "top_finding": top,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"ok": 200 <= resp.status < 300, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.reason}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
