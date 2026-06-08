"""
netcheck.forensics
==================
Read-only DFIR triage collection of volatile host network state, ordered by
volatility (RFC 3227). Every artifact is hashed (SHA-256) and recorded in a
manifest with timestamps and the collecting operator, producing a tamper-
evident evidence bundle suitable for incident response.

This module ONLY reads system state (it runs read-only diagnostic commands and
never modifies the host). Run it on systems you are authorised to investigate.
Some artifacts (process owners, firewall rules) require elevated privileges;
collection degrades gracefully and records what was and wasn't obtained.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import time
from datetime import datetime, timezone

from .core import CheckResult, OK, WARN, INFO, SKIP, run_cmd, OSNAME

# Ordered most-volatile first (RFC 3227 spirit, scoped to network triage).
# Each artifact lists candidate commands; the first that runs is used.
_ARTIFACTS = {
    "Linux": [
        ("active_connections", ["ss", "-tan"], ["netstat", "-an"]),
        ("listening_sockets", ["ss", "-tulpn"], ["netstat", "-tulpn"]),
        ("arp_neighbors", ["ip", "neigh"], ["arp", "-a"]),
        ("routing_table", ["ip", "route"], ["netstat", "-rn"]),
        ("interfaces", ["ip", "addr"], ["ifconfig", "-a"]),
        ("dns_config", ["resolvectl", "status"], ["cat", "/etc/resolv.conf"]),
        ("firewall_rules", ["nft", "list", "ruleset"], ["iptables", "-L", "-n", "-v"]),
        ("process_list", ["ps", "-eo", "pid,user,comm,args"], None),
    ],
    "Darwin": [
        ("active_connections", ["netstat", "-an"], None),
        ("listening_sockets", ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], None),
        ("arp_neighbors", ["arp", "-a"], None),
        ("routing_table", ["netstat", "-rn"], None),
        ("interfaces", ["ifconfig", "-a"], None),
        ("dns_config", ["scutil", "--dns"], None),
        ("firewall_rules", ["pfctl", "-s", "rules"], None),
        ("process_list", ["ps", "-axo", "pid,user,comm"], None),
    ],
    "Windows": [
        ("active_connections", ["netstat", "-ano"], None),
        ("listening_sockets", ["netstat", "-anob"], None),
        ("arp_neighbors", ["arp", "-a"], None),
        ("routing_table", ["route", "print"], None),
        ("interfaces", ["ipconfig", "/all"], None),
        ("dns_config", ["ipconfig", "/displaydns"], None),
        ("firewall_rules", ["netsh", "advfirewall", "show", "allprofiles"], None),
        ("process_list", ["tasklist"], None),
    ],
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_evidence(output_dir: str, operator: str = "",
                     case_id: str = "", timeout: float = 20.0) -> dict:
    """Collect a read-only evidence bundle. Returns the manifest dict."""
    started = datetime.now(timezone.utc)
    bundle_name = "evidence-" + started.strftime("%Y%m%dT%H%M%SZ")
    bundle_dir = os.path.join(output_dir, bundle_name)
    art_dir = os.path.join(bundle_dir, "artifacts")
    os.makedirs(art_dir, exist_ok=True)

    try:
        operator = operator or getpass.getuser()
    except Exception:
        operator = operator or "unknown"

    manifest = {
        "tool": "NetCheck",
        "schema": "netcheck-evidence-1",
        "case_id": case_id,
        "operator": operator,
        "collected_at_utc": started.isoformat(),
        "host": {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "is_admin": _is_admin(),
        },
        "artifacts": [],
    }

    specs = _ARTIFACTS.get(OSNAME, _ARTIFACTS["Linux"])
    for entry in specs:
        artname, primary, fallback = entry
        rc, out = run_cmd(primary, timeout=timeout)
        used = primary
        if rc in (124, 127) and fallback:
            rc, out = run_cmd(fallback, timeout=timeout)
            used = fallback
        content = out.encode("utf-8", "replace")
        fname = f"{artname}.txt"
        with open(os.path.join(art_dir, fname), "wb") as fh:
            fh.write(content)
        manifest["artifacts"].append({
            "name": artname,
            "file": f"artifacts/{fname}",
            "command": " ".join(used),
            "returncode": rc,
            "bytes": len(content),
            "sha256": _sha256(content),
            "collected_at_utc": datetime.now(timezone.utc).isoformat(),
            "note": ("command unavailable" if rc == 127 else
                     "timed out" if rc == 124 else
                     "may be incomplete without elevated privileges"
                     if (artname in ("listening_sockets", "firewall_rules") and not manifest["host"]["is_admin"])
                     else ""),
        })

    # Tamper-evident: hash over the per-artifact hashes + metadata.
    digest_material = json.dumps(
        [(a["name"], a["sha256"], a["bytes"]) for a in manifest["artifacts"]],
        sort_keys=True).encode("utf-8")
    manifest["bundle_sha256"] = _sha256(digest_material)
    manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()

    with open(os.path.join(bundle_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    manifest["_bundle_dir"] = bundle_dir
    return manifest


def _is_admin() -> bool:
    try:
        if OSNAME == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def evidence_results(manifest: dict):
    """Turn a manifest into CheckResult rows for the dashboard."""
    results = []
    for a in manifest.get("artifacts", []):
        if a["returncode"] == 127:
            results.append(CheckResult(f"collect: {a['name']}", SKIP,
                                       "tool unavailable on host", a, category="forensic"))
        elif a["returncode"] == 124:
            results.append(CheckResult(f"collect: {a['name']}", WARN,
                                       "collection timed out", a, category="forensic"))
        else:
            note = f"  ({a['note']})" if a["note"] else ""
            results.append(CheckResult(
                f"collect: {a['name']}", OK,
                f"{a['bytes']}B  sha256:{a['sha256'][:12]}…{note}", a, category="forensic"))
    return results


def verify_bundle(bundle_dir: str) -> dict:
    """Re-hash a previously collected bundle and confirm integrity."""
    mpath = os.path.join(bundle_dir, "manifest.json")
    with open(mpath, encoding="utf-8") as fh:
        manifest = json.load(fh)
    results = {"ok": True, "artifacts": [], "bundle_match": False}
    for a in manifest.get("artifacts", []):
        fpath = os.path.join(bundle_dir, a["file"])
        try:
            with open(fpath, "rb") as fh:
                actual = _sha256(fh.read())
        except FileNotFoundError:
            results["ok"] = False
            results["artifacts"].append({"name": a["name"], "status": "MISSING"})
            continue
        match = actual == a["sha256"]
        results["ok"] = results["ok"] and match
        results["artifacts"].append({"name": a["name"],
                                     "status": "OK" if match else "TAMPERED"})
    material = json.dumps(
        [(a["name"], a["sha256"], a["bytes"]) for a in manifest["artifacts"]],
        sort_keys=True).encode("utf-8")
    results["bundle_match"] = (_sha256(material) == manifest.get("bundle_sha256"))
    results["ok"] = results["ok"] and results["bundle_match"]
    return results
