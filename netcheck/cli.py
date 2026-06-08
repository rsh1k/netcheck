"""
netcheck.cli
============
Command-line entry point and orchestration for all modes:
  triage    - layered network diagnostics + root-cause diagnosis (default)
  security  - defensive security-posture assessment of an authorised target
  incident  - full IR snapshot: diagnostics + security + host forensics + report
  collect   - read-only forensic evidence collection of local host state
  verify    - verify the integrity of a previously collected evidence bundle

Optional AI analysis (Claude / OpenAI / Azure / Ollama) layers expert narrative
on top of the structured findings.
"""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .core import (CheckResult, Style, supports_color, OK, WARN, FAIL, INFO, SKIP,
                   worst_severity)
from .config import (AppConfig, load_config, DEFAULT_TARGET, DEFAULT_PORTS)
from . import checks, security, forensics, report, notify, ai
from .diagnosis import diagnose


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

class Dashboard:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.style = Style(supports_color(cfg.no_color))
        self.quiet = cfg.json_only

    def header(self, env, mode):
        if self.quiet:
            return
        s = self.style
        print()
        print(s.bold(s.cyan("  NetCheck ")) + s.grey(f"v{__version__}  ·  {mode}"))
        print(s.grey("  " + "─" * 60))
        rows = [("host", env.get("hostname")), ("os", env.get("os")),
                ("platform", env.get("platform")),
                ("local IPv4", env.get("local_ip") or s.red("none")),
                ("gateway", env.get("gateway") or s.red("unknown")),
                ("configured DNS", ", ".join(env.get("dns_servers") or []) or s.red("none")),
                ("target", env.get("target"))]
        if env.get("operator"):
            rows.append(("operator", env["operator"]))
        cloud = env.get("cloud") or {}
        if cloud.get("provider"):
            cp = (env.get("cloud") or {})
            label = f"{cp.get('product', cloud['provider'])}"
            if cp.get("service_model"):
                label += f"  [{cp['service_model']}]"
            rows.insert(3, ("cloud", label))
        for k, v in rows:
            print(f"  {s.dim(k):<22} {v}")
        print(s.grey("  " + "─" * 60))
        print()

    def emit(self, r: CheckResult):
        if self.quiet:
            return
        s = self.style
        print(f"  {s.badge(r.status)}  {s.bold(r.name):<40} {r.detail}  {s.grey(f'{r.duration_ms:4.0f}ms')}")

    def section(self, title):
        if self.quiet:
            return
        print()
        print("  " + self.style.bold(self.style.cyan(title)))
        print()

    def summary(self, results, findings, mode="triage"):
        if self.quiet:
            return
        s = self.style
        sev = worst_severity(results)
        label = report.verdict_label(results, mode)
        color = {0: s.green, 1: s.yellow, 2: s.red}[sev]
        heading = {"security": "SECURITY POSTURE", "incident": "INCIDENT ASSESSMENT",
                   "collect": "COLLECTION"}.get(mode, "DIAGNOSIS")
        print()
        print(s.grey("  " + "─" * 60))
        print(f"  {s.bold(heading)}   verdict: {color(s.bold(label))}")
        print(s.grey("  " + "─" * 60))
        for i, f in enumerate(findings, 1):
            head = {OK: s.green, WARN: s.yellow, FAIL: s.red}.get(f["severity"], s.cyan)
            print()
            print(f"  {head(s.bold(f'{i}. ' + f['title']))}")
            print(f"     {s.dim('why:')} {f['cause']}")
            print(f"     {s.dim('fix:')} {s.cyan(f['fix'])}")
        print()

    def ai_block(self, ai_result):
        if self.quiet or not ai_result:
            return
        s = self.style
        print(s.grey("  " + "─" * 60))
        if ai_result.get("ok"):
            print(f"  {s.bold('AI ANALYSIS')}   {s.grey(ai_result['provider'] + ' · ' + ai_result['model'])}")
            print(s.grey("  " + "─" * 60))
            for line in ai_result["text"].splitlines():
                print("  " + line)
        else:
            print(f"  {s.bold('AI ANALYSIS')}   {s.yellow('unavailable')}")
            print(s.grey("  " + "─" * 60))
            print("  " + s.yellow(ai_result.get("error", "unknown error")))
        print()

    def note(self, msg):
        if not self.quiet:
            print(self.style.grey("  " + msg))


# --------------------------------------------------------------------------- #
# Shared post-processing (diagnosis, AI, outputs, notify, audit)
# --------------------------------------------------------------------------- #

def finalize(cfg, dash, env, results, mode):
    findings = diagnose(results, cfg.target, env)
    dash.summary(results, findings, mode)

    ai_result = None
    if cfg.ai.enabled:
        if not dash.quiet:
            dash.note(f"running AI analysis via {cfg.ai.provider} ({cfg.ai.resolved_model()})…")
        ai_result = ai.analyze(cfg.ai, env, results, findings, mode=mode)
        dash.ai_block(ai_result)

    if cfg.output:
        report.write_markdown(cfg.output, env, results, findings, ai_result, mode)
        dash.note(f"report saved → {cfg.output}")
    if cfg.log_file:
        report.append_audit_log(cfg.log_file, env, results, findings, mode)
        dash.note(f"audit entry appended → {cfg.log_file}")

    v = report.verdict(results)
    if cfg.notify.webhook_url and notify.should_notify(v, cfg.notify.on_severity):
        res = notify.send_webhook(cfg.notify.webhook_url, env, v, findings)
        dash.note("webhook sent" if res.get("ok") else f"webhook failed: {res.get('error') or res.get('status')}")

    if cfg.json or cfg.json_only:
        import json as _json
        doc = report.build_document(env, results, findings, ai_result, mode)
        print(_json.dumps(doc, indent=2, default=str))

    return findings, ai_result


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #

def mode_triage(cfg, dash):
    env = checks.gather_env(cfg)
    dash.header(env, "network triage")
    results = checks.run_diagnostics(cfg, env, emit=dash.emit)
    finalize(cfg, dash, env, results, "triage")
    return worst_severity(results)


def mode_security(cfg, dash):
    env = checks.gather_env(cfg)
    dash.header(env, "security posture")
    results = []
    dash.section("Defensive security assessment (authorised target only)")
    for r in security.run_security_assessment(cfg.target, timeout=max(cfg.timeout, 5.0)):
        r.duration_ms = 0.0
        results.append(r)
        dash.emit(r)
    imds = security.check_imds(env.get("cloud") or {})
    results.append(imds)
    dash.emit(imds)
    finalize(cfg, dash, env, results, "security")
    return worst_severity(results)


def mode_incident(cfg, dash):
    env = checks.gather_env(cfg)
    dash.header(env, "incident response snapshot")
    results = checks.run_diagnostics(cfg, env, emit=dash.emit)
    dash.section("Defensive security assessment")
    for r in security.run_security_assessment(cfg.target, timeout=max(cfg.timeout, 5.0)):
        results.append(r)
        dash.emit(r)
    imds = security.check_imds(env.get("cloud") or {})
    results.append(imds)
    dash.emit(imds)
    dash.section("Forensic evidence collection (read-only host state)")
    manifest = forensics.collect_evidence(cfg.evidence_dir, operator=cfg.operator,
                                          case_id=cfg.case_id)
    fres = forensics.evidence_results(manifest)
    results.extend(fres)
    for r in fres:
        dash.emit(r)
    dash.note(f"evidence bundle → {manifest['_bundle_dir']}  (bundle sha256 {manifest['bundle_sha256'][:16]}…)")
    finalize(cfg, dash, env, results, "incident")
    return worst_severity(results)


def mode_collect(cfg, dash):
    env = checks.gather_env(cfg)
    dash.header(env, "forensic collection")
    dash.section("Collecting read-only host network state")
    manifest = forensics.collect_evidence(cfg.evidence_dir, operator=cfg.operator,
                                          case_id=cfg.case_id)
    fres = forensics.evidence_results(manifest)
    for r in fres:
        dash.emit(r)
    dash.note(f"evidence bundle → {manifest['_bundle_dir']}")
    dash.note(f"bundle sha256: {manifest['bundle_sha256']}")
    findings = diagnose(fres, cfg.target, env)
    ai_result = None
    if cfg.ai.enabled:
        dash.note(f"running AI analysis via {cfg.ai.provider}…")
        ai_result = ai.analyze(cfg.ai, env, fres, findings, mode="incident")
        dash.ai_block(ai_result)
    if cfg.json or cfg.json_only:
        import json as _json
        print(_json.dumps(manifest, indent=2, default=str))
    return 0


def mode_verify(cfg, dash, bundle_path):
    res = forensics.verify_bundle(bundle_path)
    s = dash.style
    print()
    status = s.green("INTACT") if res["ok"] else s.red("INTEGRITY FAILURE")
    print(f"  Bundle verification: {s.bold(status)}")
    for a in res["artifacts"]:
        mark = s.green("✓") if a["status"] == "OK" else s.red("✗")
        print(f"    {mark} {a['name']:<24} {a['status']}")
    print(f"  bundle hash match: {'yes' if res['bundle_match'] else s.red('NO')}")
    print()
    return 0 if res["ok"] else 2


def mode_ai_test(cfg, dash):
    """Validate AI provider connectivity with a trivial request."""
    sample = [CheckResult("connectivity self-test", OK, "this is a NetCheck AI connectivity test")]
    env = {"os": "test", "target": "test", "timestamp": "test", "hostname": "test"}
    dash.note(f"testing AI provider '{cfg.ai.provider}' (model {cfg.ai.resolved_model()})…")
    res = ai.analyze(cfg.ai, env, sample, [], mode="triage")
    if res["ok"]:
        print(dash.style.green(f"  AI OK — {res['provider']}/{res['model']} responded "
                               f"({len(res['text'])} chars)"))
        return 0
    print(dash.style.red(f"  AI FAILED — {res['error']}"))
    return 1


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def parse_ports(value):
    out = [int(c) for c in value.replace(" ", "").split(",") if c.isdigit()]
    return out or list(DEFAULT_PORTS)


def build_parser():
    p = argparse.ArgumentParser(
        prog="netcheck",
        description="Enterprise network triage, security posture, and IR/forensics — with optional AI analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""modes:
  netcheck                      network triage (default)
  netcheck security             defensive security posture of --target
  netcheck incident             full IR snapshot (diagnostics+security+forensics)
  netcheck collect              read-only forensic evidence collection
  netcheck verify <bundle-dir>  verify an evidence bundle's integrity

AI analysis (opt-in):
  netcheck --ai                              use the configured/Ollama provider
  netcheck --ai --ai-provider anthropic      use Claude (needs ANTHROPIC_API_KEY)
  netcheck --ai --ai-provider openai         use OpenAI (needs OPENAI_API_KEY)
  netcheck --ai --ai-provider ollama         fully local, no data egress
  netcheck --ai-test --ai-provider ollama    validate provider connectivity

Responsible use: only run security/forensic checks on hosts and systems you own
or are explicitly authorised to assess. Defaults touch only public infrastructure.
""")
    p.add_argument("mode", nargs="?", default="triage",
                   choices=["triage", "security", "incident", "collect", "verify"],
                   help="operation mode (default: triage)")
    p.add_argument("bundle", nargs="?", help="evidence bundle dir (for 'verify')")

    p.add_argument("-t", "--target", help=f"host for port/HTTP/TLS/security checks (default: {DEFAULT_TARGET})")
    p.add_argument("-p", "--ports", type=parse_ports, help="comma-separated ports (default: 80,443,22,53)")
    p.add_argument("--timeout", type=float, help="per-connection timeout seconds (default: 3)")
    p.add_argument("--full", action="store_true", help="run deep checks (traceroute, MTU, IPv6)")
    p.add_argument("-o", "--output", metavar="FILE", help="write a Markdown report")
    p.add_argument("--json", action="store_true", help="also print full JSON")
    p.add_argument("--json-only", action="store_true", help="JSON only, suppress dashboard")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--config", metavar="FILE", help="config file (TOML/JSON)")
    p.add_argument("--operator", help="operator name (audit/IR reports)")
    p.add_argument("--log-file", metavar="FILE", help="append a JSON-lines audit record")
    p.add_argument("--evidence-dir", default=".", help="output dir for evidence bundles (default: .)")
    p.add_argument("--case-id", default="", help="incident/case identifier for forensics")
    p.add_argument("--webhook", metavar="URL", help="notify this webhook on DEGRADED/DOWN")

    g = p.add_argument_group("AI analysis")
    g.add_argument("--ai", action="store_true", help="enable AI analysis of results")
    g.add_argument("--ai-test", action="store_true", help="test AI provider connectivity and exit")
    g.add_argument("--ai-provider", choices=ai.list_providers(), help="anthropic | openai | azure | ollama")
    g.add_argument("--ai-model", help="model/deployment name override")
    g.add_argument("--ai-base-url", help="endpoint override (self-hosted / proxy / compat)")
    g.add_argument("--no-redact", action="store_true", help="do NOT redact internal IPs/host before cloud AI")

    p.add_argument("--version", action="version", version=f"NetCheck {__version__}")
    return p


def apply_args(cfg: AppConfig, args) -> AppConfig:
    if args.target is not None:
        cfg.target = args.target
    if args.ports is not None:
        cfg.ports = args.ports
    if args.timeout is not None:
        cfg.timeout = args.timeout
    if args.full:
        cfg.full = True
    if args.output:
        cfg.output = args.output
    if args.json:
        cfg.json = True
    if args.json_only:
        cfg.json = True
        cfg.json_only = True
    if args.no_color:
        cfg.no_color = True
    if args.operator:
        cfg.operator = args.operator
    if args.log_file:
        cfg.log_file = args.log_file
    if args.webhook:
        cfg.notify.webhook_url = args.webhook
    # AI
    if args.ai or args.ai_test or args.ai_provider:
        cfg.ai.enabled = True
    if args.ai_provider:
        cfg.ai.provider = args.ai_provider
    if args.ai_model:
        cfg.ai.model = args.ai_model
    if args.ai_base_url:
        cfg.ai.base_url = args.ai_base_url
    if args.no_redact:
        cfg.ai.redact = False
    # extra dynamic attrs used by forensic/incident modes
    cfg.evidence_dir = args.evidence_dir
    cfg.case_id = args.case_id
    # expose .json attribute name used in finalize
    cfg.json = getattr(cfg, "json", False) or args.json or args.json_only
    return cfg


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    cfg = apply_args(cfg, args)
    dash = Dashboard(cfg)

    try:
        if args.ai_test:
            return mode_ai_test(cfg, dash)
        if args.mode == "verify":
            if not args.bundle:
                print("error: 'verify' requires a bundle directory path", file=sys.stderr)
                return 2
            return mode_verify(cfg, dash, args.bundle)
        if args.mode == "security":
            return mode_security(cfg, dash)
        if args.mode == "incident":
            return mode_incident(cfg, dash)
        if args.mode == "collect":
            return mode_collect(cfg, dash)
        return mode_triage(cfg, dash)
    except KeyboardInterrupt:
        print("\n  interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
