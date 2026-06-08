# NetCheck

**Enterprise network triage, security posture, and incident-response/forensics in one command — with optional AI analysis.**

NetCheck runs the full network-troubleshooting workflow (interface → gateway → internet → DNS → ports → HTTP/captive-portal → TLS → quality, plus optional traceroute/MTU/IPv6), then **diagnoses the root cause** instead of just dumping raw output. On top of that it adds a defensive **security-posture assessment**, read-only **DFIR evidence collection**, and an **incident-response snapshot** mode — each of which can be enriched with **AI analysis** from Claude, OpenAI, Azure OpenAI, or a fully-local Ollama model.

- **Zero runtime dependencies.** Pure Python standard library — including the AI calls (raw `urllib`, no vendor SDKs). Nothing to vet, nothing to pin, runs in locked-down and air-gapped environments.
- **Cross-platform.** Linux, macOS, Windows. Python 3.8+.
- **Fast.** Probes run in parallel; a full triage completes in a few seconds.
- **Automation-friendly.** JSON output, JSON-lines audit log, webhook alerts, and meaningful exit codes.

---

## Why it exists

Most "network test" tools answer *what* (ping failed) but not *why*. NetCheck encodes the logic an experienced engineer applies — if the gateway is unreachable, that's the root cause and the ISP doesn't matter; if the internet works by IP but your resolver doesn't answer, your DNS is broken, not the internet; if small packets pass but 1500-byte packets don't, you have an MTU black hole — and states the cause and the fix in plain language. The optional AI layer then adds expert narrative on top of those structured findings.

---
## Install

```bash
pip install netcheck-ir
```

For a command-line tool, `pipx` is cleaner — it installs into an isolated
environment but still puts `netcheck` on your PATH:

```bash
pipx install netcheck-ir
```

No dependencies are pulled in — NetCheck is pure standard library. (TOML config
files need Python 3.11+, or `pip install netcheck-ir[toml]`; JSON config works
on any version.)

<details>
<summary>From source (for development)</summary>

```bash
git clone https://github.com/rsh1k/netcheck.git
cd netcheck
pip install -e .
python3 -m unittest discover -s tests   # run the test suite
```
</details>

## Quick start

```bash
netcheck                            # full network triage + root-cause diagnosis
netcheck -t api.example.com         # triage a specific host
netcheck security -t example.com    # defensive security-posture assessment
netcheck incident -t example.com    # diagnostics + security + host forensics
netcheck collect --evidence-dir ./ev   # read-only forensic evidence bundle
netcheck --ai --ai-provider ollama  # add local AI analysis (no data leaves)
```
---

## Modes

| Mode | What it does |
|---|---|
| `triage` *(default)* | Layered connectivity diagnostics + rule-based root-cause diagnosis. |
| `security` | Defensive posture review of an authorised target: TLS-version audit, weak-cipher check, certificate hygiene, OWASP security headers, exposed risky/management ports. |
| `incident` | Full IR snapshot: diagnostics **+** security assessment **+** read-only host forensics, written to one report with an evidence bundle. |
| `collect` | Read-only DFIR collection of volatile host network state (connections, listeners, ARP, routes, interfaces, DNS, firewall) into a hashed, manifested evidence bundle. |
| `verify <bundle>` | Re-hashes a previously collected bundle and confirms it hasn't been tampered with. |

---

## AI-powered analysis

NetCheck can send its **structured** results to an LLM and get back a prioritised root-cause analysis and concrete remediation steps. Four providers are supported; pick based on your environment.

| Provider | Flag | API key (env var) | Notes |
|---|---|---|---|
| **Claude** (Anthropic) | `--ai-provider anthropic` | `ANTHROPIC_API_KEY` | Default model `claude-sonnet-4-6` (use `claude-opus-4-8` for deepest analysis). |
| **OpenAI / ChatGPT** | `--ai-provider openai` | `OPENAI_API_KEY` | Default `gpt-5.4-mini`. Works with any OpenAI-compatible server via `--ai-base-url`. |
| **Azure OpenAI** | `--ai-provider azure` | `AZURE_OPENAI_API_KEY` | Set `--ai-base-url https://<resource>.openai.azure.com` and `--ai-model <deployment>`. |
| **Ollama** (local) | `--ai-provider ollama` | *(none)* | Fully local / on-prem. **No data leaves the machine.** Default model `llama3.1`. |

```bash
# Validate provider connectivity first (great for setup / CI):
netcheck --ai-test --ai-provider ollama

# Claude-powered triage:
export ANTHROPIC_API_KEY=sk-ant-...
netcheck --ai --ai-provider anthropic

# Fully local analysis, nothing leaves the host:
netcheck --ai --ai-provider ollama --ai-model llama3.1

# AI-assisted security review:
netcheck security -t example.com --ai --ai-provider openai
```

**Privacy by design.** API keys are read **only** from environment variables — never from the config file, never logged. Before any request to a *cloud* provider, NetCheck redacts internal IPs, MAC addresses, and the local hostname (public IPs are kept so analysis stays useful). Use `--no-redact` to disable, or use **Ollama** for zero data egress. The prompts never include the host's internal addressing in the first place beyond what the checks surface, and redaction is applied on top of that.

---

## Security posture assessment

`netcheck security -t <host>` performs a **defensive, read-only** review of a host you **own or are explicitly authorised to assess**:

- **TLS protocol audit** — flags deprecated TLS 1.0/1.1 support; confirms modern TLS 1.2/1.3 and reports the negotiated cipher (weak ciphers raised as warnings).
- **Certificate hygiene** — validity, expiry window (warns < 30 days, fails < 15), issuer, hostname match, self-signed detection.
- **HTTP security headers** — checks for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy (per OWASP Secure Headers).
- **Exposed services** — reports reachable risky/management/database ports (Telnet, SMB, RDP, MySQL, Redis, MongoDB, …).

These are configuration/hygiene checks only — **no exploitation, no credential testing, no network scanning** beyond the single specified target. It's blue-team auditing, comparable to what a CIS benchmark or OWASP review inspects.

---

## Forensics & incident response

`netcheck collect` performs **read-only** DFIR triage collection of volatile host network state, ordered by volatility (RFC 3227 spirit): active connections, listening sockets, ARP/neighbour table, routing table, interfaces, DNS configuration, firewall rules, and the process list. It **never modifies the host**.

Every artifact is hashed (SHA-256) and recorded in a `manifest.json` with timestamps, the collecting operator, an optional case ID, and a bundle-level integrity hash — a tamper-evident evidence bundle:

```bash
netcheck collect --evidence-dir ./evidence --operator analyst1 --case-id IR-2026-007
netcheck verify ./evidence/evidence-20260608T063439Z   # confirm integrity later
```

`netcheck incident` chains diagnostics + security + forensics into a single timestamped IR report with its evidence bundle, and (with `--ai`) an AI-generated incident analysis following standard IR phases (scope → severity → containment → eradication/recovery → further evidence to collect).

Collection degrades gracefully: tools that need elevated privileges or aren't installed are skipped and noted in the manifest rather than failing the run.

---

## Configuration

Settings resolve in order: **CLI flags → environment variables → config file → defaults.** Copy `netcheck.example.toml` to `netcheck.toml` (or use JSON). The config file is **safe to commit** — secrets never live in it.

```toml
target = "cloudflare.com"
ports = [80, 443, 22, 53]
operator = "netops"
log_file = "/var/log/netcheck/audit.jsonl"

[ai]
enabled = false
provider = "ollama"
redact = true

[notify]
webhook_url = ""
on_severity = "WARN"
```

Useful environment variables: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `OLLAMA_HOST`, `NETCHECK_TARGET`, `NETCHECK_AI_PROVIDER`, `NETCHECK_WEBHOOK_URL`, `NETCHECK_OPERATOR`.

---

## Output, alerting & automation

- **Markdown report:** `-o report.md` — grouped by Diagnostic / Security / Forensic, with the diagnosis and any AI analysis.
- **JSON:** `--json` (alongside the dashboard) or `--json-only` (pipe-friendly) — stable schema `netcheck-report-2`.
- **Audit log:** `--log-file audit.jsonl` appends one JSON object per run (verdict, per-check status, top finding) — ready for SIEM ingestion.
- **Webhook alerts:** `--webhook <url>` posts a Slack/Teams/Mattermost-compatible JSON payload when the verdict reaches the configured severity.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | HEALTHY — all checks passed (or bundle INTACT). |
| `1` | DEGRADED — at least one warning. |
| `2` | DOWN — at least one failure (or bundle INTEGRITY FAILURE). |

These make NetCheck easy to wire into cron, CI, monitoring, or runbooks.

---

## Responsible use

NetCheck's defaults touch only public infrastructure (Cloudflare/Google anycast resolvers, the configured target). The `security` and `collect`/`incident` modes are for systems you **own or are explicitly authorised to assess**. NetCheck performs read-only assessment and collection only — it does not exploit, scan networks, or test credentials.

---

## Architecture

```
netcheck/
├── core.py        status model + low-level primitives (ping, TCP, DNS, HTTP, TLS)
├── checks.py      layered diagnostic checks + runner
├── security.py    defensive posture checks (TLS/cert/headers/exposed services)
├── forensics.py   read-only evidence collection + integrity verification
├── diagnosis.py   rule-based root-cause engine
├── ai.py          provider abstraction (Claude/OpenAI/Azure/Ollama) + redaction
├── config.py      config + secret handling
├── report.py      Markdown / JSON / audit-log renderers
├── notify.py      webhook notifier
└── cli.py         orchestration + live dashboard
```

The rule-based engine runs locally and instantly; the AI layer is strictly additive and optional. No third-party packages at runtime.

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```

The suite (stdlib `unittest`, no extra deps) covers the status model, DNS packet parse, TCP connectivity, **all four AI providers via local mock servers** (including a test that the internal-IP redaction actually happens before data leaves for cloud providers), the diagnosis rules, forensic collection + tamper detection, config loading, and report generation. Live TLS/certificate checks run against real infrastructure and skip automatically when offline.

---

## License

MIT — see [LICENSE](LICENSE).
