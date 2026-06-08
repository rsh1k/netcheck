# NetCheck

**Enterprise network triage, security posture, and incident-response/forensics in one command — with optional AI analysis.**

NetCheck runs the full network-troubleshooting workflow (interface → gateway → internet → DNS → ports → HTTP/captive-portal → TLS → quality, plus optional traceroute/MTU/IPv6), then **diagnoses the root cause** instead of just dumping raw output. On top of that it adds a defensive **security-posture assessment**, read-only **DFIR evidence collection**, and an **incident-response snapshot** mode — each of which can be enriched with **AI analysis** from Claude, OpenAI, Azure OpenAI, or a fully-local Ollama model.

- **Zero runtime dependencies.** Pure Python standard library — including the AI calls (raw `urllib`, no vendor SDKs). Nothing to vet, nothing to pin, runs in locked-down and air-gapped environments.
- **Environment-aware.** Detects WSL2, VirtualBox, VMware, KVM/QEMU, Hyper-V, Xen, containers, and cloud VMs, and interprets results accordingly — so normal NAT/virtualized behaviour (like a gateway that ignores ICMP) is no longer misreported as an outage.
- **Cloud & enterprise topology.** Detects AWS/GCP/Azure instances, serverless/PaaS (Lambda, Cloud Run, App Engine, Azure Functions/App Service), Kubernetes, and Heroku (NIST SP 800-145 service models); flags risky IMDSv1 exposure; fingerprints WAF/CDN edge protection; audits SSH algorithm hygiene; and infers DMZ/bastion/multi-homed roles. Security findings are mapped to **NIST** publications.
- **Cross-platform.** Linux, macOS, Windows. Python 3.8+.
- **Fast.** Probes run in parallel; a full triage completes in a few seconds.
- **Automation-friendly.** JSON output, JSON-lines audit log, webhook alerts, and meaningful exit codes.

---

## Environment awareness

The most common cause of bogus network diagnostics is a tool that doesn't know it's running inside a VM or NAT. NetCheck detects its platform first (via `systemd-detect-virt`, DMI vendor strings, WSL kernel markers, container markers, and MAC OUIs) and adjusts its reasoning:

- **Gateway checks don't rely on ICMP alone.** WSL2's gateway, VirtualBox's `10.0.2.2`, and many hardened/virtual routers silently drop ping. NetCheck falls back to the ARP/neighbour table and a TCP probe, and if the internet is reachable it concludes the gateway is forwarding — reporting *informational*, not a failure.
- **NAT topology.** It compares your local address to your public egress IP to classify standard NAT, recognised hypervisor NAT (VirtualBox/WSL2), or **carrier-grade NAT** (`100.64.0.0/10`, which breaks inbound/port-forwarding).
- **Proxy & VPN.** Detects `http(s)_proxy` environment proxies (which can re-sign TLS and explain odd certificate issuers) and active VPN/tunnel interfaces (which affect routing, DNS, and MTU).
- **Captive-portal sanity.** In a VM/NAT where the connectivity probes are rewritten by the virtual network layer, NetCheck recognises that and won't cry "captive portal" when the internet plainly works.

The result: running `netcheck` inside WSL2, VirtualBox, VMware, or a container gives the *real* diagnosis instead of a false "gateway down."

---

## Cloud & enterprise environments

NetCheck understands modern deployment topologies, not just laptops and servers:

- **Cloud instance & service model.** Detects AWS EC2/ECS/Fargate/Lambda, GCP GCE/Cloud Run/App Engine/Functions, Azure VM/App Service/Functions/Container Apps, Kubernetes, and Heroku — classified by **NIST SP 800-145** service model (IaaS / PaaS / SaaS / FaaS / CaaS). Detection uses serverless environment markers and the host's own instance-metadata service (link-local `169.254.169.254`), read-only.
- **IMDS posture (SSRF).** On AWS, flags whether **IMDSv1** is reachable without a token — the classic metadata credential-theft vector — and recommends enforcing IMDSv2. Maps to NIST SP 800-53 SC-7 / AC-6.
- **WAF / CDN fingerprint.** Passively identifies edge protection in front of a target (Cloudflare, Akamai, Imperva, AWS CloudFront/WAF, Azure Front Door, Fastly, F5 BIG-IP, Citrix, Sucuri, ModSecurity, …) from response headers and cookies.
- **SSH algorithm hygiene.** Performs a read-only SSH version-exchange + KEXINIT handshake (no authentication) and flags weak key-exchange, host-key, cipher, and MAC algorithms (e.g. `diffie-hellman-group1-sha1`, `ssh-rsa`, `*-cbc`, `hmac-sha1`). Aligns with NISTIR 7966 and NIST SP 800-52 Rev. 2.
- **Network role inference.** Flags multi-homed hosts (possible DMZ / bastion / router / gateway), VPN/tunnel endpoints, and cloud service roles.
- **Bastion / DMZ / VPN / SSH paths.** Tunnel-interface and proxy detection, plus the gateway/NAT logic above, make diagnosis correct when traffic traverses jump hosts, VPNs, and segmented networks.

### NIST alignment

Security findings are tagged with the relevant NIST publication and surfaced in the report's **NIST mapping** line, so a `netcheck security` or `netcheck incident` run doubles as lightweight compliance evidence:

| Area | NIST reference |
|---|---|
| TLS / cipher / certificate | SP 800-52 Rev. 2 |
| Security headers | SP 800-53 SC-8 / OWASP |
| Exposed services, segmentation, DMZ | SP 800-41 Rev. 1, SP 800-207 (Zero Trust) |
| SSH hygiene | NISTIR 7966, SP 800-52 Rev. 2 |
| Cloud IMDS / boundary protection | SP 800-53 SC-7, AC-6 |
| Cloud service models | SP 800-145 |
| Containers | SP 800-190 |

NetCheck is an assessment aid, not a certification; it helps you spot gaps that map to these controls.

---

## Why it exists

Most "network test" tools answer *what* (ping failed) but not *why*. NetCheck encodes the logic an experienced engineer applies — if the gateway is unreachable, that's the root cause and the ISP doesn't matter; if the internet works by IP but your resolver doesn't answer, your DNS is broken, not the internet; if small packets pass but 1500-byte packets don't, you have an MTU black hole — and states the cause and the fix in plain language. The optional AI layer then adds expert narrative on top of those structured findings.

---

## Install

```bash
# from source
git clone https://github.com/your-username/netcheck.git
cd netcheck
pip install .

# or run without installing
python3 -m netcheck
```

TOML config files need Python 3.11+ (or `pip install netcheck-cli[toml]`); JSON config works on any version. Nothing else is required.

---

## Quick start

```bash
netcheck                       # full network triage + root-cause diagnosis
netcheck -t api.example.com    # triage against a specific host
netcheck --full                # add traceroute, MTU black-hole, IPv6 checks
netcheck security -t example.com   # defensive security-posture assessment
netcheck incident -t example.com   # diagnostics + security + host forensics
netcheck collect --evidence-dir ./ev   # read-only forensic evidence bundle
netcheck verify ./ev/evidence-...      # verify an evidence bundle's integrity
```

Add `--ai` to any run to layer on AI analysis (see below), `-o report.md` to save a report, and `--json` for machine-readable output.

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
- **WAF / CDN fingerprint** — identifies edge protection in front of the target.
- **SSH algorithm audit** — read-only handshake flagging weak KEX/host-key/cipher/MAC algorithms (no authentication attempted).
- **Cloud IMDS posture** — flags AWS IMDSv1 SSRF exposure on the host.

Every finding is tagged with its **NIST** reference. These are configuration/hygiene checks only — **no exploitation, no credential testing, no network scanning** beyond the single specified target. It's blue-team auditing, comparable to what a CIS benchmark or OWASP review inspects.

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
├── environment.py virtualization/NAT/proxy/VPN detection (WSL2, VBox, VMware, …)
├── cloud.py       cloud/serverless detection (AWS/GCP/Azure, IMDS, Lambda/Cloud Run)
├── checks.py      layered diagnostic checks + runner
├── security.py    posture checks (TLS/cert/headers/exposed/WAF/SSH/IMDS) + NIST tags
├── forensics.py   read-only evidence collection + integrity verification
├── diagnosis.py   environment-aware rule-based root-cause engine
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
