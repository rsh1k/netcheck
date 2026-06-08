"""
NetCheck test suite (stdlib unittest - no external deps).

Run:  python3 -m unittest -v
      python3 -m unittest discover -s tests

Covers: status model, DNS packet parse, TCP connect, AI provider plumbing for
all four providers (via local mock servers), cloud redaction-in-flight,
diagnosis rules, forensic collection + integrity verification, config loading,
report generation, and live security checks (skipped if offline).
"""

import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netcheck import core, config, ai, diagnosis, forensics, report, security, notify
from netcheck import environment as envmod
from netcheck import cloud
from netcheck import checks
from netcheck.core import CheckResult, OK, WARN, FAIL, INFO, SKIP
from unittest import mock


# --------------------------------------------------------------------------- #
# Helpers: a mock LLM HTTP server that mimics all four provider wire formats
# --------------------------------------------------------------------------- #

class _MockLLMHandler(BaseHTTPRequestHandler):
    captured = []  # (path, parsed_body)

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}
        _MockLLMHandler.captured.append((self.path, body, dict(self.headers)))

        path = self.path
        if "/v1/messages" in path:                       # Anthropic
            payload = {"content": [{"type": "text", "text": "ANTHROPIC_OK"}]}
        elif "/api/chat" in path:                        # Ollama
            payload = {"message": {"role": "assistant", "content": "OLLAMA_OK"}}
        elif "/chat/completions" in path:                # OpenAI + Azure
            tag = "AZURE_OK" if "/openai/deployments/" in path else "OPENAI_OK"
            payload = {"choices": [{"message": {"content": tag}}]}
        else:
            payload = {"error": "unknown path"}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class MockServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockLLMHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        _MockLLMHandler.captured = []
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"


# --------------------------------------------------------------------------- #
# Status model
# --------------------------------------------------------------------------- #

class TestModel(unittest.TestCase):
    def test_check_result_dict(self):
        r = CheckResult("x", OK, "fine", {"a": 1})
        d = r.to_dict()
        self.assertEqual(d["status"], OK)
        self.assertEqual(d["category"], "diagnostic")
        self.assertEqual(d["data"]["a"], 1)

    def test_worst_severity_and_verdict(self):
        rs = [CheckResult("a", OK), CheckResult("b", WARN), CheckResult("c", OK)]
        self.assertEqual(core.worst_severity(rs), 1)
        self.assertEqual(report.verdict(rs), "DEGRADED")
        rs.append(CheckResult("d", FAIL))
        self.assertEqual(report.verdict(rs), "DOWN")
        self.assertEqual(report.verdict([CheckResult("a", OK)]), "HEALTHY")


# --------------------------------------------------------------------------- #
# DNS packet building/parsing
# --------------------------------------------------------------------------- #

class TestDNS(unittest.TestCase):
    def test_build_and_parse_roundtrip(self):
        # Build a response packet by hand: 1 question + 1 A answer = 93.184.216.34
        txid = 0x1234
        q = core.build_dns_query("example.com", txid)
        # turn the query into a response: set QR bit, ancount=1, append answer
        header = q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        question = q[12:]
        answer = (b"\xc0\x0c"            # pointer to qname
                  b"\x00\x01\x00\x01"    # type A, class IN
                  b"\x00\x00\x00\x3c"    # ttl 60
                  b"\x00\x04"            # rdlength 4
                  + bytes([93, 184, 216, 34]))
        packet = header + question + answer
        ips = core.parse_dns_answers(packet)
        self.assertEqual(ips, ["93.184.216.34"])

    def test_is_private_or_bogus(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "0.0.0.0"):
            self.assertTrue(core.is_private_or_bogus(ip), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            self.assertFalse(core.is_private_or_bogus(ip), ip)


# --------------------------------------------------------------------------- #
# TCP connect against a real local listener
# --------------------------------------------------------------------------- #

class TestTCP(unittest.TestCase):
    def test_open_and_closed(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            ok, lat, err = core.tcp_connect("127.0.0.1", port, timeout=2)
            self.assertTrue(ok, err)
            self.assertIsNotNone(lat)
        finally:
            srv.close()
        # now closed
        ok, lat, err = core.tcp_connect("127.0.0.1", port, timeout=1)
        self.assertFalse(ok)


# --------------------------------------------------------------------------- #
# AI: redaction + all four providers via mock server
# --------------------------------------------------------------------------- #

class TestRedaction(unittest.TestCase):
    def test_redact_internal_only(self):
        t = "gw 192.168.1.1 mac 00:11:22:33:44:55 host BOX01 public 8.8.8.8"
        out = ai.redact(t, "BOX01")
        self.assertIn("[REDACTED-INTERNAL-IP]", out)
        self.assertIn("[REDACTED-MAC]", out)
        self.assertIn("[REDACTED-HOST]", out)
        self.assertIn("8.8.8.8", out)          # public IP preserved
        self.assertNotIn("192.168.1.1", out)


class TestAIProviders(unittest.TestCase):
    def setUp(self):
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        os.environ["OPENAI_API_KEY"] = "test-key"
        os.environ["AZURE_OPENAI_API_KEY"] = "test-key"
        self.env = {"os": "TestOS", "target": "t", "timestamp": "now", "hostname": "BOX01"}
        self.results = [CheckResult("Gateway reachability", FAIL,
                                    "Cannot reach gateway 192.168.1.1", {"gateway": "192.168.1.1"})]

    def _cfg(self, provider, base, **kw):
        c = config.AIConfig(enabled=True, provider=provider, base_url=base, **kw)
        return c

    def test_anthropic(self):
        with MockServer() as s:
            out = ai.analyze(self._cfg("anthropic", s.base), self.env, self.results, [], "triage")
        self.assertTrue(out["ok"], out["error"])
        self.assertEqual(out["text"], "ANTHROPIC_OK")

    def test_openai(self):
        with MockServer() as s:
            out = ai.analyze(self._cfg("openai", s.base + "/v1"), self.env, self.results, [], "triage")
        self.assertTrue(out["ok"], out["error"])
        self.assertEqual(out["text"], "OPENAI_OK")

    def test_ollama(self):
        with MockServer() as s:
            out = ai.analyze(self._cfg("ollama", s.base), self.env, self.results, [], "triage")
        self.assertTrue(out["ok"], out["error"])
        self.assertEqual(out["text"], "OLLAMA_OK")

    def test_azure(self):
        with MockServer() as s:
            out = ai.analyze(self._cfg("azure", s.base, deployment="mydeploy"),
                             self.env, self.results, [], "security")
        self.assertTrue(out["ok"], out["error"])
        self.assertEqual(out["text"], "AZURE_OK")

    def test_cloud_redaction_in_flight(self):
        """The internal IP must be redacted in the body the cloud server receives."""
        with MockServer() as s:
            ai.analyze(self._cfg("anthropic", s.base, redact=True),
                       self.env, self.results, [], "triage")
            path, body, headers = _MockLLMHandler.captured[-1]
        sent = json.dumps(body)
        self.assertIn("[REDACTED-INTERNAL-IP]", sent)
        self.assertNotIn("192.168.1.1", sent)
        # anthropic auth header present
        self.assertIn("x-api-key", {k.lower() for k in headers})

    def test_local_no_redaction(self):
        """Ollama (local) should NOT redact - keeps full fidelity on-prem."""
        with MockServer() as s:
            ai.analyze(self._cfg("ollama", s.base, redact=True),
                       self.env, self.results, [], "triage")
            path, body, headers = _MockLLMHandler.captured[-1]
        self.assertIn("192.168.1.1", json.dumps(body))

    def test_unknown_provider(self):
        out = ai.analyze(self._cfg("nope", ""), self.env, self.results, [], "triage")
        self.assertFalse(out["ok"])
        self.assertIn("unknown provider", out["error"])

    def test_missing_key(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        out = ai.analyze(self._cfg("anthropic", ""), self.env, self.results, [], "triage")
        self.assertFalse(out["ok"])
        self.assertIn("ANTHROPIC_API_KEY", out["error"])
        os.environ["ANTHROPIC_API_KEY"] = "test-key"


# --------------------------------------------------------------------------- #
# Diagnosis rule engine
# --------------------------------------------------------------------------- #

class TestDiagnosis(unittest.TestCase):
    def test_gateway_down_is_root_cause(self):
        rs = [
            CheckResult("Local interface", OK, "", {"has_ip": True}),
            CheckResult("Gateway reachability", FAIL, "", {"gateway": "192.168.1.1"}),
            CheckResult("Internet (by IP)", FAIL, "", {"reachable": False}),
        ]
        f = diagnosis.diagnose(rs, "cloudflare.com")
        self.assertTrue(f[0]["title"].lower().startswith("cannot reach your router"))

    def test_dns_broken_internet_ok(self):
        rs = [
            CheckResult("Local interface", OK, "", {"has_ip": True}),
            CheckResult("Gateway reachability", OK, "", {"gateway": "192.168.1.1"}),
            CheckResult("Internet (by IP)", OK, "", {"reachable": True}),
            CheckResult("DNS resolution", FAIL, "",
                        {"system_ok": False, "public_ok_count": 2}),
        ]
        f = diagnosis.diagnose(rs, "cloudflare.com")
        self.assertTrue(any("DNS" in x["title"] for x in f))

    def test_apipa_dhcp(self):
        rs = [CheckResult("Local interface", FAIL, "", {"has_ip": True, "apipa": True})]
        f = diagnosis.diagnose(rs, "x")
        self.assertEqual(f[0]["title"], "DHCP failure")

    def test_healthy(self):
        rs = [CheckResult("Local interface", OK), CheckResult("Internet (by IP)", OK)]
        f = diagnosis.diagnose(rs, "x")
        self.assertEqual(f[0]["severity"], OK)

    def test_security_findings_passthrough(self):
        rs = [
            CheckResult("Local interface", OK),
            CheckResult("TLS protocol audit → h", FAIL, "accepts TLS 1.0",
                        category="security"),
        ]
        f = diagnosis.diagnose(rs, "h")
        self.assertTrue(any(x["title"].startswith("Security:") for x in f))


# --------------------------------------------------------------------------- #
# Forensics: collection + integrity verification + tamper detection
# --------------------------------------------------------------------------- #

class TestForensics(unittest.TestCase):
    def test_collect_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = forensics.collect_evidence(d, operator="tester", case_id="CASE-1")
            self.assertEqual(manifest["case_id"], "CASE-1")
            self.assertTrue(manifest["artifacts"])
            for a in manifest["artifacts"]:
                self.assertEqual(len(a["sha256"]), 64)
            bundle = manifest["_bundle_dir"]
            res = forensics.verify_bundle(bundle)
            self.assertTrue(res["ok"], res)
            self.assertTrue(res["bundle_match"])

            # tamper with one artifact -> verification must fail
            art = manifest["artifacts"][0]["file"]
            with open(os.path.join(bundle, art), "ab") as fh:
                fh.write(b"TAMPERED")
            res2 = forensics.verify_bundle(bundle)
            self.assertFalse(res2["ok"])

    def test_evidence_results(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = forensics.collect_evidence(d, operator="t")
            rows = forensics.evidence_results(manifest)
            self.assertEqual(len(rows), len(manifest["artifacts"]))
            self.assertTrue(all(r.category == "forensic" for r in rows))


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #

class TestConfig(unittest.TestCase):
    def test_json_config_and_env_override(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "netcheck.json")
            with open(p, "w") as fh:
                json.dump({"target": "example.org", "ports": [443, 8080],
                           "ai": {"provider": "openai", "model": "gpt-x"},
                           "notify": {"on_severity": "FAIL"}}, fh)
            cfg = config.load_config(p)
            self.assertEqual(cfg.target, "example.org")
            self.assertEqual(cfg.ports, [443, 8080])
            self.assertEqual(cfg.ai.provider, "openai")
            self.assertEqual(cfg.notify.on_severity, "FAIL")

            os.environ["NETCHECK_TARGET"] = "override.net"
            try:
                cfg2 = config.load_config(p)
                self.assertEqual(cfg2.target, "override.net")
            finally:
                os.environ.pop("NETCHECK_TARGET")

    def test_resolved_model_defaults(self):
        self.assertEqual(config.AIConfig(provider="anthropic").resolved_model(), "claude-sonnet-4-6")
        self.assertEqual(config.AIConfig(provider="openai").resolved_model(), "gpt-5.4-mini")
        self.assertEqual(config.AIConfig(provider="ollama").resolved_model(), "llama3.1")
        self.assertEqual(config.AIConfig(provider="anthropic", model="x").resolved_model(), "x")


# --------------------------------------------------------------------------- #
# Reports + notify gating
# --------------------------------------------------------------------------- #

class TestReport(unittest.TestCase):
    def setUp(self):
        self.env = {"hostname": "h", "os": "o", "target": "t", "timestamp": "now",
                    "local_ip": "10.0.0.2", "gateway": "10.0.0.1", "dns_servers": ["1.1.1.1"]}
        self.results = [CheckResult("Internet (by IP)", FAIL, "down", {})]
        self.findings = diagnosis.diagnose(self.results, "t")

    def test_markdown_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            md = report.write_markdown(os.path.join(d, "r.md"), self.env,
                                       self.results, self.findings, None, "triage")
            js = report.write_json(os.path.join(d, "r.json"), self.env,
                                   self.results, self.findings, None, "triage")
            with open(md) as fh:
                text = fh.read()
            self.assertIn("NetCheck Report", text)
            self.assertIn("DOWN", text)
            with open(js) as fh:
                doc = json.load(fh)
            self.assertEqual(doc["verdict"], "DOWN")
            self.assertEqual(doc["schema"], "netcheck-report-2")

    def test_audit_log_append(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "audit.jsonl")
            report.append_audit_log(p, self.env, self.results, self.findings, "triage")
            report.append_audit_log(p, self.env, self.results, self.findings, "triage")
            with open(p) as fh:
                lines = [l for l in fh if l.strip()]
            self.assertEqual(len(lines), 2)
            rec = json.loads(lines[0])
            self.assertEqual(rec["verdict"], "DOWN")

    def test_notify_gating(self):
        self.assertTrue(notify.should_notify("DOWN", "WARN"))
        self.assertTrue(notify.should_notify("DEGRADED", "WARN"))
        self.assertFalse(notify.should_notify("HEALTHY", "WARN"))
        self.assertFalse(notify.should_notify("DEGRADED", "FAIL"))
        self.assertTrue(notify.should_notify("DOWN", "FAIL"))

    def test_verdict_labels_mode_aware(self):
        warn = [CheckResult("a", WARN)]
        fail = [CheckResult("a", FAIL)]
        ok = [CheckResult("a", OK)]
        # operational wording (triage/collect)
        self.assertEqual(report.verdict_label(fail, "triage"), "DOWN")
        # security wording
        self.assertEqual(report.verdict_label(ok, "security"), "SECURE")
        self.assertEqual(report.verdict_label(warn, "security"), "AT RISK")
        self.assertEqual(report.verdict_label(fail, "security"), "CRITICAL")
        # incident wording
        self.assertEqual(report.verdict_label(warn, "incident"), "ELEVATED")
        # canonical verdict unchanged
        self.assertEqual(report.verdict(fail), "DOWN")


# --------------------------------------------------------------------------- #
# Live security checks (skipped automatically if offline)
# --------------------------------------------------------------------------- #

def _online():
    try:
        ok, _, _ = core.tcp_connect("1.1.1.1", 443, timeout=3)
        return ok
    except Exception:
        return False


@unittest.skipUnless(_online(), "network unavailable")
class TestSecurityLive(unittest.TestCase):
    def test_tls_and_cert(self):
        r = security.check_tls_protocols("cloudflare.com", 443, timeout=6)
        self.assertEqual(r.category, "security")
        self.assertIn(r.status, (OK, WARN, FAIL))
        c = security.check_certificate("cloudflare.com", 443, timeout=6)
        # OK (valid) or WARN (valid but near expiry) are both correct outcomes;
        # only a verification failure would be wrong here.
        self.assertIn(c.status, (OK, WARN))
        self.assertIsNotNone(c.data.get("days_to_expiry"))

    def test_exposed_services_clean(self):
        r = security.check_exposed_services("cloudflare.com", timeout=2)
        self.assertEqual(r.category, "security")


class TestEnvironment(unittest.TestCase):
    def test_detect_returns_shape(self):
        e = envmod.detect_environment()
        for k in ("platform", "pretty", "family", "method", "virtual"):
            self.assertIn(k, e)
        self.assertIsInstance(e["virtual"], bool)

    def test_private_and_cgnat(self):
        for ip in ("10.1.2.3", "192.168.0.5", "172.20.1.1", "169.254.1.1"):
            self.assertTrue(envmod.is_private(ip), ip)
        self.assertFalse(envmod.is_private("8.8.8.8"))
        self.assertTrue(envmod.is_cgnat("100.70.1.1"))
        self.assertFalse(envmod.is_cgnat("192.168.1.1"))

    def test_classify_nat_virtualbox(self):
        out = envmod.classify_nat("10.0.2.15", None, "10.0.2.2", ["10.0.2.3"],
                                  {"platform": "virtualbox"})
        self.assertTrue(out["behind_nat"])
        self.assertEqual(out["type"], "VirtualBox NAT")

    def test_classify_nat_wsl(self):
        out = envmod.classify_nat("172.31.65.93", None, "172.31.64.1", ["10.255.255.254"],
                                  {"platform": "wsl2"})
        self.assertEqual(out["type"], "WSL2 NAT")

    def test_classify_nat_cgnat(self):
        out = envmod.classify_nat("192.168.1.5", "100.66.3.4", "192.168.1.1", [], {})
        self.assertIn("CGNAT", out["type"])

    def test_classify_nat_standard_and_public(self):
        std = envmod.classify_nat("192.168.1.5", "203.0.113.9", "192.168.1.1", [], {})
        self.assertTrue(std["behind_nat"])
        self.assertEqual(std["type"], "standard NAT")
        pub = envmod.classify_nat("203.0.113.9", "203.0.113.9", "203.0.113.1", [], {})
        self.assertFalse(pub["behind_nat"])

    def test_neighbor_state_unknown(self):
        self.assertIn(envmod.neighbor_state("203.0.113.250"),
                      ("unknown", "unreachable", "reachable"))

    def test_proxy_env_detection(self):
        os.environ["HTTPS_PROXY"] = "http://proxy.local:8080"
        try:
            p = envmod.proxy_env()
            self.assertIn("https_proxy", p)
        finally:
            os.environ.pop("HTTPS_PROXY")


class TestGatewayLogic(unittest.TestCase):
    """Lock in the fix: filtered ICMP must not be a FAIL when upstream works."""

    def _env(self, plat="wsl2", gw="172.31.64.1"):
        return {"gateway": gw, "virt": {"platform": plat, "pretty": "WSL2", "virtual": True}}

    def test_filtered_icmp_but_upstream_ok_is_not_fail(self):
        bad_ping = mock.Mock(return_value=core.PingStats(reachable=False, loss_pct=100.0))
        with mock.patch.object(checks, "ping", bad_ping), \
             mock.patch.object(checks.envmod, "neighbor_state", return_value="unknown"), \
             mock.patch.object(checks, "tcp_connect", return_value=(False, None, "x")), \
             mock.patch.object(checks, "_upstream_reachable", return_value=True):
            r = checks.check_gateway(self._env())
        self.assertEqual(r.status, INFO)
        self.assertNotEqual(r.status, FAIL)

    def test_arp_reachable_is_ok(self):
        bad_ping = mock.Mock(return_value=core.PingStats(reachable=False, loss_pct=100.0))
        with mock.patch.object(checks, "ping", bad_ping), \
             mock.patch.object(checks.envmod, "neighbor_state", return_value="reachable"):
            r = checks.check_gateway(self._env())
        self.assertEqual(r.status, OK)
        self.assertIn("layer-2", r.detail)

    def test_truly_down_is_fail(self):
        bad_ping = mock.Mock(return_value=core.PingStats(reachable=False, loss_pct=100.0))
        with mock.patch.object(checks, "ping", bad_ping), \
             mock.patch.object(checks.envmod, "neighbor_state", return_value="unreachable"), \
             mock.patch.object(checks, "tcp_connect", return_value=(False, None, "x")), \
             mock.patch.object(checks, "_upstream_reachable", return_value=False):
            r = checks.check_gateway(self._env(plat="physical", gw="192.168.1.1"))
        self.assertEqual(r.status, FAIL)

    def test_no_gateway_but_upstream_ok(self):
        with mock.patch.object(checks, "_upstream_reachable", return_value=True):
            r = checks.check_gateway({"gateway": None, "virt": {"platform": "wsl2"}})
        self.assertEqual(r.status, INFO)


class TestDiagnosisEnvAware(unittest.TestCase):
    def test_captive_reframed_in_vm(self):
        rs = [
            CheckResult("Internet (by IP)", OK, "", {"reachable": True}),
            CheckResult("DNS resolution", OK, "", {}),
            CheckResult("HTTP / captive portal", WARN, "", {"captive_portal": True}),
        ]
        env = {"virt": {"platform": "wsl2", "pretty": "WSL2", "virtual": True}}
        f = diagnosis.diagnose(rs, "t", env)
        titles = " ".join(x["title"] for x in f)
        self.assertIn("virtual network layer", titles)

    def test_captive_real_on_physical(self):
        rs = [
            CheckResult("Internet (by IP)", OK, "", {"reachable": True}),
            CheckResult("HTTP / captive portal", WARN, "", {"captive_portal": True}),
        ]
        env = {"virt": {"platform": "physical", "pretty": "physical", "virtual": False}}
        f = diagnosis.diagnose(rs, "t", env)
        self.assertTrue(any("Captive portal is blocking" in x["title"] for x in f))


class TestCloud(unittest.TestCase):
    def test_serverless_env_cloud_run(self):
        os.environ["K_SERVICE"] = "my-svc"
        try:
            c = cloud.detect_cloud(probe_imds=False)
        finally:
            os.environ.pop("K_SERVICE")
        self.assertEqual(c["provider"], "gcp")
        self.assertEqual(c["product"], "Google Cloud Run")
        self.assertIn("PaaS", c["service_model"])

    def test_serverless_env_lambda(self):
        os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "fn"
        try:
            c = cloud.detect_cloud(probe_imds=False)
        finally:
            os.environ.pop("AWS_LAMBDA_FUNCTION_NAME")
        self.assertEqual(c["provider"], "aws")
        self.assertIn("FaaS", c["service_model"])

    def test_no_cloud_fast(self):
        c = cloud.detect_cloud(probe_imds=False)
        self.assertIsNone(c["provider"])

    def test_imds_findings(self):
        warn = security.check_imds({"provider": "aws", "imds": {"imdsv1_enabled": True}})
        self.assertEqual(warn.status, WARN)
        self.assertIn("IMDSv1", warn.detail)
        ok = security.check_imds({"provider": "aws", "imds": {"imdsv2": True, "imdsv1_enabled": False}})
        self.assertEqual(ok.status, OK)
        skip = security.check_imds({"provider": None})
        self.assertEqual(skip.status, SKIP)


def _build_kexinit(kex, hostkey, enc, mac):
    import struct
    nls = [kex, hostkey, enc, enc, mac, mac, "none", "none", "", ""]
    payload = b"\x14" + b"\x00" * 16
    for s in nls:
        b = s.encode()
        payload += struct.pack(">I", len(b)) + b
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_follows + reserved
    pad = 8 - ((4 + 1 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">I", 1 + len(payload) + pad) + bytes([pad]) + payload + b"\x00" * pad


class MockSSHServer(threading.Thread):
    def __init__(self, packet, banner=b"SSH-2.0-OpenSSH_8.9p1\r\n"):
        super().__init__(daemon=True)
        self.packet, self.banner = packet, banner
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]

    def run(self):
        try:
            conn, _ = self.srv.accept()
            conn.sendall(self.banner)
            conn.sendall(self.packet)
            try:
                conn.recv(256)
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        finally:
            self.srv.close()


class TestSSHAudit(unittest.TestCase):
    def test_parses_and_flags_weak(self):
        pkt = _build_kexinit(
            kex="curve25519-sha256,diffie-hellman-group1-sha1",
            hostkey="rsa-sha2-512,ssh-rsa",
            enc="aes256-gcm@openssh.com,3des-cbc",
            mac="hmac-sha2-256-etm@openssh.com,hmac-sha1")
        srv = MockSSHServer(pkt)
        srv.start()
        info = security.ssh_audit("127.0.0.1", srv.port, timeout=4)
        self.assertTrue(info["reachable"])
        self.assertIn("OpenSSH_8.9p1", info["software"])
        self.assertIn("curve25519-sha256", info["kex"])
        joined = " ".join(info["weak"])
        self.assertIn("ssh-rsa", joined)
        self.assertIn("3des-cbc", joined)
        self.assertIn("diffie-hellman-group1-sha1", joined)
        self.assertIn("hmac-sha1", joined)

    def test_check_ssh_warns_on_weak(self):
        pkt = _build_kexinit("diffie-hellman-group1-sha1", "ssh-rsa", "3des-cbc", "hmac-md5")
        srv = MockSSHServer(pkt)
        srv.start()
        r = security.check_ssh("127.0.0.1", srv.port, timeout=4)
        self.assertEqual(r.status, WARN)
        self.assertEqual(r.category, "security")

    def test_ssh_closed_is_skip(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        r = security.check_ssh("127.0.0.1", port, timeout=2)
        self.assertEqual(r.status, SKIP)


class TestWAF(unittest.TestCase):
    def test_cloudflare_signature(self):
        fake = (200, "", "", {"cf-ray": "abc123", "server": "cloudflare"})
        with mock.patch.object(security, "http_probe", return_value=fake):
            info = security.detect_waf("example.com")
        self.assertIn("Cloudflare", info["vendors"])

    def test_no_waf(self):
        fake = (200, "", "", {"server": "nginx"})
        with mock.patch.object(security, "http_probe", return_value=fake):
            info = security.detect_waf("example.com")
        self.assertEqual(info["vendors"], [])

    def test_imperva_via_cookie(self):
        fake = (200, "", "", {"x-iinfo": "1-2-3", "set-cookie": "visid_incap_1=xyz"})
        with mock.patch.object(security, "http_probe", return_value=fake):
            info = security.detect_waf("example.com")
        self.assertIn("Imperva Incapsula", info["vendors"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
