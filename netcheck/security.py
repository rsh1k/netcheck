"""
netcheck.security
=================
Defensive security-posture assessment for a host you OWN or are AUTHORISED to
assess. These are configuration/hygiene checks (read-only, full TCP handshakes
only) - there is no exploitation, no credential testing, and no network
scanning beyond a single specified target. This is blue-team auditing, akin to
what testssl.sh / OWASP Secure Headers / a CIS benchmark would inspect.
"""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from datetime import datetime, timezone

from .core import CheckResult, OK, WARN, FAIL, INFO, SKIP, tcp_connect, http_probe
from .config import RISKY_PORTS, PORT_NAMES

# NIST publications referenced by these checks (for enterprise/compliance mapping).
NIST = {
    "tls": "NIST SP 800-52 Rev. 2 (TLS)",
    "cert": "NIST SP 800-52 Rev. 2 (TLS)",
    "headers": "OWASP Secure Headers / NIST SP 800-53 SC-8",
    "exposed": "NIST SP 800-41 Rev. 1 (firewalls/DMZ), SP 800-207 (Zero Trust)",
    "ssh": "NISTIR 7966 (SSH), NIST SP 800-52 Rev. 2 (crypto)",
    "waf": "NIST SP 800-41 Rev. 1, SP 800-44 (public web servers)",
    "imds": "NIST SP 800-53 SC-7 (boundary protection), AC-6 (least privilege)",
    "cloud": "NIST SP 800-145 (cloud service models)",
}

# Security headers OWASP recommends, with why-they-matter notes.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS - forces HTTPS, prevents SSL-strip",
    "content-security-policy": "CSP - mitigates XSS / injection",
    "x-content-type-options": "blocks MIME-sniffing",
    "x-frame-options": "clickjacking protection (or use CSP frame-ancestors)",
    "referrer-policy": "limits referrer leakage",
}

WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon")


def _tls_supports(host, port, version, timeout):
    """Return negotiated version string if the server accepts exactly `version`,
    False if it rejects it, or None if this client can't offer it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Probing deprecated versions on purpose; silence the deprecation notice.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError):
        return None  # legacy protocol compiled out of this OpenSSL build
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.version()
    except Exception:
        return False


def check_tls_protocols(host: str, port: int = 443, timeout: float = 5.0) -> CheckResult:
    """Audit which TLS versions the server accepts and the negotiated cipher."""
    name = f"TLS protocol audit → {host}"
    versions = {
        "TLS 1.0": ssl.TLSVersion.TLSv1,
        "TLS 1.1": ssl.TLSVersion.TLSv1_1,
        "TLS 1.2": ssl.TLSVersion.TLSv1_2,
        "TLS 1.3": ssl.TLSVersion.TLSv1_3,
    }
    supported, untestable = {}, []
    for label, ver in versions.items():
        res = _tls_supports(host, port, ver, timeout)
        if res is None:
            untestable.append(label)
        else:
            supported[label] = bool(res)

    # Negotiated cipher on a default handshake
    cipher = None
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cipher = ss.cipher()  # (name, protocol, secret_bits)
    except Exception:
        pass

    data = {"supported": supported, "untestable": untestable, "cipher": cipher}
    weak = [v for v in ("TLS 1.0", "TLS 1.1") if supported.get(v)]
    has_modern = supported.get("TLS 1.2") or supported.get("TLS 1.3")
    cipher_weak = bool(cipher and any(t in (cipher[0] or "") for t in WEAK_CIPHER_TOKENS))
    if cipher and cipher[2] and cipher[2] < 128:
        cipher_weak = True

    if not has_modern and not supported:
        return CheckResult(name, FAIL, "could not complete any TLS handshake", data, category="security")
    if weak:
        return CheckResult(name, FAIL,
                           f"server accepts deprecated {', '.join(weak)} - disable them (keep 1.2/1.3 only)",
                           data, category="security")
    if cipher_weak:
        return CheckResult(name, WARN,
                           f"weak negotiated cipher {cipher[0]} ({cipher[2]} bits)", data, category="security")
    best = "TLS 1.3" if supported.get("TLS 1.3") else "TLS 1.2"
    cname = f"  cipher {cipher[0]}" if cipher else ""
    return CheckResult(name, OK, f"modern only (max {best}){cname}", data, category="security")


def check_certificate(host: str, port: int = 443, timeout: float = 5.0) -> CheckResult:
    """Certificate hygiene: validity, expiry window, issuer, hostname match."""
    name = f"Certificate hygiene → {host}"
    info = {"verified": False, "error": "", "days_to_expiry": None,
            "issuer": "", "subject": "", "not_after": ""}

    # Verified handshake (catches hostname mismatch, untrusted CA, expiry).
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                info["verified"] = True
                cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        info["error"] = str(e)
        cert = None
    except Exception as e:
        return CheckResult(name, WARN, f"could not retrieve certificate: {type(e).__name__}",
                           info, category="security")

    # Read dates/issuer even if verification failed (unverified context).
    try:
        nc = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with nc.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert() or cert
    except Exception:
        pass

    if cert:
        na = cert.get("notAfter", "")
        info["not_after"] = na
        if na:
            exp = ssl.cert_time_to_seconds(na)
            info["days_to_expiry"] = round((exp - time.time()) / 86400, 1)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName", "")
        info["subject"] = subject.get("commonName", "")

    d = info["days_to_expiry"]
    if not info["verified"]:
        err = info["error"].lower()
        if "hostname mismatch" in err or "doesn't match" in err:
            return CheckResult(name, FAIL, "certificate hostname mismatch", info, category="security")
        if "self signed" in err or "self-signed" in err:
            return CheckResult(name, WARN, "self-signed certificate (untrusted CA)", info, category="security")
        if "expired" in err:
            return CheckResult(name, FAIL, "certificate has expired", info, category="security")
        return CheckResult(name, WARN, f"validation failed: {info['error'][:80]}", info, category="security")
    if d is not None and d < 0:
        return CheckResult(name, FAIL, "certificate has expired", info, category="security")
    if d is not None and d < 15:
        return CheckResult(name, FAIL, f"certificate expires in {d:.0f} days - renew now", info, category="security")
    if d is not None and d < 30:
        return CheckResult(name, WARN, f"certificate expires in {d:.0f} days", info, category="security")
    extra = f"  issuer {info['issuer']}" if info["issuer"] else ""
    return CheckResult(name, OK,
                       f"valid" + (f", {d:.0f} days left" if d is not None else "") + extra,
                       info, category="security")


def check_security_headers(host: str, timeout: float = 5.0) -> CheckResult:
    name = f"HTTP security headers → {host}"
    url = f"https://{host}/"
    status, body, err, headers = http_probe(url, timeout=timeout, want_headers=True)
    if status is None:
        return CheckResult(name, SKIP, f"no HTTPS response ({err})", {"error": err}, category="security")
    present = {h: headers.get(h, "") for h in SECURITY_HEADERS}
    missing = [h for h in SECURITY_HEADERS if not present[h]]
    data = {"status": status, "present": {h: bool(present[h]) for h in SECURITY_HEADERS},
            "missing": missing}
    if not missing:
        return CheckResult(name, OK, "all key security headers present", data, category="security")
    crit = [h for h in ("strict-transport-security", "content-security-policy") if h in missing]
    sev = WARN if not crit else WARN  # missing headers are hygiene, not an outage
    short = ", ".join(h.replace("strict-transport-security", "HSTS")
                       .replace("content-security-policy", "CSP")
                       .replace("x-content-type-options", "X-Content-Type-Options")
                       .replace("x-frame-options", "X-Frame-Options")
                       .replace("referrer-policy", "Referrer-Policy") for h in missing)
    return CheckResult(name, sev, f"missing: {short}", data, category="security")


def check_exposed_services(host: str, timeout: float = 3.0) -> CheckResult:
    """Flag risky/management/database ports reachable on the target.

    Only the curated RISKY_PORTS set is assessed - standard service ports like
    80/443 are expected to be open and are intentionally not flagged here.
    """
    name = f"Exposed services → {host}"
    ports = sorted(RISKY_PORTS)
    import concurrent.futures
    open_ports = []

    def probe(p):
        ok, _, _ = tcp_connect(host, p, timeout=timeout)
        return (p, ok)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(ports))) as ex:
        for p, ok in ex.map(probe, ports):
            if ok:
                open_ports.append(p)

    data = {"open_risky_ports": [
        {"port": p, "name": PORT_NAMES.get(p, "?"),
         "risk": RISKY_PORTS.get(p, "")} for p in open_ports]}
    if not open_ports:
        return CheckResult(name, OK, "no risky/management ports reachable", data, category="security")
    desc = ", ".join(f"{p}/{PORT_NAMES.get(p,'?')}" for p in open_ports)
    sev = FAIL if any(p in (23, 21, 445, 3389) for p in open_ports) else WARN
    return CheckResult(name, sev, f"reachable risky ports: {desc}", data, category="security")


def run_security_assessment(target: str, timeout: float = 5.0, deep: bool = True):
    """Run the full defensive posture assessment against a single target.
    `deep` adds the SSH algorithm audit and WAF fingerprint."""
    results = [
        check_tls_protocols(target, 443, timeout),
        check_certificate(target, 443, timeout),
        check_security_headers(target, timeout),
        check_exposed_services(target, min(timeout, 3.0)),
    ]
    if deep:
        results.append(check_waf(target, timeout))
        results.append(check_ssh(target, 22, timeout))
    # Tag NIST references for compliance reporting.
    for r in results:
        key = ("tls" if "TLS protocol" in r.name else
               "cert" if "Certificate" in r.name else
               "headers" if "headers" in r.name else
               "exposed" if "Exposed" in r.name else
               "waf" if "WAF" in r.name else
               "ssh" if "SSH" in r.name else "")
        if key:
            r.data["nist"] = NIST[key]
    return results


# --------------------------------------------------------------------------- #
# SSH algorithm hygiene (read-only KEXINIT handshake - no authentication)
# --------------------------------------------------------------------------- #

_SSH_WEAK_KEX = ("group1-sha1", "group14-sha1", "group-exchange-sha1",
                 "gss-group1", "gss-group14", "rsa1024-sha1", "diffie-hellman-group1")
_SSH_WEAK_HOSTKEY = ("ssh-dss", "ssh-rsa")  # ssh-rsa = SHA-1 signature (deprecated)
_SSH_WEAK_CIPHER = ("arcfour", "-cbc", "3des", "blowfish", "cast128", "des-", "none")
_SSH_WEAK_MAC = ("hmac-md5", "hmac-sha1", "umac-64")


class _Buf:
    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def _fill(self):
        chunk = self.s.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        self.buf += chunk

    def read_line(self, limit=8192):
        while b"\n" not in self.buf:
            if len(self.buf) > limit:
                raise ValueError("line too long")
            self._fill()
        line, self.buf = self.buf.split(b"\n", 1)
        return line + b"\n"

    def read_exact(self, n):
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def _ssh_namelists(payload):
    """Parse the 10 name-lists from an SSH_MSG_KEXINIT payload (after cookie)."""
    import struct
    idx = 17  # 1 byte msg type + 16 byte cookie
    lists = []
    for _ in range(10):
        if idx + 4 > len(payload):
            break
        (ln,) = struct.unpack(">I", payload[idx:idx + 4])
        idx += 4
        lists.append(payload[idx:idx + ln].decode("ascii", "replace"))
        idx += ln
    return lists


def ssh_audit(host: str, port: int = 22, timeout: float = 6.0) -> dict:
    import socket as _socket
    import struct
    out = {"reachable": False, "banner": "", "software": "", "kex": [], "host_keys": [],
           "ciphers": [], "macs": [], "weak": [], "error": ""}
    try:
        s = _socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
    except Exception as e:
        out["error"] = type(e).__name__
        return out
    try:
        buf = _Buf(s)
        # Server identification string (skip any pre-banner lines).
        banner = ""
        for _ in range(10):
            line = buf.read_line().decode("latin-1", "replace").strip()
            if line.startswith("SSH-"):
                banner = line
                break
        out["reachable"] = True
        out["banner"] = banner
        out["software"] = banner.split("-", 2)[-1] if banner.count("-") >= 2 else banner
        s.sendall(b"SSH-2.0-NetCheck\r\n")
        # Read the server's KEXINIT binary packet.
        for _ in range(5):
            length = struct.unpack(">I", buf.read_exact(4))[0]
            if length <= 0 or length > 35000:
                break
            body = buf.read_exact(length)
            pad = body[0]
            payload = body[1:len(body) - pad]
            if payload and payload[0] == 20:  # SSH_MSG_KEXINIT
                nl = _ssh_namelists(payload)
                if len(nl) >= 4:
                    out["kex"] = [a for a in nl[0].split(",") if a]
                    out["host_keys"] = [a for a in nl[1].split(",") if a]
                    out["ciphers"] = [a for a in nl[2].split(",") if a]
                    out["macs"] = [a for a in nl[4].split(",") if a]
                break
    except Exception as e:
        out["error"] = out["error"] or type(e).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass

    weak = []
    for a in out["kex"]:
        if any(w in a for w in _SSH_WEAK_KEX):
            weak.append("kex:" + a)
    for a in out["host_keys"]:
        if a in _SSH_WEAK_HOSTKEY:
            weak.append("hostkey:" + a)
    for a in out["ciphers"]:
        if any(w in a for w in _SSH_WEAK_CIPHER):
            weak.append("cipher:" + a)
    for a in out["macs"]:
        if any(w in a for w in _SSH_WEAK_MAC):
            weak.append("mac:" + a)
    out["weak"] = weak
    return out


def check_ssh(host: str, port: int = 22, timeout: float = 6.0) -> CheckResult:
    name = f"SSH posture → {host}:{port}"
    info = ssh_audit(host, port, timeout)
    if not info["reachable"]:
        return CheckResult(name, SKIP, f"no SSH service reachable ({info.get('error') or 'closed'})",
                           info, category="security")
    sw = info.get("software", "")
    if info["weak"]:
        return CheckResult(name, WARN,
                           f"{sw or 'SSH'} offers weak algorithms: {', '.join(info['weak'][:6])}"
                           + ("…" if len(info["weak"]) > 6 else ""), info, category="security")
    if not info["kex"]:
        return CheckResult(name, INFO, f"SSH present ({sw})  — could not enumerate algorithms", info, category="security")
    return CheckResult(name, OK, f"{sw or 'SSH'} — modern algorithms only", info, category="security")


# --------------------------------------------------------------------------- #
# WAF / CDN fingerprint (passive - reads response headers from one request)
# --------------------------------------------------------------------------- #

# (header-or-cookie substring, vendor). Matched case-insensitively.
_WAF_SIGNS = [
    ("cf-ray", "Cloudflare"), ("__cfduid", "Cloudflare"), ("cf-cache-status", "Cloudflare"),
    ("x-sucuri-id", "Sucuri CloudProxy"), ("x-sucuri-cache", "Sucuri CloudProxy"),
    ("x-iinfo", "Imperva Incapsula"), ("incap_ses", "Imperva Incapsula"), ("visid_incap", "Imperva Incapsula"),
    ("akamaighost", "Akamai"), ("x-akamai", "Akamai"),
    ("x-amz-cf-id", "AWS CloudFront"), ("x-amzn-requestid", "AWS API Gateway/WAF"),
    ("awselb", "AWS ELB"),
    ("x-azure-ref", "Azure Front Door"), ("microsoft-azure-application-gateway", "Azure App Gateway"),
    ("x-served-by", "Fastly/Varnish"), ("fastly", "Fastly"),
    ("barracuda", "Barracuda"),
    ("fortiwafsid", "Fortinet FortiWeb"),
    ("ns_af", "Citrix NetScaler"), ("citrix_ns_id", "Citrix NetScaler"),
    ("x-wa-info", "F5 BIG-IP ASM"), ("x-cdn", "generic CDN"),
    ("mod_security", "ModSecurity"), ("modsecurity", "ModSecurity"),
]


def detect_waf(host: str, timeout: float = 5.0) -> dict:
    status, body, err, headers = http_probe(f"https://{host}/", timeout=timeout, want_headers=True)
    if status is None:
        return {"reachable": False, "error": err, "vendors": [], "server": ""}
    blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    server = headers.get("server", "")
    vendors = []
    for needle, vendor in _WAF_SIGNS:
        if needle in blob and vendor not in vendors:
            vendors.append(vendor)
    # Server header sometimes names the WAF/CDN directly.
    for token, vendor in (("cloudflare", "Cloudflare"), ("sucuri", "Sucuri CloudProxy"),
                          ("akamaighost", "Akamai"), ("cloudfront", "AWS CloudFront"),
                          ("bigip", "F5 BIG-IP")):
        if token in server.lower() and vendor not in vendors:
            vendors.append(vendor)
    return {"reachable": True, "vendors": vendors, "server": server, "status": status}


def check_waf(host: str, timeout: float = 5.0) -> CheckResult:
    name = f"WAF / CDN → {host}"
    info = detect_waf(host, timeout)
    if not info["reachable"]:
        return CheckResult(name, SKIP, f"no HTTPS response ({info.get('error')})", info, category="security")
    if info["vendors"]:
        return CheckResult(name, INFO, f"edge protection detected: {', '.join(info['vendors'])}",
                           info, category="security")
    srv = f"  (Server: {info['server']})" if info.get("server") else ""
    return CheckResult(name, INFO, f"no WAF/CDN signature detected{srv}", info, category="security")


# --------------------------------------------------------------------------- #
# Cloud instance-metadata-service (IMDS) posture
# --------------------------------------------------------------------------- #

def check_imds(cloud_info: dict) -> CheckResult:
    name = "Cloud IMDS posture"
    provider = cloud_info.get("provider")
    imds = cloud_info.get("imds") or {}
    data = {"provider": provider, "imds": imds, "nist": NIST["imds"]}
    if not provider:
        return CheckResult(name, SKIP, "not running on a detected cloud instance", data, category="security")
    if provider == "aws":
        if imds.get("imdsv1_enabled"):
            return CheckResult(name, WARN,
                               "IMDSv1 is reachable without a token — SSRF credential-theft risk. "
                               "Enforce IMDSv2 (HttpTokens=required).", data, category="security")
        if imds.get("imdsv2"):
            return CheckResult(name, OK, "IMDSv2 enforced (token required) — good", data, category="security")
    return CheckResult(name, INFO,
                       f"{provider.upper()} metadata service present (header-gated)", data, category="security")
