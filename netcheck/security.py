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


def run_security_assessment(target: str, timeout: float = 5.0):
    """Run the full defensive posture assessment against a single target."""
    return [
        check_tls_protocols(target, 443, timeout),
        check_certificate(target, 443, timeout),
        check_security_headers(target, timeout),
        check_exposed_services(target, min(timeout, 3.0)),
    ]
