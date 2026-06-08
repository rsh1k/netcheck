"""
netcheck.core
=============
Status model, result objects, terminal styling, and the low-level network
primitives every check is built on. Standard library only.
"""

from __future__ import annotations

import concurrent.futures
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

# --------------------------------------------------------------------------- #
# Status model
# --------------------------------------------------------------------------- #

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"
INFO = "INFO"
SKIP = "SKIP"

SEVERITY = {OK: 0, INFO: 0, SKIP: 0, WARN: 1, FAIL: 2}
VERDICT_BY_SEVERITY = {0: "HEALTHY", 1: "DEGRADED", 2: "DOWN"}


@dataclass
class CheckResult:
    name: str
    status: str = INFO
    detail: str = ""
    data: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    category: str = "diagnostic"  # diagnostic | security | forensic

    def to_dict(self) -> dict:
        return asdict(self)


def worst_severity(results) -> int:
    return max((SEVERITY.get(r.status, 0) for r in results), default=0)


# --------------------------------------------------------------------------- #
# Terminal styling (ANSI with graceful fallback)
# --------------------------------------------------------------------------- #

class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, t):    return self._wrap("31", t)
    def green(self, t):  return self._wrap("32", t)
    def yellow(self, t): return self._wrap("33", t)
    def blue(self, t):   return self._wrap("34", t)
    def cyan(self, t):   return self._wrap("36", t)
    def grey(self, t):   return self._wrap("90", t)
    def bold(self, t):   return self._wrap("1", t)
    def dim(self, t):    return self._wrap("2", t)

    def badge(self, status: str) -> str:
        labels = {
            OK:   ("  OK  ", "42;30"),
            WARN: (" WARN ", "43;30"),
            FAIL: (" FAIL ", "41;37"),
            INFO: (" INFO ", "44;37"),
            SKIP: (" SKIP ", "100;37"),
        }
        text, code = labels.get(status, (f" {status} ", "47;30"))
        if not self.enabled:
            return f"[{status:^4}]"
        return f"\033[{code}m{text}\033[0m"


def supports_color(force_disable: bool = False) -> bool:
    if force_disable or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if platform.system() == "Windows":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


# --------------------------------------------------------------------------- #
# Platform helpers
# --------------------------------------------------------------------------- #

OSNAME = platform.system()  # 'Linux', 'Darwin', 'Windows'


def run_cmd(cmd, timeout: float = 8.0):
    """Run a command, returning (returncode, combined_output). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:  # pragma: no cover
        return 1, str(e)


def get_local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_ipv6() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2606:4700:4700::1111", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_default_gateway() -> Optional[str]:
    try:
        if OSNAME == "Linux":
            try:
                with open("/proc/net/route") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == "00000000":
                            return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
            except FileNotFoundError:
                pass
            rc, out = run_cmd(["ip", "route", "show", "default"])
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        elif OSNAME == "Darwin":
            rc, out = run_cmd(["route", "-n", "get", "default"])
            m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        elif OSNAME == "Windows":
            rc, out = run_cmd(["ipconfig"])
            m = re.search(r"Default Gateway[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def get_configured_dns():
    servers = []
    try:
        if OSNAME in ("Linux", "Darwin"):
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        m = re.match(r"\s*nameserver\s+(\S+)", line)
                        if m:
                            servers.append(m.group(1))
            except FileNotFoundError:
                pass
            if not servers and OSNAME == "Darwin":
                rc, out = run_cmd(["scutil", "--dns"])
                servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)
        elif OSNAME == "Windows":
            rc, out = run_cmd(["ipconfig", "/all"])
            block = re.search(r"DNS Servers[ .]*:\s*(.+?)(?:\n\S|\Z)", out, re.S)
            if block:
                servers = re.findall(r"(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{3,})", block.group(1))
    except Exception:
        pass
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


# --------------------------------------------------------------------------- #
# ICMP ping
# --------------------------------------------------------------------------- #

@dataclass
class PingStats:
    reachable: bool = False
    loss_pct: Optional[float] = None
    rtt_avg_ms: Optional[float] = None
    rtt_min_ms: Optional[float] = None
    rtt_max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    raw: str = ""


def ping(host: str, count: int = 4, timeout_per: float = 2.0) -> PingStats:
    if OSNAME == "Windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout_per * 1000)), host]
    else:
        cmd = ["ping", "-c", str(count), host]
    rc, out = run_cmd(cmd, timeout=count * timeout_per + 5)
    st = PingStats(raw=out)

    m = re.search(r"([\d.]+)%\s*packet loss", out) or re.search(r"\(([\d.]+)%\s*loss\)", out)
    if m:
        st.loss_pct = float(m.group(1))

    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", out)
    if m:
        st.rtt_min_ms, st.rtt_avg_ms, st.rtt_max_ms, st.jitter_ms = map(float, m.groups())
    else:
        mn = re.search(r"Minimum = (\d+)ms", out)
        mx = re.search(r"Maximum = (\d+)ms", out)
        av = re.search(r"Average = (\d+)ms", out)
        if av:
            st.rtt_avg_ms = float(av.group(1))
        if mn:
            st.rtt_min_ms = float(mn.group(1))
        if mx:
            st.rtt_max_ms = float(mx.group(1))
        if mn and mx:
            st.jitter_ms = float(mx.group(1)) - float(mn.group(1))

    st.reachable = (st.loss_pct is not None and st.loss_pct < 100) or (
        rc == 0 and "unreachable" not in out.lower())
    return st


# --------------------------------------------------------------------------- #
# TCP connectivity (races address families - happy eyeballs style)
# --------------------------------------------------------------------------- #

def tcp_connect(host: str, port: int, timeout: float = 3.0):
    """Return (success, latency_ms, error)."""
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, None, f"dns: {e}"
    if not infos:
        return False, None, "no address"

    def attempt(info):
        family, stype, proto, _, sockaddr = info
        s = None
        try:
            s = socket.socket(family, stype, proto)
            s.settimeout(timeout)
            s.connect(sockaddr)
            return True, ""
        except OSError as e:
            return False, type(e).__name__
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    seen, candidates = [], []
    for info in infos:
        if info[0] not in seen:
            seen.append(info[0])
            candidates.append(info)

    last_err = "unreachable"
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(candidates)) as ex:
        futures = [ex.submit(attempt, c) for c in candidates]
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=timeout + 1):
                ok, err = fut.result()
                if ok:
                    return True, (time.perf_counter() - start) * 1000, ""
                last_err = err
        except concurrent.futures.TimeoutError:
            last_err = "timeout"
    return False, None, last_err


# --------------------------------------------------------------------------- #
# Minimal DNS resolver (pure stdlib) - query a *specific* server
# --------------------------------------------------------------------------- #

def build_dns_query(name: str, txid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        struct.pack(">B", len(p)) + p.encode("ascii")
        for p in name.rstrip(".").split(".")
    ) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def parse_dns_answers(data: bytes):
    """Parse A records from a DNS response. Returns list of dotted IPv4 strings."""
    ancount = struct.unpack(">H", data[6:8])[0]
    idx = 12
    # skip question
    while data[idx] != 0:
        if data[idx] & 0xC0:
            idx += 1
            break
        idx += data[idx] + 1
    idx += 1
    idx += 4  # QTYPE + QCLASS
    ips = []
    for _ in range(ancount):
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
        idx += 10
        rdata = data[idx:idx + rdlen]
        idx += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
    return ips


def dns_query_a(name: str, server: str, timeout: float = 3.0):
    """Query an A record from a specific DNS server. Returns (ips, latency_ms, error)."""
    packet = build_dns_query(name, txid=int(time.time() * 1000) & 0xFFFF)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    start = time.perf_counter()
    try:
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(2048)
    except Exception as e:
        return [], None, type(e).__name__
    finally:
        s.close()
    latency = (time.perf_counter() - start) * 1000
    try:
        return parse_dns_answers(data), latency, ""
    except Exception as e:
        return [], latency, f"parse: {e}"


def is_private_or_bogus(ip: str) -> bool:
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(o) != 4:
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 127:
        return True
    if ip == "0.0.0.0":
        return True
    return False


# --------------------------------------------------------------------------- #
# HTTP probe (no redirects followed)
# --------------------------------------------------------------------------- #

def http_probe(url: str, timeout: float = 4.0, want_headers: bool = False):
    """Return (status_code, body_snippet, error) or (status, body, error, headers)."""
    import urllib.request
    import urllib.error

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "NetCheck/2.0"})
    headers = {}
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(2048).decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        status = resp.status
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            pass
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        status = e.code
    except Exception as e:
        if want_headers:
            return None, "", type(e).__name__, {}
        return None, "", type(e).__name__
    if want_headers:
        return status, body, "", headers
    return status, body, ""


# --------------------------------------------------------------------------- #
# TLS (cert validity + clock-skew detection)
# --------------------------------------------------------------------------- #

def tls_check(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    out = {"verified": False, "error": "", "not_before": "", "not_after": "",
           "clock_skew": False, "expired": False, "not_yet_valid": False}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["verified"] = True
                cert = ssock.getpeercert()
                out["not_before"] = cert.get("notBefore", "")
                out["not_after"] = cert.get("notAfter", "")
    except ssl.SSLCertVerificationError as e:
        out["error"] = str(e)
    except Exception as e:
        out["error"] = type(e).__name__

    try:
        nc = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with nc.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
        nb, na = cert.get("notBefore", ""), cert.get("notAfter", "")
        out["not_before"] = out["not_before"] or nb
        out["not_after"] = out["not_after"] or na
        now = time.time()
        if na and now > ssl.cert_time_to_seconds(na):
            out["expired"] = True
        if nb and now < ssl.cert_time_to_seconds(nb):
            out["not_yet_valid"] = True
        if not out["verified"] and out["error"]:
            err = out["error"].lower()
            if ("not yet valid" in err or "expired" in err) and not out["expired"] and not out["not_yet_valid"]:
                out["clock_skew"] = True
    except Exception:
        pass
    return out
