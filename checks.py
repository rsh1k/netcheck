"""
netcheck.checks
===============
The layered diagnostic checks. Each returns a CheckResult; run_diagnostics()
orchestrates them in OSI order.
"""

from __future__ import annotations

import concurrent.futures
import socket
import time
from datetime import datetime, timezone

from . import core
from .core import (CheckResult, OK, WARN, FAIL, INFO, SKIP,
                   ping, tcp_connect, dns_query_a, http_probe, tls_check,
                   is_private_or_bogus, OSNAME, run_cmd)
from .config import (AppConfig, INTERNET_ANCHORS, PUBLIC_RESOLVERS,
                     DNS_PROBE_NAME, CAPTIVE_PROBES, PORT_NAMES)


def gather_env(cfg: AppConfig) -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": f"{core.platform.system()} {core.platform.release()}",
        "python": core.platform.python_version(),
        "local_ip": core.get_local_ip(),
        "local_ipv6": core.get_local_ipv6(),
        "gateway": core.get_default_gateway(),
        "dns_servers": core.get_configured_dns(),
        "target": cfg.target,
        "operator": cfg.operator,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def check_interface(env: dict) -> CheckResult:
    ip = env.get("local_ip")
    if not ip:
        return CheckResult("Local interface", FAIL,
                           "No outbound IPv4 address - interface down or no DHCP lease",
                           {"has_ip": False})
    if ip.startswith("169.254."):
        return CheckResult("Local interface", FAIL,
                           f"APIPA address {ip} - DHCP failed", {"has_ip": True, "apipa": True})
    return CheckResult("Local interface", OK, f"IPv4 {ip}", {"has_ip": True, "ip": ip})


def check_gateway(env: dict) -> CheckResult:
    gw = env.get("gateway")
    if not gw:
        return CheckResult("Gateway reachability", WARN, "Could not determine default gateway",
                           {"gateway": None})
    st = ping(gw, count=3)
    data = {"gateway": gw, "loss_pct": st.loss_pct, "rtt_avg_ms": st.rtt_avg_ms,
            "reachable": st.reachable}
    if not st.reachable:
        return CheckResult("Gateway reachability", FAIL,
                           f"Cannot reach gateway {gw} - local link/Wi-Fi/router problem", data)
    if st.loss_pct and st.loss_pct > 0:
        return CheckResult("Gateway reachability", WARN, f"{gw} reachable but {st.loss_pct:.0f}% loss", data)
    return CheckResult("Gateway reachability", OK,
                       f"{gw}  {st.rtt_avg_ms:.1f}ms" if st.rtt_avg_ms else f"{gw} reachable", data)


def check_internet(cfg: AppConfig) -> CheckResult:
    results, any_ok = [], False
    for ip, name in INTERNET_ANCHORS:
        ok, lat, err = tcp_connect(ip, 443, timeout=cfg.timeout)
        results.append({"ip": ip, "name": name, "ok": ok, "latency_ms": lat, "err": err})
        any_ok = any_ok or ok
    st = ping(INTERNET_ANCHORS[0][0], count=4)
    data = {"anchors": results, "icmp_loss_pct": st.loss_pct, "icmp_rtt_avg_ms": st.rtt_avg_ms,
            "icmp_jitter_ms": st.jitter_ms, "reachable": any_ok}
    if not any_ok:
        return CheckResult("Internet (by IP)", FAIL,
                           "No route to the internet - cannot reach 1.1.1.1 or 8.8.8.8 on :443", data)
    good = next(r for r in results if r["ok"])
    return CheckResult("Internet (by IP)", OK,
                       f"reachable via {good['name']} {good['ip']}  {good['latency_ms']:.0f}ms", data)


def check_dns(cfg: AppConfig) -> CheckResult:
    per = []
    try:
        sys_ips = sorted({ai[4][0] for ai in socket.getaddrinfo(DNS_PROBE_NAME, None,
                                                                family=socket.AF_INET)})
        sys_err = ""
    except Exception as e:
        sys_ips, sys_err = [], type(e).__name__
    per.append({"server": "system", "name": "system resolver", "ips": sys_ips,
                "error": sys_err, "latency_ms": None})

    def q(item):
        ip, name = item
        ips, lat, err = dns_query_a(DNS_PROBE_NAME, ip, timeout=cfg.timeout)
        return {"server": ip, "name": name, "ips": ips, "error": err, "latency_ms": lat}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PUBLIC_RESOLVERS)) as ex:
        per.extend(ex.map(q, PUBLIC_RESOLVERS))

    sys_ok = bool(sys_ips)
    public_ok = [r for r in per if r["server"] != "system" and r["ips"]]
    hijacked = [r["name"] for r in per for ip in r["ips"] if is_private_or_bogus(ip)]
    data = {"resolvers": per, "system_ok": sys_ok, "public_ok_count": len(public_ok),
            "hijack_suspects": hijacked}

    if hijacked:
        return CheckResult("DNS resolution", WARN,
                           f"Suspicious private-IP answers from: {', '.join(set(hijacked))} - possible hijack/captive portal",
                           data)
    if not sys_ok and not public_ok:
        return CheckResult("DNS resolution", FAIL, "DNS fully broken - no resolver answered", data)
    if not sys_ok and public_ok:
        return CheckResult("DNS resolution", FAIL,
                           "System DNS broken, but public resolvers (1.1.1.1) work - your configured DNS is the problem",
                           data)
    if sys_ok and len(public_ok) < len(PUBLIC_RESOLVERS):
        slow = ", ".join(r["name"] for r in per if r["server"] != "system" and not r["ips"])
        return CheckResult("DNS resolution", WARN,
                           f"System DNS OK; unreachable public resolvers: {slow}", data)
    avg = [r["latency_ms"] for r in public_ok if r["latency_ms"]]
    lat_txt = f"  avg {sum(avg)/len(avg):.0f}ms" if avg else ""
    return CheckResult("DNS resolution", OK,
                       f"resolves on system + {len(public_ok)} public resolvers{lat_txt}", data)


def check_ports(cfg: AppConfig) -> CheckResult:
    target, ports = cfg.target, cfg.ports

    def probe(port):
        ok, lat, err = tcp_connect(target, port, timeout=cfg.timeout)
        return {"port": port, "name": PORT_NAMES.get(port, "?"), "open": ok,
                "latency_ms": lat, "error": err}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ports))) as ex:
        port_results = list(ex.map(probe, ports))
    port_results.sort(key=lambda p: ports.index(p["port"]))

    opened = [p for p in port_results if p["open"]]
    dns_failed = any("dns" in (p["error"] or "") for p in port_results)
    data = {"target": target, "ports": port_results}
    summary = "  ".join(f"{p['port']}/{p['name']}{'✓' if p['open'] else '✗'}" for p in port_results)
    name = f"TCP ports → {target}"
    if dns_failed:
        return CheckResult(name, FAIL, f"cannot resolve {target} (DNS) - port test inconclusive", data)
    if not opened:
        return CheckResult(name, FAIL, f"no ports reachable on {target}  [{summary}]", data)
    if len(opened) < len(port_results):
        return CheckResult(name, WARN, summary, data)
    return CheckResult(name, OK, summary, data)


def check_http_captive(cfg: AppConfig) -> CheckResult:
    def probe(item):
        url, exp_status, exp_body = item
        status, body, err = http_probe(url, timeout=cfg.timeout)
        matched = (status == exp_status and (exp_body is None or exp_body.lower() in body.lower()))
        return {"url": url, "status": status, "expected": exp_status, "matched": matched,
                "intercepted": (status is not None and not matched), "err": err}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(CAPTIVE_PROBES)) as ex:
        probes = list(ex.map(probe, CAPTIVE_PROBES))
    any_ok = any(p["matched"] for p in probes)
    captive = any(p["intercepted"] for p in probes)
    data = {"probes": probes, "captive_portal": captive and not any_ok, "internet_open": any_ok}
    if any_ok and not captive:
        return CheckResult("HTTP / captive portal", OK, "open internet confirmed (probes passed)", data)
    if captive:
        return CheckResult("HTTP / captive portal", WARN,
                           "Captive portal detected - a login/splash page is intercepting traffic.", data)
    return CheckResult("HTTP / captive portal", FAIL,
                       "Connectivity probes failed - HTTP egress blocked or no internet", data)


def check_tls(cfg: AppConfig) -> CheckResult:
    host = cfg.target
    name = f"TLS → {host}"
    if 443 not in cfg.ports:
        return CheckResult(name, SKIP, "443 not in port list")
    res = tls_check(host, 443, timeout=cfg.timeout)
    if res["verified"]:
        exp = res.get("not_after", "")
        return CheckResult(name, OK, "certificate valid" + (f" (expires {exp})" if exp else ""), res)
    if res["clock_skew"]:
        return CheckResult(name, WARN, "TLS validation failed - system clock looks wrong", res)
    if res["expired"]:
        return CheckResult(name, WARN, "server certificate is expired", res)
    if res["not_yet_valid"]:
        return CheckResult(name, WARN, "server certificate not yet valid", res)
    return CheckResult(name, WARN, f"TLS handshake/validation failed: {res['error']}", res)


def check_quality(internet_result: CheckResult) -> CheckResult:
    if not internet_result or not internet_result.data.get("reachable"):
        return CheckResult("Connection quality", SKIP, "internet unreachable")
    d = internet_result.data
    loss, rtt, jit = d.get("icmp_loss_pct"), d.get("icmp_rtt_avg_ms"), d.get("icmp_jitter_ms")
    data = {"loss_pct": loss, "rtt_avg_ms": rtt, "jitter_ms": jit}
    parts = []
    if rtt is not None:
        parts.append(f"{rtt:.0f}ms RTT")
    if jit is not None:
        parts.append(f"{jit:.0f}ms jitter")
    if loss is not None:
        parts.append(f"{loss:.0f}% loss")
    detail = "  ".join(parts) or "no ICMP stats (ICMP may be filtered)"
    status, notes = OK, []
    if loss is not None and loss >= 5:
        status, _ = WARN, notes.append("packet loss")
    if rtt is not None and rtt >= 200:
        status, _ = WARN, notes.append("high latency")
    if jit is not None and jit >= 50:
        status, _ = WARN, notes.append("high jitter")
    if notes:
        detail += "  (" + ", ".join(notes) + ")"
    return CheckResult("Connection quality", status, detail, data)


def _df_ping(host: str, payload: int) -> bool:
    if OSNAME == "Windows":
        cmd = ["ping", "-n", "1", "-w", "2000", "-f", "-l", str(payload), host]
    elif OSNAME == "Darwin":
        cmd = ["ping", "-c", "1", "-D", "-s", str(payload), host]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), host]
    rc, out = run_cmd(cmd, timeout=5)
    low = out.lower()
    if "too long" in low or "frag" in low or "needs to be fragmented" in low:
        return False
    return rc == 0 and ("1 received" in low or "1 packets received" in low
                        or "received = 1" in low or "ttl=" in low)


def check_mtu(cfg: AppConfig) -> CheckResult:
    target = INTERNET_ANCHORS[0][0]
    small_ok = _df_ping(target, 1200)
    big_ok = _df_ping(target, 1472)
    data = {"target": target, "df_1200": small_ok, "df_1500": big_ok}
    if small_ok and not big_ok:
        lo, hi = 1200, 1472
        while hi - lo > 8:
            mid = (lo + hi) // 2
            if _df_ping(target, mid):
                lo = mid
            else:
                hi = mid
        data["estimated_mtu"] = lo + 28
        return CheckResult("Path MTU", WARN,
                           f"MTU black hole - 1500B blocked, ~{lo+28}B works (VPN/PPPoE). Clamp MSS / lower MTU.", data)
    if not small_ok and not big_ok:
        return CheckResult("Path MTU", SKIP, "ICMP DF probes filtered - cannot test", data)
    return CheckResult("Path MTU", OK, "1500-byte packets pass (no black hole)", data)


def check_traceroute(cfg: AppConfig) -> CheckResult:
    target = cfg.target
    name = f"Traceroute → {target}"
    if OSNAME == "Windows":
        cmd = ["tracert", "-d", "-h", "20", "-w", "1500", target]
    else:
        cmd = ["traceroute", "-n", "-m", "20", "-w", "2", target]
    rc, out = run_cmd(cmd, timeout=60)
    if rc == 127:
        return CheckResult(name, SKIP, "traceroute not installed", {"raw": out})
    import re
    lines = [l for l in out.splitlines() if l.strip()]
    hops = len([l for l in lines if re.match(r"\s*\d+", l)])
    dead = 0
    for l in reversed(lines):
        if re.match(r"\s*\d+", l) and l.count("*") >= 3:
            dead += 1
        elif re.match(r"\s*\d+", l):
            break
    data = {"target": target, "hops": hops, "dead_tail_hops": dead, "raw": out}
    if dead >= 2:
        return CheckResult(name, WARN, f"path stops responding after hop {hops-dead} ({hops} total)", data)
    return CheckResult(name, OK, f"reached target in {hops} hops", data)


def check_ipv6(cfg: AppConfig, env: dict) -> CheckResult:
    if not env.get("local_ipv6"):
        return CheckResult("IPv6", INFO, "no global IPv6 address (IPv4-only network)", {"available": False})
    ok, lat, err = tcp_connect("2606:4700:4700::1111", 443, timeout=cfg.timeout)
    data = {"available": True, "reachable": ok, "latency_ms": lat}
    if ok:
        return CheckResult("IPv6", OK, f"reachable  {lat:.0f}ms", data)
    return CheckResult("IPv6", WARN,
                       "IPv6 present but no IPv6 internet - may cause slow 'Happy Eyeballs' fallbacks", data)


def run_diagnostics(cfg: AppConfig, env: dict, emit=None):
    """Run all diagnostic checks. `emit(result)` is called as each completes."""
    results = []

    def step(fn, *a):
        t0 = time.perf_counter()
        try:
            r = fn(*a)
        except Exception as e:
            r = CheckResult(getattr(fn, "__name__", "check"), FAIL, f"internal error: {e}")
        r.duration_ms = (time.perf_counter() - t0) * 1000
        results.append(r)
        if emit:
            emit(r)
        return r

    step(check_interface, env)
    step(check_gateway, env)
    inet = step(check_internet, cfg)
    step(check_dns, cfg)
    step(check_ports, cfg)
    step(check_http_captive, cfg)
    step(check_tls, cfg)
    step(lambda c: check_quality(inet), cfg)

    if cfg.full:
        step(check_ipv6, cfg, env)
        step(check_mtu, cfg)
        step(check_traceroute, cfg)
    return results
