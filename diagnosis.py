"""
netcheck.diagnosis
==================
The rule-based "brain": turns the pattern of check results into a ranked list
of likely root causes with concrete fixes. This runs locally and instantly;
the optional AI layer (netcheck.ai) builds on top of these structured findings.
"""

from __future__ import annotations

from .core import OK, WARN, FAIL, INFO, SKIP, SEVERITY


def _finder(results):
    by_name = {r.name: r for r in results}

    def find(substr):
        for name, r in by_name.items():
            if substr in name:
                return r
        return None
    return find


def diagnose(results, target: str) -> list:
    f = []
    find = _finder(results)

    iface = find("Local interface")
    gw = find("Gateway reachability")
    inet = find("Internet (by IP)")
    dns = find("DNS resolution")
    http = find("captive portal")
    tls = find("TLS →")
    mtu = find("Path MTU")
    ports = find("TCP ports")
    quality = find("Connection quality")

    def add(sev, title, cause, fix):
        f.append({"severity": sev, "title": title, "cause": cause, "fix": fix})

    # L1/L2 - no address
    if iface and iface.status == FAIL:
        if iface.data.get("apipa"):
            add(FAIL, "DHCP failure",
                "Self-assigned 169.254.x.x address - no DHCP lease from the router.",
                "Renew DHCP (reconnect), check the router's DHCP pool, or set a static IP.")
        else:
            add(FAIL, "No network interface up",
                "No outbound IPv4 address; the link is down or unassociated.",
                "Check the cable/Wi-Fi and that the adapter is enabled. Fix this first.")
        return _rank(f)

    # L3 local - gateway is the root cause if unreachable
    if gw and gw.status == FAIL:
        add(FAIL, "Cannot reach your router (gateway)",
            f"Pings to the gateway {gw.data.get('gateway')} fail - the problem is between you and the router, not the ISP.",
            "Check Wi-Fi/Ethernet, reconnect, or reboot the router. Everything downstream depends on it.")
        return _rank(f)

    # L3 WAN - gateway OK, internet not
    if inet and inet.status == FAIL and (not gw or gw.status != FAIL):
        add(FAIL, "Internet is down past your router (likely ISP/modem)",
            "The router is reachable but nothing beyond it is (1.1.1.1 and 8.8.8.8 both unreachable on :443).",
            "Reboot the modem/ONT, check for an ISP outage and the WAN light. If others are down too, it's the ISP.")

    # DNS patterns
    if dns and dns.status == FAIL and inet and inet.status == OK:
        if dns.data.get("public_ok_count", 0) > 0 and not dns.data.get("system_ok"):
            add(FAIL, "Your DNS server is broken (the internet itself is fine)",
                "Internet works by IP and public resolvers (1.1.1.1) answer, but your configured DNS does not - so names won't load.",
                "Switch DNS to 1.1.1.1 / 8.8.8.8, or flush the DNS cache.")
        else:
            add(FAIL, "DNS resolution is failing",
                "Name lookups fail across resolvers while raw IP connectivity works.",
                "Set DNS to 1.1.1.1 / 8.8.8.8, flush the cache, check for a misbehaving local DNS/VPN.")
    if dns and dns.data.get("hijack_suspects"):
        add(WARN, "Possible DNS hijacking / interception",
            "A resolver returned private/bogus IPs for a public domain - typical of captive portals or tampering.",
            "Complete any captive-portal login; otherwise use a trusted resolver (1.1.1.1) and consider DNS-over-HTTPS.")

    # Captive portal
    if http and http.data.get("captive_portal"):
        add(WARN, "Captive portal is blocking you",
            "Connectivity probes were intercepted by a login/splash page (hotel/airport/café Wi-Fi).",
            "Open any http:// site in a browser to trigger the portal, then sign in.")

    # Clock skew
    if tls and tls.data.get("clock_skew"):
        add(WARN, "System clock is wrong (breaks HTTPS everywhere)",
            "TLS certificates failed validation consistent with a wrong system date/time, not a server fault.",
            "Fix date/time (enable network time / NTP); HTTPS should work again immediately.")

    # MTU black hole
    if mtu and mtu.status == WARN and mtu.data.get("estimated_mtu"):
        add(WARN, "Path MTU black hole",
            f"Small packets pass but 1500-byte packets are dropped (usable MTU ≈ {mtu.data['estimated_mtu']}B) - pages start loading then hang. Classic on VPN/PPPoE.",
            f"Lower interface MTU to ~{mtu.data['estimated_mtu']} or clamp TCP MSS (MSS = MTU - 40).")

    # Specific port blocked
    if inet and inet.status == OK and ports and ports.status in (FAIL, WARN):
        closed = [p for p in ports.data.get("ports", []) if not p["open"]]
        if closed and not (dns and dns.status == FAIL):
            names = ", ".join(f"{p['port']}/{p['name']}" for p in closed)
            add(WARN, f"Specific port(s) blocked to {target}",
                f"General internet is fine but {names} are unreachable - a firewall, the remote service, or egress filtering (not your link).",
                "Confirm the remote service is up, check firewall egress rules, and test from another network.")

    # Quality degradation
    if quality and quality.status == WARN:
        add(WARN, "Connection works but quality is degraded",
            f"Reachability is fine but {quality.detail} indicates instability (Wi-Fi signal, congestion, or a flaky link).",
            "Move closer to the AP / use Ethernet, check for saturation, watch for retransmits.")

    # ---- Security findings (when present) ----
    for r in results:
        if r.category != "security":
            continue
        if r.status in (FAIL, WARN):
            add(r.status, f"Security: {r.name.split(' →')[0]}",
                r.detail,
                "Review the security section; remediate per the detail above.")

    if not f:
        if all(r.status in (OK, INFO, SKIP) for r in results):
            add(OK, "Network is healthy",
                "All layers passed: local link, gateway, internet, DNS, ports, HTTP, and TLS.",
                "No action needed. If a specific app still fails, the issue is app-side.")
    return _rank(f)


def _rank(findings):
    return sorted(findings, key=lambda x: -SEVERITY.get(x["severity"], 0))
