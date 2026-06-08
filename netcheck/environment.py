"""
netcheck.environment
=====================
Detects *where NetCheck is running* and the shape of the local network, so the
diagnosis engine can interpret results correctly instead of misreading normal
virtualized/NAT behaviour as a fault.

Covers:
  - Virtualization / platform: WSL2, VirtualBox, VMware, KVM/QEMU, Hyper-V,
    Xen, Parallels, Docker/LXC/Podman containers, AWS/GCP/Azure, or physical.
  - NAT topology: private vs public egress IP, carrier-grade NAT (RFC 6598),
    and recognised hypervisor NAT fingerprints (VirtualBox 10.0.2.x, WSL2, …).
  - Layer-2 gateway reachability via the ARP / neighbour table (works even when
    ICMP is filtered, which is the norm in WSL2 and many VMs).
  - Proxy environment, VPN / tunnel interfaces.

Everything here is read-only and uses the standard library plus a couple of
read-only system commands.
"""

from __future__ import annotations

import os
import platform
import re
import socket

from .core import run_cmd, OSNAME, http_probe

# MAC OUI prefixes (lower-case, no separators) -> hypervisor.
_MAC_OUI = {
    "080027": "virtualbox", "0a0027": "virtualbox",
    "000569": "vmware", "000c29": "vmware", "001c14": "vmware", "005056": "vmware",
    "00155d": "hyperv",
    "00163e": "xen",
    "525400": "kvm",
    "001c42": "parallels",
}

# DMI vendor / product substrings -> platform (checked case-insensitively).
_DMI_SIGNS = [
    ("virtualbox", "virtualbox"), ("innotek", "virtualbox"), ("oracle", "virtualbox"),
    ("vmware", "vmware"),
    ("qemu", "qemu"), ("bochs", "qemu"),
    ("kvm", "kvm"),
    ("xen", "xen"),
    ("amazon", "aws"), ("ec2", "aws"),
    ("google", "gcp"),
    ("microsoft corporation", "hyperv"),
    ("parallels", "parallels"),
]

# systemd-detect-virt ids -> our platform label.
_SDV = {
    "oracle": "virtualbox", "vmware": "vmware", "kvm": "kvm", "qemu": "qemu",
    "microsoft": "hyperv", "xen": "xen", "amazon": "aws", "parallels": "parallels",
    "docker": "docker", "lxc": "lxc", "lxc-libvirt": "lxc", "podman": "podman",
    "openvz": "openvz", "wsl": "wsl2",
}

_PRETTY = {
    "wsl2": "WSL2 (Windows Subsystem for Linux)", "virtualbox": "Oracle VirtualBox",
    "vmware": "VMware", "kvm": "KVM/QEMU", "qemu": "QEMU", "hyperv": "Microsoft Hyper-V",
    "xen": "Xen", "parallels": "Parallels", "docker": "Docker container",
    "lxc": "LXC container", "podman": "Podman container", "openvz": "OpenVZ container",
    "aws": "Amazon EC2", "gcp": "Google Cloud", "azure": "Microsoft Azure",
    "physical": "physical/bare-metal host", "unknown": "undetermined",
}

_CONTAINERS = {"docker", "lxc", "podman", "openvz"}
_VMS = {"virtualbox", "vmware", "kvm", "qemu", "hyperv", "xen", "parallels"}
_CLOUD = {"aws", "gcp", "azure"}


def _read(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def _is_wsl():
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    blob = (_read("/proc/sys/kernel/osrelease") + " " + _read("/proc/version")).lower()
    return "microsoft" in blob or "wsl" in blob


def _detect_container():
    if os.path.exists("/.dockerenv"):
        return "docker"
    if os.path.exists("/run/.containerenv"):
        return "podman"
    cg = _read("/proc/1/cgroup").lower()
    if "docker" in cg:
        return "docker"
    if "lxc" in cg:
        return "lxc"
    if "kubepods" in cg:
        return "docker"
    return ""


def _detect_dmi():
    blob = " ".join(_read(f"/sys/class/dmi/id/{k}") for k in
                    ("product_name", "sys_vendor", "board_vendor", "bios_vendor",
                     "chassis_vendor")).lower()
    for needle, label in _DMI_SIGNS:
        if needle in blob:
            return label
    return ""


def _primary_mac():
    """Best-effort MAC of the primary interface (Linux), for OUI fallback."""
    try:
        if OSNAME == "Linux":
            base = "/sys/class/net"
            for iface in sorted(os.listdir(base)):
                if iface == "lo":
                    continue
                mac = _read(f"{base}/{iface}/address").replace(":", "").lower()
                if mac and mac != "000000000000":
                    return mac
    except Exception:
        pass
    return ""


def _detect_mac_oui():
    mac = _primary_mac()
    if len(mac) >= 6:
        return _MAC_OUI.get(mac[:6], "")
    return ""


def _detect_cloud():
    blob = (_read("/sys/class/dmi/id/product_name") + " " +
            _read("/sys/class/dmi/id/sys_vendor") + " " +
            _read("/sys/class/dmi/id/chassis_asset_tag")).lower()
    if "amazon" in blob or "ec2" in blob:
        return "aws"
    if "google" in blob:
        return "gcp"
    if "7783-7084-3265-9085-8269-3286-77" in blob:  # Azure chassis asset tag
        return "azure"
    return ""


def detect_environment() -> dict:
    """Return {platform, pretty, family, method, virtual}."""
    plat, method = "", ""

    # 1) WSL is special - it reports as a Hyper-V VM but behaves uniquely.
    if OSNAME == "Linux" and _is_wsl():
        plat, method = "wsl2", "proc/osrelease"

    # 2) Containers
    if not plat:
        c = _detect_container()
        if c:
            plat, method = c, "container marker"

    # 3) systemd-detect-virt (authoritative when present)
    if not plat and OSNAME in ("Linux",):
        rc, out = run_cmd(["systemd-detect-virt"], timeout=4)
        ident = out.strip().lower()
        if rc == 0 and ident and ident != "none":
            plat = _SDV.get(ident, ident)
            method = "systemd-detect-virt"

    # 4) DMI vendor strings (no root needed for these fields)
    if not plat:
        d = _detect_dmi()
        if d:
            plat, method = d, "dmi"

    # 5) Cloud chassis tags
    if not plat:
        cl = _detect_cloud()
        if cl:
            plat, method = cl, "dmi-cloud"

    # 6) Windows / macOS best-effort via system tooling
    if not plat and OSNAME == "Windows":
        rc, out = run_cmd(["wmic", "computersystem", "get", "model"], timeout=6)
        low = out.lower()
        for needle, label in _DMI_SIGNS:
            if needle in low:
                plat, method = label, "wmic"
                break
        if not plat and "virtual" in low:
            plat, method = "hyperv", "wmic"
    if not plat and OSNAME == "Darwin":
        rc, out = run_cmd(["sysctl", "-n", "kern.hv_vmm_present"], timeout=4)
        if out.strip() == "1":
            plat, method = "unknown", "sysctl-hv"

    # 7) MAC OUI fallback
    if not plat:
        m = _detect_mac_oui()
        if m:
            plat, method = m, "mac-oui"

    if not plat:
        plat, method = "physical", "no-virt-markers"

    family = ("container" if plat in _CONTAINERS else
              "wsl" if plat == "wsl2" else
              "cloud" if plat in _CLOUD else
              "vm" if plat in _VMS else
              "physical" if plat == "physical" else "vm")
    return {
        "platform": plat,
        "pretty": _PRETTY.get(plat, plat),
        "family": family,
        "method": method,
        "virtual": plat not in ("physical",),
    }


# --------------------------------------------------------------------------- #
# NAT / egress
# --------------------------------------------------------------------------- #

_EGRESS_PROBES = [
    ("https://www.cloudflare.com/cdn-cgi/trace", "trace"),
    ("https://api.ipify.org", "plain"),
    ("https://checkip.amazonaws.com", "plain"),
]
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def public_egress_ip(timeout: float = 4.0):
    """Return (ip, source) the internet sees us as, or (None, error)."""
    for url, kind in _EGRESS_PROBES:
        status, body, err = http_probe(url, timeout=timeout)
        if status and body:
            if kind == "trace":
                m = re.search(r"^ip=(\S+)", body, re.M)
                if m:
                    return m.group(1), url
            m = _IP_RE.search(body)
            if m:
                return m.group(1), url
    return None, "no egress probe succeeded"


def _in_net(ip, prefix, bits):
    try:
        a = [int(x) for x in ip.split(".")]
        p = [int(x) for x in prefix.split(".")]
    except ValueError:
        return False
    if len(a) != 4:
        return False
    ai = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]
    pi = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (ai & mask) == (pi & mask)


def is_private(ip):
    return (_in_net(ip, "10.0.0.0", 8) or _in_net(ip, "172.16.0.0", 12) or
            _in_net(ip, "192.168.0.0", 16) or _in_net(ip, "169.254.0.0", 16) or
            _in_net(ip, "127.0.0.0", 8))


def is_cgnat(ip):
    return _in_net(ip, "100.64.0.0", 10)


def classify_nat(local_ip, egress_ip, gateway, dns_servers, virt) -> dict:
    out = {"local_ip": local_ip, "egress_ip": egress_ip, "behind_nat": None,
           "type": "", "note": ""}
    plat = virt.get("platform")

    # Recognised hypervisor NAT fingerprints
    if plat == "virtualbox" and local_ip and _in_net(local_ip, "10.0.2.0", 24):
        out.update(behind_nat=True, type="VirtualBox NAT",
                   note="VirtualBox built-in NAT (10.0.2.x, gateway 10.0.2.2, DNS 10.0.2.3).")
        return out
    if plat == "wsl2":
        out.update(behind_nat=True, type="WSL2 NAT",
                   note="WSL2 NAT via the Hyper-V virtual switch; the gateway does not answer ICMP by design.")
        return out

    if egress_ip is None:
        out["type"] = "unknown (no egress detected)"
        return out
    if local_ip and is_cgnat(egress_ip):
        out.update(behind_nat=True, type="carrier-grade NAT (CGNAT)",
                   note=f"Public egress {egress_ip} is in 100.64.0.0/10 - your ISP is double-NATing you. "
                        "Inbound connections/port-forwarding won't work without ISP cooperation.")
        return out
    if local_ip and is_private(local_ip) and not is_private(egress_ip):
        out.update(behind_nat=True, type="standard NAT",
                   note=f"Private {local_ip} behind a router; internet sees {egress_ip}. Normal for home/office/VM networks.")
        return out
    if local_ip and local_ip == egress_ip:
        out.update(behind_nat=False, type="public (no NAT)",
                   note=f"This host holds the public IP {egress_ip} directly.")
        return out
    if local_ip and egress_ip and local_ip != egress_ip:
        out.update(behind_nat=True, type="NAT",
                   note=f"Local address {local_ip} is translated; the internet sees {egress_ip}.")
        return out
    out.update(behind_nat=bool(local_ip and is_private(local_ip)), type="indeterminate")
    return out


# --------------------------------------------------------------------------- #
# Layer-2 gateway reachability (ARP / neighbour table)
# --------------------------------------------------------------------------- #

def neighbor_state(ip: str) -> str:
    """Return 'reachable' | 'unreachable' | 'unknown' for a gateway's L2 entry."""
    if not ip:
        return "unknown"
    try:
        if OSNAME == "Linux":
            rc, out = run_cmd(["ip", "neigh", "show", ip], timeout=4)
            if rc == 0 and out.strip():
                up = out.upper()
                if any(s in up for s in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT")):
                    return "reachable"
                if "FAILED" in up or "INCOMPLETE" in up:
                    return "unreachable"
            arp = _read("/proc/net/arp")
            for line in arp.splitlines()[1:]:
                cols = line.split()
                if cols and cols[0] == ip:
                    # flags col 2: 0x2 = complete
                    return "reachable" if cols[2] != "0x0" else "unreachable"
            return "unknown"
        else:
            rc, out = run_cmd(["arp", "-n", ip] if OSNAME != "Windows" else ["arp", "-a", ip], timeout=4)
            if rc == 0 and re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", out):
                return "reachable"
            return "unknown"
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------- #
# Proxy / VPN
# --------------------------------------------------------------------------- #

def proxy_env() -> dict:
    keys = ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy")
    found = {}
    for k in keys:
        v = os.environ.get(k) or os.environ.get(k.upper())
        if v:
            found[k] = v
    return found


def tunnel_interfaces() -> list:
    """Detect VPN/overlay/tunnel interfaces (tun/tap/wg/ppp/utun)."""
    ifaces = []
    try:
        if OSNAME == "Linux":
            for n in sorted(os.listdir("/sys/class/net")):
                if re.match(r"(tun|tap|wg|ppp|tailscale|zt|nordlynx)", n):
                    ifaces.append(n)
        else:
            rc, out = run_cmd(["ifconfig" if OSNAME == "Darwin" else "ipconfig"], timeout=6)
            ifaces = re.findall(r"\b(utun\d+|ppp\d+|tun\d+|tap\d+)\b", out)
    except Exception:
        pass
    seen, uniq = set(), []
    for i in ifaces:
        if i not in seen:
            seen.add(i)
            uniq.append(i)
    return uniq


def primary_mtu():
    """MTU of the primary (default-route) interface on Linux, else None."""
    try:
        if OSNAME == "Linux":
            rc, out = run_cmd(["ip", "route", "show", "default"], timeout=4)
            m = re.search(r"dev (\S+)", out)
            if m:
                return int(_read(f"/sys/class/net/{m.group(1)}/mtu") or 0) or None
    except Exception:
        pass
    return None
