#!/usr/bin/env python3
"""
WiFind: lightweight local network scanner using ARP.

ARP scanning works on the local broadcast domain only. Run this tool only on
networks you own or are authorized to inspect.
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Iterable

try:
    from scapy.all import ARP, Ether, conf, get_if_addr, srp
    if os.name == "nt":
        from scapy.arch.windows import get_windows_if_list
    else:
        get_windows_if_list = None
except ImportError as exc:
    ARP = Ether = conf = get_if_addr = srp = None  # type: ignore[assignment]
    get_windows_if_list = None  # type: ignore[assignment]
    SCAPY_IMPORT_ERROR: ImportError | None = exc
else:
    SCAPY_IMPORT_ERROR = None


DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_RETRIES = 1
UNKNOWN_HOSTNAMES = {"", "Unknown", "Unknown Device", "Skipped"}


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str
    hostname: str
    vendor: str
    source: str = "arp"

    def as_dict(self) -> dict[str, str]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "source": self.source,
        }


@dataclass(frozen=True)
class InterfaceInfo:
    id: str
    name: str
    description: str
    ip: str
    mac: str
    is_active: bool

    @property
    def label(self) -> str:
        if self.name and self.ip:
            return f"{self.name} ({self.ip})"
        return self.name or self.description or self.id

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "ip": self.ip,
            "mac": self.mac,
            "label": self.label,
            "isActive": self.is_active,
        }


def is_admin() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def require_admin() -> None:
    if not is_admin():
        if os.name == "nt":
            raise RuntimeError("Administrator privileges are required. Open PowerShell with 'Run as Administrator'.")
        raise RuntimeError("Root privileges are required. Re-run this command with sudo.")


def ensure_scapy_available() -> None:
    if SCAPY_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Scapy is not installed. Install it with: python -m pip install -r requirements.txt"
        ) from SCAPY_IMPORT_ERROR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan the local network with ARP and list responding devices."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="CIDR range to scan, for example 192.168.1.0/24. Defaults to the active interface subnet.",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to use. Defaults to Scapy's active route interface.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Seconds to wait for ARP replies. Default: {DEFAULT_TIMEOUT_SECONDS}",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Number of ARP retry attempts. Default: {DEFAULT_RETRIES}",
    )
    parser.add_argument(
        "--no-hostnames",
        action="store_true",
        help="Skip reverse DNS lookups. This makes scans faster on many home networks.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Do not merge devices from the operating system ARP cache.",
    )
    return parser.parse_args()


def active_interface() -> str:
    """Return the interface used for the default IPv4 route."""
    ensure_scapy_available()
    try:
        interface, _source_ip, _gateway = conf.route.route("0.0.0.0")
    except Exception as exc:
        raise RuntimeError("Could not determine the active network interface.") from exc

    if not interface:
        raise RuntimeError("Could not determine the active network interface.")
    return str(interface)


def default_gateway_for_interface(interface: str) -> str | None:
    ensure_scapy_available()
    try:
        for destination, netmask, gateway, route_interface, *_rest in conf.route.routes:
            if destination == 0 and netmask == 0 and str(route_interface) == interface:
                return str(gateway) if gateway and gateway != "0.0.0.0" else None
    except Exception:
        return None
    return None


def _interface_from_guid(guid: str) -> str | None:
    normalized_guid = guid.strip("{}").lower()
    for interface in conf.ifaces.values():
        network_name = str(getattr(interface, "network_name", "") or "")
        if normalized_guid in network_name.lower():
            return network_name
    return None


def _friendly_windows_interfaces(active_id: str) -> list[InterfaceInfo]:
    ensure_scapy_available()

    if get_windows_if_list is None:
        return []

    interfaces: list[InterfaceInfo] = []
    for adapter in get_windows_if_list():
        ips = [ip for ip in adapter.get("ips", []) if _is_ipv4(ip)]
        if not ips:
            continue

        npf_id = _interface_from_guid(str(adapter.get("guid", "")))
        if not npf_id:
            continue

        name = str(adapter.get("name", "") or "")
        description = str(adapter.get("description", "") or "")
        if _is_noise_windows_adapter(name, description):
            continue

        interfaces.append(
            InterfaceInfo(
                id=npf_id,
                name=name,
                description=description,
                ip=ips[0],
                mac=str(adapter.get("mac", "") or "").upper(),
                is_active=npf_id == active_id,
            )
        )

    return sorted(interfaces, key=lambda item: (not item.is_active, item.name.lower()))


def _fallback_interfaces(active_id: str) -> list[InterfaceInfo]:
    interfaces: list[InterfaceInfo] = []
    for interface in conf.ifaces.values():
        interface_id = str(getattr(interface, "network_name", "") or interface)
        ip = str(getattr(interface, "ip", "") or "")
        if not _is_ipv4(ip):
            continue

        interfaces.append(
            InterfaceInfo(
                id=interface_id,
                name=str(getattr(interface, "name", "") or interface_id),
                description=str(getattr(interface, "description", "") or ""),
                ip=ip,
                mac=str(getattr(interface, "mac", "") or "").upper(),
                is_active=interface_id == active_id,
            )
        )
    return sorted(interfaces, key=lambda item: (not item.is_active, item.name.lower()))


def available_interfaces() -> list[InterfaceInfo]:
    ensure_scapy_available()
    active_id = active_interface()
    interfaces = _friendly_windows_interfaces(active_id) if os.name == "nt" else []
    return interfaces or _fallback_interfaces(active_id)


def display_name_for_interface(interface: str) -> str:
    for item in available_interfaces():
        if item.id == interface:
            return item.label
    return interface


def resolve_interface(interface: str | None) -> str:
    ensure_scapy_available()
    if not interface:
        return active_interface()

    requested = interface.strip()
    if not requested:
        return active_interface()

    for item in available_interfaces():
        candidates = {
            item.id.lower(),
            item.name.lower(),
            item.description.lower(),
            item.label.lower(),
        }
        if requested.lower() in candidates:
            return item.id

    try:
        return str(conf.ifaces.dev_from_name(requested))
    except Exception as exc:
        raise RuntimeError(f"Network interface '{requested}' was not found.") from exc


def scapy_interface(interface: str) -> Any:
    ensure_scapy_available()
    for candidate in conf.ifaces.values():
        if str(getattr(candidate, "network_name", "") or candidate) == interface:
            return candidate

    try:
        return conf.ifaces.dev_from_name(interface)
    except Exception:
        return interface


def interface_ipv4(interface: str) -> str:
    ensure_scapy_available()
    try:
        ip_address = get_if_addr(interface)
    except Exception as exc:
        raise RuntimeError(f"Could not read IPv4 address for interface '{interface}'.") from exc

    if not ip_address or ip_address == "0.0.0.0":
        raise RuntimeError(f"Interface '{interface}' does not have a usable IPv4 address.")
    return ip_address


def _is_ipv4(value: Any) -> bool:
    try:
        ipaddress.IPv4Address(str(value))
    except ipaddress.AddressValueError:
        return False
    return True


def _is_noise_windows_adapter(name: str, description: str) -> bool:
    text = f"{name} {description}".lower()
    blocked_terms = (
        "loopback",
        "miniport",
        "filter",
        "teredo",
        "6to4",
        "ip-https",
        "wintun",
    )
    return any(term in text for term in blocked_terms)


def local_ipv4_for_interface(interface: str) -> str | None:
    try:
        return interface_ipv4(interface)
    except RuntimeError:
        return None


def route_subnet_for_interface(interface: str, local_ip: str) -> ipaddress.IPv4Network:
    """
    Find the connected IPv4 route for the selected interface.

    Scapy route entries vary a bit by platform, but the first three fields are
    destination, netmask, and gateway. If no specific route is available, use a
    conservative /24 fallback for typical home Wi-Fi networks.
    """
    ip_obj = ipaddress.IPv4Address(local_ip)

    try:
        routes = conf.route.routes
    except Exception:
        routes = []

    best_match: ipaddress.IPv4Network | None = None
    for route in routes:
        if len(route) < 4 or str(route[3]) != interface:
            continue

        destination_raw, netmask_raw = route[0], route[1]
        try:
            destination = socket.inet_ntoa(int(destination_raw).to_bytes(4, "big"))
            netmask = socket.inet_ntoa(int(netmask_raw).to_bytes(4, "big"))
            network = ipaddress.IPv4Network(f"{destination}/{netmask}", strict=False)
        except Exception:
            continue

        if ip_obj in network and not network.is_loopback and network.prefixlen <= 30:
            if best_match is None or network.prefixlen > best_match.prefixlen:
                best_match = network

    if best_match is not None:
        return best_match

    return ipaddress.IPv4Network(f"{local_ip}/24", strict=False)


def target_network(target: str | None, interface: str) -> ipaddress.IPv4Network:
    if target:
        try:
            return ipaddress.IPv4Network(target, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid target network '{target}'. Use CIDR notation like 192.168.1.0/24.") from exc

    local_ip = interface_ipv4(interface)
    return route_subnet_for_interface(interface, local_ip)


def discovery_networks(interface: str, target: str | None = None) -> list[ipaddress.IPv4Network]:
    """Return scan targets for automatic discovery."""
    if target:
        return [target_network(target, interface)]

    local_ip = interface_ipv4(interface)
    networks: list[ipaddress.IPv4Network] = []
    for candidate in (
        route_subnet_for_interface(interface, local_ip),
        ipaddress.IPv4Network(f"{local_ip}/24", strict=False),
    ):
        if candidate not in networks:
            networks.append(candidate)
    return networks


def is_locally_administered_mac(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (IndexError, ValueError):
        return False
    return bool(first_octet & 0b00000010)


def vendor_for_mac(mac: str) -> str:
    """Resolve a MAC vendor from Scapy's bundled/manuf database when available."""
    ensure_scapy_available()

    if is_locally_administered_mac(mac):
        return "Private/randomized MAC"

    manufdb = getattr(conf, "manufdb", None)
    if manufdb is None:
        return "Unknown"

    for method_name in ("_get_manuf", "get_manuf"):
        method = getattr(manufdb, method_name, None)
        if method is None:
            continue
        try:
            result = method(mac)
        except Exception:
            continue

        if isinstance(result, tuple):
            for value in reversed(result):
                if value and isinstance(value, str) and value.lower() != mac.lower():
                    return value
        elif isinstance(result, str) and result and result.lower() != mac.lower():
            return result

    return "Unknown"


def hostname_for_ip(ip_address: str) -> str:
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        hostname = ""

    clean_hostname = normalize_hostname(hostname, ip_address)
    if clean_hostname:
        return clean_hostname

    command_hostname = command_hostname_for_ip(ip_address)
    if command_hostname:
        return command_hostname

    netbios_name = netbios_hostname_for_ip(ip_address)
    return netbios_name or "Unknown Device"


def normalize_hostname(hostname: str, ip_address: str) -> str | None:
    cleaned = hostname.strip().rstrip(".")
    if not cleaned or cleaned == ip_address:
        return None
    return cleaned


def command_hostname_for_ip(ip_address: str) -> str | None:
    return nslookup_hostname_for_ip(ip_address) or ping_hostname_for_ip(ip_address)


def nslookup_hostname_for_ip(ip_address: str) -> str | None:
    try:
        result = subprocess.run(
            ["nslookup", ip_address],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        match = re.match(r"\s*Name:\s+(.+?)\s*$", line, flags=re.IGNORECASE)
        if match:
            return normalize_hostname(match.group(1), ip_address)
    return None


def ping_hostname_for_ip(ip_address: str) -> str | None:
    if os.name != "nt":
        return None

    try:
        result = subprocess.run(
            ["ping", "-a", "-n", "1", "-w", "500", ip_address],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for line in result.stdout.splitlines():
        match = re.match(r"\s*Pinging\s+([^\s\[]+)\s+\[" + re.escape(ip_address) + r"\]", line, flags=re.IGNORECASE)
        if match:
            return normalize_hostname(match.group(1), ip_address)
    return None


def netbios_hostname_for_ip(ip_address: str) -> str | None:
    if os.name != "nt":
        return None

    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip_address],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        match = re.match(r"\s*([^\s<]{1,15})\s+<00>\s+UNIQUE", line, flags=re.IGNORECASE)
        if match:
            name = match.group(1).strip()
            if name and name.upper() != "WORKGROUP":
                return name
    return None


def scan_network(
    network: ipaddress.IPv4Network,
    interface: str,
    timeout: float,
    retries: int,
    resolve_hostnames: bool,
) -> list[Device]:
    ensure_scapy_available()
    capture_interface = scapy_interface(interface)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

    try:
        answered, _unanswered = srp(
            packet,
            iface=capture_interface,
            timeout=timeout,
            retry=retries,
            verbose=False,
        )
    except PermissionError as exc:
        raise RuntimeError("Permission denied. Re-run this script as Administrator/root.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not scan on interface '{interface}': {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"ARP scan failed on interface '{interface}': {exc}") from exc

    devices_by_ip: dict[str, Device] = {}
    for _sent, received in answered:
        ip_address = str(received.psrc)
        mac_address = str(received.hwsrc).upper()
        devices_by_ip[ip_address] = Device(
            ip=ip_address,
            mac=mac_address,
            hostname=hostname_for_ip(ip_address) if resolve_hostnames else "Skipped",
            vendor=vendor_for_mac(mac_address),
            source="arp",
        )

    return sorted(devices_by_ip.values(), key=lambda device: ipaddress.IPv4Address(device.ip))


def scan_network_sources(
    network: ipaddress.IPv4Network,
    interface: str,
    timeout: float,
    retries: int,
    resolve_hostnames: bool,
    include_cache: bool = True,
) -> list[Device]:
    local_ip = local_ipv4_for_interface(interface)
    groups = [scan_network(network, interface, timeout, retries, resolve_hostnames)]
    if include_cache:
        groups.append(arp_cache_devices(network, local_ip, resolve_hostnames))
    return merge_devices(groups)


def arp_cache_devices(
    network: ipaddress.IPv4Network,
    interface_ip: str | None,
    resolve_hostnames: bool,
) -> list[Device]:
    if os.name != "nt":
        return []

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0:
        return []

    current_interface: str | None = None
    devices: list[Device] = []
    for line in result.stdout.splitlines():
        interface_match = re.match(r"\s*Interface:\s+(\d+\.\d+\.\d+\.\d+)\s+---", line)
        if interface_match:
            current_interface = interface_match.group(1)
            continue

        entry_match = re.match(
            r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+dynamic\s*$",
            line,
        )
        if not entry_match:
            continue

        ip_address = entry_match.group(1)
        if interface_ip and current_interface != interface_ip:
            continue
        if ipaddress.IPv4Address(ip_address) not in network:
            continue

        mac_address = entry_match.group(2).replace("-", ":").upper()
        devices.append(
            Device(
                ip=ip_address,
                mac=mac_address,
                hostname=hostname_for_ip(ip_address) if resolve_hostnames else "Skipped",
                vendor=vendor_for_mac(mac_address),
                source="arp-cache",
            )
        )

    return devices


def merge_devices(device_groups: Iterable[Iterable[Device]]) -> list[Device]:
    devices_by_ip: dict[str, Device] = {}
    source_rank = {"arp": 0, "arp+cache": 0, "arp-cache": 1}

    for group in device_groups:
        for device in group:
            existing = devices_by_ip.get(device.ip)
            if existing is None:
                devices_by_ip[device.ip] = device
                continue

            preferred = device if source_rank.get(device.source, 9) < source_rank.get(existing.source, 9) else existing
            hostname = preferred.hostname
            if hostname in UNKNOWN_HOSTNAMES and device.hostname not in UNKNOWN_HOSTNAMES:
                hostname = device.hostname

            vendor = preferred.vendor
            if vendor == "Unknown" and device.vendor != "Unknown":
                vendor = device.vendor

            source = preferred.source if existing.source == device.source else "arp+cache"
            devices_by_ip[device.ip] = Device(
                ip=preferred.ip,
                mac=preferred.mac,
                hostname=hostname,
                vendor=vendor,
                source=source,
            )

    return sorted(devices_by_ip.values(), key=lambda device: ipaddress.IPv4Address(device.ip))


def smart_scan(
    interface: str,
    target: str | None,
    timeout: float,
    retries: int,
    resolve_hostnames: bool,
    include_cache: bool = True,
) -> tuple[list[Device], list[ipaddress.IPv4Network]]:
    networks = discovery_networks(interface, target)
    local_ip = local_ipv4_for_interface(interface)
    groups: list[list[Device]] = []

    for network in networks:
        groups.append(
            scan_network(
                network=network,
                interface=interface,
                timeout=timeout,
                retries=retries,
                resolve_hostnames=resolve_hostnames,
            )
        )
        if include_cache:
            groups.append(arp_cache_devices(network, local_ip, resolve_hostnames))

    return merge_devices(groups), networks


def print_table(devices: Iterable[Device]) -> None:
    rows = [(device.ip, device.mac, device.vendor, device.hostname, device.source) for device in devices]
    headers = ("IP Address", "MAC Address", "Vendor", "Hostname", "Source")
    widths = [len(header) for header in headers]

    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    header_line = "| " + " | ".join(header.ljust(width) for header, width in zip(headers, widths)) + " |"

    print(separator)
    print(header_line)
    print(separator)

    if not rows:
        empty = "No ARP replies received"
        print("| " + empty.ljust(sum(widths) + (3 * (len(widths) - 1))) + " |")
    else:
        for row in rows:
            print("| " + " | ".join(value.ljust(width) for value, width in zip(row, widths)) + " |")

    print(separator)


def main() -> int:
    args = parse_args()

    try:
        require_admin()
        interface = resolve_interface(args.interface)
        devices, networks = smart_scan(
            interface=interface,
            target=args.target,
            timeout=args.timeout,
            retries=args.retries,
            resolve_hostnames=not args.no_hostnames,
            include_cache=not args.no_cache,
        )
        network_label = ", ".join(str(network) for network in networks)
        print(f"Scanned {network_label} on interface {display_name_for_interface(interface)}.")
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return 130

    print_table(devices)
    print(f"\nFound {len(devices)} device(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
