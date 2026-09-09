#!/usr/bin/env python3
"""
Local web UI for WiFind.

The server binds to localhost by default and calls scanner.py for ARP scans.
Run it with administrator/root privileges for live scans.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from scanner import (
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    UNKNOWN_HOSTNAMES,
    active_interface,
    arp_cache_devices,
    available_interfaces,
    default_gateway_for_interface,
    discovery_networks,
    display_name_for_interface,
    is_admin,
    is_locally_administered_mac,
    local_ipv4_for_interface,
    merge_devices,
    require_admin,
    resolve_interface,
    scan_network,
    smart_scan,
    target_network,
)


PROJECT_ROOT = Path(__file__).resolve().parent
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
STATIC_ROOT = BUNDLE_ROOT / "static"
DEFAULT_STATE_ROOT = Path(os.environ.get("LOCALAPPDATA", PROJECT_ROOT)) / "WiFind" if sys.platform == "win32" else PROJECT_ROOT / ".wifind"
STATE_DIR = Path(os.environ.get("WIFIND_STATE_DIR", str(DEFAULT_STATE_ROOT)))
HISTORY_PATH = STATE_DIR / "device_history.json"
SNAPSHOT_PATH = STATE_DIR / "last_scan_snapshot.json"
NETWORK_HISTORY_PATH = STATE_DIR / "network_history.json"
MAX_NETWORK_HISTORY_ENTRIES = 250
CANCELLED_SCANS: set[str] = set()


class WiFindHandler(SimpleHTTPRequestHandler):
    server_version = "WiFind/1.0"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.path = "/index.html"
            return super().do_GET()

        if parsed.path == "/api/context":
            return self.handle_context()

        if parsed.path == "/api/scan-stream":
            return self.handle_scan_stream(parsed.query)

        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/scan":
            return self.handle_scan()

        if parsed.path == "/api/alias":
            return self.handle_alias()

        if parsed.path == "/api/cancel":
            return self.handle_cancel()

        self.send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def handle_context(self) -> None:
        try:
            interface = active_interface()
            network = target_network(None, interface)
            interfaces = available_interfaces()
        except RuntimeError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.OK)
            return

        local_ip = local_ipv4_for_interface(interface)
        gateway_ip = default_gateway_for_interface(interface)
        self.send_json(
            {
                "ok": True,
                "activeInterface": interface,
                "activeInterfaceLabel": display_name_for_interface(interface),
                "defaultTarget": str(network),
                "interfaces": [item.as_dict() for item in interfaces],
                "isPrivileged": is_admin(),
                "localIp": local_ip,
                "gatewayIp": gateway_ip,
                "history": load_history(),
            }
        )

    def handle_scan(self) -> None:
        try:
            payload = self.read_json_body()
            require_admin()
            interface = resolve_interface(clean_optional(payload.get("interface")))
            target = clean_optional(payload.get("target"))
            timeout = parse_float(payload.get("timeout"), DEFAULT_TIMEOUT_SECONDS, 0.5, 10.0)
            retries = parse_int(payload.get("retries"), DEFAULT_RETRIES, 0, 5)
            resolve_hostnames = bool(payload.get("resolveHostnames", True))

            devices, networks = smart_scan(
                interface=interface,
                target=target,
                timeout=timeout,
                retries=retries,
                resolve_hostnames=resolve_hostnames,
                include_cache=True,
                scan_ports=True,
            )
        except RuntimeError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        local_ip = local_ipv4_for_interface(interface)
        gateway_ip = default_gateway_for_interface(interface)
        history = load_history()
        previous_snapshot = load_snapshot()
        previous_keys = set(previous_snapshot.get("keys", []))
        enriched_devices = [
            enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history, previous_keys=previous_keys)
            for device in devices
        ]
        annotate_duplicate_macs(enriched_devices)
        timeline_summary = append_network_history(
            enriched_devices,
            previous_snapshot=previous_snapshot,
            targets=[str(network) for network in networks],
            interface_label=display_name_for_interface(interface),
        )
        save_seen_devices(enriched_devices)
        save_snapshot(enriched_devices)
        self.send_json(
            {
                "ok": True,
                "target": ", ".join(str(network) for network in networks),
                "targets": [str(network) for network in networks],
                "interface": interface,
                "interfaceLabel": display_name_for_interface(interface),
                "isPrivileged": is_admin(),
                "localIp": local_ip,
                "gatewayIp": gateway_ip,
                "deviceCount": len(enriched_devices),
                "devices": enriched_devices,
                "summary": summarize_devices(enriched_devices, previous_keys),
                "timelineSummary": timeline_summary,
            }
        )

    def handle_scan_stream(self, query: str) -> None:
        try:
            require_admin()
            params = parse_qs(query)
            interface = resolve_interface(first_query_value(params, "interface"))
            target = first_query_value(params, "target")
            scan_id = first_query_value(params, "scanId") or utc_now()
            timeout = parse_float(first_query_value(params, "timeout"), DEFAULT_TIMEOUT_SECONDS, 0.5, 10.0)
            retries = parse_int(first_query_value(params, "retries"), DEFAULT_RETRIES, 0, 5)
            resolve_hostnames = parse_bool(first_query_value(params, "resolveHostnames"), True)
            networks = discovery_networks(interface, target)
            local_ip = local_ipv4_for_interface(interface)
            gateway_ip = default_gateway_for_interface(interface)
        except (RuntimeError, ValueError) as exc:
            self.start_event_stream()
            self.write_event("error", {"message": str(exc)})
            self.write_event("done", {"ok": False})
            return

        self.start_event_stream()
        history = load_history()
        previous_snapshot = load_snapshot()
        previous_keys = set(previous_snapshot.get("keys", []))
        seen_groups = []
        progress = {"cache": 0, "live": 0}

        self.write_event(
            "start",
            {
                "ok": True,
                "target": ", ".join(str(network) for network in networks),
                "targets": [str(network) for network in networks],
                "interface": interface,
                "interfaceLabel": display_name_for_interface(interface),
                "isPrivileged": is_admin(),
                "localIp": local_ip,
                "gatewayIp": gateway_ip,
                "scanId": scan_id,
            },
        )

        for network in networks:
            if scan_id in CANCELLED_SCANS:
                self.write_event("done", {"ok": False, "cancelled": True})
                CANCELLED_SCANS.discard(scan_id)
                return

            self.write_event("phase", {"id": "cache", "label": "Reading local neighbor cache"})
            cache_devices = arp_cache_devices(network, local_ip, resolve_hostnames, scan_ports=True)
            seen_groups.append(cache_devices)
            for device in cache_devices:
                progress["cache"] += 1
                self.write_event(
                    "device",
                    enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history, previous_keys=previous_keys),
                )
                self.write_event("progress", progress)

            if scan_id in CANCELLED_SCANS:
                self.write_event("done", {"ok": False, "cancelled": True})
                CANCELLED_SCANS.discard(scan_id)
                return

            self.write_event("phase", {"id": "arp", "label": f"Broadcasting ARP probes on {network}"})
            live_devices = scan_network(network, interface, timeout, retries, resolve_hostnames, scan_ports=True)
            seen_groups.append(live_devices)
            for device in live_devices:
                progress["live"] += 1
                enriched = enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history, previous_keys=previous_keys)
                self.write_event("device", enriched)
                self.write_event("progress", progress)

        self.write_event("phase", {"id": "enrich", "label": "Merging history and classifying devices"})
        final_devices = [
            enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history, previous_keys=previous_keys)
            for device in merge_devices(seen_groups)
        ]
        annotate_duplicate_macs(final_devices)
        timeline_summary = append_network_history(
            final_devices,
            previous_snapshot=previous_snapshot,
            targets=[str(network) for network in networks],
            interface_label=display_name_for_interface(interface),
        )
        save_seen_devices(final_devices)
        save_snapshot(final_devices)
        self.write_event(
            "done",
            {
                "ok": True,
                "deviceCount": len(final_devices),
                "devices": final_devices,
                "summary": summarize_devices(final_devices, previous_keys),
                "timelineSummary": timeline_summary,
            },
        )

    def handle_cancel(self) -> None:
        try:
            payload = self.read_json_body()
            scan_id = clean_optional(payload.get("scanId"))
            if not scan_id:
                raise ValueError("Scan id is required.")
            CANCELLED_SCANS.add(scan_id)
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self.send_json({"ok": True, "scanId": scan_id})

    def handle_alias(self) -> None:
        try:
            payload = self.read_json_body()
            key = clean_optional(payload.get("key"))
            alias = clean_optional(payload.get("alias")) or ""
            if not key:
                raise ValueError("Device key is required.")
            history = load_history()
            record = history.setdefault(key, {})
            record["alias"] = alias[:80]
            record["updatedAt"] = utc_now()
            save_history(history)
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        self.send_json({"ok": True, "key": key, "alias": alias[:80]})

    def read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        if content_length == 0:
            return {}

        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON.") from exc

        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        response = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)

    def start_event_stream(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def write_event(self, event: str, payload: dict[str, Any]) -> None:
        data = json.dumps(payload)
        self.wfile.write(f"event: {event}\ndata: {data}\n\n".encode("utf-8"))
        self.wfile.flush()

    def log_message(self, format: str, *args: Any) -> None:
        if not getattr(self.server, "quiet", False):
            super().log_message(format, *args)


def clean_optional(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def first_query_value(params: dict[str, list[str]], key: str) -> str | None:
    values = params.get(key, [])
    if not values:
        return None
    return clean_optional(values[0])


def parse_bool(value: Any, default: bool) -> bool:
    if value in (None, ""):
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    if value in (None, ""):
        return default

    parsed = float(value)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"Value must be between {minimum} and {maximum}.")
    return parsed


def parse_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if value in (None, ""):
        return default

    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"Value must be between {minimum} and {maximum}.")
    return parsed


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_history() -> dict[str, dict[str, Any]]:
    try:
        with HISTORY_PATH.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_history(history: dict[str, dict[str, Any]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("w", encoding="utf-8") as file:
        json.dump(history, file, indent=2, sort_keys=True)


def load_snapshot() -> dict[str, Any]:
    try:
        with SNAPSHOT_PATH.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_snapshot(devices: list[dict[str, Any]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "createdAt": utc_now(),
        "keys": sorted(str(device["key"]) for device in devices),
        "devices": [
            {
                "key": device["key"],
                "ip": device["ip"],
                "mac": device["mac"],
                "hostname": device["hostname"],
                "vendor": device["vendor"],
                "openPorts": device.get("openPorts", []),
                "services": device.get("services", []),
                "source": device.get("source", ""),
            }
            for device in devices
        ],
    }
    with SNAPSHOT_PATH.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)


def load_network_history() -> list[dict[str, Any]]:
    try:
        with NETWORK_HISTORY_PATH.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError):
        return []
    return payload if isinstance(payload, list) else []


def save_network_history(entries: list[dict[str, Any]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with NETWORK_HISTORY_PATH.open("w", encoding="utf-8") as file:
        json.dump(entries[-MAX_NETWORK_HISTORY_ENTRIES:], file, indent=2, sort_keys=True)


def append_network_history(
    devices: list[dict[str, Any]],
    previous_snapshot: dict[str, Any],
    targets: list[str],
    interface_label: str,
) -> dict[str, int]:
    timestamp = utc_now()
    previous_devices = previous_snapshot.get("devices", [])
    if not isinstance(previous_devices, list):
        previous_devices = []

    current_keys = {str(device.get("key", "")) for device in devices}
    previous_by_key = {str(device.get("key", "")): device for device in previous_devices if device.get("key")}
    previous_macs = {
        str(device.get("mac", "")).upper()
        for device in previous_devices
        if clean_optional(device.get("mac"))
    }
    has_baseline = bool(previous_macs)

    events: list[dict[str, Any]] = []
    new_device_count = 0
    open_service_count = 0

    for device in devices:
        open_ports = list(device.get("openPorts") or [])
        open_service_count += len(open_ports)
        warning = ""
        if has_baseline and str(device.get("mac", "")).upper() not in previous_macs:
            warning = "NEW DEVICE WARNING"
            new_device_count += 1
            device["timelineWarning"] = warning

        device["timelineStatus"] = "Online"
        events.append(
            {
                "timestamp": timestamp,
                "status": "Online",
                "warning": warning,
                "key": device.get("key"),
                "ip": device.get("ip"),
                "mac": device.get("mac"),
                "hostname": device.get("hostname"),
                "vendor": device.get("vendor"),
                "source": device.get("source"),
                "openPorts": open_ports,
                "services": list(device.get("services") or []),
            }
        )

    offline_count = 0
    for key, previous_device in previous_by_key.items():
        if key in current_keys:
            continue
        offline_count += 1
        events.append(
            {
                "timestamp": timestamp,
                "status": "Offline",
                "warning": "",
                "key": key,
                "ip": previous_device.get("ip"),
                "mac": previous_device.get("mac"),
                "hostname": previous_device.get("hostname"),
                "vendor": previous_device.get("vendor"),
                "source": previous_device.get("source"),
                "openPorts": list(previous_device.get("openPorts") or []),
                "services": list(previous_device.get("services") or []),
            }
        )

    summary = {
        "online": len(devices),
        "offline": offline_count,
        "newDeviceWarnings": new_device_count,
        "openServices": open_service_count,
    }
    entries = load_network_history()
    entries.append(
        {
            "timestamp": timestamp,
            "targets": targets,
            "interface": interface_label,
            "summary": summary,
            "events": events,
        }
    )
    save_network_history(entries)
    return summary


def device_key(device: dict[str, Any]) -> str:
    mac = clean_optional(device.get("mac"))
    if mac:
        if is_locally_administered_mac(mac):
            return f"private:{device.get('ip', '')}:{mac.upper()}"
        return f"mac:{mac.upper()}"
    return f"ip:{device.get('ip', '')}"


def save_seen_devices(devices: list[dict[str, Any]]) -> None:
    history = load_history()
    now = utc_now()
    for device in devices:
        key = device["key"]
        record = history.setdefault(key, {})
        record.setdefault("firstSeen", now)
        record["lastSeen"] = now
        record["seenCount"] = int(record.get("seenCount", 0)) + 1
        record["lastIp"] = device["ip"]
        record["lastMac"] = device["mac"]
        record["lastHostname"] = device["hostname"]
        record["lastVendor"] = device["vendor"]
        record["lastDeviceType"] = device["deviceType"]
    save_history(history)


def enrich_device(
    device: Any,
    local_ip: str | None,
    gateway_ip: str | None,
    networks: list[ipaddress.IPv4Network],
    history: dict[str, dict[str, Any]],
    previous_keys: set[str] | None = None,
) -> dict[str, Any]:
    payload = device.as_dict()
    key = device_key(payload)
    record = history.get(key, {})
    ip_address = payload["ip"]
    is_local = bool(local_ip and ip_address == local_ip)
    is_gateway = bool(gateway_ip and ip_address == gateway_ip)
    if not is_gateway:
        is_gateway = any(ip_address == str(next(network.hosts(), "")) for network in networks if network.num_addresses > 2)
    private_mac = is_locally_administered_mac(payload["mac"])
    device_type = guess_device_type(payload, is_local=is_local, is_gateway=is_gateway)
    confidence_score = confidence_for(payload, is_local=is_local, is_gateway=is_gateway)
    confidence = "High" if confidence_score >= 80 else "Medium" if confidence_score >= 55 else "Low"
    now = utc_now()
    first_seen = str(record.get("firstSeen") or now)
    seen_count = int(record.get("seenCount", 0))

    notes = []
    is_new_since_last_scan = bool(previous_keys is not None and key not in previous_keys)
    if is_gateway:
        notes.append("Default gateway candidate")
    if is_local:
        notes.append("This computer")
    if private_mac:
        notes.append("Vendor hidden by private MAC")
    if payload["source"] == "arp-cache":
        notes.append("Seen from local neighbor cache")
    if is_new_since_last_scan:
        notes.append("New since previous scan")
    open_ports = list(payload.get("openPorts") or [])
    if any(port in open_ports for port in (80, 443, 8080)):
        notes.append("Web or management service detected")
    if 22 in open_ports:
        notes.append("SSH service detected")

    payload.update(
        {
            "key": key,
            "alias": str(record.get("alias") or ""),
            "deviceType": device_type,
            "confidence": confidence,
            "confidenceScore": confidence_score,
            "isNew": seen_count == 0,
            "isNewSinceLastScan": is_new_since_last_scan,
            "firstSeen": first_seen,
            "lastSeen": str(record.get("lastSeen") or now),
            "seenCount": seen_count,
            "isLocal": is_local,
            "isGateway": is_gateway,
            "isPrivateMac": private_mac,
            "notes": notes,
        }
    )
    return payload


def annotate_duplicate_macs(devices: list[dict[str, Any]]) -> None:
    devices_by_mac: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        devices_by_mac.setdefault(str(device.get("mac", "")).upper(), []).append(device)

    for mac, mac_devices in devices_by_mac.items():
        if len(mac_devices) < 2:
            continue
        is_private = is_locally_administered_mac(mac)
        for device in mac_devices:
            device["hasDuplicateMac"] = True
            if is_private:
                device["hasDuplicatePrivateMac"] = True
                device.setdefault("notes", []).append("Same private MAC appears on multiple IPs")
            else:
                device.setdefault("notes", []).append("Same MAC appears on multiple IPs")


def guess_device_type(device: dict[str, str], is_local: bool, is_gateway: bool) -> str:
    if is_gateway:
        return "Gateway"
    if is_local:
        return "This computer"

    text = " ".join([device.get("hostname", ""), device.get("vendor", "")]).lower()
    if any(term in text for term in ("iphone", "ipad", "android", "samsung", "huawei", "xiaomi", "oneplus")):
        return "Phone or tablet"
    if any(term in text for term in ("tv", "roku", "chromecast", "cast", "lg ", "bravia")):
        return "Media or TV"
    if any(term in text for term in ("printer", "epson", "canon", "brother", "hp inc")):
        return "Printer"
    if any(term in text for term in ("intel", "desktop", "laptop", "pc", "macbook", "windows")):
        return "Computer"
    if device.get("vendor") == "Private/randomized MAC":
        return "Private device"
    return "Unknown"


def confidence_for(device: dict[str, str], is_local: bool, is_gateway: bool) -> int:
    score = 30
    if device.get("source") in {"arp", "arp+cache"}:
        score += 30
    if device.get("vendor") not in {"Unknown", "Private/randomized MAC"}:
        score += 25
    if device.get("hostname") not in UNKNOWN_HOSTNAMES:
        score += 20
    if is_local or is_gateway:
        score += 10
    if device.get("vendor") == "Private/randomized MAC":
        score -= 10
    return max(0, min(score, 100))


def summarize_devices(devices: list[dict[str, Any]], previous_keys: set[str] | None = None) -> dict[str, int]:
    current_keys = {str(device.get("key", "")) for device in devices}
    previous_keys = previous_keys or set()
    return {
        "total": len(devices),
        "live": sum(1 for device in devices if device.get("source") in {"arp", "arp+cache"}),
        "cached": sum(1 for device in devices if device.get("source") == "arp-cache"),
        "privateMac": sum(1 for device in devices if device.get("isPrivateMac")),
        "unknownHostnames": sum(1 for device in devices if device.get("hostname") in UNKNOWN_HOSTNAMES),
        "gateways": sum(1 for device in devices if device.get("isGateway")),
        "newDevices": sum(1 for device in devices if device.get("isNew")),
        "newSinceLastScan": sum(1 for device in devices if device.get("isNewSinceLastScan")),
        "missingSinceLastScan": len(previous_keys - current_keys),
        "previousTotal": len(previous_keys),
        "openServices": sum(len(device.get("openPorts") or []) for device in devices),
        "newDeviceWarnings": sum(1 for device in devices if device.get("timelineWarning") == "NEW DEVICE WARNING"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the WiFind local web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind. Default: 8765")
    parser.add_argument("--quiet", action="store_true", help="Disable request logging.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        require_admin()
        server = ThreadingHTTPServer((args.host, args.port), WiFindHandler)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"Could not bind to {args.host}:{args.port}. Try another port with --port.",
            file=sys.stderr,
        )
        print(f"Details: {exc}", file=sys.stderr)
        return 1

    server.quiet = args.quiet  # type: ignore[attr-defined]

    print(f"WiFind UI is running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping WiFind UI.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
