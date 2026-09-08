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
STATIC_ROOT = PROJECT_ROOT / "static"
STATE_DIR = PROJECT_ROOT / ".wifind"
HISTORY_PATH = STATE_DIR / "device_history.json"


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
        enriched_devices = [
            enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history)
            for device in devices
        ]
        save_seen_devices(enriched_devices)
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
                "summary": summarize_devices(enriched_devices),
            }
        )

    def handle_scan_stream(self, query: str) -> None:
        try:
            require_admin()
            params = parse_qs(query)
            interface = resolve_interface(first_query_value(params, "interface"))
            target = first_query_value(params, "target")
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
        seen_groups = []

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
            },
        )

        for network in networks:
            self.write_event("phase", {"id": "cache", "label": "Reading local neighbor cache"})
            cache_devices = arp_cache_devices(network, local_ip, resolve_hostnames)
            seen_groups.append(cache_devices)
            for device in cache_devices:
                self.write_event(
                    "device",
                    enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history),
                )

            self.write_event("phase", {"id": "arp", "label": f"Broadcasting ARP probes on {network}"})
            live_devices = scan_network(network, interface, timeout, retries, resolve_hostnames)
            seen_groups.append(live_devices)
            merged = merge_devices(seen_groups)
            for device in live_devices:
                enriched = enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history)
                self.write_event("device", enriched)

        self.write_event("phase", {"id": "enrich", "label": "Merging history and classifying devices"})
        final_devices = [
            enrich_device(device, local_ip=local_ip, gateway_ip=gateway_ip, networks=networks, history=history)
            for device in merge_devices(seen_groups)
        ]
        save_seen_devices(final_devices)
        self.write_event(
            "done",
            {
                "ok": True,
                "deviceCount": len(final_devices),
                "devices": final_devices,
                "summary": summarize_devices(final_devices),
            },
        )

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
    STATE_DIR.mkdir(exist_ok=True)
    with HISTORY_PATH.open("w", encoding="utf-8") as file:
        json.dump(history, file, indent=2, sort_keys=True)


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
    if is_gateway:
        notes.append("Default gateway candidate")
    if is_local:
        notes.append("This computer")
    if private_mac:
        notes.append("Vendor hidden by private MAC")
    if payload["source"] == "arp-cache":
        notes.append("Seen from local neighbor cache")

    payload.update(
        {
            "key": key,
            "alias": str(record.get("alias") or ""),
            "deviceType": device_type,
            "confidence": confidence,
            "confidenceScore": confidence_score,
            "isNew": seen_count == 0,
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
    if device.get("hostname") not in {"Unknown", "Skipped"}:
        score += 20
    if is_local or is_gateway:
        score += 10
    if device.get("vendor") == "Private/randomized MAC":
        score -= 10
    return max(0, min(score, 100))


def summarize_devices(devices: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(devices),
        "live": sum(1 for device in devices if device.get("source") in {"arp", "arp+cache"}),
        "cached": sum(1 for device in devices if device.get("source") == "arp-cache"),
        "privateMac": sum(1 for device in devices if device.get("isPrivateMac")),
        "unknownHostnames": sum(1 for device in devices if device.get("hostname") in {"Unknown", "Skipped"}),
        "gateways": sum(1 for device in devices if device.get("isGateway")),
        "newDevices": sum(1 for device in devices if device.get("isNew")),
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
