from __future__ import annotations

import ipaddress
import socket
import time

from src.models.scan_result import DnsResolution


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
ALL_PORTS = list(range(1, 65536))
PRESET_PORTS = {
    "all": ALL_PORTS,
    "all-ports": ALL_PORTS,
    "full": ALL_PORTS,
    "65535": ALL_PORTS,
    "wellknown": DEFAULT_PORTS,
    "well-known": DEFAULT_PORTS,
    "common": DEFAULT_PORTS,
    "fundamental": DEFAULT_PORTS,
    "default": DEFAULT_PORTS,
}


def parse_ports(port_text: str) -> list[int]:
    text = port_text.strip()
    if not text:
        return DEFAULT_PORTS.copy()

    preset = PRESET_PORTS.get(text.lower())
    if preset is not None:
        return preset.copy()

    ports: set[int] = set()
    for chunk in text.split(","):
        part = chunk.strip()
        if not part:
            continue
        preset = PRESET_PORTS.get(part.lower())
        if preset is not None:
            ports.update(preset)
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start_port = int(start_text.strip())
            end_port = int(end_text.strip())
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            for port in range(start_port, end_port + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)

    return sorted(ports)


def normalize_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Target is required")
    return value


def resolve_target(target: str) -> DnsResolution:
    started = time.perf_counter()
    try:
        ipaddress.ip_address(target)
        lookup_time_ms = (time.perf_counter() - started) * 1000
        ipv4_addresses = [target] if isinstance(ipaddress.ip_address(target), ipaddress.IPv4Address) else []
        ipv6_addresses = [target] if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address) else []
        return DnsResolution(
            target=target,
            resolved_ips=[target],
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            lookup_time_ms=round(lookup_time_ms, 2),
        )
    except ValueError:
        pass

    try:
        info = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        resolved_ips = sorted({entry[4][0] for entry in info})
        ipv4_addresses = sorted({address for address in resolved_ips if ipaddress.ip_address(address).version == 4})
        ipv6_addresses = sorted({address for address in resolved_ips if ipaddress.ip_address(address).version == 6})
        lookup_time_ms = (time.perf_counter() - started) * 1000
        return DnsResolution(
            target=target,
            resolved_ips=resolved_ips,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            lookup_time_ms=round(lookup_time_ms, 2),
        )
    except socket.gaierror as exc:
        lookup_time_ms = (time.perf_counter() - started) * 1000
        return DnsResolution(
            target=target,
            lookup_time_ms=round(lookup_time_ms, 2),
            error=str(exc),
        )
