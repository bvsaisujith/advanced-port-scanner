from __future__ import annotations

from dataclasses import dataclass

from src.models.scan_result import PortScanResult, ScanSession


@dataclass(slots=True)
class ScanResultSections:
    open_ports: list[PortScanResult]
    banner_ports: list[PortScanResult]
    closed_ports: list[PortScanResult]


def build_result_sections(session: ScanSession) -> ScanResultSections:
    open_ports = sorted(session.open_ports, key=lambda result: result.port)
    banner_ports = sorted(session.banner_ports, key=lambda result: result.port)
    closed_ports = sorted(session.closed_ports, key=lambda result: result.port)
    return ScanResultSections(
        open_ports=open_ports,
        banner_ports=banner_ports,
        closed_ports=closed_ports,
    )


def _traceroute_lines(session: ScanSession) -> list[str]:
    if session.traceroute_error:
        return [f"Traceroute: failed ({session.traceroute_error})"]

    if not session.traceroute_output:
        return []

    lines = [line.strip() for line in session.traceroute_output.splitlines() if line.strip()]
    if not lines:
        return []

    if session.traceroute_time_ms is not None:
        lines.insert(0, f"Traceroute time: {session.traceroute_time_ms:.2f} ms")
    lines.insert(0, "Traceroute: captured")
    return lines[:6]


def build_summary_text(session: ScanSession) -> str:
    dns = session.dns_resolution
    sections = build_result_sections(session)
    dns_lines = []
    if dns is not None:
        if dns.error:
            dns_lines.append(f"DNS lookup: failed ({dns.error})")
        else:
            ipv4 = ", ".join(dns.ipv4_addresses) if dns.ipv4_addresses else "-"
            ipv6 = ", ".join(dns.ipv6_addresses) if dns.ipv6_addresses else "-"
            dns_lines.append(f"DNS lookup: IPv4 [{ipv4}] | IPv6 [{ipv6}]")
        if dns.lookup_time_ms is not None:
            dns_lines.append(f"DNS time: {dns.lookup_time_ms:.2f} ms")

    lines = [
        f"Target: {session.target}",
        f"Ports scanned: {len(session.ports)}",
        *dns_lines,
        *_traceroute_lines(session),
        f"Open ports: {len(sections.open_ports)}",
        f"Ports with banner: {len(sections.banner_ports)}",
        f"Closed ports: {len(sections.closed_ports)}",
    ]
    return "\n".join(lines)


def format_result_line(port: int, state: str, response_time_ms: float | None) -> str:
    response = f"{response_time_ms:.2f} ms" if response_time_ms is not None else "-"
    return f"Port {port:<5} {state:<6} {response}"
