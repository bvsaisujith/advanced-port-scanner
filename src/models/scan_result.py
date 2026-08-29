from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass(slots=True)
class DnsResolution:
    target: str
    resolved_ips: list[str] = field(default_factory=list)
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    lookup_time_ms: float | None = None
    error: str | None = None


@dataclass(slots=True)
class PortScanResult:
    target: str
    port: int
    is_open: bool
    response_time_ms: float | None = None
    banner: str | None = None
    error: str | None = None
    # Enhanced fields for new features
    scan_type: str = "tcp_connect"  # tcp_connect, syn_stealth, udp, etc.
    service_name: str | None = None  # Detected service (http, ssh, ftp, etc.)
    service_version: str | None = None  # Version string if detectable
    os_guess: str | None = None  # Guessed operating system (for target-level)
    os_confidence: float | None = None  # Confidence in OS guess (0-1)
    banner_enhanced: str | None = None  # Enhanced banner with service info
    vulnerability_ids: List[str] = field(default_factory=list)  # CVE IDs found
    risk_score: float | None = None  # Risk assessment (0-10)


@dataclass(slots=True)
class OSDetectionResult:
    target: str
    os_guess: str
    confidence: float
    fingerprints: Dict[str, Any] = field(default_factory=dict)  # TTL, window size, etc.


@dataclass(slots=True)
class ScanSession:
    target: str
    ports: list[int]
    dns_resolution: DnsResolution | None = None
    traceroute_output: str | None = None
    traceroute_error: str | None = None
    traceroute_time_ms: float | None = None
    stopped: bool = False
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    results: list[PortScanResult] = field(default_factory=list)
    # Session-level enhancements
    os_detection: OSDetectionResult | None = None

    @property
    def open_ports(self) -> list[PortScanResult]:
        return [result for result in self.results if result.is_open]

    @property
    def closed_ports(self) -> list[PortScanResult]:
        return [result for result in self.results if not result.is_open]

    @property
    def banner_ports(self) -> list[PortScanResult]:
        return [result for result in self.open_ports if result.banner]
