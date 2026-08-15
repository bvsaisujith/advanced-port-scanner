from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


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


@dataclass(slots=True)
class ScanSession:
    target: str
    ports: list[int]
    dns_resolution: DnsResolution | None = None
    traceroute_output: str | None = None
    traceroute_error: str | None = None
    traceroute_time_ms: float | None = None
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    results: list[PortScanResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortScanResult]:
        return [result for result in self.results if result.is_open]

    @property
    def closed_ports(self) -> list[PortScanResult]:
        return [result for result in self.results if not result.is_open]

    @property
    def banner_ports(self) -> list[PortScanResult]:
        return [result for result in self.open_ports if result.banner]
