from __future__ import annotations

import subprocess
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections.abc import Callable
from threading import Event
from itertools import islice

from src.models.scan_result import PortScanResult, ScanSession
from src.scanner.target_parser import resolve_target
from src.scanner.service_detector import detect_service_from_banner
from src.scanner.vuln_mapper import lookup_cves


class PortScanner:
    def __init__(
        self,
        timeout: float = 0.8,
        max_workers: int = 10,
        batch_size: int = 10,
        scan_type: str = "tcp_connect",
        os_detection: bool = False,
        service_detection: bool = True,
        vulnerability_scan: bool = False,
        ai_enhancements: bool = True,
    ) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.scan_type = scan_type
        self.os_detection = os_detection
        self.service_detection = service_detection
        self.vulnerability_scan = vulnerability_scan
        self.ai_enhancements = ai_enhancements

    def scan_port(self, target: str, port: int) -> PortScanResult:
        """Scan a single port using the configured scan type."""
        from src.scanner.syn_scanner import (
            syn_scan_port, udp_scan_port, fin_scan_port, null_scan_port, xmas_scan_port
        )
        if self.scan_type == "syn_stealth":
            return syn_scan_port(target, port, self.timeout)
        elif self.scan_type == "udp":
            return udp_scan_port(target, port, self.timeout)
        elif self.scan_type == "fin":
            return fin_scan_port(target, port, self.timeout)
        elif self.scan_type == "null":
            return null_scan_port(target, port, self.timeout)
        elif self.scan_type == "xmas":
            return xmas_scan_port(target, port, self.timeout)
        else:
            return self._tcp_connect_scan(target, port)

    def _tcp_connect_scan(self, target: str, port: int) -> PortScanResult:
        """Standard TCP connect scan."""
        started = time.perf_counter()
        try:
            with socket.create_connection((target, port), timeout=self.timeout) as connection:
                response_time_ms = (time.perf_counter() - started) * 1000
                banner = self._read_banner(connection)
                return PortScanResult(
                    target=target,
                    port=port,
                    is_open=True,
                    response_time_ms=round(response_time_ms, 2),
                    banner=banner,
                    scan_type="tcp_connect",
                )
        except Exception as exc:
            response_time_ms = (time.perf_counter() - started) * 1000
            return PortScanResult(
                target=target,
                port=port,
                is_open=False,
                response_time_ms=round(response_time_ms, 2),
                error=str(exc),
                scan_type="tcp_connect",
            )

    def scan(
        self,
        target: str,
        ports: list[int],
        progress_callback: Callable[[int, int, PortScanResult], None] | None = None,
        dns_resolution=None,
        traceroute: bool = False,
        stop_event: Event | None = None,
    ) -> ScanSession:
        session = ScanSession(target=target, ports=ports, dns_resolution=dns_resolution or resolve_target(target))

        if traceroute:
            traceroute_started = time.perf_counter()
            try:
                completed = subprocess.run(
                    ["tracert", "-d", "-h", "8", "-w", "1000", target],
                    capture_output=True,
                    text=True,
                    timeout=25,
                    check=False,
                )
                session.traceroute_output = completed.stdout.strip() or completed.stderr.strip() or None
                session.traceroute_time_ms = round((time.perf_counter() - traceroute_started) * 1000, 2)
                if completed.returncode != 0 and not session.traceroute_output:
                    session.traceroute_error = f"tracert exited with code {completed.returncode}"
            except FileNotFoundError:
                session.traceroute_error = "tracert not available"
            except subprocess.TimeoutExpired:
                session.traceroute_error = "timed out"
                session.traceroute_time_ms = round((time.perf_counter() - traceroute_started) * 1000, 2)
            except Exception as exc:
                session.traceroute_error = str(exc)
                session.traceroute_time_ms = round((time.perf_counter() - traceroute_started) * 1000, 2)

        completed = 0
        total = len(ports)
        for batch in self._chunk_ports(ports, self.batch_size):
            if stop_event is not None and stop_event.is_set():
                session.stopped = True
                break
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(batch))) as executor:
                futures = [executor.submit(self.scan_port, target, port) for port in batch]
                for future in as_completed(futures):
                    result = future.result()
                    session.results.append(result)
                    completed += 1
                    if progress_callback is not None:
                        progress_callback(completed, total, result)
                    if stop_event is not None and stop_event.is_set():
                        session.stopped = True
                        break
                if session.stopped:
                    break

        session.results.sort(key=lambda result: result.port)

        # Apply service detection to open ports
        if self.service_detection:
            self._apply_service_detection(session)

        # Apply OS detection (once per target, after scanning)
        if self.os_detection:
            from src.scanner.os_detector import detect_os
            session.os_detection = detect_os(
                target,
                [r.port for r in session.open_ports],
                timeout=self.timeout * 2,
            )

        # Apply vulnerability mapping
        if self.vulnerability_scan:
            self._apply_vulnerability_mapping(session)

        # Apply AI enhancements
        if self.ai_enhancements:
            from src.scanner.ai_enhancer import apply_ai_enhancements
            apply_ai_enhancements(session)

        session.finished_at = datetime.now()
        return session

    def _chunk_ports(self, ports: list[int], chunk_size: int) -> list[list[int]]:
        iterator = iter(ports)
        chunks: list[list[int]] = []
        while True:
            batch = list(islice(iterator, chunk_size))
            if not batch:
                break
            chunks.append(batch)
        return chunks

    def _apply_service_detection(self, session: ScanSession) -> None:
        """Apply service and version detection to all open ports."""
        from src.scanner.service_detector import probe_service
        for result in session.open_ports:
            # Try banner parsing
            if result.banner:
                service_info = detect_service_from_banner(result.banner, result.port)
                result.service_name = service_info.service_name
                result.service_version = service_info.service_version
                result.banner_enhanced = service_info.banner_enhanced

            # Try active probe if no banner or for web services
            if result.service_name is None or result.service_name == "unknown":
                try:
                    service_info = probe_service(session.target, result.port, self.timeout)
                    result.service_name = service_info.service_name
                    result.service_version = service_info.service_version
                except Exception:
                    pass

    def _apply_vulnerability_mapping(self, session: ScanSession) -> None:
        """Look up CVEs for each open port's service."""
        for result in session.open_ports:
            cves = lookup_cves(result.service_name, result.service_version, result.port)
            result.vulnerability_ids = [cve[0] for cve in cves]
            # Calculate risk score based on vulnerabilities found
            if cves:
                # Base risk from open port + vulnerability severity
                base_risk = 2.0
                vuln_risk = sum(min(2.0, cvss / 5.0) for _, _, cvss in cves)
                result.risk_score = round(min(10.0, base_risk + vuln_risk), 1)

    def _read_banner(self, connection: socket.socket) -> str | None:
        try:
            connection.settimeout(0.2)
            data = connection.recv(128)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            return None
        return None
