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


class PortScanner:
    def __init__(self, timeout: float = 0.8, max_workers: int = 10, batch_size: int = 10) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.batch_size = batch_size

    def scan_port(self, target: str, port: int) -> PortScanResult:
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
                )
        except Exception as exc:
            response_time_ms = (time.perf_counter() - started) * 1000
            return PortScanResult(
                target=target,
                port=port,
                is_open=False,
                response_time_ms=round(response_time_ms, 2),
                error=str(exc),
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

    def _read_banner(self, connection: socket.socket) -> str | None:
        try:
            connection.settimeout(0.2)
            data = connection.recv(128)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            return None
        return None
