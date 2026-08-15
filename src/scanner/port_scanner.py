from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections.abc import Callable

from src.models.scan_result import PortScanResult, ScanSession


class PortScanner:
    def __init__(self, timeout: float = 0.8, max_workers: int = 100) -> None:
        self.timeout = timeout
        self.max_workers = max_workers

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
    ) -> ScanSession:
        session = ScanSession(target=target, ports=ports)
        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(ports)))) as executor:
            futures = [executor.submit(self.scan_port, target, port) for port in ports]
            completed = 0
            total = len(futures)
            for future in as_completed(futures):
                result = future.result()
                session.results.append(result)
                completed += 1
                if progress_callback is not None:
                    progress_callback(completed, total, result)

        session.results.sort(key=lambda result: result.port)
        session.finished_at = datetime.now()
        return session

    def _read_banner(self, connection: socket.socket) -> str | None:
        try:
            connection.settimeout(0.2)
            data = connection.recv(128)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            return None
        return None
