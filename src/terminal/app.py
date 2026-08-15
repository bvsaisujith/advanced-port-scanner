from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from src.scanner.port_scanner import PortScanner
from src.scanner.target_parser import normalize_target, parse_ports, resolve_target
from src.utils.formatters import build_result_sections, build_summary_text


@dataclass(slots=True)
class TerminalOptions:
    target: str
    ports: str
    traceroute: bool = False
    tui: bool = False
    timeout: float = 0.8
    max_workers: int = 10
    batch_size: int = 10


class TerminalScannerApp:
    def __init__(self) -> None:
        self.scanner = PortScanner()

    def run(self, options: TerminalOptions) -> int:
        target = normalize_target(options.target)
        ports = parse_ports(options.ports)
        dns_resolution = resolve_target(target)

        self.scanner.timeout = options.timeout
        self.scanner.max_workers = options.max_workers
        self.scanner.batch_size = options.batch_size

        if options.tui:
            self._run_tui(target, ports, dns_resolution, options.traceroute)
        else:
            session = self.scanner.scan(
                target,
                ports,
                dns_resolution=dns_resolution,
                traceroute=options.traceroute,
            )
            self._print_session(session)
        return 0

    def _run_tui(self, target: str, ports: list[int], dns_resolution, traceroute: bool) -> None:
        total = len(ports)
        completed = 0
        last_result = None

        def on_progress(done: int, total_count: int, result) -> None:
            nonlocal completed, last_result
            completed = done
            last_result = result
            self._render_progress(target, total_count, completed, result)

        session = self.scanner.scan(
            target,
            ports,
            progress_callback=on_progress,
            dns_resolution=dns_resolution,
            traceroute=traceroute,
        )
        self._clear_screen()
        self._print_session(session)

    def _render_progress(self, target: str, total: int, completed: int, result) -> None:
        self._clear_screen()
        percent = (completed / total * 100) if total else 0
        state = "open" if result.is_open else "closed"
        print(f"Scanning {target}  {completed}/{total}  {percent:.1f}%  last: port {result.port} {state}")
        print()
        print(f"Current port: {result.port}")
        print(f"State: {state}")
        print(f"Response: {result.response_time_ms:.2f} ms" if result.response_time_ms is not None else "Response: -")
        if result.banner:
            print(f"Banner: {result.banner}")
        if result.error:
            print(f"Error: {result.error}")

    def _print_session(self, session) -> None:
        print(build_summary_text(session))
        print()
        sections = build_result_sections(session)
        self._print_group("Open Ports", sections.open_ports, use_banner=True)
        self._print_group("Ports With Banners", sections.banner_ports, use_banner=True)
        self._print_group("Closed Ports", sections.closed_ports, use_banner=False)

    def _print_group(self, title: str, results, use_banner: bool) -> None:
        print(title)
        print("-" * len(title))
        if not results:
            print("No data.")
            print()
            return

        for result in results:
            response = f"{result.response_time_ms:.2f} ms" if result.response_time_ms is not None else "-"
            extra = result.banner if use_banner else result.error
            extra = extra or "-"
            print(f"{result.port:<6} {response:<12} {extra}")
        print()

    def _clear_screen(self) -> None:
        if sys.stdout.isatty():
            os.system("cls" if os.name == "nt" else "clear")