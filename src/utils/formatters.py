from __future__ import annotations

from src.models.scan_result import ScanSession


def build_summary_text(session: ScanSession) -> str:
    lines = [
        f"Target: {session.target}",
        f"Ports scanned: {len(session.ports)}",
        f"Open ports: {len(session.open_ports)}",
        f"Closed ports: {len(session.closed_ports)}",
    ]
    return "\n".join(lines)


def format_result_line(port: int, state: str, response_time_ms: float | None) -> str:
    response = f"{response_time_ms:.2f} ms" if response_time_ms is not None else "-"
    return f"Port {port:<5} {state:<6} {response}"
