from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Any

from src.models.scan_result import OSDetectionResult


# OS fingerprint signatures keyed by (TTL range, window_size hint)
# TTL thresholds: Linux ~64, Windows ~128, Cisco/BSD ~255
OS_TTL_SIGNATURES: list[tuple[int, int, str]] = [
    (0, 64, "Linux/Unix"),
    (65, 128, "Windows"),
    (129, 255, "Cisco/BSD/MacOS"),
]

# Common Windows TCP window sizes
WINDOWS_WINDOW_SIZES = {65535, 8192, 16384, 32768, 64240}
LINUX_WINDOW_SIZES = {5840, 29200, 65000, 43690}


@dataclass(slots=True)
class TTLProbeResult:
    ttl: int | None = None
    window_size: int | None = None
    os_clue: str | None = None


def _guess_os_from_ttl(ttl: int) -> tuple[str, float]:
    """Return (os_name, confidence) from TTL value."""
    for low, high, os_name in OS_TTL_SIGNATURES:
        if low <= ttl <= high:
            # Confidence higher when TTL is close to round numbers (64, 128, 255)
            distance = min(abs(ttl - 64), abs(ttl - 128), abs(ttl - 255))
            confidence = max(0.4, 1.0 - (distance / 64.0))
            return os_name, round(confidence, 2)
    return "Unknown", 0.2


def _guess_os_from_window(window_size: int, current_os: str, current_conf: float) -> tuple[str, float]:
    """Refine OS guess using TCP window size."""
    if window_size in WINDOWS_WINDOW_SIZES:
        if "Windows" in current_os:
            return current_os, min(1.0, current_conf + 0.2)
        return "Windows", 0.6
    if window_size in LINUX_WINDOW_SIZES:
        if "Linux" in current_os:
            return current_os, min(1.0, current_conf + 0.2)
        return "Linux/Unix", 0.6
    return current_os, current_conf


def _passive_probe_ttl(target: str, port: int, timeout: float = 1.5) -> TTLProbeResult:
    """Attempt a TCP connect and extract TTL from the socket if possible."""
    result = TTLProbeResult()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Attempt to read TTL from socket option (Linux / Windows getsockopt)
        try:
            ttl_val = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            result.ttl = ttl_val
        except Exception:
            pass

        sock.close()
    except Exception:
        pass
    return result


def _active_probe_icmp(target: str, timeout: float = 2.0) -> TTLProbeResult:
    """Send ICMP echo and parse the TTL from the raw response (best-effort, may need admin)."""
    result = TTLProbeResult()
    try:
        # Raw ICMP socket — may fail without elevated privileges, handled gracefully
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        # Build minimal ICMP echo request
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_id = 1
        icmp_seq = 1
        payload = b"x" * 8
        header = struct.pack("bbHHh", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        # simple checksum
        checksum = 0
        raw = header + payload
        for i in range(0, len(raw), 2):
            word = (raw[i] << 8) + (raw[i + 1] if i + 1 < len(raw) else 0)
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(checksum), icmp_id, icmp_seq)
        packet = header + payload

        sock.sendto(packet, (target, 0))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) >= 20:
            # IP header TTL is at byte offset 8
            result.ttl = data[8]
    except Exception:
        pass
    return result


def detect_os(target: str, open_ports: list[int], timeout: float = 2.0) -> OSDetectionResult:
    """Detect OS via passive TTL analysis and active ICMP probing.

    Falls back gracefully when raw socket access is unavailable.
    """
    fingerprints: Dict[str, Any] = {}

    # Passive probe: connect to an open port and read TTL
    passive = TTLProbeResult()
    if open_ports:
        passive = _passive_probe_ttl(target, open_ports[0], timeout)

    # Active probe: ICMP echo (requires admin/elevated, graceful fallback)
    active = _active_probe_icmp(target, timeout)

    # Prefer active (ICMP) TTL if available
    ttl = active.ttl or passive.ttl

    if ttl is None:
        # No TTL data — try guessing from well-known port heuristics
        fingerprints["method"] = "heuristic"
        if 3389 in open_ports:
            return OSDetectionResult(target=target, os_guess="Windows", confidence=0.7,
                                     fingerprints={"port_clue": "RDP (3389) open → likely Windows"})
        if 22 in open_ports and 139 not in open_ports and 445 not in open_ports:
            return OSDetectionResult(target=target, os_guess="Linux/Unix", confidence=0.55,
                                     fingerprints={"port_clue": "SSH open, no SMB → likely Linux/Unix"})
        return OSDetectionResult(target=target, os_guess="Unknown", confidence=0.1,
                                 fingerprints={"method": "no data"})

    fingerprints["ttl"] = ttl
    fingerprints["method"] = "icmp" if active.ttl else "tcp_passive"

    os_guess, confidence = _guess_os_from_ttl(ttl)

    # Refine with port heuristics
    if open_ports:
        if 3389 in open_ports:
            os_guess = "Windows"
            confidence = min(1.0, confidence + 0.2)
            fingerprints["port_clue"] = "RDP port 3389 open"
        elif 445 in open_ports and 139 in open_ports:
            os_guess = "Windows"
            confidence = min(1.0, confidence + 0.15)
            fingerprints["port_clue"] = "SMB ports 139/445 open"
        elif 22 in open_ports and 3389 not in open_ports:
            if "Windows" not in os_guess:
                confidence = min(1.0, confidence + 0.1)
            fingerprints["port_clue"] = "SSH port 22 open"

    return OSDetectionResult(
        target=target,
        os_guess=os_guess,
        confidence=round(confidence, 2),
        fingerprints=fingerprints,
    )
