from __future__ import annotations

import socket
import struct
import time
from threading import Event

from src.models.scan_result import PortScanResult


# ── SYN scanner (raw sockets – requires admin/elevated privileges) ──────────

def _checksum(data: bytes) -> int:
    """Compute Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_syn_packet(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Build a minimal raw IP+TCP SYN packet."""
    # TCP header fields
    src_port = 45678
    seq = 0
    ack_seq = 0
    doff = 5  # 4-bit header length
    syn_flag = 0x002  # SYN
    window = socket.htons(1024)
    urg_ptr = 0

    # Pseudo header for checksum
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        (doff << 4), syn_flag, window, 0, urg_ptr,
    )
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, len(tcp_header))
    chk = _checksum(pseudo + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        (doff << 4), syn_flag, window, chk, urg_ptr,
    )
    return tcp_header


def syn_scan_port(target: str, port: int, timeout: float = 1.0) -> PortScanResult:
    """Attempt a SYN (half-open/stealth) scan on a single port.

    Requires administrator/root privileges. Falls back to TCP connect on failure.
    """
    started = time.perf_counter()
    try:
        src_ip = socket.gethostbyname(socket.gethostname())
        dst_ip = socket.gethostbyname(target)

        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.settimeout(timeout)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)

        pkt = _build_syn_packet(src_ip, dst_ip, port)
        raw.sendto(pkt, (dst_ip, 0))

        # Listen for SYN-ACK
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            try:
                data, _ = raw.recvfrom(1024)
                if len(data) >= 40:
                    # Parse IP header (20 bytes) + TCP header
                    ip_len = (data[0] & 0x0F) * 4
                    if len(data) >= ip_len + 14:
                        tcp_offset = ip_len
                        src_p = struct.unpack("!H", data[tcp_offset: tcp_offset + 2])[0]
                        flags = data[tcp_offset + 13]
                        if src_p == port:
                            response_time_ms = round((time.perf_counter() - started) * 1000, 2)
                            raw.close()
                            if flags & 0x12:  # SYN-ACK → open
                                return PortScanResult(
                                    target=target, port=port, is_open=True,
                                    response_time_ms=response_time_ms,
                                    scan_type="syn_stealth",
                                )
                            elif flags & 0x14:  # RST-ACK → closed
                                return PortScanResult(
                                    target=target, port=port, is_open=False,
                                    response_time_ms=response_time_ms,
                                    scan_type="syn_stealth",
                                    error="RST received",
                                )
            except socket.timeout:
                break

        raw.close()
        response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortScanResult(
            target=target, port=port, is_open=False,
            response_time_ms=response_time_ms,
            scan_type="syn_stealth",
            error="No response (filtered)",
        )

    except PermissionError:
        # Fall back to TCP connect scan if no raw socket access
        return _tcp_connect_fallback(target, port, timeout, started)
    except Exception as exc:
        return _tcp_connect_fallback(target, port, timeout, started)


def _tcp_connect_fallback(target: str, port: int, timeout: float, started: float) -> PortScanResult:
    """TCP connect fallback for SYN scanner when raw sockets are unavailable."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as conn:
            response_time_ms = round((time.perf_counter() - started) * 1000, 2)
            return PortScanResult(
                target=target, port=port, is_open=True,
                response_time_ms=response_time_ms,
                scan_type="syn_stealth(fallback:tcp)",
            )
    except Exception as exc:
        response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortScanResult(
            target=target, port=port, is_open=False,
            response_time_ms=response_time_ms,
            scan_type="syn_stealth(fallback:tcp)",
            error=str(exc),
        )


# ── UDP scanner ─────────────────────────────────────────────────────────────

def udp_scan_port(target: str, port: int, timeout: float = 2.0) -> PortScanResult:
    """Scan a UDP port by sending an empty datagram and checking for ICMP unreachable."""
    started = time.perf_counter()
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        udp_sock.sendto(b"\x00" * 4, (target, port))

        try:
            data, _ = udp_sock.recvfrom(1024)
            response_time_ms = round((time.perf_counter() - started) * 1000, 2)
            udp_sock.close()
            return PortScanResult(
                target=target, port=port, is_open=True,
                response_time_ms=response_time_ms,
                scan_type="udp",
                banner=data.decode(errors="ignore").strip() if data else None,
            )
        except socket.timeout:
            # No response → port may be open|filtered
            response_time_ms = round((time.perf_counter() - started) * 1000, 2)
            udp_sock.close()
            return PortScanResult(
                target=target, port=port, is_open=True,
                response_time_ms=response_time_ms,
                scan_type="udp",
                error="open|filtered (no response)",
            )
    except Exception as exc:
        response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortScanResult(
            target=target, port=port, is_open=False,
            response_time_ms=response_time_ms,
            scan_type="udp",
            error=str(exc),
        )


# ── FIN / NULL / XMAS scanners ───────────────────────────────────────────────

def _raw_tcp_flag_scan(target: str, port: int, flags: int, scan_type: str, timeout: float = 1.5) -> PortScanResult:
    """Generic raw TCP scan with a custom flag byte. Requires admin/elevated."""
    started = time.perf_counter()
    try:
        src_ip = socket.gethostbyname(socket.gethostname())
        dst_ip = socket.gethostbyname(target)

        src_port = 45679
        seq, ack_seq = 0, 0
        doff = 5
        window = socket.htons(1024)
        urg_ptr = 0

        # Build TCP header with custom flags
        tcp_header = struct.pack(
            "!HHIIBBHHH", src_port, port, seq, ack_seq,
            (doff << 4), flags, window, 0, urg_ptr,
        )
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, len(tcp_header))
        chk = _checksum(pseudo + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH", src_port, port, seq, ack_seq,
            (doff << 4), flags, window, chk, urg_ptr,
        )

        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.settimeout(timeout)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
        raw.sendto(tcp_header, (dst_ip, 0))

        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            try:
                data, _ = raw.recvfrom(1024)
                if len(data) >= 40:
                    ip_len = (data[0] & 0x0F) * 4
                    if len(data) >= ip_len + 14:
                        tcp_offset = ip_len
                        src_p = struct.unpack("!H", data[tcp_offset: tcp_offset + 2])[0]
                        resp_flags = data[tcp_offset + 13]
                        if src_p == port:
                            response_time_ms = round((time.perf_counter() - started) * 1000, 2)
                            raw.close()
                            if resp_flags & 0x04:  # RST → closed
                                return PortScanResult(
                                    target=target, port=port, is_open=False,
                                    response_time_ms=response_time_ms,
                                    scan_type=scan_type,
                                    error="RST → closed",
                                )
            except socket.timeout:
                break

        raw.close()
        # No RST received → open or filtered
        response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortScanResult(
            target=target, port=port, is_open=True,
            response_time_ms=response_time_ms,
            scan_type=scan_type,
            error="open|filtered (no RST)",
        )

    except PermissionError:
        response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortScanResult(
            target=target, port=port, is_open=False,
            response_time_ms=response_time_ms,
            scan_type=scan_type,
            error="Permission denied: admin required for raw socket scans",
        )
    except Exception as exc:
        response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return PortScanResult(
            target=target, port=port, is_open=False,
            response_time_ms=response_time_ms,
            scan_type=scan_type,
            error=str(exc),
        )


def fin_scan_port(target: str, port: int, timeout: float = 1.5) -> PortScanResult:
    """FIN scan — sends FIN flag; closed ports respond with RST."""
    return _raw_tcp_flag_scan(target, port, 0x001, "fin", timeout)


def null_scan_port(target: str, port: int, timeout: float = 1.5) -> PortScanResult:
    """NULL scan — sends no flags; closed ports respond with RST."""
    return _raw_tcp_flag_scan(target, port, 0x000, "null", timeout)


def xmas_scan_port(target: str, port: int, timeout: float = 1.5) -> PortScanResult:
    """XMAS scan — sends FIN+PSH+URG; closed ports respond with RST."""
    return _raw_tcp_flag_scan(target, port, 0x029, "xmas", timeout)
