from __future__ import annotations

import re
import socket
from dataclasses import dataclass


# Known port-to-service mapping
PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpc", 119: "nntp",
    123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1443: "ms-sql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 4444: "metasploit",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis",
    6443: "kubernetes", 7001: "weblogic", 8080: "http-proxy",
    8443: "https-alt", 8888: "jupyter", 9200: "elasticsearch",
    27017: "mongodb", 27018: "mongodb-shard",
}

# Banner fingerprint patterns for service + version detection
BANNER_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("ssh", r"SSH-(\S+)-OpenSSH[_\s]([\d.]+\w*)", re.compile(
        r"SSH-[\d.]+-OpenSSH[_\s]([\d.]+)", re.IGNORECASE)),
    ("ssh", r"", re.compile(r"SSH-([\d.]+)", re.IGNORECASE)),
    ("ftp", r"", re.compile(
        r"(?:220|230)[^\n]*(?:vsFTPd|ProFTPD|FileZilla|PureFTPd)[^\n]*([\d.]+)", re.IGNORECASE)),
    ("smtp", r"", re.compile(r"220[^\n]*SMTP[^\n]*([\d.]+)?", re.IGNORECASE)),
    ("http", r"", re.compile(
        r"Server:\s*([\w/\s.\-]+(?:[\d.]+))", re.IGNORECASE)),
    ("imap", r"", re.compile(r"\* OK[^\n]*IMAP[^\n]*([\d.]+)?", re.IGNORECASE)),
    ("pop3", r"", re.compile(r"\+OK[^\n]*([\d.]+)?", re.IGNORECASE)),
    ("mysql", r"", re.compile(r"mysql[^\n]*([\d.]+)", re.IGNORECASE)),
    ("redis", r"", re.compile(r"redis[^\n]*([\d.]+)", re.IGNORECASE)),
    ("telnet", r"", re.compile(r"telnet", re.IGNORECASE)),
    ("mongodb", r"", re.compile(r"mongodb[^\n]*([\d.]+)", re.IGNORECASE)),
]

# HTTP banner probes (send HTTP request and parse response)
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"


@dataclass(slots=True)
class ServiceInfo:
    service_name: str
    service_version: str | None = None
    banner_enhanced: str | None = None


def detect_service_from_port(port: int) -> str | None:
    """Return known service name for a standard port number."""
    return PORT_SERVICE_MAP.get(port)


def detect_service_from_banner(banner: str, port: int) -> ServiceInfo:
    """Parse banner text to identify service name and version."""
    if not banner:
        name = detect_service_from_port(port)
        return ServiceInfo(service_name=name or "unknown")

    # Try each banner pattern
    for service, _, pattern in BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
            enhanced = f"{service}/{version}" if version else service
            return ServiceInfo(
                service_name=service,
                service_version=version,
                banner_enhanced=enhanced,
            )

    # Fall back to port-based guess
    name = detect_service_from_port(port)
    return ServiceInfo(service_name=name or "unknown", banner_enhanced=banner[:80])


def probe_service(target: str, port: int, timeout: float = 1.0) -> ServiceInfo:
    """Actively probe a port for service information via banner + HTTP probe."""
    # First try banner grab
    raw_banner: str | None = None
    try:
        with socket.create_connection((target, port), timeout=timeout) as conn:
            conn.settimeout(0.5)
            data = conn.recv(256)
            if data:
                raw_banner = data.decode(errors="ignore").strip()
    except Exception:
        pass

    # If no banner, try HTTP probe for common web ports
    if not raw_banner and port in {80, 8080, 8000, 8443, 443, 8888, 3000, 4000, 5000}:
        try:
            with socket.create_connection((target, port), timeout=timeout) as conn:
                conn.sendall(HTTP_PROBE)
                conn.settimeout(0.5)
                data = conn.recv(512)
                if data:
                    raw_banner = data.decode(errors="ignore").strip()
        except Exception:
            pass

    return detect_service_from_banner(raw_banner or "", port)
