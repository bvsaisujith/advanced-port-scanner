from __future__ import annotations


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]


def parse_ports(port_text: str) -> list[int]:
    text = port_text.strip()
    if not text:
        return DEFAULT_PORTS.copy()

    ports: set[int] = set()
    for chunk in text.split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start_port = int(start_text.strip())
            end_port = int(end_text.strip())
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            for port in range(start_port, end_port + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)

    return sorted(ports)


def normalize_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Target is required")
    return value
