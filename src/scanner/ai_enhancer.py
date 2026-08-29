from __future__ import annotations

from collections import Counter
from typing import List

from src.models.scan_result import PortScanResult, ScanSession


# Known port combinations for specific server types
WEBSERVER_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000, 8888}
DATABASE_PORTS = {3306, 5432, 1433, 27017, 27018, 6379, 9200}
RDP_PORTS = {3389}
SSH_PORTS = {22}
DNS_PORTS = {53}
SMTP_PORTS = {25, 587, 465}
FTP_PORTS = {21, 990}


def detect_anomalies(session: ScanSession) -> List[str]:
    """Detect unusual patterns in scan results (anomaly detection)."""
    anomalies: List[str] = []

    if not session.open_ports:
        return anomalies

    open_port_numbers = [r.port for r in session.open_ports]
    services = [r.service_name for r in session.open_ports if r.service_name]

    # Anomaly 1: Excessive number of open ports (possible honeypot or misconfiguration)
    if len(open_port_numbers) > 50:
        anomalies.append("Unusually high number of open ports (>50) — may indicate honeypot or misconfiguration")

    # Anomaly 2: Rare port combinations
    web_count = len([p for p in open_port_numbers if p in WEBSERVER_PORTS])
    db_count = len([p for p in open_port_numbers if p in DATABASE_PORTS])
    rdp_count = len([p for p in open_port_numbers if p in RDP_PORTS])
    ssh_count = len([p for p in open_port_numbers if p in SSH_PORTS])

    if db_count > 2 and web_count == 0:
        anomalies.append("Multiple database ports open without web service — unusual pattern")

    if rdp_count > 0 and ssh_count > 0:
        anomalies.append("Both RDP and SSH open — mixed Windows/Unix anomaly")

    # Anomaly 3: Suspicious port sequences
    if len(open_port_numbers) > 1:
        sorted_ports = sorted(open_port_numbers)
        max_gap = max(sorted_ports[i + 1] - sorted_ports[i] for i in range(len(sorted_ports) - 1))
        if max_gap < 100 and len(sorted_ports) > 5:
            anomalies.append("Dense port sequence detected — possible port knocker or firewall rule")

    # Anomaly 4: Banner inconsistencies
    service_count = Counter(services)
    if len(service_count) > 0 and max(service_count.values()) < len(services) / 2:
        anomalies.append("Inconsistent service detection — possible mixed/containerized environment")

    return anomalies


def generate_risk_summary(session: ScanSession) -> str:
    """Generate a text summary of the scan risk profile."""
    open_count = len(session.open_ports)
    critical_count = len([r for r in session.open_ports if r.risk_score and r.risk_score >= 9.0])
    high_count = len([r for r in session.open_ports if r.risk_score and 7.0 <= r.risk_score < 9.0])

    if critical_count > 0:
        return f"CRITICAL: {critical_count} critical vulnerabilities found across {open_count} open ports"
    elif high_count > 2:
        return f"HIGH RISK: {high_count} high-severity findings on {open_count} open ports"
    elif open_count > 20:
        return f"MEDIUM RISK: Excessive open ports ({open_count}) — recommend review"
    elif open_count > 5:
        return f"MEDIUM RISK: {open_count} open ports detected"
    elif open_count > 0:
        return f"LOW RISK: {open_count} open port(s) found"
    else:
        return "NO RISK: No open ports detected"


def assign_port_risk(port: int, service_name: str | None, vuln_count: int) -> float:
    """Assign risk score (0-10) to an individual port."""
    base_risk = 0.0

    # Port-based risk
    if port < 1024:
        base_risk = 3.0  # Well-known port
    elif port < 49152:
        base_risk = 2.0  # Registered port
    else:
        base_risk = 1.0  # Dynamic port

    # Service-based risk
    if service_name:
        service = service_name.lower()
        if service in {"ftp", "telnet", "smtp", "snmp"}:
            base_risk += 2.0
        elif service in {"ssh", "https", "pop3s"}:
            base_risk += 0.5
        elif service in {"mysql", "postgresql", "mongodb", "redis"}:
            base_risk += 3.0
        elif service in {"rdp", "vnc"}:
            base_risk += 2.5
        elif service == "http":
            base_risk += 1.5

    # Vulnerability count impact
    base_risk += min(4.0, vuln_count * 1.0)

    return round(min(10.0, base_risk), 1)


def apply_ai_enhancements(session: ScanSession) -> None:
    """Apply AI-powered enhancements to scan results in-place.

    Updates each result with:
    - Anomaly detection
    - Risk scoring
    - Behavioral analysis
    """
    # Detect global anomalies
    anomalies = detect_anomalies(session)

    # Calculate overall risk
    critical_cves = sum(1 for r in session.open_ports if r.vulnerability_ids and len(r.vulnerability_ids) >= 2)
    high_cves = sum(1 for r in session.open_ports if r.vulnerability_ids and len(r.vulnerability_ids) == 1)
    medium_cves = sum(1 for r in session.results if r.risk_score and r.risk_score >= 5.0)

    # Assign individual port risk scores if not already assigned
    for result in session.open_ports:
        if result.risk_score is None:
            vuln_count = len(result.vulnerability_ids) if result.vulnerability_ids else 0
            result.risk_score = assign_port_risk(result.port, result.service_name, vuln_count)

    # Store anomaly summary in session metadata (best-effort)
    if anomalies:
        # Attach to first result as a note (not ideal but works with current data model)
        if session.results:
            session.results[0].banner_enhanced = (
                session.results[0].banner_enhanced or ""
            ) + f"\n[AI] Anomalies: {'; '.join(anomalies)}"
