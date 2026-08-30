from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

# Local CVE database mapping (service_name, version) -> [(cve_id, severity, cvss_score), ...]
# This is a minimal curated database for common vulnerabilities
CVE_DATABASE: Dict[Tuple[str, str], List[Tuple[str, str, float]]] = {
    ("ssh", "openssh_7.4"): [
        ("CVE-2018-15473", "high", 5.3),
    ],
    ("ssh", "openssh_6.6"): [
        ("CVE-2014-6271", "critical", 10.0),
        ("CVE-2015-3224", "high", 7.5),
    ],
    ("http", "apache_2.4.49"): [
        ("CVE-2021-41773", "critical", 9.8),
        ("CVE-2021-42013", "critical", 9.8),
    ],
    ("http", "nginx_1.16"): [
        ("CVE-2019-9511", "high", 7.5),
    ],
    ("mysql", "5.7.0"): [
        ("CVE-2016-3471", "high", 8.1),
    ],
    ("ftp", "vsftpd_2.3.4"): [
        ("CVE-2011-2523", "critical", 9.0),
    ],
    ("smtp", "postfix_2.11"): [
        ("CVE-2016-6554", "medium", 4.3),
    ],
}

# Port-based vulnerability hints (common exploitable services)
PORT_VULNERABILITIES: Dict[int, List[Tuple[str, str, float]]] = {
    21: [("ftp-common", "FTP commonly exploited", 3.0)],
    23: [("telnet-cleartext", "Telnet sends credentials in cleartext", 7.5)],
    445: [("smb-common", "SMB frequently targeted", 6.5)],
    3389: [("rdp-common", "RDP exposed to internet risk", 5.0)],
    3306: [("mysql-exposed", "MySQL exposed externally", 6.0)],
    5432: [("postgres-exposed", "PostgreSQL exposed externally", 6.0)],
    6379: [("redis-exposed", "Redis typically no auth required", 8.0)],
    27017: [("mongodb-exposed", "MongoDB often exposed without auth", 9.0)],
}

# Severity scoring
SEVERITY_SCORES: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def lookup_cves(service_name: str | None, service_version: str | None, port: int) -> List[Tuple[str, str, float]]:
    """Look up known CVEs for a service and version.

    Returns list of (cve_id, severity, cvss_score) tuples.
    """
    if not service_name:
        service_name = "unknown"

    cves: List[Tuple[str, str, float]] = []

    # Try exact service + version match
    if service_version:
        key = (service_name.lower(), service_version.lower())
        if key in CVE_DATABASE:
            cves.extend(CVE_DATABASE[key])

    # Check port-based vulnerabilities (as fallback hints)
    if port in PORT_VULNERABILITIES:
        for vuln_id, desc, score in PORT_VULNERABILITIES[port]:
            # Map score to severity
            severity = "high" if score >= 7.0 else "medium" if score >= 5.0 else "low"
            cves.append((vuln_id, severity, score))

    return cves


def apply_risk_to_results(results: List) -> None:
    """Apply risk scoring to results (stub for compatibility)."""
    for result in results:
        if result.vulnerability_ids:
            base_risk = 2.0
            cve_count = len(result.vulnerability_ids)
            result.risk_score = round(min(10.0, base_risk + (cve_count * 0.5)), 1)


def assign_risk_score(open_port_count: int, critical_cves: int, high_cves: int, medium_cves: int) -> float:
    """Assign an overall risk score (0-10) based on findings."""
    # Base score from port count
    base_score = min(2.0, open_port_count * 0.5)

    # Add scores for vulnerabilities
    vuln_score = (critical_cves * 3.0) + (high_cves * 2.0) + (medium_cves * 0.5)
    vuln_score = min(5.0, vuln_score)

    # Combine
    total = base_score + vuln_score
    return round(min(10.0, total), 1)


def generate_cve_summary(cves: List[Tuple[str, str, float]]) -> str:
    """Generate a human-readable summary of CVEs."""
    if not cves:
        return "No known CVEs"

    by_severity: Dict[str, List[str]] = {"critical": [], "high": [], "medium": [], "low": []}
    for cve_id, severity, _ in cves:
        by_severity[severity].append(cve_id)

    parts = []
    if by_severity["critical"]:
        parts.append(f"Critical: {', '.join(by_severity['critical'])}")
    if by_severity["high"]:
        parts.append(f"High: {', '.join(by_severity['high'])}")
    if by_severity["medium"]:
        parts.append(f"Medium: {', '.join(by_severity['medium'])}")

    return " | ".join(parts) if parts else "No known CVEs"


def save_cve_cache(cache_path: str | Path) -> None:
    """Save the CVE database to a JSON file for persistence (stub)."""
    cache_path = Path(cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        # Convert database to JSON-serializable format
        serializable = {
            f"{service}:{version}": [(cve, sev, score) for cve, sev, score in vulns]
            for (service, version), vulns in CVE_DATABASE.items()
        }
        json.dump(serializable, f, indent=2)


def load_cve_cache(cache_path: str | Path) -> None:
    """Load CVE database from a JSON file (stub for future enhancement)."""
    # Placeholder for loading external CVE data
    pass
