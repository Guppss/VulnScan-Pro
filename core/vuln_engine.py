"""
Vulnerability detection engine for VulnScan Pro.

Matches detected services and versions against the local vulnerability
database to produce a list of findings with severity ratings.
"""
from __future__ import annotations

import re
from typing import List

from database.vuln_db import VULNERABILITY_DATABASE, PORT_RISK_CHECKS
from utils.logger import logger


def _parse_version(version_str: str) -> tuple[int, ...]:
    """
    Parse a version string into a tuple of integers for comparison.

    '9.3p2' → (9, 3, 2)  |  '2.4.49' → (2, 4, 49)  |  '' → (0,)
    """
    if not version_str:
        return (0,)
    # Extract all numeric groups
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_le(detected: str, max_version: str) -> bool:
    """Return True if detected version is ≤ max_version."""
    return _parse_version(detected) <= _parse_version(max_version)


def _version_eq(detected: str, exact: str) -> bool:
    """Return True if detected version equals exact version."""
    return _parse_version(detected) == _parse_version(exact)


class VulnerabilityEngine:
    """Match scan results against the local CVE database."""

    def analyze(
        self, port_results: List[dict], scan_id: str = ""
    ) -> List[dict]:
        """
        Analyze a list of open-port results and return vulnerability findings.

        Each finding is a dict compatible with db_manager.save_vulnerabilities().
        """
        findings: list[dict] = []
        open_ports: set[int] = set()

        for port_result in port_results:
            if port_result.get("status") != "open":
                continue

            port = port_result["port"]
            open_ports.add(port)
            host = port_result["host"]
            service = port_result.get("service", "").lower()
            product = port_result.get("product", "").lower()
            version = port_result.get("version", "")
            banner = port_result.get("banner", "").lower()

            # Match service against vulnerability database entries
            for db_key, db_entry in VULNERABILITY_DATABASE.items():
                patterns = [p.lower() for p in db_entry["service_patterns"]]
                matched = any(
                    p in service or p in product or p in banner
                    for p in patterns
                )
                if not matched:
                    continue

                for vuln in db_entry["vulnerabilities"]:
                    finding = self._check_vulnerability(
                        vuln, host, port, db_entry["display_name"], version
                    )
                    if finding:
                        findings.append(finding)
                        logger.debug(
                            "Found %s on %s:%d", vuln["cve_id"], host, port
                        )

        # Port-based risk checks (don't require version matching)
        for check in PORT_RISK_CHECKS:
            for risk_port in check["ports"]:
                if risk_port in open_ports:
                    host = next(
                        (r["host"] for r in port_results if r.get("port") == risk_port),
                        "unknown",
                    )
                    findings.append({
                        "host": host,
                        "port": risk_port,
                        "service": PORT_RISK_CHECKS[PORT_RISK_CHECKS.index(check)].get(
                            "service", ""
                        ),
                        "cve_id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "cvss_score": check["cvss_score"],
                        "description": check["description"],
                        "remediation": check["remediation"],
                        "detected_version": "",
                    })

        # Deduplicate by (host, port, cve_id)
        seen: set[tuple] = set()
        unique: list[dict] = []
        for f in findings:
            key = (f["host"], f["port"], f["cve_id"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Sort by CVSS score descending
        unique.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return unique

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _check_vulnerability(
        vuln: dict, host: str, port: int, service_name: str, detected_version: str
    ) -> dict | None:
        """
        Determine if a vulnerability applies given the detected version.

        Returns a finding dict or None if the version is not affected.
        """
        max_ver = vuln.get("affected_max_version", "")
        exact_ver = vuln.get("affected_exact_version", "")

        # If we have no version info, report all matching CVEs as informational
        if not detected_version:
            finding = {
                "host": host,
                "port": port,
                "service": service_name,
                "cve_id": vuln["cve_id"],
                "name": f"{vuln['name']} (version unconfirmed)",
                "severity": "LOW",
                "cvss_score": min(vuln.get("cvss_score", 0.0), 4.0),
                "description": (
                    vuln["description"] +
                    "\n\nNote: Version could not be determined. "
                    "Manual verification is recommended."
                ),
                "remediation": vuln["remediation"],
                "detected_version": "unknown",
            }
            return finding

        if exact_ver:
            if _version_eq(detected_version, exact_ver):
                return VulnerabilityEngine._make_finding(
                    vuln, host, port, service_name, detected_version
                )
            return None

        if max_ver:
            if _version_le(detected_version, max_ver):
                return VulnerabilityEngine._make_finding(
                    vuln, host, port, service_name, detected_version
                )
            return None

        # No version constraint — always applies
        return VulnerabilityEngine._make_finding(
            vuln, host, port, service_name, detected_version
        )

    @staticmethod
    def _make_finding(
        vuln: dict, host: str, port: int, service_name: str, detected_version: str
    ) -> dict:
        return {
            "host": host,
            "port": port,
            "service": service_name,
            "cve_id": vuln["cve_id"],
            "name": vuln["name"],
            "severity": vuln["severity"],
            "cvss_score": vuln.get("cvss_score", 0.0),
            "description": vuln["description"],
            "remediation": vuln["remediation"],
            "detected_version": detected_version,
        }
