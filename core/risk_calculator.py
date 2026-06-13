"""
Risk score calculator for VulnScan Pro.

Computes an overall risk score (0–100) from a list of vulnerability findings
using weighted CVSS scores and severity multipliers.
"""
from __future__ import annotations

from typing import List

SEVERITY_WEIGHT: dict[str, float] = {
    "CRITICAL": 4.0,
    "HIGH": 2.5,
    "MEDIUM": 1.5,
    "LOW": 0.75,
    "INFORMATIONAL": 0.25,
}

# Maximum raw score that maps to 100 (calibrated against typical scan results)
_NORMALISATION_CAP = 120.0


class RiskCalculator:
    """Calculate a normalised risk score from vulnerability findings."""

    @staticmethod
    def calculate(vulnerabilities: List[dict]) -> float:
        """
        Return a risk score between 0.0 and 100.0.

        The score is a weighted sum of (CVSS × severity_weight) for each
        finding, clamped and normalised to the 0–100 range.
        """
        if not vulnerabilities:
            return 0.0

        raw = 0.0
        for vuln in vulnerabilities:
            cvss = float(vuln.get("cvss_score", 0.0))
            sev = vuln.get("severity", "LOW").upper()
            weight = SEVERITY_WEIGHT.get(sev, 1.0)
            raw += cvss * weight

        # Normalise: score grows with finding count but caps at 100
        normalised = (raw / _NORMALISATION_CAP) * 100.0
        return round(min(normalised, 100.0), 1)

    @staticmethod
    def severity_label(score: float) -> str:
        """Return a human-readable label for a 0–100 risk score."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "MINIMAL"

    @staticmethod
    def severity_counts(vulnerabilities: List[dict]) -> dict[str, int]:
        """Return a mapping of severity → count from the findings list."""
        counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0,
        }
        for v in vulnerabilities:
            sev = v.get("severity", "").upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def recommendations(vulnerabilities: List[dict]) -> List[str]:
        """
        Return a deduplicated list of actionable recommendation strings
        sorted from highest-CVSS finding to lowest.
        """
        seen: set[str] = set()
        recs: list[str] = []
        sorted_vulns = sorted(
            vulnerabilities, key=lambda v: v.get("cvss_score", 0), reverse=True
        )
        for vuln in sorted_vulns:
            rem = vuln.get("remediation", "").strip()
            if rem and rem not in seen:
                seen.add(rem)
                recs.append(rem)
        return recs
