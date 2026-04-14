"""Trivy scanner wrapper -- filesystem vulnerability scanning."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def run_trivy(target_dir: str, output_dir: str) -> ScanResults:
    """Run Trivy filesystem scan to detect vulnerabilities."""
    return run_scanner(
        ScanSpec(
            name="trivy",
            cmd=["trivy", "fs", "--format", "json", "--skip-db-update", target_dir],
        ),
        output_dir=output_dir,
    )


def parse_trivy_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Trivy JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Trivy's ``--format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("Results", [])

    for target_result in results:
        vulns = target_result.get("Vulnerabilities") or []

        for vuln in vulns:
            vuln_id = vuln.get("VulnerabilityID", "unknown")
            pkg_name = vuln.get("PkgName", "unknown")
            installed_version = vuln.get("InstalledVersion", "unknown")
            fixed_version = vuln.get("FixedVersion") or None
            severity_raw = vuln.get("Severity", "UNKNOWN")
            title = vuln.get("Title", "")
            description = vuln.get("Description", "")

            severity = _SEVERITY_MAP.get(severity_raw.upper(), "info")

            finding_title = f"{vuln_id} in {pkg_name}@{installed_version}"
            if title:
                finding_title = f"{vuln_id}: {title}"

            finding_id = f"trivy-{vuln_id}-{pkg_name}"

            findings.append(
                Finding(
                    id=finding_id,
                    source_tool="trivy",
                    category="sca",
                    severity=severity,
                    cvss_score=None,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    title=finding_title,
                    description=description,
                    file_path=None,
                    line_number=None,
                    package_name=pkg_name,
                    package_version=installed_version,
                    fix_version=fixed_version,
                    raw_output=vuln,
                )
            )

    return findings
