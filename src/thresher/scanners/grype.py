"""Grype scanner wrapper -- SCA vulnerability scanning against an SBOM."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

# Grype severity values mapped to our normalized scale.
_SEVERITY_MAP: dict[str, str] = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "info",
    "Unknown": "info",
}


def run_grype(sbom_path: str, output_dir: str) -> ScanResults:
    """Run Grype against a CycloneDX SBOM produced by Syft."""
    return run_scanner(
        ScanSpec(
            name="grype",
            cmd=["grype", f"sbom:{sbom_path}", "-o", "json"],
        ),
        output_dir=output_dir,
    )


def parse_grype_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Grype JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Grype's ``-o json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    matches = raw.get("matches", [])

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        cve_id = vulnerability.get("id", "")
        severity_raw = vulnerability.get("severity", "Unknown")
        severity = _SEVERITY_MAP.get(severity_raw, "info")

        # Extract CVSS score -- Grype may include multiple CVSS entries.
        cvss_score = _extract_cvss_score(vulnerability)

        pkg_name = artifact.get("name", "unknown")
        pkg_version = artifact.get("version", "unknown")

        # Fix version from the first available fixed-in entry.
        fix_versions = vulnerability.get("fix", {}).get("versions", [])
        fix_version = fix_versions[0] if fix_versions else None

        description = vulnerability.get("description", "")
        if not description:
            # Fall back to the data source description if the top-level one is empty.
            for ds in vulnerability.get("dataSource", []):
                if isinstance(ds, str):
                    description = f"See: {ds}"
                    break

        finding_id = f"grype-{cve_id}" if cve_id else f"grype-{pkg_name}-{pkg_version}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="grype",
                category="sca",
                severity=severity,
                cvss_score=cvss_score,
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                title=f"{cve_id} in {pkg_name}@{pkg_version}",
                description=description,
                file_path=None,
                line_number=None,
                package_name=pkg_name,
                package_version=pkg_version,
                fix_version=fix_version,
                raw_output=match,
            )
        )

    return findings


def _extract_cvss_score(vulnerability: dict[str, Any]) -> float | None:
    """Extract the highest CVSS score from a Grype vulnerability entry."""
    best: float | None = None
    for cvss_entry in vulnerability.get("cvss", []):
        metrics = cvss_entry.get("metrics", {})
        score = metrics.get("baseScore")
        if score is not None:
            if best is None or score > best:
                best = score
    return best
