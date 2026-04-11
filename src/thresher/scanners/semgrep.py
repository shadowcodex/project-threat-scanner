"""Semgrep scanner wrapper -- SAST code vulnerability scanning."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def run_semgrep(target_dir: str, output_dir: str) -> ScanResults:
    """Run Semgrep SAST scan with the auto config ruleset."""
    return run_scanner(
        ScanSpec(
            name="semgrep",
            cmd=["semgrep", "scan", "--config", "auto", "--json", target_dir],
            timeout=600,
        ),
        output_dir=output_dir,
    )


def parse_semgrep_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Semgrep JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Semgrep's ``--json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("results", [])

    for hit in results:
        check_id = hit.get("check_id", "unknown")
        extra = hit.get("extra", {})

        severity_raw = extra.get("severity", "INFO")
        severity = _SEVERITY_MAP.get(severity_raw.upper(), "info")

        message = extra.get("message", "")
        metadata = extra.get("metadata", {})

        file_path = hit.get("path")
        start_info = hit.get("start", {})
        line_number = start_info.get("line")

        # Some Semgrep rules include CWE or CVE references in metadata.
        cve_id = metadata.get("cve") or None
        cwe = metadata.get("cwe", [])
        cwe_str = (", ".join(cwe) if cwe else "") if isinstance(cwe, list) else str(cwe)

        title = f"{check_id}"
        if cwe_str:
            title = f"{check_id} ({cwe_str})"

        finding_id = f"semgrep-{check_id}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="semgrep",
                category="sast",
                severity=severity,
                cvss_score=None,
                cve_id=cve_id,
                title=title,
                description=message,
                file_path=file_path,
                line_number=line_number,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=hit,
            )
        )

    return findings
