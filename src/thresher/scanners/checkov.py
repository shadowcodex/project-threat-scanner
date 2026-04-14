"""Checkov scanner wrapper -- Infrastructure-as-Code security scanning."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)


def run_checkov(target_dir: str, output_dir: str) -> ScanResults:
    """Run Checkov to detect IaC misconfigurations."""
    return run_scanner(
        ScanSpec(
            name="checkov",
            cmd=["checkov", "-d", target_dir, "-o", "json", "--quiet"],
        ),
        output_dir=output_dir,
    )


def parse_checkov_output(raw: Any) -> list[Finding]:
    """Parse Checkov JSON output into normalized Finding objects.

    Checkov output can be a single dict or a list of dicts (one per
    framework scanned).

    Args:
        raw: Parsed JSON from Checkov's ``-o json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    # Normalize to a list of framework result dicts.
    if isinstance(raw, dict):
        frameworks = [raw]
    elif isinstance(raw, list):
        frameworks = raw
    else:
        logger.error("Unexpected Checkov output type: %s", type(raw))
        return findings

    idx = 0
    for framework_result in frameworks:
        results = framework_result.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for check in failed_checks:
            check_id = check.get("check_id", "unknown")
            check_type = check.get("check_type", "")
            check.get("check_result", {}).get("result", "FAILED")
            file_path = check.get("file_path")
            line_range = check.get("file_line_range", [])
            resource = check.get("resource", "")
            guideline = check.get("guideline", "")

            line_number = line_range[0] if line_range else None

            title = f"{check_id}: {check_type}" if check_type else check_id
            description_parts = [f"Resource: {resource}"]
            if guideline:
                description_parts.append(f"Guideline: {guideline}")
            description = "; ".join(description_parts)

            finding_id = f"checkov-{check_id}-{idx}"
            idx += 1

            findings.append(
                Finding(
                    id=finding_id,
                    source_tool="checkov",
                    category="iac",
                    severity="medium",
                    cvss_score=None,
                    cve_id=None,
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_number,
                    package_name=None,
                    package_version=None,
                    fix_version=None,
                    raw_output=check,
                )
            )

    return findings
