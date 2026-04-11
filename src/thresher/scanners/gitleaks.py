"""Gitleaks scanner wrapper -- secrets detection."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)


def run_gitleaks(target_dir: str, output_dir: str) -> ScanResults:
    """Run Gitleaks to detect hardcoded secrets in the repository."""
    output_path = f"{output_dir}/gitleaks.json"
    return run_scanner(
        ScanSpec(
            name="gitleaks",
            cmd=[
                "gitleaks", "detect",
                "--source", target_dir,
                "--report-format", "json",
                "--report-path", output_path,
                "--no-banner",
            ],
            output_mode="self",
        ),
        output_dir=output_dir,
    )


def parse_gitleaks_output(raw: list[dict[str, Any]]) -> list[Finding]:
    """Parse Gitleaks JSON output into normalized Finding objects.

    Gitleaks outputs a JSON array of leak objects, each containing the
    rule that matched, file path, line number, and a redacted match.

    Args:
        raw: Parsed JSON list from Gitleaks' ``--report-format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, leak in enumerate(raw):
        rule_id = leak.get("RuleID", "unknown")
        description = leak.get("Description", rule_id)
        file_path = leak.get("File", None)
        start_line = leak.get("StartLine", None)
        commit = leak.get("Commit", "")
        author = leak.get("Author", "")
        date = leak.get("Date", "")
        match = leak.get("Match", "")

        # Build a descriptive title.
        title = f"Secret detected: {description}"
        if file_path:
            title = f"Secret detected in {file_path}: {description}"

        detail_parts = [f"Rule: {rule_id}"]
        if commit:
            detail_parts.append(f"Commit: {commit}")
        if author:
            detail_parts.append(f"Author: {author}")
        if date:
            detail_parts.append(f"Date: {date}")
        if match:
            # Truncate the match to avoid leaking full secrets in reports.
            redacted = match[:20] + "..." if len(match) > 20 else match
            detail_parts.append(f"Match: {redacted}")

        full_description = "; ".join(detail_parts)

        finding_id = f"gitleaks-{rule_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="gitleaks",
                category="secrets",
                severity="high",
                cvss_score=None,
                cve_id=None,
                title=title,
                description=full_description,
                file_path=file_path,
                line_number=start_line,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=leak,
            )
        )

    return findings
