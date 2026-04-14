"""Bandit scanner wrapper -- Python SAST analysis."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Directories to exclude from bandit scans. Test code uses asserts and
# subprocess calls everywhere as part of normal practice — scanning them
# drowns the real findings in noise. The target repo's own security
# posture is what we care about.
_BANDIT_EXCLUDE_DIRS = "tests,test,e2e,examples,docs,build,dist,.tox,.venv,venv"


def run_bandit(target_dir: str, output_dir: str) -> ScanResults:
    """Run Bandit to detect security issues in Python code."""
    return run_scanner(
        ScanSpec(
            name="bandit",
            cmd=[
                "bandit",
                "-r",
                target_dir,
                "-f",
                "json",
                "-q",
                "-x",
                _BANDIT_EXCLUDE_DIRS,
            ],
        ),
        output_dir=output_dir,
    )


def parse_bandit_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Bandit JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Bandit's ``-f json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("results", [])

    for idx, issue in enumerate(results):
        test_id = issue.get("test_id", "unknown")
        test_name = issue.get("test_name", "")
        file_path = issue.get("filename")
        line_number = issue.get("line_number")
        severity_raw = issue.get("issue_severity", "LOW")
        confidence = issue.get("issue_confidence", "")
        issue_text = issue.get("issue_text", "")

        severity = _SEVERITY_MAP.get(severity_raw.upper(), "low")

        title = f"{test_id}: {test_name}"
        description = f"{issue_text} (confidence: {confidence})"

        finding_id = f"bandit-{test_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="bandit",
                category="sast",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=title,
                description=description,
                file_path=file_path,
                line_number=line_number,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=issue,
            )
        )

    return findings
