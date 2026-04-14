"""Hadolint scanner wrapper -- Dockerfile linting."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_LEVEL_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "style": "low",
}


def run_hadolint(target_dir: str, output_dir: str) -> ScanResults:
    """Run Hadolint against every Dockerfile* in the target directory.

    Skips quietly when no Dockerfiles are found.
    """
    dockerfiles = [str(p) for p in Path(target_dir).rglob("Dockerfile*") if ".git" not in p.parts]
    if not dockerfiles:
        logger.info("No Dockerfiles found, skipping Hadolint")
        return ScanResults(
            tool_name="hadolint",
            execution_time_seconds=0.0,
            exit_code=0,
            findings=[],
        )

    return run_scanner(
        ScanSpec(
            name="hadolint",
            cmd=["hadolint", "--format", "json", *dockerfiles],
        ),
        output_dir=output_dir,
    )


def parse_hadolint_output(raw: list[dict[str, Any]]) -> list[Finding]:
    """Parse Hadolint JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON list from Hadolint's ``--format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, item in enumerate(raw):
        code = item.get("code", "unknown")
        message = item.get("message", "")
        level = item.get("level", "info")
        file_path = item.get("file")
        line_number = item.get("line")

        severity = _LEVEL_MAP.get(level, "low")

        title = f"{code}: {message}"
        finding_id = f"hadolint-{code}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="hadolint",
                category="iac",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=title,
                description=message,
                file_path=file_path,
                line_number=line_number,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=item,
            )
        )

    return findings
