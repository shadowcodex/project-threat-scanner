"""Semgrep supply-chain scanner -- runs custom rules against dependency source."""

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

DEPS_DIR = "/opt/deps"
RULES_PATH = "/opt/rules/semgrep/supply-chain.yaml"


def run_semgrep_supply_chain(output_dir: str) -> ScanResults:
    """Run Semgrep with custom supply-chain rules against /opt/deps/."""
    return run_scanner(
        ScanSpec(
            name="semgrep-supply-chain",
            cmd=["semgrep", "scan", "--config", RULES_PATH, "--json", DEPS_DIR],
            timeout=600,
        ),
        output_dir=output_dir,
    )


def parse_semgrep_supply_chain_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Semgrep supply-chain JSON output into normalized Finding objects.

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

        finding_id = f"semgrep-sc-{check_id}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="semgrep-supply-chain",
                category="behavioral",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=check_id,
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
