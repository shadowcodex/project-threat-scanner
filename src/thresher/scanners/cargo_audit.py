"""cargo-audit scanner wrapper -- Rust dependency vulnerability scanning."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "none": "info",
}


def run_cargo_audit(target_dir: str, output_dir: str) -> ScanResults:
    """Run cargo-audit to detect vulnerabilities in Rust dependencies.

    Skips quietly when there's no ``Cargo.lock`` to audit.
    """
    if not Path(target_dir, "Cargo.lock").exists():
        logger.info("No Cargo.lock found, skipping cargo-audit")
        return ScanResults(
            tool_name="cargo-audit",
            execution_time_seconds=0.0,
            exit_code=0,
            findings=[],
        )

    return run_scanner(
        ScanSpec(
            name="cargo-audit",
            cmd=["cargo-audit", "audit", "--json"],
            cwd=target_dir,
        ),
        output_dir=output_dir,
    )


def parse_cargo_audit_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse cargo-audit JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from cargo-audit's ``--json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    vuln_list = raw.get("vulnerabilities", {}).get("list", [])

    for idx, vuln in enumerate(vuln_list):
        advisory = vuln.get("advisory", {})
        package = vuln.get("package", {})
        versions = vuln.get("versions", {})

        advisory_id = advisory.get("id", "unknown")
        title = advisory.get("title", "")
        description = advisory.get("description", "")
        url = advisory.get("url", "")
        severity_raw = advisory.get("severity", "")

        pkg_name = package.get("name", "unknown")
        pkg_version = package.get("version", "unknown")

        patched = versions.get("patched", [])
        fix_version = patched[0] if patched else None

        severity = _SEVERITY_MAP.get(severity_raw.lower(), "high")

        if url:
            description = f"{description}\nRef: {url}" if description else f"See: {url}"

        finding_title = f"{advisory_id}: {title}" if title else advisory_id
        finding_id = f"cargo-audit-{advisory_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="cargo-audit",
                category="sca",
                severity=severity,
                cvss_score=None,
                cve_id=advisory_id if advisory_id.startswith("CVE-") else None,
                title=finding_title,
                description=description,
                file_path=None,
                line_number=None,
                package_name=pkg_name,
                package_version=pkg_version,
                fix_version=fix_version,
                raw_output=vuln,
            )
        )

    return findings
