"""govulncheck scanner wrapper -- Go vulnerability scanning."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)


def run_govulncheck(target_dir: str, output_dir: str) -> ScanResults:
    """Run govulncheck to detect reachable vulnerabilities in Go modules.

    Skips quietly when there's no ``go.mod`` to scan.
    """
    if not Path(target_dir, "go.mod").exists():
        logger.info("No go.mod found, skipping govulncheck")
        return ScanResults(
            tool_name="govulncheck",
            execution_time_seconds=0.0,
            exit_code=0,
            findings=[],
        )

    return run_scanner(
        ScanSpec(
            name="govulncheck",
            cmd=["govulncheck", "-json", "./..."],
            cwd=target_dir,
        ),
        output_dir=output_dir,
    )


def parse_govulncheck_output(raw_text: str) -> list[Finding]:
    """Parse govulncheck newline-delimited JSON output into Finding objects.

    govulncheck outputs newline-delimited JSON objects.  We look for
    objects with a ``finding`` key which indicate reachable vulnerabilities.

    Args:
        raw_text: Raw text output from govulncheck (NDJSON format).

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, line in enumerate(raw_text.strip().splitlines()):
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        finding_data = obj.get("finding")
        if finding_data is None:
            continue

        osv_id = finding_data.get("osv", "unknown")
        trace = finding_data.get("trace", [])

        # Build description from trace information.
        trace_parts = []
        for entry in trace:
            module = entry.get("module", "")
            function = entry.get("function", "")
            if module:
                part = module
                if function:
                    part = f"{module}.{function}"
                trace_parts.append(part)

        title = f"govulncheck: {osv_id}"
        description = f"Reachable vulnerability {osv_id}"
        if trace_parts:
            description += f" via: {' -> '.join(trace_parts)}"

        finding_id = f"govulncheck-{osv_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="govulncheck",
                category="sca",
                severity="high",
                cvss_score=None,
                cve_id=osv_id if osv_id.startswith("CVE-") else None,
                title=title,
                description=description,
                file_path=None,
                line_number=None,
                package_name=trace_parts[0] if trace_parts else None,
                package_version=None,
                fix_version=None,
                raw_output=obj,
            )
        )

    return findings
