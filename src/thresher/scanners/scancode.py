"""ScanCode scanner wrapper -- license compliance scanning."""

from __future__ import annotations

import logging
from typing import Any

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

# Copyleft license families that warrant a medium-severity finding.
_COPYLEFT_PREFIXES = frozenset(
    {
        "GPL",
        "AGPL",
        "LGPL",
        "SSPL",
        "EUPL",
        "MPL",
        "CPAL",
        "OSL",
        "gpl",
        "agpl",
        "lgpl",
        "sspl",
        "eupl",
        "mpl",
        "cpal",
        "osl",
    }
)


def run_scancode(target_dir: str, output_dir: str) -> ScanResults:
    """Run ScanCode to detect license compliance issues.

    ScanCode is slow, so we use ``--timeout 120`` and ``-n 4`` for
    parallel processing. Exit 1 means "completed with per-file issues"
    (timeouts, perms) and is treated as success — the output file is
    still valid.
    """
    output_path = f"{output_dir}/scancode.json"
    return run_scanner(
        ScanSpec(
            name="scancode",
            cmd=[
                "scancode",
                "--license",
                "--json-pp",
                output_path,
                target_dir,
                "-n",
                "4",
                "--timeout",
                "120",
            ],
            timeout=600,
            output_mode="self",
        ),
        output_dir=output_dir,
    )


def parse_scancode_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse ScanCode JSON output into normalized Finding objects.

    Only creates findings for copyleft or other flagged licenses.

    Args:
        raw: Parsed JSON dict from ScanCode's ``--json-pp`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    files = raw.get("files", [])

    idx = 0
    for file_entry in files:
        file_path = file_entry.get("path")

        # Newer scancode (v32+) uses detected_license_expression at file level
        license_expr = file_entry.get("detected_license_expression", "") or ""
        spdx_expr = file_entry.get("detected_license_expression_spdx", "") or ""

        # Older scancode uses a "licenses" array
        old_licenses = file_entry.get("licenses", [])

        if license_expr:
            # New format: single expression per file
            if not _is_copyleft(license_expr) and not _is_copyleft(spdx_expr):
                continue

            title = f"Copyleft license: {license_expr}"
            description = f"License: {license_expr}"
            if spdx_expr:
                description += f" (SPDX: {spdx_expr})"

            findings.append(
                Finding(
                    id=f"scancode-{idx}",
                    source_tool="scancode",
                    category="license",
                    severity="medium",
                    cvss_score=None,
                    cve_id=None,
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=None,
                    package_name=None,
                    package_version=None,
                    fix_version=None,
                    raw_output={"license_expression": license_expr, "spdx": spdx_expr},
                )
            )
            idx += 1
        elif old_licenses:
            # Old format: array of license objects
            for lic in old_licenses:
                lic_expr = lic.get("license_expression", "") or ""
                spdx_key = lic.get("spdx_license_key", "") or ""
                score = lic.get("score", 0)

                if not _is_copyleft(lic_expr) and not _is_copyleft(spdx_key):
                    continue

                title = f"Copyleft license: {lic_expr or spdx_key}"
                description = f"License: {lic_expr}"
                if spdx_key:
                    description += f" (SPDX: {spdx_key})"
                description += f", score: {score}"

                findings.append(
                    Finding(
                        id=f"scancode-{idx}",
                        source_tool="scancode",
                        category="license",
                        severity="medium",
                        cvss_score=None,
                        cve_id=None,
                        title=title,
                        description=description,
                        file_path=file_path,
                        line_number=None,
                        package_name=None,
                        package_version=None,
                        fix_version=None,
                        raw_output=lic,
                    )
                )
                idx += 1

    return findings


def _is_copyleft(license_text: str) -> bool:
    """Check if a license string contains a copyleft license identifier."""
    return any(prefix in license_text for prefix in _COPYLEFT_PREFIXES)
