"""ClamAV scanner wrapper -- open source antivirus scanning."""

from __future__ import annotations

import logging

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)


def run_clamav(target_dir: str, output_dir: str) -> ScanResults:
    """Run ClamAV to scan for known viruses and malware.

    Uses clamscan (on-demand scanner) rather than the daemon.
    Exit 0 = clean, 1 = virus found, 2 = error.
    """
    return run_scanner(
        ScanSpec(
            name="clamav",
            cmd=["clamscan", "-r", "--infected", "--no-summary", target_dir],
            timeout=600,
            output_filename="clamav.txt",
            sanitize_stdout=False,
        ),
        output_dir=output_dir,
    )


def _parse_clamav_output(text: str) -> list[Finding]:
    """Parse ClamAV text output into Finding objects.

    ClamAV --infected output format: ``/path/to/file: VirusName FOUND``
    """
    findings: list[Finding] = []

    for idx, line in enumerate(text.strip().splitlines()):
        line = line.strip()
        if not line or "FOUND" not in line:
            continue

        # Format: /path/to/file: Virus.Name FOUND
        parts = line.rsplit(":", 1)
        if len(parts) != 2:
            continue

        file_path = parts[0].strip()
        virus_info = parts[1].strip()
        virus_name = virus_info.replace(" FOUND", "").strip()

        findings.append(
            Finding(
                id=f"clamav-{virus_name}-{idx}",
                source_tool="clamav",
                category="malware",
                severity="critical",
                cvss_score=None,
                cve_id=None,
                title=f"Virus detected: {virus_name}",
                description=f"ClamAV detected {virus_name} in {file_path}",
                file_path=file_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output={"file": file_path, "virus": virus_name},
            )
        )

    return findings
