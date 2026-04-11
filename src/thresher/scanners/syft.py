"""Syft scanner wrapper -- generates CycloneDX SBOM."""

from __future__ import annotations

import logging

from thresher.scanners._runner import ScanSpec, run_scanner
from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)


def run_syft(target_dir: str, output_dir: str) -> ScanResults:
    """Run Syft to generate a CycloneDX JSON SBOM.

    The SBOM path is stored in ``metadata["sbom_path"]`` for downstream
    consumers (e.g. Grype).
    """
    result = run_scanner(
        ScanSpec(
            name="syft",
            cmd=["syft", target_dir, "-o", "cyclonedx-json"],
            ok_codes=(0,),
            output_filename="sbom.json",
        ),
        output_dir=output_dir,
    )
    if result.raw_output_path:
        result.metadata["sbom_path"] = result.raw_output_path
    return result
