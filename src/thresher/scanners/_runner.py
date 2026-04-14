"""Shared driver for subprocess scanners.

Almost every Thresher scanner module follows the same recipe:

1. Build a command line that points at the target dir.
2. Run it with a timeout and a tuple of "OK" exit codes (typically
   ``(0, 1)`` because most scanners use exit 1 to signal "findings
   present, not an error").
3. Capture stdout, optionally strip non-JSON warm-up bytes, and write
   it to ``<output_dir>/<tool>.json``.
4. Map the exit code into a ``ScanResults`` with timing, errors, and
   the output path.
5. Catch any subprocess exception and turn it into a ``ScanResults``
   with ``exit_code=-1``.

This module owns that recipe so each scanner file shrinks to a spec
plus its parser. Pre-execution checks (e.g. cargo-audit needs
``Cargo.lock``) and other unusual logic stay in the scanner module —
they're cheap to do before constructing the spec.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from thresher.run import run as run_cmd
from thresher.scanners.models import ScanResults, sanitize_json_bytes

logger = logging.getLogger(__name__)


@dataclass
class ScanSpec:
    """Description of a subprocess scanner invocation."""

    name: str
    cmd: list[str]
    timeout: int = 300
    ok_codes: tuple[int, ...] = (0, 1)
    cwd: str | None = None
    # How the scanner produces its output file:
    #   "stdout" (default): the helper writes captured stdout to
    #     ``<output_dir>/<output_filename>``.
    #   "self": the scanner writes its own file via flags in cmd; the
    #     helper just records the expected path.
    output_mode: Literal["stdout", "self"] = "stdout"
    # Strip non-JSON warm-up bytes from stdout (e.g. bandit progress
    # bars). Only honored when output_mode == "stdout".
    sanitize_stdout: bool = True
    # File written under output_dir; defaults to ``f"{name}.json"``.
    output_filename: str | None = None


def run_scanner(spec: ScanSpec, *, output_dir: str) -> ScanResults:
    """Run a subprocess scanner and return its ``ScanResults``.

    Handles timing, output capture, exit-code shaping, and exception
    shaping. Per-scanner pre-checks (manifest existence, dockerfile
    discovery, etc.) belong in the caller, *before* the spec is built.
    """
    output_filename = spec.output_filename or f"{spec.name}.json"
    output_path = f"{output_dir}/{output_filename}"

    start = time.monotonic()
    try:
        kwargs: dict = {}
        if spec.cwd is not None:
            kwargs["cwd"] = spec.cwd
        result = run_cmd(
            spec.cmd,
            label=spec.name,
            timeout=spec.timeout,
            ok_codes=spec.ok_codes,
            **kwargs,
        )

        if spec.output_mode == "stdout":
            data = result.stdout
            if spec.sanitize_stdout:
                data = sanitize_json_bytes(data, spec.name)
            Path(output_path).write_bytes(data)

        elapsed = time.monotonic() - start

        if result.returncode not in spec.ok_codes:
            logger.warning("%s exited with code %d", spec.name, result.returncode)
            return ScanResults(
                tool_name=spec.name,
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"{spec.name} failed (exit {result.returncode})"],
            )

        return ScanResults(
            tool_name=spec.name,
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("%s execution failed", spec.name)
        return ScanResults(
            tool_name=spec.name,
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"{spec.name} execution error: {exc}"],
        )
