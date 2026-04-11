"""Scanner orchestration — runs all scanners in parallel."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)
MAX_WORKERS = 15


def run_all_scanners(
    sbom_path: str,
    target_dir: str,
    deps_dir: str,
    output_dir: str,
    config: dict,
) -> list[ScanResults]:
    """Run all configured scanners in parallel.

    Args:
        sbom_path: Path to the SBOM JSON file (produced by Syft).
        target_dir: Path to the cloned repository.
        deps_dir: Path to the resolved dependencies directory.
        output_dir: Directory where scanner output files are written.
        config: Scan configuration dict.

    Returns:
        List of ScanResults with execution metadata and parsed findings.
    """
    tasks = _get_scanner_tasks()
    results: list[ScanResults] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures: dict = {}
        for name, fn in tasks:
            kwargs = _resolve_scanner_kwargs(
                name,
                sbom_path=sbom_path,
                target_dir=target_dir,
                deps_dir=deps_dir,
                output_dir=output_dir,
            )
            futures[pool.submit(fn, **kwargs)] = name

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                _populate_findings(result)
                results.append(result)
                logger.info(
                    "Scanner %s done (exit=%d, %.1fs, %d findings)",
                    name,
                    result.exit_code,
                    result.execution_time_seconds,
                    len(result.findings),
                )
            except Exception as exc:
                logger.exception("Scanner %s failed", name)
                results.append(
                    ScanResults(
                        tool_name=name,
                        execution_time_seconds=0.0,
                        exit_code=-1,
                        errors=[str(exc)],
                    )
                )

    return results


def _populate_findings(result: ScanResults) -> None:
    """Parse scanner output file and populate result.findings.

    Reads the raw output file written by the scanner, runs it through
    the corresponding parse function, and attaches the normalized
    Finding objects to the ScanResults. Skips gracefully if the output
    file is missing, empty, or unparseable.
    """
    if result.findings:
        return
    if not result.raw_output_path:
        return

    path = Path(result.raw_output_path)
    if not path.exists() or path.stat().st_size == 0:
        return

    parser = _get_parser(result.tool_name)
    if parser is None:
        return

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")

        # Text-based parsers (yara, govulncheck) take raw text directly
        if result.tool_name in _TEXT_PARSERS:
            result.findings = parser(raw_text)
        else:
            raw = json.loads(raw_text)
            result.findings = parser(raw)

        logger.debug(
            "Parsed %d findings from %s",
            len(result.findings),
            result.tool_name,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning(
            "Failed to parse %s output (%s): %s",
            result.tool_name,
            path,
            exc,
        )
    except Exception:
        logger.warning(
            "Unexpected error parsing %s output",
            result.tool_name,
            exc_info=True,
        )


# Scanners whose parse functions accept raw text instead of parsed JSON.
_TEXT_PARSERS = frozenset({"yara", "govulncheck"})


def _get_parser(tool_name: str) -> Callable | None:
    """Return the parse function for a scanner, or None if unavailable.

    Uses lazy imports so we don't load every scanner module at startup.
    Scanners without a parse function (clamav) or with special signatures
    (capa — requires binary_path) return None.
    """
    try:
        if tool_name == "grype":
            from thresher.scanners.grype import parse_grype_output

            return parse_grype_output
        elif tool_name == "osv":
            from thresher.scanners.osv import parse_osv_output

            return parse_osv_output
        elif tool_name == "trivy":
            from thresher.scanners.trivy import parse_trivy_output

            return parse_trivy_output
        elif tool_name == "semgrep":
            from thresher.scanners.semgrep import parse_semgrep_output

            return parse_semgrep_output
        elif tool_name == "bandit":
            from thresher.scanners.bandit import parse_bandit_output

            return parse_bandit_output
        elif tool_name == "checkov":
            from thresher.scanners.checkov import parse_checkov_output

            return parse_checkov_output
        elif tool_name == "guarddog":
            from thresher.scanners.guarddog import parse_guarddog_output

            return parse_guarddog_output
        elif tool_name == "guarddog-deps":
            from thresher.scanners.guarddog_deps import parse_guarddog_deps_output

            return parse_guarddog_deps_output
        elif tool_name == "gitleaks":
            from thresher.scanners.gitleaks import parse_gitleaks_output

            return parse_gitleaks_output
        elif tool_name == "hadolint":
            from thresher.scanners.hadolint import parse_hadolint_output

            return parse_hadolint_output
        elif tool_name == "cargo-audit":
            from thresher.scanners.cargo_audit import parse_cargo_audit_output

            return parse_cargo_audit_output
        elif tool_name == "scancode":
            from thresher.scanners.scancode import parse_scancode_output

            return parse_scancode_output
        elif tool_name == "entropy":
            from thresher.scanners.entropy import parse_entropy_output

            return parse_entropy_output
        elif tool_name == "install-hooks":
            from thresher.scanners.install_hooks import parse_install_hooks_output

            return parse_install_hooks_output
        elif tool_name == "deps-dev":
            from thresher.scanners.deps_dev import parse_deps_dev_output

            return parse_deps_dev_output
        elif tool_name == "registry-meta":
            from thresher.scanners.registry_meta import parse_registry_meta_output

            return parse_registry_meta_output
        elif tool_name == "semgrep-sc":
            from thresher.scanners.semgrep_supply_chain import parse_semgrep_supply_chain_output

            return parse_semgrep_supply_chain_output
        elif tool_name == "yara":
            from thresher.scanners.yara_scanner import parse_yara_output

            return parse_yara_output
        elif tool_name == "govulncheck":
            from thresher.scanners.govulncheck import parse_govulncheck_output

            return parse_govulncheck_output
    except ImportError:
        logger.debug("Could not import parser for %s", tool_name)
    return None


def _get_scanner_tasks() -> list[tuple[str, Callable]]:
    """Return (name, run_function) pairs for all scanners.

    NOTE: These scanner modules currently expect a ``vm_name`` first
    argument because they were written for the VM-based pipeline.  Task 7
    will refactor them to run natively (without SSH).  Until then this
    function is the seam that tests mock out.
    """
    from thresher.scanners.bandit import run_bandit
    from thresher.scanners.capa_scanner import run_capa
    from thresher.scanners.cargo_audit import run_cargo_audit
    from thresher.scanners.checkov import run_checkov
    from thresher.scanners.clamav import run_clamav
    from thresher.scanners.deps_dev import run_deps_dev
    from thresher.scanners.entropy import run_entropy
    from thresher.scanners.gitleaks import run_gitleaks
    from thresher.scanners.govulncheck import run_govulncheck
    from thresher.scanners.grype import run_grype
    from thresher.scanners.guarddog import run_guarddog
    from thresher.scanners.guarddog_deps import run_guarddog_deps
    from thresher.scanners.hadolint import run_hadolint
    from thresher.scanners.install_hooks import run_install_hooks
    from thresher.scanners.osv import run_osv
    from thresher.scanners.registry_meta import run_registry_meta
    from thresher.scanners.scancode import run_scancode
    from thresher.scanners.semgrep import run_semgrep
    from thresher.scanners.semgrep_supply_chain import run_semgrep_supply_chain
    from thresher.scanners.trivy import run_trivy
    from thresher.scanners.yara_scanner import run_yara

    return [
        ("grype", run_grype),
        ("osv", run_osv),
        ("trivy", run_trivy),
        ("semgrep", run_semgrep),
        ("bandit", run_bandit),
        ("checkov", run_checkov),
        ("guarddog", run_guarddog),
        ("guarddog-deps", run_guarddog_deps),
        ("gitleaks", run_gitleaks),
        ("clamav", run_clamav),
        ("yara", run_yara),
        ("capa", run_capa),
        ("govulncheck", run_govulncheck),
        ("cargo-audit", run_cargo_audit),
        ("scancode", run_scancode),
        ("hadolint", run_hadolint),
        ("entropy", run_entropy),
        ("install-hooks", run_install_hooks),
        ("deps-dev", run_deps_dev),
        ("registry-meta", run_registry_meta),
        ("semgrep-sc", run_semgrep_supply_chain),
    ]


def _resolve_scanner_kwargs(
    name: str,
    sbom_path: str,
    target_dir: str,
    deps_dir: str,
    output_dir: str,
) -> dict:
    """Build the kwargs dict for each scanner based on its signature.

    Scanners fall into three groups:
      - grype: needs sbom_path (not target_dir)
      - output-only: entropy, install-hooks, guarddog-deps, deps-dev,
        registry-meta, semgrep-sc — just need output_dir
      - standard: target_dir + output_dir
    """
    output_only = {
        "entropy",
        "install-hooks",
        "guarddog-deps",
        "deps-dev",
        "registry-meta",
        "semgrep-sc",
    }

    if name == "grype":
        return {"sbom_path": sbom_path, "output_dir": output_dir}
    if name in output_only:
        return {"output_dir": output_dir}
    return {"target_dir": target_dir, "output_dir": output_dir}
