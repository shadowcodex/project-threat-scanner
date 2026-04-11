"""Unit tests for thresher.harness.scanning."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from thresher.harness.scanning import run_all_scanners, _populate_findings, _get_parser
from thresher.scanners.models import Finding, ScanResults


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_returns_results(mock_tasks):
    mock_tasks.return_value = [
        (
            "grype",
            lambda **kw: ScanResults(
                tool_name="grype", execution_time_seconds=1.0, exit_code=0
            ),
        ),
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 1
    assert results[0].tool_name == "grype"


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_handles_failure(mock_tasks):
    def failing_scanner(**kwargs):
        raise RuntimeError("scanner exploded")

    mock_tasks.return_value = [
        ("broken", failing_scanner),
        (
            "working",
            lambda **kw: ScanResults(
                tool_name="working", execution_time_seconds=0.5, exit_code=0
            ),
        ),
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 2
    broken = [r for r in results if r.tool_name == "broken"][0]
    assert broken.exit_code == -1


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_empty_tasks(mock_tasks):
    mock_tasks.return_value = []
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert results == []


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_failure_error_message(mock_tasks):
    def failing_scanner(**kwargs):
        raise ValueError("bad input")

    mock_tasks.return_value = [("bad", failing_scanner)]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 1
    assert results[0].exit_code == -1
    assert "bad input" in results[0].errors[0]


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_multiple_results(mock_tasks):
    names = ["grype", "osv", "semgrep"]
    mock_tasks.return_value = [
        (
            name,
            (lambda n: lambda **kw: ScanResults(
                tool_name=n, execution_time_seconds=0.1, exit_code=0
            ))(name),
        )
        for name in names
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 3
    result_names = {r.tool_name for r in results}
    assert result_names == set(names)


def test_run_all_scanners_all_21_scanners():
    """Verify all 21 scanners are listed and counted."""
    from thresher.harness.scanning import _get_scanner_tasks
    real_tasks = _get_scanner_tasks()
    assert len(real_tasks) == 21
    # Verify all are tuples with (name, callable)
    for name, fn in real_tasks:
        assert isinstance(name, str)
        assert callable(fn)


def test_resolve_scanner_kwargs_grype():
    """Grype scanner should use sbom_path instead of target_dir."""
    from thresher.harness.scanning import _resolve_scanner_kwargs
    kwargs = _resolve_scanner_kwargs(
        "grype",
        sbom_path="/sbom.json",
        target_dir="/target",
        deps_dir="/deps",
        output_dir="/output",
    )
    assert "sbom_path" in kwargs
    assert "target_dir" not in kwargs
    assert kwargs["sbom_path"] == "/sbom.json"
    assert kwargs["output_dir"] == "/output"


def test_resolve_scanner_kwargs_output_only():
    """Output-only scanners should only receive output_dir."""
    from thresher.harness.scanning import _resolve_scanner_kwargs
    output_only = ["entropy", "install-hooks", "guarddog-deps", "deps-dev", "registry-meta", "semgrep-sc"]
    for name in output_only:
        kwargs = _resolve_scanner_kwargs(
            name,
            sbom_path="/sbom.json",
            target_dir="/target",
            deps_dir="/deps",
            output_dir="/output",
        )
        assert list(kwargs.keys()) == ["output_dir"]
        assert kwargs["output_dir"] == "/output"


def test_resolve_scanner_kwargs_standard():
    """Standard scanners should receive target_dir and output_dir."""
    from thresher.harness.scanning import _resolve_scanner_kwargs
    standard = ["osv", "trivy", "semgrep", "bandit", "checkov", "guarddog"]
    for name in standard:
        kwargs = _resolve_scanner_kwargs(
            name,
            sbom_path="/sbom.json",
            target_dir="/target",
            deps_dir="/deps",
            output_dir="/output",
        )
        assert set(kwargs.keys()) == {"target_dir", "output_dir"}
        assert kwargs["target_dir"] == "/target"
        assert kwargs["output_dir"] == "/output"


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_preserves_exit_code(mock_tasks):
    """Should preserve exit codes from successful scanners."""
    mock_tasks.return_value = [
        (
            "tool1",
            lambda **kw: ScanResults(
                tool_name="tool1", execution_time_seconds=1.0, exit_code=0
            ),
        ),
        (
            "tool2",
            lambda **kw: ScanResults(
                tool_name="tool2", execution_time_seconds=0.5, exit_code=1
            ),
        ),
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    exit_codes = {r.tool_name: r.exit_code for r in results}
    assert exit_codes["tool1"] == 0
    assert exit_codes["tool2"] == 1


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_exception_contains_error_message(mock_tasks):
    """Exceptions should be captured in errors list."""
    def failing(**kwargs):
        raise ValueError("specific error message")

    mock_tasks.return_value = [("fail", failing)]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 1
    assert "specific error message" in results[0].errors[0]


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_partial_failure_continues(mock_tasks):
    """If one scanner fails, others should still run."""
    def failing(**kwargs):
        raise RuntimeError("boom")

    def passing(**kwargs):
        return ScanResults(
            tool_name="passing", execution_time_seconds=0.1, exit_code=0
        )

    mock_tasks.return_value = [
        ("fail1", failing),
        ("pass1", passing),
        ("fail2", failing),
        ("pass2", passing),
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 4
    failed = [r for r in results if r.exit_code == -1]
    passed = [r for r in results if r.exit_code == 0]
    assert len(failed) == 2
    assert len(passed) == 2


class TestGetParser:
    """Verify _get_parser returns a callable for all scanners with parsers."""

    def test_all_json_scanners_have_parser(self):
        json_scanners = [
            "grype", "osv", "trivy", "semgrep", "bandit", "checkov",
            "guarddog", "guarddog-deps", "gitleaks", "hadolint",
            "cargo-audit", "scancode", "entropy", "install-hooks",
            "deps-dev", "registry-meta", "semgrep-sc",
        ]
        for name in json_scanners:
            parser = _get_parser(name)
            assert parser is not None, f"No parser for {name}"
            assert callable(parser), f"Parser for {name} is not callable"

    def test_text_parsers_exist(self):
        for name in ("yara", "govulncheck"):
            parser = _get_parser(name)
            assert parser is not None, f"No parser for {name}"

    def test_clamav_has_no_parser(self):
        assert _get_parser("clamav") is None

    def test_unknown_scanner_returns_none(self):
        assert _get_parser("nonexistent-scanner") is None


class TestPopulateFindings:
    def test_populates_from_grype_json(self, tmp_path):
        output_file = tmp_path / "grype.json"
        output_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "High",
                    "description": "test vuln",
                    "cvss": [{"metrics": {"baseScore": 8.1}}],
                    "fix": {"versions": ["2.0.0"]},
                },
                "artifact": {"name": "requests", "version": "1.0.0"},
            }]
        }))
        result = ScanResults(
            tool_name="grype",
            execution_time_seconds=1.0,
            exit_code=0,
            raw_output_path=str(output_file),
        )
        _populate_findings(result)
        assert len(result.findings) == 1
        assert result.findings[0].source_tool == "grype"
        assert result.findings[0].cve_id == "CVE-2024-1234"
        assert result.findings[0].severity == "high"

    def test_populates_from_semgrep_json(self, tmp_path):
        output_file = tmp_path / "semgrep.json"
        output_file.write_text(json.dumps({
            "results": [{
                "check_id": "test-rule",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "Test finding",
                    "severity": "WARNING",
                    "metadata": {},
                },
            }]
        }))
        result = ScanResults(
            tool_name="semgrep",
            execution_time_seconds=0.5,
            exit_code=0,
            raw_output_path=str(output_file),
        )
        _populate_findings(result)
        assert len(result.findings) == 1
        assert result.findings[0].source_tool == "semgrep"

    def test_skips_when_no_output_path(self):
        result = ScanResults(
            tool_name="grype", execution_time_seconds=1.0, exit_code=0,
        )
        _populate_findings(result)
        assert result.findings == []

    def test_skips_when_file_missing(self, tmp_path):
        result = ScanResults(
            tool_name="grype",
            execution_time_seconds=1.0,
            exit_code=0,
            raw_output_path=str(tmp_path / "nonexistent.json"),
        )
        _populate_findings(result)
        assert result.findings == []

    def test_skips_when_file_empty(self, tmp_path):
        output_file = tmp_path / "grype.json"
        output_file.write_text("")
        result = ScanResults(
            tool_name="grype",
            execution_time_seconds=1.0,
            exit_code=0,
            raw_output_path=str(output_file),
        )
        _populate_findings(result)
        assert result.findings == []

    def test_skips_when_no_parser(self, tmp_path):
        output_file = tmp_path / "clamav.txt"
        output_file.write_text("some output")
        result = ScanResults(
            tool_name="clamav",
            execution_time_seconds=1.0,
            exit_code=0,
            raw_output_path=str(output_file),
        )
        _populate_findings(result)
        assert result.findings == []

    def test_does_not_overwrite_existing_findings(self, tmp_path):
        output_file = tmp_path / "grype.json"
        output_file.write_text(json.dumps({"matches": []}))
        existing = Finding(
            id="existing", source_tool="grype", category="sca",
            severity="high", cvss_score=None, cve_id=None,
            title="pre-existing", description="already here",
            file_path=None, line_number=None, package_name=None,
            package_version=None, fix_version=None, raw_output={},
        )
        result = ScanResults(
            tool_name="grype",
            execution_time_seconds=1.0,
            exit_code=0,
            findings=[existing],
            raw_output_path=str(output_file),
        )
        _populate_findings(result)
        assert len(result.findings) == 1
        assert result.findings[0].title == "pre-existing"

    def test_handles_invalid_json_gracefully(self, tmp_path):
        output_file = tmp_path / "grype.json"
        output_file.write_text("not valid json {{{")
        result = ScanResults(
            tool_name="grype",
            execution_time_seconds=1.0,
            exit_code=0,
            raw_output_path=str(output_file),
        )
        _populate_findings(result)
        assert result.findings == []

    def test_text_parser_yara(self, tmp_path):
        output_file = tmp_path / "yara.txt"
        output_file.write_text("")
        result = ScanResults(
            tool_name="yara",
            execution_time_seconds=0.5,
            exit_code=0,
            raw_output_path=str(output_file),
        )
        # yara output is text-based, empty text produces no findings
        _populate_findings(result)
        assert result.findings == []


class TestRunAllScannersPopulatesFindings:
    @patch("thresher.harness.scanning._get_scanner_tasks")
    def test_findings_populated_after_scan(self, mock_tasks, tmp_path):
        """Scanner output should be parsed and findings populated on ScanResults."""
        output_file = tmp_path / "grype.json"
        output_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "Critical",
                    "description": "rce",
                    "cvss": [{"metrics": {"baseScore": 9.8}}],
                    "fix": {"versions": ["3.0.0"]},
                },
                "artifact": {"name": "evil-lib", "version": "0.1.0"},
            }]
        }))

        def mock_grype(**kwargs):
            return ScanResults(
                tool_name="grype",
                execution_time_seconds=1.0,
                exit_code=1,
                raw_output_path=str(output_file),
            )

        mock_tasks.return_value = [("grype", mock_grype)]
        results = run_all_scanners(
            sbom_path="/x", target_dir="/x", deps_dir="/x",
            output_dir=str(tmp_path), config={},
        )
        assert len(results) == 1
        assert len(results[0].findings) == 1
        assert results[0].findings[0].cve_id == "CVE-2024-9999"
        assert results[0].findings[0].severity == "critical"
