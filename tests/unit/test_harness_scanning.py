"""Unit tests for thresher.harness.scanning."""

import pytest
from unittest.mock import patch, MagicMock
from thresher.harness.scanning import run_all_scanners
from thresher.scanners.models import ScanResults


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
