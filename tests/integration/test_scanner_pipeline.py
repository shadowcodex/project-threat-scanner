"""Integration tests for scanner pipeline with mocked subprocess."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

from thresher.config import ScanConfig
from thresher.scanners.runner import run_all_scanners

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_scanner_output"


def _make_config() -> ScanConfig:
    return ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="key")


def _mock_popen(returncode=0, stdout=b""):
    """Create a mock that behaves like subprocess.Popen."""
    m = MagicMock()
    m.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    m.returncode = returncode
    m.wait.return_value = returncode
    return m


def _make_popen_side_effect(overrides: dict | None = None):
    """Return a side_effect function for _popen based on the command invoked."""
    defaults = {
        "gitleaks": _mock_popen(0),
        "guarddog": _mock_popen(0),
        "semgrep": _mock_popen(0),
        "osv-scanner": _mock_popen(0, b'{"results":[]}'),
        "grype": _mock_popen(0, b'{"matches":[]}'),
        "syft": _mock_popen(0, b'{"bomFormat":"CycloneDX"}'),
        "bandit": _mock_popen(0),
        "checkov": _mock_popen(0),
        "hadolint": _mock_popen(0),
        "trivy": _mock_popen(0),
        "clamscan": _mock_popen(0),
        "freshclam": _mock_popen(0),
        "scancode": _mock_popen(0),
        "python3": _mock_popen(0),
        "yara": _mock_popen(0),
        "capa": _mock_popen(0),
        "go": _mock_popen(0),
        "cargo": _mock_popen(0),
    }
    if overrides:
        defaults.update(overrides)

    def side_effect(cmd, **kwargs):
        tool = cmd[0] if cmd else ""
        # Match by tool name (first element of cmd)
        for key, mock in defaults.items():
            if tool == key or tool.endswith(f"/{key}"):
                return mock
        # Default: success with empty output
        return _mock_popen(0)

    return side_effect


class TestRunAllScanners:
    def test_happy_path(self):
        """All scanners run, 22 results returned."""
        overrides = {
            "grype": _mock_popen(1, b'{"matches":[]}'),
            "osv-scanner": _mock_popen(1, b'{"results":[]}'),
            "gitleaks": _mock_popen(1, b'[]'),
        }
        side_effect = _make_popen_side_effect(overrides)

        with patch("thresher.run._popen", side_effect=side_effect), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("pathlib.Path.is_dir", return_value=False), \
             patch("pathlib.Path.rglob", return_value=[]):
            results = run_all_scanners("/opt/target", "/opt/scan-results", _make_config())

        assert len(results) == 22

        tool_names = {r.tool_name for r in results}
        assert tool_names == {
            "syft", "grype", "osv-scanner", "semgrep", "guarddog", "gitleaks",
            "bandit", "checkov", "hadolint", "trivy", "yara", "capa",
            "govulncheck", "cargo-audit", "scancode", "clamav",
            "semgrep-supply-chain", "guarddog-deps", "install-hooks", "entropy",
            "deps-dev", "registry-meta",
        }

    def test_scanner_exception_handled(self):
        """If a scanner raises an exception, it's caught and returned as error."""
        call_count = [0]

        def side_effect(cmd, **kwargs):
            # Make grype raise an error
            if cmd and cmd[0] == "grype":
                raise RuntimeError("connection lost")
            return _mock_popen(0)

        with patch("thresher.run._popen", side_effect=side_effect), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("pathlib.Path.is_dir", return_value=False), \
             patch("pathlib.Path.rglob", return_value=[]):
            results = run_all_scanners("/opt/target", "/opt/scan-results", _make_config())

        assert len(results) == 22

        grype = [r for r in results if r.tool_name == "grype"][0]
        assert grype.exit_code == -1
        assert len(grype.errors) > 0

    def test_exit_code_1_is_findings(self):
        """Exit code 1 from Grype/OSV/Gitleaks means findings found, not error."""
        overrides = {
            "grype": _mock_popen(1, b'{"matches":[]}'),
            "osv-scanner": _mock_popen(1, b'{"results":[]}'),
            "gitleaks": _mock_popen(1, b'[]'),
        }
        side_effect = _make_popen_side_effect(overrides)

        with patch("thresher.run._popen", side_effect=side_effect), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("pathlib.Path.is_dir", return_value=False), \
             patch("pathlib.Path.rglob", return_value=[]):
            results = run_all_scanners("/opt/target", "/opt/scan-results", _make_config())

        for r in results:
            assert len(r.errors) == 0, f"{r.tool_name} should not have errors for exit code 1"
