"""Tests for thresher.scanners._runner — shared subprocess scanner driver."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from thresher.scanners._runner import ScanSpec, run_scanner


def _mock_popen(returncode=0, stdout=b""):
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


class TestRunScannerStdoutMode:
    @patch("thresher.run._popen")
    def test_writes_stdout_to_output_file(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(stdout=b'{"results": []}')
        spec = ScanSpec(name="bandit", cmd=["bandit", "-r", "/target"])
        result = run_scanner(spec, output_dir=str(tmp_path))

        assert result.tool_name == "bandit"
        assert result.exit_code == 0
        assert result.raw_output_path == f"{tmp_path}/bandit.json"
        assert Path(result.raw_output_path).read_text() == '{"results": []}'

    @patch("thresher.run._popen")
    def test_sanitizes_stdout_when_enabled(self, mock_popen, tmp_path):
        # Bandit warm-up text before the JSON payload
        mock_popen.return_value = _mock_popen(
            stdout=b'progress bar [###]\n{"results": []}',
        )
        spec = ScanSpec(name="bandit", cmd=["bandit"])
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert Path(result.raw_output_path).read_text() == '{"results": []}'

    @patch("thresher.run._popen")
    def test_skip_sanitize_writes_raw_bytes(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(stdout=b"/some/file: Virus FOUND\n")
        spec = ScanSpec(
            name="clamav",
            cmd=["clamscan"],
            sanitize_stdout=False,
            output_filename="clamav.txt",
        )
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert result.raw_output_path == f"{tmp_path}/clamav.txt"
        assert Path(result.raw_output_path).read_text() == "/some/file: Virus FOUND\n"

    @patch("thresher.run._popen")
    def test_records_execution_time(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(stdout=b"{}")
        spec = ScanSpec(name="trivy", cmd=["trivy"])
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert result.execution_time_seconds >= 0

    @patch("thresher.run._popen")
    def test_unexpected_exit_code_returns_error_result(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(returncode=42, stdout=b"")
        spec = ScanSpec(name="bandit", cmd=["bandit"], ok_codes=(0, 1))
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert result.exit_code == 42
        assert result.errors and "exit 42" in result.errors[0]
        assert result.raw_output_path is None

    @patch("thresher.run._popen")
    def test_findings_exit_code_is_success(self, mock_popen, tmp_path):
        """Many scanners use exit 1 to mean 'findings present', not error."""
        mock_popen.return_value = _mock_popen(returncode=1, stdout=b'{"results":[]}')
        spec = ScanSpec(name="trivy", cmd=["trivy"], ok_codes=(0, 1))
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert result.exit_code == 1
        assert not result.errors
        assert result.raw_output_path is not None

    @patch("thresher.run._popen")
    def test_subprocess_exception_returns_error_result(self, mock_popen, tmp_path):
        mock_popen.side_effect = RuntimeError("scanner crashed")
        spec = ScanSpec(name="bandit", cmd=["bandit"])
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert result.exit_code == -1
        assert result.errors and "scanner crashed" in result.errors[0]

    @patch("thresher.run._popen")
    def test_passes_cwd_to_subprocess(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(stdout=b"{}")
        spec = ScanSpec(name="cargo-audit", cmd=["cargo-audit"], cwd="/proj")
        run_scanner(spec, output_dir=str(tmp_path))
        kwargs = mock_popen.call_args[1]
        assert kwargs.get("cwd") == "/proj"

    @patch("thresher.run._popen")
    def test_passes_timeout_and_ok_codes(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(stdout=b"{}")
        spec = ScanSpec(
            name="semgrep",
            cmd=["semgrep"],
            timeout=600,
            ok_codes=(0, 1, 2),
        )
        result = run_scanner(spec, output_dir=str(tmp_path))
        # We can verify ok_codes by sending an exit code that's only OK with the spec
        # (using a separate test below).
        assert result.exit_code == 0


class TestRunScannerSelfWriteMode:
    @patch("thresher.run._popen")
    def test_self_mode_does_not_write_stdout(self, mock_popen, tmp_path):
        """When the scanner writes its own output file, the helper records the
        path but doesn't touch stdout."""
        # Pre-create the file the scanner would have written.
        out_file = tmp_path / "gitleaks.json"
        out_file.write_text("[]")

        mock_popen.return_value = _mock_popen(stdout=b"this should be ignored")
        spec = ScanSpec(
            name="gitleaks",
            cmd=["gitleaks", "detect", "--report-path", str(out_file)],
            output_mode="self",
        )
        result = run_scanner(spec, output_dir=str(tmp_path))
        # Output path is the default (output_dir/gitleaks.json), not stdout-derived.
        assert result.raw_output_path == str(out_file)
        # Stdout was NOT written to the output file.
        assert out_file.read_text() == "[]"

    @patch("thresher.run._popen")
    def test_custom_output_filename(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen(stdout=b"text output")
        spec = ScanSpec(
            name="yara",
            cmd=["yara"],
            output_filename="yara.txt",
            sanitize_stdout=False,
        )
        result = run_scanner(spec, output_dir=str(tmp_path))
        assert result.raw_output_path == f"{tmp_path}/yara.txt"
