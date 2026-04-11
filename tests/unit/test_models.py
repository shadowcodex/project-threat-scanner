"""Tests for thresher.scanners.models."""

from __future__ import annotations

from thresher.scanners.models import Finding, ScanResults, sanitize_json_bytes


class TestFinding:
    def test_to_dict_keys(self, sample_finding: Finding):
        d = sample_finding.to_dict()
        expected_keys = {
            "id", "source_tool", "category", "severity", "cvss_score",
            "cve_id", "title", "description", "file_path", "line_number",
            "package_name", "package_version", "fix_version", "raw_output",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self, sample_finding: Finding):
        d = sample_finding.to_dict()
        assert d["id"] == "grype-CVE-2024-1234"
        assert d["severity"] == "critical"
        assert d["cvss_score"] == 9.8
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["package_name"] == "example-lib"
        assert d["fix_version"] == "1.2.4"

    def test_to_dict_roundtrip(self, sample_finding: Finding):
        d = sample_finding.to_dict()
        reconstructed = Finding(**d)
        assert reconstructed.to_dict() == d

    def test_to_dict_minimal(self, sample_finding_minimal: Finding):
        d = sample_finding_minimal.to_dict()
        assert d["cvss_score"] is None
        assert d["cve_id"] is None
        assert d["file_path"] is None


class TestScanResults:
    def test_to_dict(self, sample_scan_results: ScanResults):
        d = sample_scan_results.to_dict()
        assert d["tool_name"] == "grype"
        assert d["exit_code"] == 1
        assert len(d["findings"]) == 1
        assert d["findings"][0]["id"] == "grype-CVE-2024-1234"

    def test_defaults(self):
        sr = ScanResults(tool_name="test", execution_time_seconds=0.0, exit_code=0)
        assert sr.findings == []
        assert sr.errors == []
        assert sr.raw_output_path is None
        assert sr.metadata == {}


class TestSanitizeJsonBytes:
    def test_clean_json_object_unchanged(self):
        data = b'{"matches": []}'
        assert sanitize_json_bytes(data) == data

    def test_clean_json_array_unchanged(self):
        data = b'[{"id": 1}]'
        assert sanitize_json_bytes(data) == data

    def test_strips_progress_bar_prefix(self):
        data = b'Working... [####] 100% 0:00:01\n{"results": []}'
        result = sanitize_json_bytes(data, "bandit")
        assert result == b'{"results": []}'

    def test_strips_warning_lines_prefix(self):
        data = b'WARNING: something bad\nINFO: starting\n[{"id": 1}]'
        result = sanitize_json_bytes(data, "tool")
        assert result == b'[{"id": 1}]'

    def test_strips_leading_whitespace(self):
        data = b'  \n  {"key": "value"}'
        result = sanitize_json_bytes(data)
        assert result == b'{"key": "value"}'

    def test_empty_input_returned(self):
        assert sanitize_json_bytes(b"") == b""

    def test_no_json_returns_original(self):
        data = b"no json here at all"
        assert sanitize_json_bytes(data) == data

    def test_whitespace_only_returns_original(self):
        data = b"   \n\n  "
        assert sanitize_json_bytes(data) == data

    def test_array_with_prefix(self):
        data = b'some prefix text\n[{"vuln": "CVE-2024-1"}]'
        result = sanitize_json_bytes(data, "scanner")
        assert result == b'[{"vuln": "CVE-2024-1"}]'

    def test_picks_earlier_of_brace_or_bracket(self):
        data = b'prefix [{"inside": true}]'
        result = sanitize_json_bytes(data)
        assert result == b'[{"inside": true}]'

    def test_multiline_progress_bar(self):
        data = (
            b'\r[                    ] 0%\r'
            b'[##########          ] 50%\r'
            b'[####################] 100%\n'
            b'{"results": [1, 2, 3]}'
        )
        result = sanitize_json_bytes(data, "bandit")
        assert result == b'{"results": [1, 2, 3]}'


class TestBanditQuietFlag:
    def test_bandit_command_includes_quiet_flag(self):
        """Bandit must use -q to suppress progress bar contamination."""
        from unittest.mock import patch, MagicMock
        from thresher.scanners.bandit import run_bandit

        mock_proc = MagicMock()
        mock_proc.stdout = iter([b'{"results": []}'])
        mock_proc.stderr = iter([])
        mock_proc.returncode = 0
        mock_proc.wait.return_value = 0

        with patch("thresher.run._popen", return_value=mock_proc) as mock_popen:
            run_bandit("/target", "/output")
            cmd = mock_popen.call_args[0][0]
            assert "-q" in cmd, f"bandit command missing -q flag: {cmd}"
