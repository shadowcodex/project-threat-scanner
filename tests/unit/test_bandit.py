"""Tests for thresher.scanners.bandit."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from thresher.scanners.bandit import parse_bandit_output, run_bandit


def _mock_popen(returncode=0, stdout=b'{"results": []}'):
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


class TestRunBandit:
    @patch("thresher.run._popen")
    def test_excludes_test_directories(self, mock_popen, tmp_path):
        """Regression for M3b: bandit must exclude tests/test/e2e directories
        so it doesn't dominate findings with assert/subprocess noise from
        the target repo's own test suite."""
        mock_popen.return_value = _mock_popen()
        run_bandit(str(tmp_path), str(tmp_path))

        cmd = mock_popen.call_args[0][0]
        # bandit -x / --exclude takes a comma-separated list of paths
        assert "-x" in cmd or "--exclude" in cmd, (
            f"bandit invoked without exclude flag: {cmd}"
        )
        flag_idx = cmd.index("-x") if "-x" in cmd else cmd.index("--exclude")
        excludes = cmd[flag_idx + 1]
        for needle in ("tests", "test", "e2e", "examples"):
            assert needle in excludes, (
                f"missing exclude {needle!r} in {excludes!r}"
            )

    @patch("thresher.run._popen")
    def test_writes_output_file(self, mock_popen, tmp_path):
        mock_popen.return_value = _mock_popen()
        result = run_bandit(str(tmp_path), str(tmp_path))
        out = tmp_path / "bandit.json"
        assert out.exists()
        assert result.tool_name == "bandit"
        assert result.exit_code == 0


class TestParseBanditOutput:
    def test_empty_results(self):
        assert parse_bandit_output({"results": []}) == []

    def test_single_finding(self):
        raw = {
            "results": [
                {
                    "test_id": "B102",
                    "test_name": "exec_used",
                    "filename": "/opt/target/app.py",
                    "line_number": 42,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Use of exec detected.",
                }
            ]
        }
        findings = parse_bandit_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].file_path == "/opt/target/app.py"
        assert findings[0].line_number == 42
        assert findings[0].source_tool == "bandit"

    def test_severity_mapping(self):
        for raw_sev, expected in [("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low")]:
            findings = parse_bandit_output({
                "results": [{"test_id": "B1", "issue_severity": raw_sev}]
            })
            assert findings[0].severity == expected
