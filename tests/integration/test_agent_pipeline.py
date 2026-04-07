"""Integration tests for agent pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from thresher.agents.analysts import run_all_analysts, ANALYST_DEFINITIONS
from thresher.agents.adversarial import run_adversarial_verification
from thresher.config import ScanConfig, VMConfig

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/x/y",
        anthropic_api_key="sk-ant-test-key",
        model="sonnet",
    )


def _load_agent_fixture(name: str) -> bytes:
    return (FIXTURES / "sample_agent_output" / name).read_bytes()


def _make_analyst_output(number: int, name: str, findings: list, risk_score: int = 3) -> dict:
    """Create a valid analyst findings dict."""
    return {
        "analyst": name,
        "analyst_number": number,
        "core_question": "test question",
        "files_analyzed": 10,
        "findings": findings,
        "summary": f"Assessment from {name}",
        "risk_score": risk_score,
    }


def _make_proc(data: bytes) -> MagicMock:
    """Create a mock Popen-like object."""
    proc = MagicMock()
    proc.stdout = iter(data.splitlines(keepends=True)) if data else iter([])
    proc.returncode = 0
    proc.wait.return_value = 0
    return proc


class TestAnalystsPipeline:
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_runs_all_eight_analysts(self, mock_run):
        mock_run.return_value = None

        run_all_analysts(_make_config())

        assert mock_run.call_count == 8

    @patch("thresher.run._popen")
    def test_all_use_bash_in_allowed_tools(self, mock_popen):
        valid_output = json.dumps({
            "analyst": "test",
            "analyst_number": 1,
            "core_question": "test?",
            "files_analyzed": 5,
            "findings": [],
            "summary": "clean",
            "risk_score": 0,
        }).encode()
        mock_popen.side_effect = lambda cmd, **kw: _make_proc(valid_output)

        run_all_analysts(_make_config())

        calls = mock_popen.call_args_list
        for call in calls:
            cmd = call[0][0]
            assert "Read,Glob,Grep,Bash" in cmd

    @patch("thresher.run._popen")
    def test_all_analysts_get_api_key_in_env(self, mock_popen):
        valid_output = json.dumps({
            "analyst": "test",
            "analyst_number": 1,
            "core_question": "test?",
            "files_analyzed": 5,
            "findings": [],
            "summary": "clean",
            "risk_score": 0,
        }).encode()
        mock_popen.side_effect = lambda cmd, **kw: _make_proc(valid_output)

        run_all_analysts(_make_config())

        for call in mock_popen.call_args_list:
            env = call[1].get("env", {})
            assert "ANTHROPIC_API_KEY" in env

    @patch("thresher.agents.analysts._run_single_analyst")
    def test_returns_list(self, mock_run):
        mock_run.return_value = None

        result = run_all_analysts(_make_config())
        assert isinstance(result, list)

    @patch("thresher.agents.analysts._run_single_analyst")
    def test_collects_findings_from_all_analysts(self, mock_run):
        def side_effect(config, analyst_def, target_dir=None):
            return {
                "analyst": analyst_def["name"],
                "analyst_number": analyst_def["number"],
                "core_question": analyst_def["core_question"],
                "findings": [],
                "summary": "clean",
                "risk_score": 0,
                "_timing": {"name": analyst_def["name"], "duration": 1.0, "turns": 1},
            }

        mock_run.side_effect = side_effect

        result = run_all_analysts(_make_config())
        assert len(result) == 8
        names = {r["analyst"] for r in result}
        assert len(names) == 8


class TestAdversarialPipeline:
    def _high_risk_analyst_findings(self):
        return [
            _make_analyst_output(1, "paranoid", [
                {
                    "file_path": "/opt/target/setup.py",
                    "severity": "high",
                    "title": "base64 exec",
                    "description": "bad",
                    "line_numbers": [1],
                }
            ], risk_score=7)
        ]

    def _low_risk_analyst_findings(self):
        return [
            _make_analyst_output(1, "paranoid", [
                {"file_path": "/a.py", "risk_score": 2, "findings": []}
            ], risk_score=2)
        ]

    @patch("thresher.run._popen")
    def test_runs_with_high_risk_findings(self, mock_popen):
        mock_popen.return_value = _make_proc(_load_agent_fixture("adversarial.json"))

        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=self._high_risk_analyst_findings(),
        )
        assert result is not None
        assert isinstance(result, dict)

    @patch("thresher.run._popen")
    def test_skips_no_high_risk(self, mock_popen):
        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=self._low_risk_analyst_findings(),
        )
        assert result is None
        mock_popen.assert_not_called()

    @patch("thresher.run._popen")
    def test_api_key_in_env(self, mock_popen):
        mock_popen.return_value = _make_proc(_load_agent_fixture("adversarial.json"))

        run_adversarial_verification(
            _make_config(),
            analyst_findings=self._high_risk_analyst_findings(),
        )

        call_kwargs = mock_popen.call_args[1]
        env = call_kwargs.get("env", {})
        assert "ANTHROPIC_API_KEY" in env

    @patch("thresher.run._popen")
    def test_adversarial_max_turns_from_config(self, mock_popen):
        mock_popen.return_value = _make_proc(_load_agent_fixture("adversarial.json"))

        config = _make_config()
        config.adversarial_max_turns = 35
        run_adversarial_verification(
            config,
            analyst_findings=self._high_risk_analyst_findings(),
        )

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "35"

    @patch("thresher.run._popen")
    def test_adversarial_default_20_turns(self, mock_popen):
        mock_popen.return_value = _make_proc(_load_agent_fixture("adversarial.json"))

        config = _make_config()
        assert config.adversarial_max_turns is None
        run_adversarial_verification(
            config,
            analyst_findings=self._high_risk_analyst_findings(),
        )

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "20"

    @patch("thresher.run._popen")
    def test_findings_annotated_with_source_analyst(self, mock_popen):
        """Each finding should include which analyst produced it."""
        mock_popen.return_value = _make_proc(_load_agent_fixture("adversarial.json"))

        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=self._high_risk_analyst_findings(),
        )

        assert result is not None
        for finding in result.get("findings", []):
            assert "source_analyst" in finding
            assert "source_analyst_number" in finding

    @patch("thresher.run._popen")
    def test_merges_multiple_analyst_findings(self, mock_popen):
        """Adversarial agent should merge findings from multiple analysts."""
        mock_popen.return_value = _make_proc(_load_agent_fixture("adversarial.json"))

        analyst_findings = [
            _make_analyst_output(1, "paranoid", [
                {
                    "file_path": "/opt/target/setup.py",
                    "severity": "high",
                    "title": "base64 exec",
                    "description": "bad",
                    "line_numbers": [1],
                }
            ], risk_score=7),
            _make_analyst_output(2, "behaviorist", [
                {
                    "file_path": "/opt/target/utils.py",
                    "severity": "medium",
                    "title": "unsafe deserialization",
                    "description": "pickle load",
                    "line_numbers": [10],
                }
            ], risk_score=5),
        ]

        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=analyst_findings,
        )
        assert result is not None
        assert isinstance(result, dict)
        assert "findings" in result
