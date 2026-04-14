"""Tests for thresher.scanners.yara_scanner."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from thresher.scanners.yara_scanner import (
    parse_yara_output,
    resolve_yara_rules_dir,
    run_yara,
)


def _mock_popen(returncode=0, stdout=b""):
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


class TestResolveYaraRulesDir:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("YARA_RULES_DIR", raising=False)
        assert resolve_yara_rules_dir() == "/opt/yara-rules"

    def test_env_var_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("YARA_RULES_DIR", str(tmp_path))
        assert resolve_yara_rules_dir() == str(tmp_path)


class TestRunYara:
    @patch("thresher.run._popen")
    def test_skips_cleanly_when_rules_dir_missing(
        self,
        mock_popen,
        tmp_path,
        caplog,
        monkeypatch,
    ):
        """When the rules dir is absent, the scanner returns clean results
        with a single explanatory INFO log — not a WARNING that scares
        operators (this is the default state when no rules are mounted)."""
        monkeypatch.setenv("YARA_RULES_DIR", str(tmp_path / "missing"))
        with caplog.at_level(logging.INFO, logger="thresher.scanners.yara_scanner"):
            result = run_yara(str(tmp_path), str(tmp_path))

        assert result.tool_name == "yara"
        assert result.exit_code == 0
        assert result.findings == []
        # Did NOT call yara binary
        mock_popen.assert_not_called()
        # The message must mention the env var so users know how to fix it
        assert "YARA_RULES_DIR" in caplog.text

    @patch("thresher.run._popen")
    def test_uses_custom_rules_dir(self, mock_popen, tmp_path, monkeypatch):
        """Custom YARA_RULES_DIR is honored end-to-end."""
        rules_dir = tmp_path / "rules"
        (rules_dir / "malware").mkdir(parents=True)
        (rules_dir / "packers").mkdir(parents=True)
        (rules_dir / "malware" / "MALW_test.yar").write_text("rule x { condition: true }")

        monkeypatch.setenv("YARA_RULES_DIR", str(rules_dir))
        mock_popen.return_value = _mock_popen()

        run_yara(str(tmp_path), str(tmp_path))

        mock_popen.assert_called()
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "yara"
        assert "MALW_test.yar" in " ".join(cmd)


class TestParseYaraOutput:
    def test_empty_output(self):
        assert parse_yara_output("") == []

    def test_single_match(self):
        findings = parse_yara_output("MALW_xyz /opt/target/bin/exe")
        assert len(findings) == 1
        assert findings[0].source_tool == "yara"
        assert findings[0].file_path == "/opt/target/bin/exe"
        assert "MALW_xyz" in findings[0].title

    def test_skips_blank_lines(self):
        text = "MALW_a /a/b\n\n  \nMALW_b /c/d\n"
        findings = parse_yara_output(text)
        assert len(findings) == 2
