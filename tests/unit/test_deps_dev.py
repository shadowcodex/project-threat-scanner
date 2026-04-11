"""Tests for thresher.scanners.deps_dev."""

from __future__ import annotations

import json
import os
import textwrap
from unittest.mock import patch, MagicMock

from thresher.scanners.deps_dev import parse_deps_dev_output, run_deps_dev, _DEPS_DEV_SCRIPT


def _mock_popen(returncode=0, stdout=b""):
    """Create a mock that behaves like subprocess.Popen."""
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


class TestParseDepsDevOutput:
    def test_empty_output(self):
        raw = {"scanner": "deps-dev", "findings": [], "total": 0}
        assert parse_deps_dev_output(raw) == []

    def test_low_scorecard(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "low_scorecard",
                    "package": "sketchy-pkg",
                    "ecosystem": "npm",
                    "severity": "medium",
                    "description": "Low OpenSSF Scorecard: 2.1/10",
                    "detail": {"overall_score": 2.1, "checks": {"BranchProtection": 0}},
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 1
        assert findings[0].category == "metadata"
        assert findings[0].severity == "medium"
        assert findings[0].package_name == "sketchy-pkg"
        assert "low_scorecard" in findings[0].title

    def test_typosquatting_signal(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "typosquatting_signal",
                    "package": "loadsh",
                    "ecosystem": "npm",
                    "severity": "high",
                    "description": "Package name is similar to 'lodash'",
                    "detail": {"similar_package": "lodash"},
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_dormant_reactivation(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "dormant_reactivation",
                    "package": "old-pkg",
                    "ecosystem": "pypi",
                    "severity": "medium",
                    "description": "Package was dormant for 500 days",
                    "detail": {"gap_days": 500},
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 1
        assert "dormant_reactivation" in findings[0].title

    def test_multiple_findings(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {"type": "low_scorecard", "package": "a", "ecosystem": "npm",
                 "severity": "medium", "description": "low score"},
                {"type": "typosquatting_signal", "package": "b", "ecosystem": "npm",
                 "severity": "high", "description": "similar name"},
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 2
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_no_source_repo(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "no_source_repo",
                    "package": "mystery-pkg",
                    "ecosystem": "npm",
                    "severity": "low",
                    "description": "No linked source repository found",
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert findings[0].severity == "low"


def _exec_script_function(func_name: str):
    """Exec the embedded script and return a specific function from it."""
    ns = {}
    exec(_DEPS_DEV_SCRIPT, ns)
    return ns[func_name]


class TestDepsDevScript:
    """Tests for the embedded deps.dev scanner script."""

    def test_script_searches_multiple_manifest_paths(self):
        """The script should search /opt/deps/, /opt/target/ for manifests."""
        assert "/opt/deps/dep_manifest.json" in _DEPS_DEV_SCRIPT
        assert "/opt/target/package-lock.json" in _DEPS_DEV_SCRIPT
        assert "/opt/target/package.json" in _DEPS_DEV_SCRIPT
        assert "/opt/target/Cargo.toml" in _DEPS_DEV_SCRIPT

    def test_script_searches_uv_lock(self):
        """The script should search for uv.lock files."""
        assert "/opt/target/uv.lock" in _DEPS_DEV_SCRIPT
        assert "/opt/deps/uv.lock" in _DEPS_DEV_SCRIPT

    def test_script_searches_requirements_txt(self):
        """The script should search for requirements.txt files."""
        assert "/opt/target/requirements.txt" in _DEPS_DEV_SCRIPT
        assert "/opt/deps/requirements.txt" in _DEPS_DEV_SCRIPT

    def test_script_logs_searched_paths_on_no_manifests(self):
        """When no manifests found, script should report searched paths."""
        assert "WARNING: No manifests found" in _DEPS_DEV_SCRIPT

    def test_script_outputs_warning_field_when_empty(self):
        """When no packages found, output should include warning field."""
        assert '"warning"' in _DEPS_DEV_SCRIPT

    def test_script_has_package_json_parser(self):
        """Script should contain logic to parse package.json files."""
        assert "_parse_package_json" in _DEPS_DEV_SCRIPT

    def test_script_has_cargo_toml_parser(self):
        """Script should contain logic to parse Cargo.toml files."""
        assert "_parse_cargo_toml" in _DEPS_DEV_SCRIPT

    def test_script_has_uv_lock_parser(self):
        assert "_parse_uv_lock" in _DEPS_DEV_SCRIPT

    def test_script_has_requirements_txt_parser(self):
        assert "_parse_requirements_txt" in _DEPS_DEV_SCRIPT


class TestParseUvLock:
    """Test uv.lock parsing in the embedded script."""

    def test_parses_basic_uv_lock(self, tmp_path):
        parse_uv_lock = _exec_script_function("_parse_uv_lock")
        uv_lock = tmp_path / "uv.lock"
        uv_lock.write_text(textwrap.dedent("""\
            version = 1
            requires-python = ">=3.12"

            [[package]]
            name = "requests"
            version = "2.31.0"

            [[package]]
            name = "flask"
            version = "3.0.2"
        """))
        result = parse_uv_lock(str(uv_lock))
        assert ("pypi", "requests", "2.31.0") in result
        assert ("pypi", "flask", "3.0.2") in result
        assert len(result) == 2

    def test_parses_uv_lock_with_extras(self, tmp_path):
        parse_uv_lock = _exec_script_function("_parse_uv_lock")
        uv_lock = tmp_path / "uv.lock"
        uv_lock.write_text(textwrap.dedent("""\
            [[package]]
            name = "boto3"
            version = "1.34.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "botocore" },
            ]

            [[package]]
            name = "botocore"
            version = "1.34.0"
        """))
        result = parse_uv_lock(str(uv_lock))
        assert ("pypi", "boto3", "1.34.0") in result
        assert ("pypi", "botocore", "1.34.0") in result

    def test_empty_uv_lock(self, tmp_path):
        parse_uv_lock = _exec_script_function("_parse_uv_lock")
        uv_lock = tmp_path / "uv.lock"
        uv_lock.write_text("version = 1\n")
        result = parse_uv_lock(str(uv_lock))
        assert result == []

    def test_missing_file(self):
        parse_uv_lock = _exec_script_function("_parse_uv_lock")
        result = parse_uv_lock("/nonexistent/uv.lock")
        assert result == []


class TestParseRequirementsTxt:
    """Test requirements.txt parsing in the embedded script."""

    def test_parses_pinned_versions(self, tmp_path):
        parse_req = _exec_script_function("_parse_requirements_txt")
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask==3.0.2\n")
        result = parse_req(str(req))
        assert ("pypi", "requests", "2.31.0") in result
        assert ("pypi", "flask", "3.0.2") in result

    def test_parses_range_versions(self, tmp_path):
        parse_req = _exec_script_function("_parse_requirements_txt")
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.28.0\nflask~=3.0\n")
        result = parse_req(str(req))
        assert ("pypi", "requests", "2.28.0") in result
        assert ("pypi", "flask", "3.0") in result

    def test_skips_comments_and_flags(self, tmp_path):
        parse_req = _exec_script_function("_parse_requirements_txt")
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n-r other.txt\nrequests==1.0\n\n")
        result = parse_req(str(req))
        assert len(result) == 1
        assert result[0][1] == "requests"

    def test_handles_extras(self, tmp_path):
        parse_req = _exec_script_function("_parse_requirements_txt")
        req = tmp_path / "requirements.txt"
        req.write_text("uvicorn[standard]==0.30.0\n")
        result = parse_req(str(req))
        assert result[0][1] == "uvicorn"

    def test_bare_package_name(self, tmp_path):
        parse_req = _exec_script_function("_parse_requirements_txt")
        req = tmp_path / "requirements.txt"
        req.write_text("requests\n")
        result = parse_req(str(req))
        assert ("pypi", "requests", "unknown") in result

    def test_missing_file(self):
        parse_req = _exec_script_function("_parse_requirements_txt")
        result = parse_req("/nonexistent/requirements.txt")
        assert result == []


class TestRunDepsDev:
    @patch("thresher.run._popen")
    def test_success(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=b"Checking 5 packages...")

        result = run_deps_dev("/opt/scan-results")

        assert result.tool_name == "deps-dev"
        assert result.exit_code == 0
        assert result.raw_output_path == "/opt/scan-results/deps-dev.json"

    @patch("thresher.run._popen")
    def test_failure(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=1, stdout=b"error")

        result = run_deps_dev("/opt/scan-results")

        assert result.exit_code == 1
        assert len(result.errors) > 0
