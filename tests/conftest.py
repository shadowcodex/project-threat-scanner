"""Shared fixtures and helpers for thresher tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock  # noqa: F401 — kept for test modules that import from conftest

import pytest

from thresher.config import ScanConfig, VMConfig
from thresher.scanners.models import Finding, ScanResults


FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCANNER_FIXTURES_DIR = FIXTURES_DIR / "sample_scanner_output"
AGENT_FIXTURES_DIR = FIXTURES_DIR / "sample_agent_output"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str, base: Path = SCANNER_FIXTURES_DIR) -> Any:
    """Load and parse a JSON fixture file."""
    path = base / name
    return json.loads(path.read_text())


def load_text_fixture(name: str, base: Path = AGENT_FIXTURES_DIR) -> str:
    """Load a text fixture file."""
    return (base / name).read_text()


# ---------------------------------------------------------------------------
# Fixtures: config
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/test/repo",
        depth=2,
        skip_ai=False,
        verbose=False,
        output_dir="./thresher-reports",
        vm=VMConfig(),
        anthropic_api_key="sk-ant-test-key-fake",
        model="sonnet",
    )


@pytest.fixture
def sample_config_skip_ai() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/test/repo",
        depth=2,
        skip_ai=True,
        verbose=False,
        output_dir="./thresher-reports",
        vm=VMConfig(),
        anthropic_api_key="",
        model="sonnet",
    )


# ---------------------------------------------------------------------------
# Fixtures: models
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        id="grype-CVE-2024-1234",
        source_tool="grype",
        category="sca",
        severity="critical",
        cvss_score=9.8,
        cve_id="CVE-2024-1234",
        title="CVE-2024-1234 in example-lib@1.2.3",
        description="Remote code execution in example-lib",
        file_path=None,
        line_number=None,
        package_name="example-lib",
        package_version="1.2.3",
        fix_version="1.2.4",
        raw_output={"test": True},
    )


@pytest.fixture
def sample_finding_minimal() -> Finding:
    return Finding(
        id="test-001",
        source_tool="test",
        category="sca",
        severity="low",
        cvss_score=None,
        cve_id=None,
        title="Test finding",
        description="",
        file_path=None,
        line_number=None,
        package_name=None,
        package_version=None,
        fix_version=None,
        raw_output={},
    )


@pytest.fixture
def sample_scan_results(sample_finding: Finding) -> ScanResults:
    return ScanResults(
        tool_name="grype",
        execution_time_seconds=1.5,
        exit_code=1,
        findings=[sample_finding],
    )


# ---------------------------------------------------------------------------
# Fixtures: scanner output
# ---------------------------------------------------------------------------


@pytest.fixture
def grype_fixture() -> dict:
    return load_fixture("grype.json")


@pytest.fixture
def osv_fixture() -> dict:
    return load_fixture("osv.json")


@pytest.fixture
def semgrep_fixture() -> dict:
    return load_fixture("semgrep.json")


@pytest.fixture
def guarddog_fixture() -> dict:
    return load_fixture("guarddog.json")


@pytest.fixture
def gitleaks_fixture() -> list:
    return load_fixture("gitleaks.json")


# ---------------------------------------------------------------------------
# Fixtures: agent output
# ---------------------------------------------------------------------------


@pytest.fixture
def analyst_clean_fixture() -> dict:
    return load_fixture("analyst_clean.json", AGENT_FIXTURES_DIR)


@pytest.fixture
def analyst_codeblock_fixture() -> str:
    return load_text_fixture("analyst_codeblock.txt")


@pytest.fixture
def analyst_envelope_fixture() -> dict:
    return load_fixture("analyst_envelope.json", AGENT_FIXTURES_DIR)


@pytest.fixture
def adversarial_fixture() -> dict:
    return load_fixture("adversarial.json", AGENT_FIXTURES_DIR)




@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURES_DIR
