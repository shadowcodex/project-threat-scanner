"""Tests for the Jinja report render function and fallback report builder."""

import json
from pathlib import Path


def _valid_report_data():
    """Minimal valid report data dict."""
    return {
        "meta": {
            "scan_date": "2026-04-02",
            "thresher_version": "v0.2.2",
            "scanner_count": "22",
            "analyst_count": "8",
            "repo_name": "owner/repo",
            "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {"label": "LOW RISK", "severity": "low", "callout": "No issues."},
        "counts": {
            "total_scanner": "0",
            "total_ai": "0",
            "p0": "0",
            "critical": "0",
            "high_scanner": "0",
            "high_ai": "0",
            "medium": "0",
            "low": "0",
        },
        "executive_summary": "<p>Clean scan.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {"scanners": ["grype"], "analysts": [], "notes": ""},
        "config": {"show_cta": "true", "show_remediation": "false"},
    }


def test_render_report_produces_html(tmp_path):
    from thresher.harness.report import render_report

    output = render_report(_valid_report_data(), str(tmp_path))
    html_path = Path(output)
    assert html_path.exists()
    content = html_path.read_text()
    assert "<!DOCTYPE html>" in content
    assert "owner/repo" in content


def test_render_report_embeds_json(tmp_path):
    from thresher.harness.report import render_report

    data = _valid_report_data()
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert '"scan_date"' in content
    assert '"LOW RISK"' in content


def test_render_report_with_findings(tmp_path):
    from thresher.harness.report import render_report

    data = _valid_report_data()
    data["scanner_findings"] = [
        {
            "rank": "1",
            "severity": "critical",
            "package": "foo@1.0",
            "title": "Bad vuln",
            "cve": "CVE-2026-9999",
            "cvss": "9.8",
        }
    ]
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert "CVE-2026-9999" in content


def test_render_report_null_remediation(tmp_path):
    from thresher.harness.report import render_report

    data = _valid_report_data()
    data["remediation"] = None
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert "<!DOCTYPE html>" in content


def test_build_fallback_report_data_minimal():
    from thresher.config import ScanConfig
    from thresher.harness.report import build_fallback_report_data

    config = ScanConfig(repo_url="https://github.com/owner/repo")
    findings = []
    data = build_fallback_report_data(config, findings)

    assert data["meta"]["repo_name"] == "owner/repo"
    assert data["verdict"]["severity"] == "low"
    assert data["counts"]["critical"] == "0"
    assert data["remediation"] is None
    assert data["config"]["show_remediation"] == "false"


def test_build_fallback_report_data_with_critical():
    from thresher.config import ScanConfig
    from thresher.harness.report import build_fallback_report_data

    config = ScanConfig(repo_url="https://github.com/owner/repo")
    findings = [
        {
            "id": "1",
            "source_tool": "grype",
            "category": "sca",
            "severity": "critical",
            "title": "Bad vuln",
            "description": "Very bad",
            "cvss_score": 9.8,
            "cve_id": "CVE-2026-1234",
            "package_name": "foo",
            "package_version": "1.0",
            "fix_version": "2.0",
            "composite_priority": "critical",
        },
    ]
    data = build_fallback_report_data(config, findings)

    assert data["verdict"]["severity"] == "critical"
    assert data["counts"]["critical"] == "1"
    assert len(data["scanner_findings"]) == 1
    assert data["scanner_findings"][0]["cvss"] == "9.8"


def test_build_fallback_validates_against_schema():
    """Fallback output must pass the JSON schema."""
    from jsonschema import validate

    from thresher.config import ScanConfig
    from thresher.harness.report import build_fallback_report_data

    schema_path = Path(__file__).parent.parent.parent / "templates" / "report" / "report_schema.json"
    schema = json.loads(schema_path.read_text())
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    data = build_fallback_report_data(config, [])
    validate(instance=data, schema=schema)
