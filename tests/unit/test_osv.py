"""Tests for thresher.scanners.osv."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from thresher.scanners.osv import (
    _extract_cvss_score,
    _extract_fix_version,
    _extract_severity,
    parse_osv_output,
)
from thresher.harness.scanning import _get_parser


class TestParseOSVOutput:
    def test_cve_finding(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        cve_findings = [f for f in findings if f.cve_id is not None]
        assert len(cve_findings) == 1
        cve = cve_findings[0]
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.category == "sca"
        assert cve.package_name == "example-lib"

    def test_mal_finding(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        mal_findings = [f for f in findings if f.id.startswith("osv-MAL")]
        assert len(mal_findings) == 1
        mal = mal_findings[0]
        assert mal.category == "supply_chain"
        assert mal.severity == "critical"
        assert mal.package_name == "evil-package"

    def test_fix_version_extracted(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        cve = next(f for f in findings if f.cve_id == "CVE-2024-1234")
        assert cve.fix_version == "1.2.4"

    def test_from_fixture(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        assert len(findings) == 2
        for f in findings:
            assert f.source_tool == "osv-scanner"
            assert f.id.startswith("osv-")


class TestExtractSeverity:
    def test_from_database_specific(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert _extract_severity(vuln) == "high"

    def test_default_medium(self):
        assert _extract_severity({}) == "medium"

    def test_moderate_maps_to_medium(self):
        vuln = {"database_specific": {"severity": "MODERATE"}}
        assert _extract_severity(vuln) == "medium"


class TestExtractFixVersion:
    def test_found(self):
        vuln = {
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.0.0"},
                            ]
                        }
                    ]
                }
            ]
        }
        assert _extract_fix_version(vuln) == "2.0.0"

    def test_not_found(self):
        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        assert _extract_fix_version(vuln) is None

    def test_empty(self):
        assert _extract_fix_version({}) is None


class TestOsvScannerName:
    def test_run_osv_name_matches_parser_dispatch(self):
        """ScanSpec name must match what _get_parser expects, or findings are silently dropped."""
        captured_spec = {}

        def mock_run_scanner(spec, **kwargs):
            captured_spec["name"] = spec.name
            return MagicMock(tool_name=spec.name)

        with patch("thresher.scanners.osv.run_scanner", side_effect=mock_run_scanner):
            from thresher.scanners.osv import run_osv

            run_osv("/tmp/target", "/tmp/output")

        # The ScanSpec name must have a parser registered
        parser = _get_parser(captured_spec["name"])
        assert parser is not None, (
            f"No parser registered for ScanSpec name='{captured_spec['name']}'. OSV findings will be silently dropped."
        )


class TestCvssV4Support:
    def test_extract_severity_from_cvss_v4(self):
        """CVSS_V4 entries should be used for severity when CVSS_V3 is absent."""
        vuln = {"severity": [{"type": "CVSS_V4", "score": "9.2"}]}
        assert _extract_severity(vuln) == "critical"

    def test_extract_severity_prefers_v3_over_v4(self):
        """When both CVSS_V3 and CVSS_V4 are present, prefer V3."""
        vuln = {
            "severity": [
                {"type": "CVSS_V4", "score": "9.2"},
                {"type": "CVSS_V3", "score": "7.5"},
            ]
        }
        assert _extract_severity(vuln) == "high"

    def test_extract_cvss_score_from_v4(self):
        """_extract_cvss_score should fall back to CVSS_V4 when V3 is absent."""
        vuln = {"severity": [{"type": "CVSS_V4", "score": "8.1"}]}
        assert _extract_cvss_score(vuln) == 8.1

    def test_extract_cvss_score_prefers_v3(self):
        """When both exist, prefer the CVSS_V3 score."""
        vuln = {
            "severity": [
                {"type": "CVSS_V4", "score": "9.2"},
                {"type": "CVSS_V3", "score": "7.5"},
            ]
        }
        assert _extract_cvss_score(vuln) == 7.5

    def test_extract_cvss_score_v4_vector_string_returns_none(self):
        """CVSS v4 vector strings can't be parsed as float, should return None gracefully."""
        vuln = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/..."}]}
        # _parse_cvss_from_vector returns None for vector strings
        assert _extract_cvss_score(vuln) is None
