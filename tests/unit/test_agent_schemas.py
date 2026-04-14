"""Tests for agent JSON Schema definitions.

Validates the schema files themselves are well-formed and that valid/invalid
data is correctly accepted/rejected by jsonschema.validate().
"""

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

_SCHEMAS_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "thresher"
    / "agents"
    / "hooks"
    / "_common"
    / "schemas"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def analyst_schema():
    return json.loads((_SCHEMAS_DIR / "analyst_schema.json").read_text())


@pytest.fixture(scope="module")
def predep_schema():
    return json.loads((_SCHEMAS_DIR / "predep_schema.json").read_text())


@pytest.fixture(scope="module")
def adversarial_schema():
    return json.loads((_SCHEMAS_DIR / "adversarial_schema.json").read_text())


# ---------------------------------------------------------------------------
# Analyst schema tests
# ---------------------------------------------------------------------------


class TestAnalystSchema:
    def _valid_data(self):
        return {
            "analyst": "paranoid",
            "analyst_number": 1,
            "core_question": "Is this code malicious?",
            "files_analyzed": 25,
            "findings": [
                {
                    "title": "Suspicious eval call",
                    "severity": "high",
                    "confidence": 85,
                    "file_path": "/opt/target/main.py",
                    "line_numbers": [42],
                    "description": "eval with user input",
                    "evidence": "eval(request.data)",
                    "reasoning": "User-controlled code execution",
                    "recommendation": "Use safe parsing instead",
                }
            ],
            "summary": "Found suspicious patterns",
            "risk_score": 7,
        }

    def test_valid_full_data(self, analyst_schema):
        validate(instance=self._valid_data(), schema=analyst_schema)

    def test_valid_empty_findings(self, analyst_schema):
        data = self._valid_data()
        data["findings"] = []
        data["risk_score"] = 0
        validate(instance=data, schema=analyst_schema)

    def test_valid_minimal_finding(self, analyst_schema):
        data = self._valid_data()
        data["findings"] = [
            {"title": "Test", "severity": "low", "description": "A thing"},
        ]
        validate(instance=data, schema=analyst_schema)

    def test_missing_analyst(self, analyst_schema):
        data = self._valid_data()
        del data["analyst"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_missing_findings(self, analyst_schema):
        data = self._valid_data()
        del data["findings"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_missing_summary(self, analyst_schema):
        data = self._valid_data()
        del data["summary"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_missing_risk_score(self, analyst_schema):
        data = self._valid_data()
        del data["risk_score"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_risk_score_too_high(self, analyst_schema):
        data = self._valid_data()
        data["risk_score"] = 15
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_risk_score_negative(self, analyst_schema):
        data = self._valid_data()
        data["risk_score"] = -1
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_invalid_severity(self, analyst_schema):
        data = self._valid_data()
        data["findings"][0]["severity"] = "URGENT"
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_finding_missing_title(self, analyst_schema):
        data = self._valid_data()
        del data["findings"][0]["title"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_finding_missing_description(self, analyst_schema):
        data = self._valid_data()
        del data["findings"][0]["description"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)

    def test_finding_missing_severity(self, analyst_schema):
        data = self._valid_data()
        del data["findings"][0]["severity"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=analyst_schema)


# ---------------------------------------------------------------------------
# Predep schema tests
# ---------------------------------------------------------------------------


class TestPredepSchema:
    def _valid_data(self):
        return {
            "hidden_dependencies": [
                {
                    "type": "git",
                    "source": "https://github.com/example/lib.git",
                    "found_in": "Makefile:42",
                    "context": "Cloned during build",
                    "confidence": "high",
                    "risk": "low",
                }
            ],
            "files_scanned": 15,
            "summary": "Found 1 hidden dependency",
        }

    def test_valid_full_data(self, predep_schema):
        validate(instance=self._valid_data(), schema=predep_schema)

    def test_valid_empty_deps(self, predep_schema):
        data = {"hidden_dependencies": [], "files_scanned": 5, "summary": "None found"}
        validate(instance=data, schema=predep_schema)

    def test_missing_hidden_dependencies(self, predep_schema):
        data = {"files_scanned": 5, "summary": "oops"}
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_missing_files_scanned(self, predep_schema):
        data = self._valid_data()
        del data["files_scanned"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_missing_summary(self, predep_schema):
        data = self._valid_data()
        del data["summary"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_invalid_dep_type(self, predep_schema):
        data = self._valid_data()
        data["hidden_dependencies"][0]["type"] = "invalid_type"
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_invalid_confidence(self, predep_schema):
        data = self._valid_data()
        data["hidden_dependencies"][0]["confidence"] = "very_high"
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_invalid_risk(self, predep_schema):
        data = self._valid_data()
        data["hidden_dependencies"][0]["risk"] = "extreme"
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_missing_dep_source(self, predep_schema):
        data = self._valid_data()
        del data["hidden_dependencies"][0]["source"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_missing_dep_found_in(self, predep_schema):
        data = self._valid_data()
        del data["hidden_dependencies"][0]["found_in"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=predep_schema)

    def test_all_dep_types_valid(self, predep_schema):
        for dep_type in ("git", "npm", "pypi", "cargo", "go", "url", "docker", "submodule"):
            data = self._valid_data()
            data["hidden_dependencies"][0]["type"] = dep_type
            validate(instance=data, schema=predep_schema)


# ---------------------------------------------------------------------------
# Adversarial schema tests
# ---------------------------------------------------------------------------


class TestAdversarialSchema:
    def _valid_data(self):
        return {
            "results": [
                {
                    "file_path": "/opt/target/main.py",
                    "title": "Suspicious eval",
                    "verdict": "confirmed",
                    "confidence": 90,
                    "benign_explanation_attempted": "Could be a debug utility",
                    "reasoning": "No legitimate reason for eval on user input",
                    "original_risk_score": 7,
                    "revised_risk_score": 7,
                }
            ],
            "verification_summary": "1 finding confirmed as genuine risk",
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }

    def test_valid_full_data(self, adversarial_schema):
        validate(instance=self._valid_data(), schema=adversarial_schema)

    def test_valid_empty_results(self, adversarial_schema):
        data = {
            "results": [],
            "verification_summary": "No findings to review",
            "total_reviewed": 0,
        }
        validate(instance=data, schema=adversarial_schema)

    def test_missing_results(self, adversarial_schema):
        data = self._valid_data()
        del data["results"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_missing_verification_summary(self, adversarial_schema):
        data = self._valid_data()
        del data["verification_summary"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_missing_total_reviewed(self, adversarial_schema):
        data = self._valid_data()
        del data["total_reviewed"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_total_reviewed_not_number(self, adversarial_schema):
        data = self._valid_data()
        data["total_reviewed"] = "one"
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_invalid_verdict(self, adversarial_schema):
        data = self._valid_data()
        data["results"][0]["verdict"] = "maybe"
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_missing_result_file_path(self, adversarial_schema):
        data = self._valid_data()
        del data["results"][0]["file_path"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_missing_result_reasoning(self, adversarial_schema):
        data = self._valid_data()
        del data["results"][0]["reasoning"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)

    def test_downgraded_verdict_valid(self, adversarial_schema):
        data = self._valid_data()
        data["results"][0]["verdict"] = "downgraded"
        validate(instance=data, schema=adversarial_schema)

    def test_missing_result_verdict(self, adversarial_schema):
        data = self._valid_data()
        del data["results"][0]["verdict"]
        with pytest.raises(ValidationError):
            validate(instance=data, schema=adversarial_schema)
