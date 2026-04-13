"""Validation rules for the analyst stop hook."""

from __future__ import annotations

from typing import Any

_REQUIRED = (
    "analyst",
    "analyst_number",
    "core_question",
    "findings",
    "summary",
    "risk_score",
)
_VALID_SEVERITIES = ("critical", "high", "medium", "low")

_HINTS = [
    "Fix your output to match the required analyst schema:",
    "  {",
    '    "analyst": "name",',
    '    "analyst_number": N,',
    '    "core_question": "...",',
    '    "files_analyzed": N,',
    '    "findings": [{"title": "...", "severity": "high", "confidence": 90, ...}],',
    '    "summary": "...",',
    '    "risk_score": 0-10',
    "  }",
]


def validate(data: Any) -> tuple[list[str], list[str]]:
    """Return ``(errors, hints)``. Empty errors == valid output."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["Response JSON is not an object"], _HINTS

    # Reject predep schema explicitly so analyst agents don't drift.
    if "hidden_dependencies" in data and "findings" not in data:
        errors.append(
            "Output uses hidden_dependencies schema — use the analyst findings schema instead",
        )

    for field in _REQUIRED:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    findings = data.get("findings")
    if findings is not None:
        if not isinstance(findings, list):
            errors.append("findings must be an array")
        else:
            for i, f in enumerate(findings):
                if not isinstance(f, dict):
                    errors.append(f"findings[{i}] is not an object")
                    continue
                for field in ("title", "severity", "description"):
                    if field not in f:
                        errors.append(f"findings[{i}] missing field: {field}")
                sev = f.get("severity", "")
                if sev not in _VALID_SEVERITIES:
                    errors.append(
                        f"findings[{i}] invalid severity: {sev} (must be critical|high|medium|low)",
                    )

    risk = data.get("risk_score")
    if risk is not None:
        try:
            r = int(risk)
            if r < 0 or r > 10:
                errors.append(f"risk_score must be 0-10, got {r}")
        except (ValueError, TypeError):
            errors.append(
                f"risk_score must be an integer 0-10, got {risk}",
            )

    return errors, _HINTS
