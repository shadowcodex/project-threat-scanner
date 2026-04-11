"""Validation rules for the adversarial verification stop hook."""

from __future__ import annotations

from typing import Any

_HINTS = [
    "Fix your output to match the required schema. Ensure:",
    "  - verification_summary is a string",
    "  - total_reviewed is a number",
    "  - results is an array of objects",
    "  - Each result has: file_path, verdict, reasoning",
    '  - verdict is "confirmed" or "downgraded"',
]


def validate(data: Any) -> tuple[list[str], list[str]]:
    """Return ``(errors, hints)``. Empty errors == valid output."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["Response JSON is not an object"], _HINTS

    if "verification_summary" not in data:
        errors.append("Missing required field: verification_summary")

    if "total_reviewed" not in data:
        errors.append("Missing required field: total_reviewed")
    elif not isinstance(data["total_reviewed"], (int, float)):
        errors.append("total_reviewed must be a number")

    if "results" not in data:
        errors.append("Missing required field: results")
    elif not isinstance(data["results"], list):
        errors.append("results must be an array")
    else:
        for i, r in enumerate(data["results"]):
            if not isinstance(r, dict):
                errors.append(f"results[{i}] is not an object")
                continue
            for field in ("file_path", "verdict", "reasoning"):
                if field not in r:
                    errors.append(f"results[{i}] missing field: {field}")
            verdict = r.get("verdict", "")
            if verdict not in ("confirmed", "downgraded"):
                errors.append(
                    f'results[{i}] verdict must be "confirmed" or '
                    f'"downgraded", got: {verdict}',
                )

    return errors, _HINTS
