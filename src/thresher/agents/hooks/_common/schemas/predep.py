"""Validation rules for the predep stop hook."""

from __future__ import annotations

from typing import Any

_VALID_TYPES = ("git", "npm", "pypi", "cargo", "go", "url", "docker", "submodule")
_VALID_LEVELS = ("high", "medium", "low")

_HINTS = [
    "Fix your output to match the required schema. Ensure:",
    "  - hidden_dependencies is an array of objects",
    "  - Each object has: type, source, found_in, confidence, risk",
    "  - type is one of: git, npm, pypi, cargo, go, url, docker, submodule",
    "  - confidence and risk are: high, medium, or low",
    "  - Top-level has: files_scanned (number) and summary (string)",
]


def validate(data: Any) -> tuple[list[str], list[str]]:
    """Return ``(errors, hints)``. Empty errors == valid output."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["Response JSON is not an object"], _HINTS

    if "hidden_dependencies" not in data:
        errors.append("Missing required field: hidden_dependencies")
    elif not isinstance(data["hidden_dependencies"], list):
        errors.append("hidden_dependencies must be an array")
    else:
        for i, dep in enumerate(data["hidden_dependencies"]):
            if not isinstance(dep, dict):
                errors.append(f"hidden_dependencies[{i}] is not an object")
                continue
            for field in ("type", "source", "found_in", "confidence", "risk"):
                if field not in dep:
                    errors.append(
                        f"hidden_dependencies[{i}] missing field: {field}",
                    )
            if dep.get("type") not in _VALID_TYPES:
                errors.append(
                    f"hidden_dependencies[{i}] invalid type: {dep.get('type')}",
                )
            if dep.get("confidence") not in _VALID_LEVELS:
                errors.append(
                    f"hidden_dependencies[{i}] invalid confidence: {dep.get('confidence')}",
                )
            if dep.get("risk") not in _VALID_LEVELS:
                errors.append(
                    f"hidden_dependencies[{i}] invalid risk: {dep.get('risk')}",
                )

    if "files_scanned" not in data:
        errors.append("Missing required field: files_scanned")
    if "summary" not in data:
        errors.append("Missing required field: summary")

    return errors, _HINTS
