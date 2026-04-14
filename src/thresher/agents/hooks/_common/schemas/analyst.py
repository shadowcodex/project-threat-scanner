"""Validation rules for the analyst stop hook.

Uses the JSON Schema in ``analyst_schema.json`` validated with
``jsonschema``. Also includes a pre-check to reject predep-shaped
output (hidden_dependencies without findings) before schema validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SCHEMA_PATH = Path(__file__).parent / "analyst_schema.json"


def validate(data: Any) -> tuple[list[str], list[str]]:
    """Return ``(errors, hints)``. Empty errors == valid output."""
    if not isinstance(data, dict):
        return ["Response JSON is not an object"], []

    # Reject predep schema explicitly so analyst agents don't drift.
    if "hidden_dependencies" in data and "findings" not in data:
        return [
            "Output uses hidden_dependencies schema — use the analyst findings schema instead",
        ], []

    try:
        import jsonschema
    except ImportError as exc:
        return [
            "jsonschema is required for analyst output validation "
            f"but is not installed ({exc}). Install with: pip install jsonschema",
        ], []

    try:
        with open(_SCHEMA_PATH) as f:
            schema = json.loads(f.read())
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        path = " -> ".join(str(p) for p in e.absolute_path) or "(root)"
        return [f"Schema validation failed at {path}: {e.message}"], []

    return [], []
