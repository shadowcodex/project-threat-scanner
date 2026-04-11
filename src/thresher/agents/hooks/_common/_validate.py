#!/usr/bin/env python3
"""Stop-hook dispatcher for Thresher agents.

Reads the Claude Code stop-hook event from stdin, extracts the
assistant's last message, runs it through the JSON cascade in
``extract_json``, and delegates to the per-schema validator named on
the command line.

Exit contract:
  - 0  : valid output, allow the agent to stop
  - 2  : invalid output, block stop and feed stderr back to the model
  - 0  : also for missing event / empty message — nothing to validate
"""

from __future__ import annotations

import importlib
import json
import os
import sys

# Make sibling modules importable when invoked as a plain script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extract_json import extract_json_object  # noqa: E402

_VALID_SCHEMAS = {"predep", "analyst", "adversarial", "report"}


def _usage_and_exit() -> None:
    print(
        f"usage: {sys.argv[0]} <{ '|'.join(sorted(_VALID_SCHEMAS)) }>",
        file=sys.stderr,
    )
    sys.exit(2)


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in _VALID_SCHEMAS:
        _usage_and_exit()

    schema_name = sys.argv[1]

    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Malformed event isn't the model's fault — let it stop.
        sys.exit(0)

    msg = event.get("last_assistant_message", "")
    if not msg:
        sys.exit(0)

    data = extract_json_object(msg)
    if data is None:
        print(
            "Response is not valid JSON. Output ONLY the raw JSON object, "
            "no markdown or explanation.",
            file=sys.stderr,
        )
        sys.exit(2)

    schema_module = importlib.import_module(f"schemas.{schema_name}")
    errors, hints = schema_module.validate(data)

    if errors:
        print("Output validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        if hints:
            print("", file=sys.stderr)
            for h in hints:
                print(h, file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
