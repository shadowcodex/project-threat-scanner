"""Extract a JSON object from a Claude assistant message.

The model often wraps structured output in ```json fences even when
asked not to. This module owns the cascade — direct parse, then
fenced-block extraction — so each schema validator can stay focused
on validation, not parsing.
"""

from __future__ import annotations

import json
import re
from typing import Any

_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def extract_json_object(msg: str) -> Any | None:
    """Return the first parseable JSON value in *msg*, or None.

    Tries direct ``json.loads``, then strips a ```json ... ```
    markdown fence and parses its contents.
    """
    if not msg:
        return None
    try:
        return json.loads(msg)
    except json.JSONDecodeError:
        pass
    fence = _FENCE_RE.search(msg)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    return None
