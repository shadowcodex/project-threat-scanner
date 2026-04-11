#!/usr/bin/env bash
# Stop hook for Thresher agents — dispatches to a per-schema validator.
#
# Usage: validate_json_output.sh <schema-name>
#   schema-name: predep | analyst | adversarial | report
#
# All four agents share this script; the per-schema validation rules
# live in schemas/<schema-name>.py and the JSON-extraction cascade lives
# in extract_json.py. See _validate.py for the dispatch logic.
set -euo pipefail
exec python3 "$(dirname "$0")/_validate.py" "$@"
