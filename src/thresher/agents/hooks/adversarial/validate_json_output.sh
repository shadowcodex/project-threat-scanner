#!/usr/bin/env bash
set -euo pipefail

# Stop hook for adversarial verification agent.
# Validates that the assistant's last message is valid JSON conforming to the
# adversarial verification schema.
# On valid: exits 0 (allows stop).
# On invalid: exits 2 with error message on stderr (blocks stop, Claude retries).
#
# SECURITY: Entire stdin is piped directly to Python. The assistant message is NEVER
# interpolated into shell variables — it could contain shell metacharacters.

python3 -c "
import sys, json, re

# Read hook event from stdin
try:
    event = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    sys.exit(0)

msg = event.get('last_assistant_message', '')
if not msg:
    sys.exit(0)

# Try direct JSON parse
data = None
try:
    data = json.loads(msg)
except json.JSONDecodeError:
    # Try extracting from markdown code fences
    match = re.search(r'\x60\x60\x60(?:json)?\s*\n(.*?)\n\x60\x60\x60', msg, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

if data is None:
    print('Response is not valid JSON. Output ONLY the raw JSON object, no markdown or explanation.', file=sys.stderr)
    sys.exit(2)

# Validate against adversarial verification schema
errors = []

if not isinstance(data, dict):
    errors.append('Response JSON is not an object')
else:
    if 'verification_summary' not in data:
        errors.append('Missing required field: verification_summary')

    if 'total_reviewed' not in data:
        errors.append('Missing required field: total_reviewed')
    elif not isinstance(data['total_reviewed'], (int, float)):
        errors.append('total_reviewed must be a number')

    if 'results' not in data:
        errors.append('Missing required field: results')
    elif not isinstance(data['results'], list):
        errors.append('results must be an array')
    else:
        for i, r in enumerate(data['results']):
            if not isinstance(r, dict):
                errors.append(f'results[{i}] is not an object')
                continue
            for field in ('file_path', 'verdict', 'reasoning'):
                if field not in r:
                    errors.append(f'results[{i}] missing field: {field}')
            verdict = r.get('verdict', '')
            if verdict not in ('confirmed', 'downgraded'):
                errors.append(f'results[{i}] verdict must be \"confirmed\" or \"downgraded\", got: {verdict}')

if errors:
    print('Output validation failed:', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix your output to match the required schema. Ensure:', file=sys.stderr)
    print('  - verification_summary is a string', file=sys.stderr)
    print('  - total_reviewed is a number', file=sys.stderr)
    print('  - results is an array of objects', file=sys.stderr)
    print('  - Each result has: file_path, verdict, reasoning', file=sys.stderr)
    print('  - verdict is \"confirmed\" or \"downgraded\"', file=sys.stderr)
    sys.exit(2)

sys.exit(0)
"
