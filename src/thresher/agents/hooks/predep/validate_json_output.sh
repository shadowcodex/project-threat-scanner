#!/usr/bin/env bash
set -euo pipefail

# Stop hook for predep agent.
# Validates that the assistant's last message is valid JSON conforming to the
# hidden_dependencies schema.
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

# Validate against hidden_dependencies schema
errors = []

if not isinstance(data, dict):
    errors.append('Response JSON is not an object')
else:
    if 'hidden_dependencies' not in data:
        errors.append('Missing required field: hidden_dependencies')
    elif not isinstance(data['hidden_dependencies'], list):
        errors.append('hidden_dependencies must be an array')
    else:
        valid_types = ('git', 'npm', 'pypi', 'cargo', 'go', 'url', 'docker', 'submodule')
        valid_levels = ('high', 'medium', 'low')
        for i, dep in enumerate(data['hidden_dependencies']):
            if not isinstance(dep, dict):
                errors.append(f'hidden_dependencies[{i}] is not an object')
                continue
            for field in ('type', 'source', 'found_in', 'confidence', 'risk'):
                if field not in dep:
                    errors.append(f'hidden_dependencies[{i}] missing field: {field}')
            if dep.get('type') not in valid_types:
                errors.append(f'hidden_dependencies[{i}] invalid type: {dep.get(\"type\")}')
            if dep.get('confidence') not in valid_levels:
                errors.append(f'hidden_dependencies[{i}] invalid confidence: {dep.get(\"confidence\")}')
            if dep.get('risk') not in valid_levels:
                errors.append(f'hidden_dependencies[{i}] invalid risk: {dep.get(\"risk\")}')

    if 'files_scanned' not in data:
        errors.append('Missing required field: files_scanned')
    if 'summary' not in data:
        errors.append('Missing required field: summary')

if errors:
    print('Output validation failed:', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix your output to match the required schema. Ensure:', file=sys.stderr)
    print('  - hidden_dependencies is an array of objects', file=sys.stderr)
    print('  - Each object has: type, source, found_in, confidence, risk', file=sys.stderr)
    print('  - type is one of: git, npm, pypi, cargo, go, url, docker, submodule', file=sys.stderr)
    print('  - confidence and risk are: high, medium, or low', file=sys.stderr)
    print('  - Top-level has: files_scanned (number) and summary (string)', file=sys.stderr)
    sys.exit(2)

sys.exit(0)
"
