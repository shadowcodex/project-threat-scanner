#!/usr/bin/env bash
set -euo pipefail

# Stop hook for analyst agents.
# Validates that the assistant's last message is valid JSON conforming to the
# analyst findings schema.
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

# Validate against analyst findings schema
errors = []

if not isinstance(data, dict):
    errors.append('Response JSON is not an object')
else:
    # Reject predep schema
    if 'hidden_dependencies' in data and 'findings' not in data:
        errors.append('Output uses hidden_dependencies schema — use the analyst findings schema instead')

    required = ('analyst', 'analyst_number', 'core_question', 'findings', 'summary', 'risk_score')
    for field in required:
        if field not in data:
            errors.append(f'Missing required field: {field}')

    findings = data.get('findings')
    if findings is not None:
        if not isinstance(findings, list):
            errors.append('findings must be an array')
        else:
            for i, f in enumerate(findings):
                if not isinstance(f, dict):
                    errors.append(f'findings[{i}] is not an object')
                    continue
                for field in ('title', 'severity', 'description'):
                    if field not in f:
                        errors.append(f'findings[{i}] missing field: {field}')
                sev = f.get('severity', '')
                if sev not in ('critical', 'high', 'medium', 'low'):
                    errors.append(f'findings[{i}] invalid severity: {sev} (must be critical|high|medium|low)')

    risk = data.get('risk_score')
    if risk is not None:
        try:
            r = int(risk)
            if r < 0 or r > 10:
                errors.append(f'risk_score must be 0-10, got {r}')
        except (ValueError, TypeError):
            errors.append(f'risk_score must be an integer 0-10, got {risk}')

if errors:
    print('Output validation failed:', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix your output to match the required analyst schema:', file=sys.stderr)
    print('  {', file=sys.stderr)
    print('    \"analyst\": \"name\",', file=sys.stderr)
    print('    \"analyst_number\": N,', file=sys.stderr)
    print('    \"core_question\": \"...\",', file=sys.stderr)
    print('    \"files_analyzed\": N,', file=sys.stderr)
    print('    \"findings\": [{\"title\": \"...\", \"severity\": \"high\", \"confidence\": 90, ...}],', file=sys.stderr)
    print('    \"summary\": \"...\",', file=sys.stderr)
    print('    \"risk_score\": 0-10', file=sys.stderr)
    print('  }', file=sys.stderr)
    print('Do NOT use hidden_dependencies format. Use findings array.', file=sys.stderr)
    sys.exit(2)

sys.exit(0)
"
