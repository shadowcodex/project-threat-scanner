# Report Maker — Design Spec

**Date:** 2026-04-09
**Status:** Draft
**Replaces:** Existing report generation in `harness/report.py`

## Overview

A data-driven HTML report generator for Thresher security scans. Replaces the current static report generation with a pipeline that uses a Claude Code headless agent to transform synthesis output into structured JSON, then renders it via a Jinja-injected template with vanilla JS components.

## Goals

1. Convert the existing example report into a data-driven template (visually identical output)
2. All dynamic content driven by a single JSON blob with enforced schema
3. Claude Code headless agent reads synthesis output and produces the JSON
4. Stop hook validates agent output against JSON schema before accepting
5. Python render function injects JSON into template via Jinja
6. Report renders beautifully with null values or few findings
7. Remediation section designed but hidden (toggle for testing), populated in future pass

## Design Decision: Vanilla JS over React

The original spec requested React. After evaluating three approaches (React via CDN with Babel, React via CDN with createElement, vanilla JS), we chose vanilla JS because:

- The report is read-only with no state management, re-renders, or user input — React's reactivity model adds weight without benefit
- Zero external dependencies means the report works offline and in air-gapped environments (important for security reports)
- No CDN dependency eliminates a network requirement and ~3MB download
- Instant load (no Babel parse step)
- Aligns with CLAUDE.md's "Frontend: Keep it Minimal" principle

The vanilla JS component pattern (functions that return HTML strings, driven by JSON data) achieves the same data-driven architecture as React without the framework overhead. The file `example_data_report.html` reflects this (not `example_react_report.html`).

## Constraints

- No build step — open the HTML file and it works
- No external dependencies — fully self-contained, works offline
- All JSON leaf values are strings (no render issues)
- Executive summary supports limited HTML: `<p>`, `<strong>`, `<code>`, `<ul>`, `<li>`
- Vanilla JS component pattern (no React/framework) — read-only report doesn't need reactivity

## File Layout

```
templates/report/
  example_report.html          # Original reference report (kept for comparison)
  example_data_report.html     # Data-driven version, visually identical to example
  report_schema.json           # JSON Schema enforcing the data structure
  template_report.html         # Jinja template ({{ report_data }} placeholder)

src/thresher/agents/
  report_maker.py              # Agent runner: builds cmd, calls thresher.run
  definitions/report/
    report_maker.yaml          # Agent persona and system prompt
  hooks/report/
    settings.json              # Hook config for report-maker agent
    validate_json_output.sh    # Stop hook: validates JSON against schema

src/thresher/harness/
  report.py                    # render_report() — Jinja injection, replaces existing logic
```

## JSON Schema Structure

All leaf values are strings. Arrays contain objects with string fields.

```json
{
  "meta": {
    "scan_date": "2026-04-02",
    "thresher_version": "v0.2.2",
    "scanner_count": "22",
    "analyst_count": "8",
    "repo_name": "BuilderIO/agent-native",
    "repo_url": "https://github.com/BuilderIO/agent-native"
  },
  "verdict": {
    "label": "FIX DEPS BEFORE USE",
    "severity": "critical",
    "callout": "DO NOT USE — CVE-2026-27606 (rollup@4.46.2, CVSS 9.8) must be resolved..."
  },
  "counts": {
    "total_scanner": "518",
    "total_ai": "28",
    "p0": "0",
    "critical": "2",
    "high_scanner": "17",
    "high_ai": "13",
    "medium": "11",
    "low": "352"
  },
  "executive_summary": "<p>Automated multi-tool scanning...</p>",
  "mitigations": [
    "Upgrade rollup to >=4.59.0 (resolves Critical CVE-2026-27606)"
  ],
  "scanner_findings": [
    {
      "rank": "1",
      "severity": "critical",
      "package": "rollup@4.46.2",
      "title": "Arbitrary File Write via Path Traversal",
      "cve": "CVE-2026-27606",
      "cvss": "9.8"
    }
  ],
  "ai_findings": [
    {
      "severity": "critical",
      "title": "IDOR: Missing Ownership Check...",
      "file": "packages/core/src/resources/handlers.ts:227-273",
      "description": "Any authenticated user can...",
      "confidence": "97",
      "analysts": ["Analyst 5: App Pentester"]
    }
  ],
  "trust_signals": [
    { "icon": "!", "text": "Single maintainer (bus factor = 1)..." }
  ],
  "dependency_upgrades": [
    {
      "package": "rollup",
      "old_version": "4.46.2",
      "new_version": "4.59.0",
      "severity": "critical",
      "cvss": "9.8",
      "cves": "CVE-2026-27606"
    }
  ],
  "remediation": {
    "pr_title": "PR #127 — Security Remediation",
    "pr_url": "https://github.com/.../pull/127",
    "summary": "Resolved 2 Critical, 28 High...",
    "fixes": ["IDOR ownership check", "Path traversal fix"]
  },
  "pipeline": {
    "scanners": ["grype", "trivy", "osv-scanner"],
    "analysts": ["The Paranoid", "The Behaviorist"],
    "notes": "Adversarial verification: An independent agent..."
  },
  "config": {
    "show_cta": "true",
    "show_remediation": "false"
  }
}
```

### Severity enum values

`"critical"`, `"high"`, `"medium"`, `"low"` — mapped to CSS classes by the template.

### Graceful degradation

- Empty `scanner_findings` array: section renders with "No scanner findings" message
- Empty `ai_findings`: section hidden
- Null `remediation`: section hidden regardless of toggle
- Empty `trust_signals`: section hidden
- `show_cta: "false"`: CTA section not rendered

## Template Component Architecture

Single self-contained HTML file with three zones:

**Zone 1 — CSS:** All styles from `example_report.html` preserved as-is.

**Zone 2 — Mount point:** `<div id="app"></div>`

**Zone 3 — JavaScript:**
- `const REPORT_DATA = {{ report_data }};` — Jinja placeholder (Zone 3a)
- Component functions that return HTML strings (Zone 3b):
  - `renderNav(data)` — fixed nav with section anchors
  - `renderHero(data)` — scan date, repo name, verdict box, severity counts
  - `renderExecSummary(data)` — prose HTML, verdict callout, mitigations list
  - `renderFindingsBar(data)` — stacked bar chart for scanner + AI findings
  - `renderScannerTable(data)` — top findings by severity
  - `renderAiFindings(data)` — cards grouped by severity, collapsible medium section
  - `renderTrustSignals(data)` — grid of trust/health items
  - `renderUpgrades(data)` — dependency upgrade table
  - `renderRemediation(data)` — fix card (hidden by default, JS toggle)
  - `renderPipeline(data)` — collapsible scanner and analyst grid
  - `renderCta(data)` — marketing section (conditional on `config.show_cta`)
  - `renderFooter(data)` — links and disclaimer
- Assembly: `renderReport(REPORT_DATA)` joins all components into `app.innerHTML` (Zone 3c)
- Interactivity: remediation toggle, copy-to-clipboard, native `<details>` (Zone 3d)

Each component:
- Takes the relevant slice of REPORT_DATA
- Returns an HTML string
- Returns `""` if data is null/empty (graceful degradation)
- Maps severity strings to CSS classes

## Report-Maker Agent

### Note: Stop Hook Pattern is New

No existing Thresher agent uses stop hooks — this functionality was dropped in a prior rewrite. The `--bare --settings` approach for scoping hooks per-agent is a new pattern being established here. It needs a proof-of-concept early in implementation to verify:
- `--bare` correctly isolates the agent from the project's `.claude/settings.json`
- The Stop hook fires correctly in headless mode
- `exit 0` with `{"decision": "block"}` causes Claude to retry as expected

Once proven for this agent, the same pattern restores hook support for all other agents.

### Role

Runs after the synthesis agent. Reads synthesis output and produces JSON conforming to `report_schema.json`.

### Inputs

The agent reads (via `--allowedTools Read,Glob,Grep`):
- `findings.json` — enriched findings from synthesis (scanner + AI, with composite priorities)
- `executive-summary.md` — AI-generated narrative from synthesis agent
- `scan-results/*.json` — raw scanner outputs for detail extraction
- `templates/report/*` — template, schema, and example report (so it knows the target format)

### System prompt (`definitions/report/report_maker.yaml`)

Note: Existing analyst YAMLs live flat in `definitions/*.yaml`. The report-maker uses a subdirectory (`definitions/report/`) intentionally — it is a different agent type with its own loading path in `report_maker.py`, not loaded by the analyst orchestrator.

- Persona: security report data compiler
- Instructions: read findings, read schema, produce JSON that conforms exactly
- Allowed HTML tags for executive_summary: `<p>`, `<strong>`, `<code>`, `<ul>`, `<li>`
- Guidance on severity mapping, verdict generation, ranking
- Leave `remediation` fields null (first pass)
- Set `show_remediation` to `"false"`, `show_cta` configurable via ScanConfig

### Invocation

Follows existing agent pattern — builds cmd list, passes to `thresher.run.run()`:

```python
cmd = [
    "claude",
    "-p", str(prompt_path),
    "--model", model,
    "--bare",
    "--settings", str(hooks_settings_path),
    "--allowedTools", "Read,Glob,Grep",
    "--output-format", "stream-json",
    "--verbose",
    "--max-turns", str(max_turns),
]

proc = run_cmd(cmd, label="report-maker", env=env, timeout=3600, cwd=target_dir)
```

The `--bare --settings` flags scope the hook config to this agent only, preventing interference with the project's `.claude/settings.json`.

### Stop Hook

**Config** (`hooks/report/settings.json`):
```json
{
  "hooks": {
    "Stop": [
      {
        "type": "command",
        "command": "src/thresher/agents/hooks/report/validate_json_output.sh",
        "timeout": 10
      }
    ]
  }
}
```

**Validation script** (`hooks/report/validate_json_output.sh`):
- Reads JSON event from stdin
- Extracts `last_assistant_message`
- Validates against `templates/report/report_schema.json` using `python -m jsonschema`
- On valid: exits 0 (allows stop)
- On invalid: exits 0 with `{"decision": "block", "reason": "<specific validation error>"}` — Claude retries
- Handles infinite loop prevention

**Reusable pattern:** Any agent needing output validation creates:
1. `hooks/<agent-name>/settings.json` pointing to its validation script
2. `hooks/<agent-name>/validate_*.sh` with agent-specific logic
3. Passes `--bare --settings <path>` in cmd

### Configuration

Add `report_maker_max_turns` to `ScanConfig` (default 15). Configurable via `thresher.toml` under `[agents]` alongside existing `analyst_max_turns`, `predep_max_turns`, etc.

### Error Handling

- **Agent subprocess failure:** Fall back to the skip-AI programmatic JSON builder (same as `--skip-ai` path). Log warning.
- **Stop hook exhausts retries** (agent hits max_turns without valid JSON): Same fallback — programmatic builder produces a valid but less polished report.
- **Agent returns schema-valid but low-quality JSON:** Accepted — the stop hook validates structure, not prose quality. This is an acceptable trade-off; quality improves with prompt iteration.

## Pipeline Integration

Two new Hamilton DAG nodes in `harness/pipeline.py`, replacing existing report generation.

The existing `report_path` node (which calls `generate_report()`) is **replaced** by `report_data` + `report_html`. The `final_vars` in `run_pipeline()` changes from `["report_path"]` to `["report_html"]`.

Existing responsibilities of `generate_report()` are redistributed:
- **findings.json writing** — stays in the existing synthesis/enrichment node (already happens before report generation)
- **Scanner output copying** (`scan-results/*.json`) — stays in the existing report validation/copy step
- **HTML report generation** — moves to the new `report_html` node
- **Markdown reports** (`executive-summary.md`, `detailed-report.md`) — these are synthesis outputs, not report-maker outputs. They continue to be written by the synthesis agent.

The existing `generate_report()` function in `harness/report.py` is replaced by `render_report()`.

```python
def report_data(scan_config, enriched_findings, output_dir) -> dict:
    """Run report-maker agent to produce structured JSON."""
    from thresher.agents.report_maker import run_report_maker
    return run_report_maker(scan_config, output_dir)

def report_html(report_data, output_dir) -> str:
    """Render final HTML from report data + Jinja template."""
    from thresher.harness.report import render_report
    return render_report(report_data, output_dir)
```

### Data flow

```
Existing DAG stages 1-10
  -> synthesis output (findings.json, executive-summary.md, scan-results/*.json)
    -> report_maker agent (Claude Code headless, stop-hook validated)
      -> report_data.json
        -> render_report() in harness/report.py
          -> loads templates/report/template_report.html
          -> Jinja injects json.dumps(report_data) into {{ report_data }}
          -> writes /output/report.html
```

### Render function

`render_report(report_data: dict, output_dir: str) -> Path`
- Loads `templates/report/template_report.html`
- Single Jinja substitution: `const REPORT_DATA = {{ report_data }};`
- Writes `report.html` to output_dir
- Returns output path

### Template path resolution

Templates live at `templates/report/` in the project root. At runtime:
- **Direct mode (`--no-vm`):** Resolved relative to the thresher package install location using `importlib.resources` or `pathlib.Path(__file__).parent` traversal.
- **Docker mode:** Templates are copied into the Docker image at build time (added to `Dockerfile` COPY step). Located at `/opt/thresher/templates/report/` inside the container.
- **Lima+Docker mode:** Same as Docker — the image contains the templates.

The `render_report()` function accepts an optional `template_dir` parameter, defaulting to the package-relative path. The Docker entrypoint can override this via environment variable if needed.

### Skip-AI fallback

When `--skip-ai` is set (or the report-maker agent fails), the agent is skipped. A `build_fallback_report_data()` function in `report_maker.py` programmatically constructs the JSON dict from raw findings:

- `meta` — populated from `ScanConfig` (scan_date, version, scanner/analyst counts)
- `verdict` — computed from highest severity finding: critical findings → "FIX BEFORE USE", high → "REVIEW BEFORE USE", medium/low → "LOW RISK"
- `counts` — computed by iterating enriched findings and counting by severity
- `executive_summary` — template string: `"<p>Automated scanning of <strong>{repo}</strong> produced <strong>{count} findings</strong> across {tool_count} tools.</p>"`
- `mitigations` — one entry per critical/high finding: `"Resolve {cve} in {package}"`
- `scanner_findings` — top 10 by CVSS score from enriched findings
- `ai_findings` — all AI findings from enriched findings (empty if skip-ai)
- `trust_signals`, `dependency_upgrades` — populated from enriched findings where available
- `remediation` — null (first pass)
- `config` — `show_cta: "true"`, `show_remediation: "false"`

## Testing

### `test_report_render.py` — Jinja render function
- Valid JSON produces correct HTML with data embedded
- Empty arrays render gracefully
- Null remediation hides section
- `show_cta: "false"` excludes CTA section
- `show_remediation: "true"` makes remediation visible

### `test_report_schema.py` — Schema validation
- Valid example JSON passes
- Missing required fields fail
- Invalid severity enum values fail
- Empty/minimal JSON passes

### `test_report_maker_agent.py` — Agent runner
- Builds correct cmd with `--bare --settings` flags
- Parses stream-json output correctly
- Returns dict matching expected structure
- Mock subprocess (existing agent test pattern)

### `test_agent_hooks.py` — Hook mechanism
- **Schema validation:** valid JSON passes, malformed JSON blocks, missing required fields block, wrong types block, invalid severity enums block, minimal valid JSON passes
- **Hook mechanics:** reads `last_assistant_message` from stdin correctly, output is well-formed JSON with `decision` and `reason` when blocking, handles edge cases (empty stdin, missing fields, large output)
- **Reusability:** hook script accepts schema path as parameter, different schema + different settings = same pattern works

### `test_report_pipeline.py` — DAG integration
- Mock `_build_driver`, verify `report_data` and `report_html` nodes wire correctly
- Verify skip-ai fallback produces valid JSON for the template

### Manual validation
- Open `example_data_report.html` in browser: visually identical to `example_report.html`
- Toggle remediation via JS console: section shows/hides
- Test with minimal-data JSON: report still renders beautifully
