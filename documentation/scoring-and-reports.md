# Scoring and Reports

## Finding Normalization

All 16 scanners produce output in different formats. The pipeline normalizes every finding into a common `Finding` dataclass so they can be de-duplicated, enriched, and prioritized uniformly.

### Normalized Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g., `grype-CVE-2024-1234-0`) |
| `source_tool` | string | Scanner that found it (e.g., `grype`, `semgrep`) |
| `category` | string | `sca`, `sast`, `supply_chain`, `secrets`, `iac`, `malware`, `binary_analysis`, `license` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `cvss_score` | float or null | CVSS v3 score (0.0-10.0) |
| `cve_id` | string or null | CVE identifier (e.g., `CVE-2024-1234`) |
| `title` | string | Human-readable one-line summary |
| `description` | string | Detailed description with context |
| `file_path` | string or null | Path to affected file |
| `line_number` | int or null | Affected line number |
| `package_name` | string or null | Affected dependency |
| `package_version` | string or null | Installed version |
| `fix_version` | string or null | Version that fixes the issue |
| `raw_output` | dict | Original scanner output (preserved for debugging) |

### De-duplication

Multiple scanners often detect the same CVE. The aggregation step de-duplicates by `(cve_id, package_name)`:

- If two findings share the same CVE ID and package name, they're duplicates
- The finding with more populated fields ("richer" detail) is kept
- Findings without a CVE ID are always included (can't be de-duplicated)
- Final list is sorted by severity (critical first)

## Enrichment

After scanning, findings are enriched with two external data sources:

### EPSS (Exploit Prediction Scoring System)

**Source**: [FIRST EPSS API](https://api.first.org/data/v1/epss)

EPSS provides a probability score (0.0 to 1.0) representing the likelihood that a CVE will be exploited in the wild in the next 30 days. Higher scores mean the vulnerability is more likely to be actively exploited.

- CVE IDs are batched in groups of 100
- Scores are fetched from the FIRST API (whitelisted in the VM firewall)
- API failures are non-fatal — findings proceed without EPSS data

### CISA KEV (Known Exploited Vulnerabilities)

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

The KEV catalog lists vulnerabilities that CISA has confirmed are being actively exploited in the wild. Presence in the KEV catalog is the strongest signal that a vulnerability is dangerous.

- The full catalog is downloaded as JSON
- Each finding's CVE ID is checked against the catalog
- KEV presence triggers automatic **P0** priority

## Priority Computation

Each finding receives a composite priority based on multiple signals:

### Priority Levels

| Priority | Criteria | What It Means |
|----------|----------|---------------|
| **P0** | In CISA KEV (actively exploited), OR AI confidence ≥90 for exfiltration/backdoor/trojan/RCE | **Emergency** — actively exploited or almost certainly malicious |
| **Critical** | CVSS ≥ 9.0, OR EPSS > 0.9, OR AI risk 9-10 confirmed by adversarial | **Severe** — high-impact vulnerability with high exploitation likelihood |
| **High** | CVSS 7.0-8.9, OR EPSS > 0.75, OR AI risk 7-8 | **Important** — significant risk requiring attention |
| **Medium** | CVSS 4.0-6.9, OR EPSS > 0.5, OR AI risk 4-6 | **Notable** — moderate risk, should be reviewed |
| **Low** | Everything else | **Informational** — low risk, track but don't block |

### Priority Decision Logic

The priority function evaluates signals in order, returning the first match:

```
1. CVE in CISA KEV? → P0
2. AI confidence ≥90 for exfiltration/backdoor? → P0
3. CVSS ≥ 9.0? → Critical
4. EPSS > 0.9? → Critical
5. AI risk 9-10 + adversarial confirmed? → Critical
6. CVSS 7.0-8.9? → High
7. EPSS > 0.75? → High
8. AI risk 7-8? → High
9. CVSS 4.0-6.9? → Medium
10. EPSS > 0.5? → Medium
11. AI risk 4-6? → Medium
12. Everything else → Low
```

### Recommendation Logic

The final recommendation is based on the highest-priority finding:

| Highest Finding | Recommendation |
|-----------------|---------------|
| Any P0 or Critical | **DO NOT USE** |
| High (no P0/Critical) | **USE WITH CAUTION** |
| Medium or below only | **GO** |

## Report Generation

Report generation is the final stage of the scan pipeline. It runs after synthesis (which merges, deduplicates, and prioritizes findings across scanner and AI tracks). The pipeline produces a data-driven HTML report plus supporting artifacts.

### Architecture

The report pipeline has three stages:

1. **Synthesis** (existing) — merges scanner + AI findings, applies priority elevation/downgrade
2. **Report-maker agent** — reads synthesis output, produces structured JSON conforming to a schema
3. **Render** — injects JSON into an HTML template via Jinja

```
synthesis output (findings.json, executive-summary.md, scan-results/*.json)
  → report-maker agent (Claude Code headless, stop-hook validated)
    → report_data.json (validated against templates/report/report_schema.json)
      → render_report() in harness/report.py
        → Jinja injects JSON into templates/report/template_report.html
          → /output/report.html
```

### Report-Maker Agent

The report-maker agent (`src/thresher/agents/report_maker.py`) transforms synthesis output into the structured JSON the template needs. It runs as a Claude Code headless subprocess, same as the analyst agents.

**Inputs** (read via `--allowedTools Read,Glob,Grep`):
- `findings.json` — enriched findings with composite priorities
- `executive-summary.md` — AI-generated narrative from synthesis
- `scan-results/*.json` — raw scanner outputs
- `templates/report/*` — schema, template, and example for reference

**Output**: A single JSON object conforming to `templates/report/report_schema.json`.

**Stop hook validation**: A Claude Code Stop hook (`src/thresher/agents/hooks/report/validate_json_output.sh`) validates the agent's output against the JSON schema before allowing the agent to exit. If validation fails, the hook blocks the stop (exit 2 + stderr feedback) and Claude retries. This ensures the agent can't finish until it produces schema-valid JSON.

The agent definition lives at `src/thresher/agents/definitions/report/report_maker.yaml`.

**Configuration**: `report_maker_max_turns` in `ScanConfig` (default 15, configurable via `thresher.toml` under `[report_maker]`).

### Skip-AI Fallback

When `--skip-ai` is set or the report-maker agent fails, `build_fallback_report_data()` constructs the JSON programmatically from raw findings:
- Verdict computed from highest severity finding
- Counts computed by iterating findings
- Executive summary is a template string
- Top 10 scanner findings by CVSS score
- Mitigations generated for critical/high findings

The fallback output passes the same JSON schema validation as agent output.

### Pipeline Integration

Two Hamilton DAG nodes in `harness/pipeline.py`:

- `report_data` — runs report-maker agent (or fallback), returns JSON dict
- `report_html` — calls `render_report()` for HTML + `finalize_output()` for findings.json/scanner copies

### HTML Report Template

The template (`templates/report/template_report.html`) is a self-contained HTML file with:
- **Zone 1**: All CSS inline (dark terminal aesthetic — violet/black/bone)
- **Zone 2**: Empty `<div id="app">` mount point
- **Zone 3**: JavaScript — Jinja injects the JSON blob as `const REPORT_DATA = {{ report_data }};`, then vanilla JS component functions render it to the DOM

Component functions: `renderNav`, `renderHero`, `renderExecSummary`, `renderFindingsBar`, `renderScannerTable`, `renderAiFindings`, `renderTrustSignals`, `renderUpgrades`, `renderRemediation`, `renderPipeline`, `renderCta`, `renderFooter`.

Each component returns an HTML string from its slice of REPORT_DATA. Empty/null data causes the section to be hidden gracefully.

No build step, no external JS dependencies. Works offline.

### JSON Schema

`templates/report/report_schema.json` enforces the report data contract:
- All leaf values are strings (prevents type issues in browser JS)
- Severity fields use `"enum": ["critical", "high", "medium", "low"]`
- Required sections: `meta`, `verdict`, `counts`, `executive_summary`, `mitigations`, `scanner_findings`, `ai_findings`, `trust_signals`, `dependency_upgrades`, `pipeline`, `config`
- `remediation` is nullable (populated in a future follow-up pass)
- `config.show_cta` / `config.show_remediation` control conditional sections

### Configurable Sections

| Config Flag | Controls |
|-------------|----------|
| `config.show_cta` | Marketing footer (brew install box). `"true"` or `"false"`. |
| `config.show_remediation` | Remediation PR section. Hidden by default (`"false"`), includes a JS toggle for testing. |

### Executive Summary HTML

The `executive_summary` field supports a limited set of HTML tags: `<p>`, `<strong>`, `<code>`, `<ul>`, `<li>`. The agent is instructed to use only these tags. The template renders the value as innerHTML.

## Report Output

Reports are written to `<output-dir>/<scan-id>/`:

### report.html (primary artifact)

Self-contained, data-driven HTML report. Dark-themed terminal aesthetic (violet/black/bone), responsive design. All content rendered by vanilla JS component functions from a single JSON blob.

Sections:
- **Hero**: Scan date, repo name, verdict box (color-coded by severity), finding counts
- **Executive Summary**: Agent-generated narrative HTML, verdict callout, mitigations list
- **Findings Distribution**: Stacked bar charts for scanner and AI finding counts by severity
- **Scanner Findings**: Top 10 findings table with severity, CVE, and CVSS
- **AI Analyst Findings**: Cards grouped by severity with confidence bars and analyst tags. Critical/High shown as full cards, Medium in collapsible `<details>`.
- **Trust Assessment**: Repository health signals grid (bus factor, SECURITY.md, release tags)
- **Dependency Upgrades**: Table of packages with current/fixed versions and CVE links
- **Remediation**: PR details and fix list (hidden by default, JS toggle for testing)
- **Pipeline Details**: Collapsible section listing all scanners and AI personas
- **CTA**: Marketing footer with install command (conditional on `config.show_cta`)

Empty/null sections are hidden automatically — the report looks clean regardless of how much data is available.

### executive-summary.md

A concise report with:
- **Recommendation**: GO / USE WITH CAUTION / DO NOT USE
- **Top findings**: The most critical issues found
- **Risk summary**: Counts by priority level
- **Scanner coverage**: Which scanners ran and what they found

### detailed-report.md

Comprehensive findings grouped by priority:

```markdown
## Priority P0 (2 findings)
### CVE-2024-1234 in example-lib@1.2.3
- Source: grype (SCA)
- CVSS: 9.8 | EPSS: 0.95 | In CISA KEV: Yes
- Description: Remote code execution via...
- Fix: Upgrade to 1.2.4
...

## Priority Critical (5 findings)
...

## Priority High (12 findings)
...
```

Each finding includes source tool, CVSS/EPSS/KEV status, description, and remediation guidance.

### synthesis-findings.md

The synthesis agent's own analysis of how findings were merged, prioritized, and evaluated across scanner and AI tracks. Includes agreements/disagreements between the two analysis approaches and reasoning for priority elevation or downgrade decisions.

### findings.json

Machine-readable JSON array of all enriched findings:

```json
[
  {
    "id": "grype-CVE-2024-1234-0",
    "source_tool": "grype",
    "category": "sca",
    "severity": "critical",
    "cvss_score": 9.8,
    "cve_id": "CVE-2024-1234",
    "title": "CVE-2024-1234 in example-lib@1.2.3",
    "description": "Remote code execution via deserialization",
    "package_name": "example-lib",
    "package_version": "1.2.3",
    "fix_version": "1.2.4",
    "epss_score": 0.95,
    "in_kev": true,
    "composite_priority": "P0"
  }
]
```

### sbom.json

CycloneDX software bill of materials generated by Syft. Lists every component (dependency) identified in the target project with version, license, and package URL (purl).

### scan-results/

Directory containing raw output from each scanner. Useful for debugging or for feeding into other tools:

```
scan-results/
├── syft.json
├── grype.json
├── osv.json
├── trivy.json
├── semgrep.json
├── bandit.json
├── checkov.json
├── hadolint.json
├── guarddog.json
├── gitleaks.json
├── yara.txt
├── capa.json
├── govulncheck.json
├── cargo-audit.json
├── scancode.json
└── clamav.txt
```

## Templates

Report templates and schema live in `templates/report/`:

| File | Purpose |
|------|---------|
| `template_report.html` | Jinja template — `{{ report_data }}` placeholder for JSON injection |
| `example_data_report.html` | Reference: data-driven report with embedded example JSON |
| `example_report.html` | Reference: original static HTML report (visual target) |
| `report_schema.json` | JSON Schema enforcing the report data structure |

The HTML template uses the same CSS design system as the Thresher website (dark theme, JetBrains Mono + Inter fonts, violet accent). Google Fonts are linked for host-side viewing but fall back gracefully to system fonts.

### Agent and Hook Files

| File | Purpose |
|------|---------|
| `src/thresher/agents/report_maker.py` | Agent runner: builds cmd, calls `thresher.run` |
| `src/thresher/agents/definitions/report/report_maker.yaml` | Agent persona and system prompt |
| `src/thresher/agents/hooks/report/validate_json_output.sh` | Stop hook: validates JSON against schema |

The stop hook uses `exit 2` + stderr to block invalid output and `exit 0` to allow valid output. Hook settings are generated at runtime with absolute paths by `_resolve_hooks_settings()` in `report_maker.py`.
