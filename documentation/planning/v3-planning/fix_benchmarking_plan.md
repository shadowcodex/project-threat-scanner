# Fix Benchmarking Plan

## Summary

Benchmark reporting for run `bandit-20260413-000642` is not matching the design intent or the raw data already present in logs.

The main problems are:

1. Analysts are grouped instead of being listed individually.
2. Token counts are underreported for analysts.
3. Token counts are also underreported for other AI agents.
4. Total findings in benchmark are wrong because the pipeline is summing unlike stage counts.

This is not a "data missing" problem. The run logs already contain the data we need. The problem is that the current benchmark pipeline collapses and discards too much of it before report generation.

## What This Run Shows

### 1. Analysts are grouped instead of listed individually

The benchmark output contains a single `analysts` stage:

- `thresher-reports/bandit-20260413-000642/benchmark.json:67-83`

But the logs clearly show all 8 analysts with separate runtime and turn counts:

- `logs/bandit-20260413-000642/scan.log:4452-4460`

Example:

- `analyst-behaviorist: 640.3s (turns=3)`
- `analyst-infra-auditor: 259.7s (turns=27)`
- `analyst-investigator: 181.2s (turns=33)`
- `analyst-paranoid: 333.6s (turns=3)`
- `analyst-pentester-appsurface: 185.7s (turns=9)`
- `analyst-pentester-memory: 212.4s (turns=4)`
- `analyst-pentester-vulns: 310.8s (turns=28)`
- `analyst-shadowcatcher: 484.2s (turns=3)`

So the benchmark report is collapsing 8 real executions into one aggregate row.

### 2. Analyst token counts are wrong

Benchmark currently says all analysts together used:

- `input_tokens: 78`
- `output_tokens: 49,328`
- `cache_creation_input_tokens: 132,098`
- `cache_read_input_tokens: 1,196,902`

Source:

- `thresher-reports/bandit-20260413-000642/benchmark.json:167-183`

The `78` total input tokens across all 8 analysts is not credible for sessions that took hundreds of seconds, multiple turns, and spawned additional agent work. The logs show many message-level usage blocks and nested local-agent activity during analyst execution, for example:

- `logs/bandit-20260413-000642/scan.log:2450`
- `logs/bandit-20260413-000642/scan.log:2478`
- `logs/bandit-20260413-000642/scan.log:2517-2518`
- `logs/bandit-20260413-000642/scan.log:2549`
- `logs/bandit-20260413-000642/scan.log:2881`

This strongly suggests the parser is only capturing a narrow subset of usage rather than the full session total.

### 3. Other AI agent token counts are also wrong

The same pattern shows up outside analysts.

Benchmark reports:

- `synthesize.input_tokens = 25` over `21` turns
- `report_maker.input_tokens = 30` over `44` turns

Source:

- `thresher-reports/bandit-20260413-000642/benchmark.json:113-156`

Those numbers are also implausibly low. The logs show rich activity, multiple reads, and substantial prompt payloads for these stages, so benchmark is undercounting them too.

### 4. Total findings in benchmark are wrong

Benchmark says pipeline findings are `731`:

- `thresher-reports/bandit-20260413-000642/benchmark.json:185-201`

The final report says total findings are `344`:

- `thresher-reports/bandit-20260413-000642/report_data.json:25`

Why benchmark says `731`:

- scanners = `301`
- analysts = `43`
- adversarial = `43`
- enrich = `344`

That sum is `731`, but those are not additive pipeline totals. They are counts from different lifecycle stages of the same findings as they move through the DAG.

## Root Causes In The Current Implementation

### 1. The pipeline records one aggregate analyst stage

`pipeline.analyst_findings()` aggregates all analyst token usage into one combined `analysts` stage:

- `src/thresher/harness/pipeline.py:165-175`

That means benchmark never gets one `StageStats` per analyst even though `_run_single_analyst()` captured that data.

### 2. Per-analyst timing metadata is stripped before artifact staging

Each analyst result contains `_timing` with:

- `name`
- `duration`
- `turns`
- `token_usage`

Source:

- `src/thresher/agents/analysts.py:297-313`

But the pipeline strips `_timing` immediately after benchmark aggregation:

- `src/thresher/harness/pipeline.py:175-177`

Then artifact staging writes the stripped result objects:

- `src/thresher/harness/report.py:168-192`

So the run produces per-analyst JSON artifacts, but they contain findings only, not timing or token metadata:

- `thresher-reports/bandit-20260413-000642/scan-results/analyst-01-paranoid.json:1-80`

### 3. Token extraction is too narrow

The shared parser only extracts token usage from `type == "result"` lines, checking `usage` and `modelUsage` on that final object:

- `src/thresher/agents/_json.py:85-112`

`run_agent()` then returns only that parsed total:

- `src/thresher/agents/_runner.py:150-155`

That misses the fact that the logs contain substantial usage across intermediate assistant events and nested local-agent sessions.

### 4. Findings totals are using the wrong semantic model

`BenchmarkCollector.total_findings()` just sums all stage `findings_count` values:

- `src/thresher/harness/benchmarks.py:53-54`

And `build_report_data()` exposes that raw sum as pipeline totals:

- `src/thresher/report/benchmarks.py:141-147`

But the pipeline records different meanings into the same field:

- raw scanner findings in `scan_results()`
- analyst candidate findings in `analyst_findings()`
- verified findings in `verified_findings()`
- final merged findings in `enriched_findings()`

These should not be summed into one headline number.

### 5. The markdown rendering hides useful token detail

The markdown table only renders `Tokens (in/out)`:

- `src/thresher/report/benchmarks.py:177-203`

But cache write/read tokens are a large part of cost. That is why stage costs look surprising in markdown even when JSON contains the fuller picture.

## Existing Design vs Implementation

The benchmark design says the final report should include:

1. Each stage of pipeline and each agent
2. Individual stats for that stage or agent
3. Total stats for all analysts
4. Total stats for the entire pipeline

Source:

- `documentation/design-decisions/benchmarks.md:23-41`

Current implementation does not satisfy "each agent" for analysts, and current pipeline totals do not represent a stable or meaningful pipeline summary.

## Target Design

Benchmarking should model three separate things clearly:

1. Stage performance
2. Token and cost accounting
3. Finding lifecycle counts

### A. Stage performance

Keep:

- pipeline wall time
- stage runtime
- stage errors
- turns when relevant

For analysts, record both:

- one row per analyst, e.g. `analyst-01-paranoid`
- one aggregate wall-clock row for the parallel block, e.g. `analysts`

These are different metrics and should both exist.

### B. Token and cost accounting

Capture token usage from the full stream, not only the final result line.

Track per stage:

- `input_tokens`
- `output_tokens`
- `cache_creation_input_tokens`
- `cache_read_input_tokens`

Also track the actual model(s) used, because logs show mixed models within runs, including nested Haiku work inside a Sonnet-driven pipeline.

### C. Findings lifecycle counts

Stop treating all counts as the same thing.

The benchmark report should distinguish:

- raw scanner findings
- analyst candidate findings
- verified findings
- final findings

The pipeline total should report stable final counts, not a sum across lifecycle stages.

## Fix Plan

### Phase 1. Fix token capture at the source

Update the stream parser to walk the full `stream-json` output and aggregate usage across:

- final result object
- assistant message usage blocks
- nested local-agent sessions where applicable

Requirements:

- dedupe repeated usage emitted for the same message update
- avoid double-counting parent and child session totals
- preserve authoritative totals when a final result contains the best summary

Primary files:

- `src/thresher/agents/_json.py`
- `src/thresher/agents/_runner.py`

### Phase 2. Record each analyst as its own benchmark stage

Update `pipeline.analyst_findings()` to emit `StageStats` for each analyst using `_timing`:

- `analyst-01-paranoid`
- `analyst-02-behaviorist`
- etc.

Keep the aggregate `analysts` stage for overall wall-clock duration of the parallel block.

Primary file:

- `src/thresher/harness/pipeline.py`

### Phase 3. Preserve benchmark detail without polluting report artifacts

Do not rely on user-facing `analyst-*.json` staged artifacts to carry benchmark detail.

Instead:

- keep `_timing` long enough for benchmark capture
- write detailed benchmark output into `benchmark.json` and, if helpful, a new `benchmark-details.json`
- continue stripping `_timing` from user-facing analyst artifacts if that remains the desired report contract

Primary files:

- `src/thresher/harness/pipeline.py`
- `src/thresher/harness/report.py`

### Phase 4. Fix benchmark totals semantics

Change benchmark totals so they report named lifecycle totals rather than a single overloaded `findings_count`.

Recommended totals section:

- `raw_scanner_findings_total`
- `analyst_candidate_findings_total`
- `verified_findings_total`
- `final_findings_total`

If a single summary field is still needed, it should map to `final_findings_total`.

Primary files:

- `src/thresher/harness/benchmarks.py`
- `src/thresher/report/benchmarks.py`

### Phase 5. Improve markdown rendering

Update the per-stage markdown table to show full token dimensions, not just in/out.

Either:

- add separate columns for cache write and cache read

or:

- render a compact four-part token summary like `in/out/write/read`

Also ensure analyst rows are shown individually.

Primary file:

- `src/thresher/report/benchmarks.py`

### Phase 6. Fix cost accounting by actual model

Current report assumes one model for the whole run:

- `src/thresher/report/benchmarks.py:92-103`

But logs show mixed-model execution in nested work. Costing should be based on the actual model IDs recorded from the stream, not only `config.model`.

## Test Plan

### 1. Token extraction tests

Add tests covering:

- final result `usage`
- final result `modelUsage`
- assistant message usage when result usage is incomplete
- nested local-agent session usage
- duplicate event handling so totals are not double-counted

Primary test file:

- `tests/unit/test_agents_json.py`

### 2. Pipeline benchmark tests

Add tests proving:

- 8 analysts produce 8 per-analyst benchmark stages plus one aggregate `analysts` stage
- benchmark capture still works after `_timing` is stripped from user-facing findings

Primary test file:

- `tests/unit/test_pipeline.py`

### 3. Collector/report tests

Add tests proving:

- analyst totals aggregate per-analyst stages, not just the aggregate wall-clock stage
- pipeline totals report final findings correctly
- stage lifecycle counts remain distinct and are not naively summed
- markdown includes cache token data and individual analyst rows

Primary test files:

- `tests/unit/test_benchmarks.py`
- `tests/unit/test_report_benchmarks.py`

### 4. Regression fixture modeled on this run

Create a regression test shaped like `bandit-20260413-000642` asserting:

- no benchmark headline count of `731`
- final findings total is `344`
- analyst rows are listed individually
- analyst and other AI token counts come from full stream aggregation rather than only final result-line totals

## Rollout And Validation

1. Implement token parser changes first.
2. Add per-analyst benchmark stage recording.
3. Change totals semantics.
4. Update markdown and JSON rendering.
5. Run targeted unit tests.
6. Re-run the Bandit scan or replay an equivalent fixture.
7. Validate expected output:
   - all 8 analysts listed
   - analyst totals derived from analyst rows
   - final findings shown as `344`
   - no misleading `731`
   - cache token usage visible
   - token counts materially higher and more plausible for analysts, synthesize, and report_maker

## Bottom Line

Benchmarking feels hard right now because the current implementation mixes three different concerns into one flat report shape:

- per-stage timing
- per-agent token accounting
- pipeline-level finding summaries

The data is mostly already there. The fix is to stop collapsing it too early, capture the full stream usage, record each analyst individually, and make pipeline totals use explicit lifecycle semantics instead of naive sums.
