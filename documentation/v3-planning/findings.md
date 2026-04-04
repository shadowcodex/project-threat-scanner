# Scan Run Findings — cli-20260403-231415

**Target:** `@googleworkspace/cli` (googleworkspace/cli)
**Date:** 2026-04-03
**Total runtime:** ~34 minutes (23:14:15 → 23:48:21)
**Logs:** /Users/josephduncan/github/thresher/logs/cli-20260403-231415/scan.log
**Report:** /Users/josephduncan/github/thresher/thresher-reports/cli-20260403-231415

This document captures issues observed in thresher's behavior during this scan run.
Findings are about **our software**, not the scanned repo.

---

## P0 — Pre-dep Agent Failed to Produce Output

The pre-dependency discovery agent ran for ~3 minutes but produced no usable output.

**What happened:**
- Stop hook fired: `"No response found in stop hook input"` (line 206)
- Parser warning: `"Could not parse predep agent output"` (line 213)
- Result: `0 hidden dependencies found` — but the agent clearly ran and explored files
- Multiple downstream analysts flagged this gap: _"pre-dep agent crashed before producing valid output: files_scanned=0"_

**Impact:** The entire hidden-dependency discovery stage was lost. Analysts had to work without pre-dep context. The synthesis report explicitly called this out as reducing confidence in the overall assessment.

**Root cause hypothesis:** The predep agent likely produced its output in a format the stop hook didn't recognize, or the agent hit its turn/token limit before writing the JSON output file. The stop hook validation (`validate_predep_output.sh`) rejected the response, but the agent didn't retry successfully.

**Fix areas:**
- Investigate stop hook validation — is it too strict or rejecting valid partial output?
- Add a fallback: if the stop hook rejects output N times, capture whatever the agent produced and surface it as degraded rather than empty
- Consider structured output enforcement (e.g., tool-use JSON mode) rather than relying on stop hook validation
- Log the actual agent response that was rejected, not just "No response found"

---

## P0 — Adversarial Agent Did 10 Minutes of Excellent Work, All Discarded (Schema Mismatch)

The adversarial verification stage reviewed 26 findings over ~10 minutes (23:29:45 → 23:40:08), confirmed 6, downgraded 20 — but the saved output shows `total_reviewed: 0, confirmed_count: 0, downgraded_count: 0`. All work was silently lost.

**What the agent actually did (visible in logs):**
- Read all 8 analyst findings files, extracted 26 high-risk findings (threshold ≥ 4 worked correctly)
- Launched parallel subagents to web-search for CVE verification, GHSL-2021-192, clawhub npm legitimacy, picomatch advisories, and pull_request_target documentation
- Read the actual workflow files, auth source code, and sheets.rs to verify findings
- **Correctly identified GHSL-2021-192 as not a real advisory** — searched multiple times, found no matching GHSL number, noted it was a _class_ reference not a specific advisory
- **Correctly downgraded pull_request_target finding** — verified that no job checks out PR head code, labeler uses only metadata, making the current config safe (though the permission scope is still overly broad)
- **Confirmed OAuth CSRF** as genuine (2 independent reports)
- **Confirmed TOFU binary checksum** issue (2 independent reports)
- **Confirmed missing validate_resource_name** in sheets.rs
- **Confirmed mutable git tag** for cross build tool
- **Downgraded clawhub** — confirmed it's a legitimate npm package, npm prevents version republishing
- **Downgraded picomatch** severity — real CVEs but confined to dev toolchain with no prod attack surface
- Produced a complete JSON with all 26 verdicts, confidence scores, and web research citations

**How the work was lost — the schema mismatch bug:**

1. The stop hook (`validate_analyst_output.sh`) is shared between analyst agents and the adversarial agent
2. The stop hook requires the `analyst` schema: `{analyst, analyst_number, core_question, findings[], summary, risk_score}`
3. The adversarial agent initially produced its natural schema: `{verification_summary, total_reviewed, confirmed_count, downgraded_count, results[]}`
4. The stop hook rejected this: `"No response found in stop hook input"`
5. The agent reformatted into the stop hook's required schema with `analyst: "defense-attorney"` and `findings[]` containing its 26 verdicts
6. The stop hook accepted this and the agent exited successfully (`is_error: false, num_turns: 18`)
7. **But on the host side**, `_parse_adversarial_output()` extracts the JSON correctly (via code block regex), then `_merge_adversarial_results()` does `verification.get("results", [])` — which returns `[]` because the key is `findings`, not `results`
8. Similarly, `verification.get("verification_summary", "")` returns `""` because the key is `summary`, and `verification.get("total_reviewed", 0)` returns `0` because that key doesn't exist in the stop-hook schema
9. Result: `adversarial_verification: {total_reviewed: 0, confirmed_count: 0, downgraded_count: 0}` — all zeros

**The `confirmed=?, downgraded=?` in the log** is because the parsed dict has neither `confirmed_count` nor `downgraded_count` keys — they don't exist in the analyst schema the stop hook forced.

**Impact:** The entire adversarial verification layer — a core differentiator for thresher — was effectively nullified. 10 minutes of compute, 18 turns of Claude, genuine security insights (GHSL-2021-192 false positive, clawhub legitimacy verification, pull_request_target safety analysis) — all silently discarded. The synthesis report had to work without adversarial input, and all High findings went unverified.

**Root cause:** Two schemas in collision — the stop hook enforces one, the host parser expects another.

**Fix areas:**
1. **Immediate:** Give the adversarial agent its own stop hook (`validate_adversarial_output.sh`) that expects the adversarial schema (`results[]`, `verification_summary`, `total_reviewed`, `confirmed_count`, `downgraded_count`), or disable the stop hook for the adversarial agent entirely
2. **Defensive:** Add schema detection in `_parse_adversarial_output` — if it finds `findings[]` with `verdict` keys instead of `results[]`, map the schema: rename `findings` → `results`, `summary` → `verification_summary`, count confirmed/downgraded from verdicts
3. **Logging:** When `confirmed=?` and `downgraded=?`, log the actual keys present in the parsed dict so the mismatch is immediately visible
4. **Testing:** Add a test case that passes stop-hook-formatted adversarial output through `_parse_adversarial_output` → `_merge_adversarial_results` and asserts non-zero counts

---

## P1 — SSH Mux Contention During Parallel Scanner Launch

When 20 scanners launch simultaneously, SSH multiplexing breaks down.

**What happened:**
- 7+ `"mux_client_request_session: session request failed: Session open refused by peer"` errors at 23:19:38
- Followed immediately by 7+ `"ControlSocket /Users/.../.lima/thresher-base/ssh.sock already exists, disabling multiplexing"` warnings
- SSH falls back to non-multiplexed connections, which works but is slower and noisier

**Impact:** Functional — scanners still ran. But the mux failure cascade adds latency and fills logs with noise. In a resource-constrained VM or with more scanners, this could cause actual failures.

**Fix areas:**
- Implement connection pooling or a semaphore to limit concurrent SSH sessions
- Pre-open a pool of mux channels before launching parallel scanners
- Or use a single SSH session that dispatches commands internally (e.g., a job queue script in the VM)

---

## P2 — Dependency Download DNS Failures (npm + cargo)

The dependency resolution stage failed to download some dependencies.

**What happened:**
- npm: `getaddrinfo EAI_AGAIN registry.npmjs.org` for `@changesets/cli` and `lefthook`
- cargo: `"cargo vendor failed"`, `"failed to load pkg lockfile"`, `"failed to parse lock file at: /tmp/rust-project/Cargo.lock"`

**Impact:** GuardDog-deps ran on incomplete dependency source. The scanners that check vendored dependency code had reduced coverage. Two npm dev-dependencies and all Rust crate sources were not available for source-level scanning.

**Root cause hypothesis:** The VM's DNS resolution or network access was intermittent during the dependency download phase. The npm packages that failed (`@changesets/cli`, `lefthook`) are devDependencies. The cargo vendor failure seems related to a missing or malformed lockfile at `/tmp/rust-project/Cargo.lock` (possibly the workspace structure wasn't properly handled).

**Fix areas:**
- Add retry logic with exponential backoff for dependency downloads
- Log DNS resolution diagnostics before starting downloads (is the resolver working?)
- Handle Rust workspace layouts properly — the `Cargo.lock` at the workspace root needs to be used, not a `/tmp` copy
- Surface dependency download failures more prominently — currently buried as INFO-level log lines from ssh output
- Consider making partial dependency download a warning in the final report

---

## P2 — guarddog-deps Output is Malformed JSON

The `guarddog-deps.json` file contains concatenated JSON objects instead of a valid JSON document.

**What happened:**
- Output file contains: `[]` on line 1, followed by 3 concatenated JSON objects (one per deps directory scanned: hidden/, node/, rust/)
- No array wrapper, no newline-delimited JSON — just raw concatenation
- Python's `json.load()` raises `JSONDecodeError: Extra data`

**Impact:** Any downstream consumer that tries to parse this file with a standard JSON parser will fail. The synthesis agent may have worked around this by reading raw text, but it's brittle.

**Fix areas:**
- Fix the guarddog-deps scanner module to collect results into a proper JSON array before writing
- Or use JSONL format consistently and document it

---

## P2 — capa Scanner Exit Code 2 on All Shell Scripts

capa exited with code 2 for every shell script in the target repo.

**What happened:**
- `capa exited with code 2 for /opt/target/scripts/coverage.sh`
- Same for `show-art.sh`, `tag-release.sh`, `version-sync.sh`
- Final: `Scanner capa completed (exit=2, errors=0)`

**Impact:** capa produced no useful results for this scan. Exit code 2 typically means "unsupported file format" for capa. Shell scripts aren't PE/ELF binaries, so capa can't analyze them.

**Fix areas:**
- Don't run capa on shell scripts — filter to only binary files (ELF, PE, Mach-O) and compiled outputs
- If the target repo has no binaries, skip capa entirely and log why
- The `errors=0` in the completion log is misleading — exit code 2 IS an error condition for capa

**Additionally:** The safe_io layer removed `capa.json._opt_target_scripts_*.sh` files during report copy — suggesting capa created per-file output with mangled filenames (dots replacing path separators). This naming convention should be fixed or the files should be consolidated.

---

## P2 — safe_io Filtered Out report.html

During the report copy from VM to host, `safe_io` removed `report.html`.

**What happened:**
- `"Removing unexpected file type from VM output: report.html"` (line 13841)

**Impact:** If the synthesis agent generated an HTML report (which is a v3 goal per notes.md), it was discarded by the safety boundary. Users don't get the HTML report.

**Fix areas:**
- Add `.html` to the allowed file types in `ssh_copy_from_safe()` if HTML reports are a supported output
- Or generate HTML on the host side after the safe copy

---

## P3 — API Token Visible in Log Lines

The OAuth token (`sk-ant-oat01-...`) appears in multiple log lines where `printf` commands write credentials to tmpfs.

**What happened:**
- Lines 35, 348-355: `printf '%s' 'sk-ant-oat01-jcFmoz--NSDpe6FVE...'` visible in logs
- This happens for both the predep agent (1 token) and all 8 analyst agents (8 tokens)

**Impact:** Anyone with access to the scan log can extract the API token. The token may be short-lived (OAuth), but it's still a credential leak.

**Fix areas:**
- Redact credential values from ssh command logging — log the command structure but mask the printf payload
- Or suppress logging of the credential-writing ssh_exec calls entirely
- The tmpfs pattern is correct for in-VM handling; the leak is in the host-side log

---

## P3 — scancode Exit Code 1

scancode completed with exit=1 but errors=0.

**What happened:**
- `Scanner scancode completed (exit=1, errors=0)` (line 322)
- No additional error context logged

**Impact:** Unclear whether scancode produced partial results or none. Exit code 1 for scancode can mean "findings found" (like grep) or "error." Without more context, we can't tell.

**Fix areas:**
- Log scancode's stderr or at least its output file size when exit code is non-zero
- Document which scanners use exit=1 to mean "findings found" vs "error" and handle accordingly

---

## P3 — Analyst Timing Variance (3m → 9m)

The 8 analyst agents had significant runtime variance.

**Timeline:**
| Analyst | Start | End | Duration |
|---------|-------|-----|----------|
| analyst-3-investigator | 23:20:12 | 23:23:05 | ~3m |
| analyst-7-infra-auditor | 23:20:12 | 23:23:34 | ~3.5m |
| analyst-6-pentester-memory | 23:20:12 | 23:24:23 | ~4m |
| analyst-1-paranoid | 23:20:12 | 23:25:04 | ~5m |
| analyst-4-pentester-vulns | 23:20:12 | 23:25:12 | ~5m |
| analyst-5-pentester-appsurface | 23:20:12 | 23:25:50 | ~5.5m |
| analyst-8-shadowcatcher | 23:20:12 | 23:28:29 | ~8m |
| analyst-2-behaviorist | 23:20:12 | 23:29:44 | ~9.5m |

**Impact:** The slowest analyst (behaviorist at 9.5m) gates the entire pipeline. All other analysts finished 3-6 minutes earlier.

**Fix areas:**
- Track and report per-analyst token usage and tool calls to understand why some take 3x longer
- Consider adding a max-turns or max-duration limit per analyst with graceful early termination
- The behaviorist and shadowcatcher prompts may need tuning to reduce scope
- This data supports the benchmarking goals already noted in notes.md

---

## P3 — deps-dev and registry-meta Scanners Produced Empty Results

Both scanners ran successfully but checked 0 packages.

**What happened:**
- deps-dev: `{"packages_checked": 0, "findings": [], "total": 0}`
- registry-meta: `{"packages_checked": 0, "findings": [], "total": 0}`

**Impact:** These scanners exist to check dependency metadata (publish dates, maintainer changes, etc.) but scanned nothing. Either the dependency manifest wasn't available when they ran, or they don't support the package ecosystems present (npm/cargo).

**Fix areas:**
- Verify these scanners can find and parse the dependency manifests for npm and cargo ecosystems
- If they depend on the dependency resolution stage, ensure they run after it (and handle the case where dep resolution partially failed)

---

## P2 — Shared Stop Hook Between Analyst and Adversarial Agents

The adversarial agent uses the same `validate_analyst_output.sh` stop hook as the analyst agents, forcing it into the wrong output schema.

**What happened:**
- The stop hook at `/opt/thresher/bin/validate_analyst_output.sh` enforces the analyst schema: `{analyst, analyst_number, core_question, findings[], summary, risk_score}`
- The `.claude/settings.local.json` injected into the VM applies to ALL Claude Code invocations, including the adversarial agent
- The adversarial agent's natural output schema is different: `{verification_summary, total_reviewed, confirmed_count, downgraded_count, results[]}`
- The stop hook rejected the adversarial agent's first attempt at output, forcing it to reformat into the analyst schema
- This reformatted output then couldn't be parsed by the host-side adversarial parser (see P0 finding above)

**Additionally:** At least one analyst (shadowcatcher, Finding 23 in its output) detected and flagged `settings.local.json` as a suspicious untracked file — the scanner harness's own stop hook was treated as a finding. The adversarial agent also noted it: `"File content: {\"hooks\": {\"Stop\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"/opt/thresher/bin/validate_analyst_output.sh\"...}]}]}}"` and correctly downgraded it (confidence 97%) as the scanner harness itself.

**Fix areas:**
- Create a separate stop hook for the adversarial agent (`validate_adversarial_output.sh`) with its own schema
- Or use separate `.claude/settings.local.json` files per agent type
- Consider `.gitignore`-ing or hiding `settings.local.json` from analysts so they don't waste time analyzing it

---

## P3 — Adversarial Agent Wasted Tokens on Duplicate Findings

The adversarial agent received 26 findings but many were duplicates of the same issue from different analysts.

**What happened:**
- picomatch CVEs were reported 6+ times across analysts (all saying the same thing)
- pull_request_target was reported 3 times
- clawhub concerns reported 3 times
- OAuth CSRF reported 2 times
- The adversarial agent spent tokens re-verifying each duplicate independently

**Impact:** The adversarial agent spent ~10 minutes on 26 findings when there were really ~12 unique issues. Token waste and runtime could be cut significantly.

**Fix areas:**
- Deduplicate findings before passing to the adversarial agent — group by file_path + title similarity and send one representative per cluster
- Or give the adversarial agent a deduplication step as the first task before verification
- This would reduce the 26 findings to ~12, potentially cutting adversarial runtime in half

---

## Positive Observations

Things that worked well and should be preserved:

1. **Report synthesis quality is excellent** — The synthesis agent correctly elevated 4 findings from Low to High with well-reasoned justifications, correctly identified false positives, and produced clear dedup logic. The 60→25 finding dedup was handled transparently.

2. **Multi-analyst convergence** — Multiple independent analysts arriving at the same findings (e.g., the picomatch CVE, workflow permissions, OAuth CSRF) provides strong confidence. The synthesis agent leveraged this well.

3. **Scanner coverage breadth** — 20 scanners ran and 17 produced results. The combination of traditional scanners + AI analysts caught things neither would find alone (scanners found CVEs, AI found logic issues like the OAuth CSRF).

4. **Trust boundary held** — safe_io correctly filtered unexpected file types. No data leaked through the boundary inappropriately.

5. **False positive handling** — The AI analysts correctly downgraded the gitleaks private key (truncated test fixture) and semgrep OAuth tokens, preventing alert fatigue.

6. **Adversarial agent quality (when it works)** — Despite its output being lost, the adversarial agent's work visible in logs was excellent: it correctly identified GHSL-2021-192 as not a real advisory (searched multiple databases, couldn't find it), verified clawhub is legitimate via npm registry lookup, confirmed 6 genuine findings with reasoning, and downgraded 20 with high-confidence evidence. The quality justifies investing in fixing the schema mismatch — this layer adds real value when its output is preserved.

7. **Analyst-5 (pentester-appsurface) strongest findings** — With risk_score=5 (highest among analysts), it independently found the OAuth CSRF (92% confidence), TOFU binary checksum issue (80%), and the sheets.rs validation gap (75%). The adversarial agent confirmed all three of these as genuine. This analyst persona appears to be the most effective at finding real application-level vulnerabilities.
