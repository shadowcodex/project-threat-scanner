{PR_URL}


# Security Remediation Summary

Based on automated security scan findings from [Thresher](https://thresher.sh) (scan date: {SCAN_DATE}), this PR resolves **{CRITICAL_COUNT} Critical**, **{HIGH_COUNT} High**, and **{MEDIUM_COUNT} Medium** severity findings — including dependency vulnerabilities, application-level security bugs, CI/CD hardening, and secrets remediation.

## Dependency Upgrades ({DEP_UPGRADE_COUNT} packages)

{DEPENDENCY_UPGRADE_NOTES}

| Package | Previous | Minimum Fixed | Severity | CVEs |
|---------|----------|---------------|----------|:----:|
| {PACKAGE_ROWS} |

## Application Security Fixes

### Critical

- **{TITLE}** — `{FILE_PATH}` — {DESCRIPTION}

### High

- **{TITLE}** — `{FILE_PATH}` — {DESCRIPTION}

### Medium

- **{TITLE}** — `{FILE_PATH}` — {DESCRIPTION}

## Secrets Remediation

- **Fixed:** {SECRET_DESCRIPTION}
- **Requires follow-up:** {FOLLOWUP_NOTES}

## GitHub Actions Hardening

- {CI_CD_FIX_DESCRIPTION}

## Scan Context

- **Scanner:** [Thresher](https://thresher.sh) multi-tool security scan (grype, trivy, osv-scanner, semgrep, gitleaks, checkov) + 8 AI security analysts
- **Total findings:** {DETERMINISTIC_COUNT} deterministic + {AI_COUNT} AI analyst findings
- **Malicious code detected:** {MALICIOUS_CODE_DETECTED}
- **CISA KEV entries:** {KEV_COUNT}

## Known Remaining Items (not addressed in this PR)

These were flagged by AI analysts but require deeper architectural changes or stakeholder decisions:

- {REMAINING_ITEM}
