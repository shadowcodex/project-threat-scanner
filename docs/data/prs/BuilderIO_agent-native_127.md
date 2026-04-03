https://github.com/BuilderIO/agent-native/pull/127


# Security Remediation Summary

Based on automated security scan findings from [Thresher](https://thresher.sh) (scan date: 2026-04-02), this PR resolves **2 Critical**, **28 High**, and **5 Medium** severity findings across the monorepo — including dependency vulnerabilities, application-level security bugs, CI/CD hardening, and a committed secret.

## Dependency Upgrades (13 packages)

All vulnerable transitive dependencies were pinned to secure versions via `pnpm.overrides` in the root and all 5 template `package.json` files. All 6 lockfiles (root + templates) were regenerated.

| Package | Previous | Minimum Fixed | Severity | CVEs |
|---------|----------|---------------|----------|:----:|
| **rollup** | 4.46.2 | 4.59.0 | **Critical (9.8)** | CVE-2026-27606 |
| multer | 2.0.2 | 2.1.1 | High (8.7) | CVE-2026-3520, CVE-2026-2359 |
| minimatch | 9.0.5 | 9.0.7 | High (8.7) | CVE-2026-26996, CVE-2026-27903, CVE-2026-27904 |
| hono | 4.12.1 | 4.12.4 | High (8.2) | GHSA-xh87-mx6m-69f3, GHSA-q5qw-h33p-qvwr |
| lodash | 4.17.21 | 4.18.0 | High (8.1) | CVE-2026-4800 |
| @remix-run/router | 1.23.0 | 1.23.2 | High (8.0) | CVE-2026-22029 |
| undici | 7.23.0 | 7.24.0 | High (7.5) | CVE-2026-2229, CVE-2026-1528, CVE-2026-1526 |
| node-forge | 1.3.3 | 1.4.0 | High (7.5) | CVE-2026-33895, CVE-2026-33894 |
| path-to-regexp | 8.2.0 / 8.3.0 | 8.4.0 | High (7.5) | CVE-2026-4926 |
| picomatch | 2.3.1 / 3.0.1 / 4.0.3 | 4.0.4 | High (7.5) | CVE-2026-33671 |
| fast-xml-parser | 5.5.3 | 5.5.6 | High (7.5) | CVE-2026-33036 |
| glob | 10.4.5 | 10.5.0 | High (7.5) | CVE-2025-64756 |
| @anthropic-ai/sdk | 0.80.0 | 0.81.0 | Medium (6.3) | CVE-2026-34451 |

## Application Security Fixes

### Critical

- **IDOR: Missing ownership check on resource PUT/DELETE** — `packages/core/src/resources/handlers.ts` — Any authenticated user could overwrite or delete any other user's resources. Added ownership verification against session email before allowing modifications.

### High

- **Path traversal via `startsWith()` bypass** — `templates/analytics/server/handlers/ai-instructions.ts` — `.builder/../../.env` passed the prefix check. Replaced with `path.resolve()` + resolved prefix comparison.
- **Stored XSS via regex HTML sanitizer bypass** — `templates/calendar/app/lib/sanitize-description.ts` — Regex sanitizer missed `javascript:` URIs, unquoted event handlers, SVG XSS. Replaced with an allowlist-based sanitizer (safe tags, safe attributes, URL scheme validation).
- **SQL injection via raw SELECT passthrough** — `templates/analytics/server/handlers/sql-query.ts` — DML keyword blocklist was bypassable via `ATTACH DATABASE`, `PRAGMA`, `LOAD_EXTENSION`. Added those keywords + `DETACH`, `VACUUM`, `REINDEX` to the blocklist, and added statement-stacking prevention.
- **OAuth CSRF via hardcoded fallback signing key** — `packages/core/src/server/google-oauth.ts` — State HMAC fell back to the publicly known string `'oauth-state-key'`. Removed fallback; now throws if `GOOGLE_CLIENT_SECRET` is absent.
- **`NODE_ENV=test` fully disabled authentication** — `packages/core/src/server/auth.ts` — `isDevMode()` included `'test'` which silently bypassed all auth. Removed `'test'` from the check.
- **User-controlled RegExp ReDoS** — `templates/calendar/server/handlers/bookings.ts` — `new RegExp(field.pattern)` from user input with no complexity bound. Added pattern length limit (200 chars).
- **PTY resize: unvalidated integers to native FFI** — `packages/core/src/terminal/pty-server.ts` — WebSocket-supplied values passed directly to C++ node-pty `resize()`. Added `Number.isFinite()` check and clamping to 1–65535 range.
- **Rate limiting bypass via X-Forwarded-For spoofing** — `packages/core/src/server/auth.ts` — Rate limiter keyed on attacker-controlled header. Now uses actual socket `remoteAddress`, only falling back to `X-Forwarded-For` when the connection is from a loopback address.

### Medium

- **CORS wildcard on all API endpoints** — `packages/core/src/server/create-server.ts` — `Access-Control-Allow-Origin: *` on all routes. Now supports `CORS_ALLOWED_ORIGINS` env var for production allowlisting, with dynamic origin echo and `Vary: Origin`.
- **Session token exposure in URL** — `packages/core/src/server/auth.ts` — Added `Referrer-Policy: no-referrer` header when `_session` query parameter is used, preventing token leakage via Referer headers.
- **Wildcard postMessage + missing origin validation** — `packages/core/src/client/agent-chat.ts` and `harness.ts` — Replaced `postMessage(payload, "*")` with targeted origin (`getHarnessOrigin()` or `window.location.origin`). Added origin validation on incoming message listeners. Secured the `harnessOrigin` trust anchor to only accept from `window.parent` and only set once.
- **`dangerouslySetInnerHTML` without sanitization** — `templates/issues/` — `IssueDescription.tsx` and `IssueComments.tsx` rendered `adfToHtml()` output without sanitization. Added allowlist-based HTML sanitizer.

## Secrets Remediation

- **Fixed:** Hardcoded Brandfetch API key removed from `templates/slides/scripts/fetch-logos.ts` and replaced with `BRANDFETCH_API_KEY` environment variable.
- **Requires follow-up:** The exposed key should be rotated since it exists in git history.
- 4 other gitleaks findings were triaged as false positives (Builder.io public CDN key, GA4 env var key names).

## GitHub Actions Hardening

- Added top-level `permissions` blocks to `ci.yml` (read-only), `publish.yml` (empty default), and `desktop-release.yml` (contents: write) — enforcing least-privilege.
- Fixed 4 shell injection vectors in `publish.yml` and `desktop-release.yml` by replacing direct `${{ inputs.* }}` interpolation in `run:` steps with environment variables.

## Scan Context

- **Scanner:** [Thresher](https://thresher.sh) multi-tool security scan (grype, trivy, osv-scanner, semgrep, gitleaks, checkov) + 8 AI security analysts
- **Total findings:** 518 deterministic + 44 AI analyst findings
- **No malicious code or supply chain compromise detected** — both automated scanners and AI analysis agree
- **No CISA KEV entries** — none of the vulnerabilities are known to be actively exploited

## Known Remaining Items (not addressed in this PR)

These were flagged by AI analysts but require deeper architectural changes or stakeholder decisions:

- **Unpinned GitHub Actions** — Actions pinned to mutable tags (`@v4`) rather than commit SHAs; supply chain risk
- **Empty-password keychain** in desktop-release.yml for Apple code-signing
- **Dynamic `npx --yes` execution at runtime** — CLI fallback downloads packages without integrity checks
- **JWT decoded without signature verification** — `templates/analytics/app/lib/track-metric.ts` — client-side only, for metric attribution
- **No SECURITY.md or release tags** — project governance improvements
- **A2A middleware non-timing-safe token comparison** — `packages/core/src/a2a/middleware.ts`
