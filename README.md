# Project Threat Scanner

AI-powered supply chain security scanner for evaluating open source packages before adoption. Scans a target repository and its dependencies for known vulnerabilities, malicious code, secrets, and supply chain risks, then produces a static go/no-go report.

## How It Works

```
Host (macOS)
  └── Lima VM (ephemeral, firewalled)
        ├── Docker containers (dependency download sandbox)
        ├── Deterministic scanners (Syft, Grype, OSV-Scanner, Semgrep, GuardDog, Gitleaks)
        └── AI analysis agents (Claude Code headless)
              ├── Agent 1: Triage + focused code analysis
              └── Agent 2: Adversarial verification (reduce false positives)
```

1. **Isolate** -- Spins up an ephemeral Lima VM with egress firewall (whitelisted domains only). No shared folders, no port forwarding.
2. **Download** -- Detects ecosystems (Python, Node, Rust, Go) and downloads dependencies source-only inside Docker containers. No install scripts executed.
3. **Scan** -- Runs 6 deterministic scanners in parallel, producing a normalized findings set.
4. **Analyze** -- (Optional) Two Claude Code agents perform deep code analysis on high-risk files, then adversarially verify findings to reduce false positives.
5. **Report** -- Enriches findings with EPSS scores and CISA KEV status, computes composite priority, and generates a static report with a clear recommendation.
6. **Cleanup** -- Destroys the VM. Nothing persists.

## Requirements

- macOS with Apple Silicon
- [Lima](https://lima-vm.io) (`brew install lima`)
- Python 3.11+
- `ANTHROPIC_API_KEY` environment variable (unless using `--skip-ai`)

## Install

```bash
pip install -e .
```

## Usage

```bash
# Full scan with AI analysis
threat-scan https://github.com/owner/repo

# Deterministic scanners only (no API key needed, faster, cheaper)
threat-scan https://github.com/owner/repo --skip-ai

# Customize VM resources and dependency depth
threat-scan https://github.com/owner/repo --cpus 8 --memory 16 --disk 100 --depth 3

# Specify output directory
threat-scan https://github.com/owner/repo --output ./my-report
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 2 | Transitive dependency depth |
| `--skip-ai` | off | Deterministic scanners only (no AI agents) |
| `--verbose` | off | Show detailed tool output |
| `--output DIR` | `./scan-results` | Host directory for report output |
| `--cpus N` | 4 | VM CPU count |
| `--memory N` | 8 | VM memory in GiB |
| `--disk N` | 50 | VM disk in GiB |

### Configuration

Optional config file at `~/.config/threat-scanner/config.yaml`:

```yaml
default_depth: 2
model: sonnet
vm:
  cpus: 4
  memory: 8
  disk: 50
```

## Output

Reports are written to the output directory:

- `executive-summary.md` -- Go / Caution / Do Not Use recommendation with top findings
- `detailed-report.md` -- All findings grouped by priority with remediation guidance
- `findings.json` -- Machine-readable findings with CVSS, EPSS, KEV, and AI scores
- `sbom.json` -- CycloneDX SBOM of the scanned project

### Priority Levels

| Priority | Criteria |
|----------|----------|
| **P0** | In CISA KEV (actively exploited), or AI-confirmed exfiltration/backdoor |
| **Critical** | CVSS >= 9.0, EPSS > 90th percentile, or AI risk 9-10 confirmed |
| **High** | CVSS 7.0-8.9, EPSS > 75th percentile, or AI risk 7-8 |
| **Medium** | CVSS 4.0-6.9, EPSS > 50th percentile, or AI risk 4-6 |
| **Low** | Everything else |

### Recommendation Logic

- Any **P0** or **Critical** finding --> **DO NOT USE**
- **High** findings only --> **USE WITH CAUTION**
- **Medium** and below only --> **GO**

## Scanners

| Tool | Category | What It Catches |
|------|----------|-----------------|
| Syft | SBOM | Bill of materials (feeds Grype) |
| Grype | SCA | Known CVEs in dependencies |
| OSV-Scanner | SCA + MAL | CVEs and malicious package advisories |
| Semgrep | SAST | Code vulnerabilities and dangerous patterns |
| GuardDog | Supply Chain | Suspicious package behaviors (typosquatting, exfiltration) |
| Gitleaks | Secrets | Hardcoded API keys, tokens, credentials |

## Security Model

- **VM isolation**: Lima VM with `vz` backend, `--plain`, no mounts, no port forwarding
- **Egress firewall**: iptables whitelist -- only Claude API, GitHub, package registries, and vulnerability databases are reachable
- **Dependency sandbox**: Docker containers inside the VM for untrusted dependency downloads
- **Source-only downloads**: `pip download --no-binary`, `npm pack`, `cargo vendor` -- no install scripts executed
- **Ephemeral**: Fresh VM per scan, force-deleted after. No cross-contamination between scans
- **API key handling**: Passed via SSH environment variables, never written to disk

## License

MIT
