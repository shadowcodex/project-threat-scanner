# Getting Started

## Prerequisites

| Requirement | How to Install |
|------------|----------------|
| macOS with Apple Silicon | (M1/M2/M3/M4) |
| Python 3.11+ | `brew install python@3.12` |
| Lima | `brew install lima` |
| tmux (optional) | `brew install tmux` |
| Anthropic API key or Claude login (optional) | For AI analysis — not needed with `--skip-ai` |

## Installation

### From source (recommended)

```bash
git clone https://github.com/<owner>/project-threat-scanner.git
cd project-threat-scanner
pip install -e .
```

### With uv (no install needed)

```bash
git clone https://github.com/<owner>/project-threat-scanner.git
cd project-threat-scanner
uv run threat-scan --help
```

## Configuration

### API Key Setup

For AI-powered analysis, provide your Anthropic API key via environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Alternatively, if you have Claude Code installed and logged in (`claude login`), the tool reads your OAuth token from the macOS Keychain automatically. `ANTHROPIC_API_KEY` takes precedence if both are available.

### Configuration File

Copy the example config to customize defaults:

```bash
cp scanner.toml.example scanner.toml
```

Edit `scanner.toml`:

```toml
model = "sonnet"              # Claude model for AI agents
depth = 2                     # Transitive dependency depth
output_dir = "./scan-results" # Where reports go
log_dir = "./logs"            # Where logs go
tmux = true                   # Split-pane UI

[vm]
cpus = 4                      # VM CPU count
memory = 8                    # VM memory in GiB
disk = 50                     # VM disk in GiB
```

CLI flags override config file values. Environment variables override both for credentials.

## First Scan

### Quick scan (no AI, no API key needed)

```bash
threat-scan https://github.com/owner/repo --skip-ai
```

### Full scan with AI analysis

```bash
threat-scan https://github.com/owner/repo
```

### Pre-build the base VM (speeds up future scans)

```bash
threat-scan-build
```

This provisions the base VM with all scanner tools and databases. Subsequent scans reuse this base image instead of provisioning from scratch.

## What Happens During a Scan

1. **VM startup** — Creates or reuses a Lima VM (~2-5 minutes on first run, seconds on reuse)
2. **Provisioning** — Installs 16 scanner tools, Docker, language runtimes (~10-15 minutes on first build)
3. **Clone** — Clones the target repository inside the VM
4. **Dependencies** — Detects ecosystems and downloads dependency source code in Docker containers
5. **Scanning** — Runs all scanners in parallel (~2-10 minutes depending on repo size)
6. **AI analysis** — Two Claude agents investigate the code (~3-8 minutes, skipped with `--skip-ai`)
7. **Reporting** — Enriches findings with EPSS/KEV data and generates the report
8. **Cleanup** — Destroys the ephemeral VM

## CLI Reference

### `threat-scan` — Run a scan

```bash
threat-scan <repo-url> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 2 | Transitive dependency depth |
| `--skip-ai` | off | Deterministic scanners only (no AI agents) |
| `--verbose` | off | Show detailed tool output |
| `--output DIR` | `./scan-results` | Host directory for report output |
| `--cpus N` | 4 | VM CPU count |
| `--memory N` | 8 | VM memory in GiB |
| `--disk N` | 50 | VM disk in GiB |
| `--no-tmux` | off | Disable tmux split-pane UI |

### `threat-scan-build` — Pre-build base VM

```bash
threat-scan-build [--cpus N] [--memory N] [--disk N]
```

Provisions a reusable base VM with all tools pre-installed.

### `threat-scan-stop` — Stop all VMs

```bash
threat-scan-stop
```

Force-stops and deletes all scanner VMs. Use this if a scan crashed and left VMs running.

## Tmux UI

By default, scans launch in a tmux split-pane layout: scan progress on the left, live logs on the right.

| Key | Action |
|-----|--------|
| `Ctrl-b h` | Switch to left pane (scan) |
| `Ctrl-b l` | Switch to right pane (logs) |
| `Ctrl-b z` | Zoom current pane full-screen (toggle) |
| `Ctrl-b [` | Scroll mode (`q` to exit) |
| `Ctrl-b q` | Quit — kills scan and closes tmux |

Disable with `--no-tmux` or `tmux = false` in `scanner.toml`.

## Reading the Output

Reports land in `<output-dir>/<repo-name>-<timestamp>/`:

| File | What It Contains |
|------|------------------|
| `executive-summary.md` | GO / CAUTION / DO NOT USE recommendation with top findings |
| `detailed-report.md` | All findings grouped by priority with remediation guidance |
| `findings.json` | Machine-readable findings with CVSS, EPSS, KEV, and AI scores |
| `sbom.json` | CycloneDX software bill of materials |
| `scan-results/` | Raw output from each scanner (JSON files) |

See [Scoring and Reports](scoring-and-reports.md) for details on priority computation and report structure.

## Disk Usage

The base VM requires about **15 GiB** of disk space for tools and databases. With the default 50 GiB disk, you'll have roughly 35 GiB available for the target repo, dependencies, and scan results. Adjust with `--disk` if scanning large repositories.

## Troubleshooting

### VM won't start

```bash
# Check Lima status
limactl list

# Force-stop all scanner VMs
threat-scan-stop

# Delete stale VMs manually
limactl delete --force scanner-base
```

### Scan hangs

Check if the VM is responsive:

```bash
limactl shell scanner-base -- echo "alive"
```

If not, force-stop and retry:

```bash
threat-scan-stop
threat-scan <repo-url>
```

### Out of disk space in VM

Increase the disk size:

```bash
# Rebuild base with more disk
threat-scan-stop
threat-scan-build --disk 100
```

### API key issues

Verify your key is set:

```bash
echo $ANTHROPIC_API_KEY
```

Or check that `claude login` has a valid session. The tool will error clearly if AI analysis is requested but no credentials are available.
