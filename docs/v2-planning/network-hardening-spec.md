# Network Hardening Spec

Hardens the VM's network isolation so that even if malware executes inside the VM, it cannot modify egress controls or escape to unauthorized destinations.

## Problem

The current egress firewall (`vm_scripts/firewall.sh`) uses iptables inside the VM with an OUTPUT DROP policy and a whitelist of approved domains. This works, but the scan user likely has `NOPASSWD: ALL` sudo access (standard in Lima VMs), which means malware running as the scan user can:

1. `sudo iptables -F` — flush all firewall rules
2. `sudo ip link` / `sudo ifconfig` — manipulate network interfaces
3. `sudo` anything else — full root access

The iptables rules are only as strong as the privilege boundary protecting them.

## Solution: Three-Layer Defense

### Layer 1: Sudoers Lockdown

After provisioning completes, restrict the scan user's sudo access to only the commands required for scanning.

**Where**: End of `vm_scripts/provision.sh` (or a new `vm_scripts/lockdown.sh` executed after provisioning and firewall setup).

**What the scan user needs sudo for**:

| Command | Why |
|---------|-----|
| `docker run` | Dependency downloads run in Docker containers |
| `docker ps` | Container status checks |
| `docker rm` | Container cleanup |

**What gets denied**: Everything else, including `iptables`, `ip`, `ifconfig`, `ufw`, `route`, `systemctl`, `apt`, `dpkg`, shell escapes.

**Implementation**:

```bash
# /etc/sudoers.d/scanner-lockdown
# Allow only Docker commands for the scan user
scanner ALL=(ALL) NOPASSWD: /usr/bin/docker
scanner ALL=(ALL) !NOPASSWD: ALL
```

**Ordering**: This file must be written AFTER all provisioning and firewall setup is complete, since those scripts use `sudo` extensively. The lockdown is the final step before scanning begins.

**Important**: The lockdown applies to the scan user only. The provisioning runs as root (via sudo before lockdown), so the base image build is unaffected.

### Layer 2: Lima hostResolver (Host-Side DNS Control)

Lima's `hostResolver` runs a DNS server on the **host machine** that resolves names for the VM. The VM cannot tamper with it.

**Where**: `lima/scanner.yaml`

**Current config**:
```yaml
hostResolver:
  enabled: null  # defaults to true
```

**New config**:
```yaml
hostResolver:
  enabled: true
  hosts:
    # Only approved domains resolve. The host resolver handles these
    # lookups using the host's native DNS, running outside the VM.
    # Malware inside the VM cannot modify these mappings.
    api.anthropic.com: api.anthropic.com
    github.com: github.com
    api.github.com: api.github.com
    pypi.org: pypi.org
    files.pythonhosted.org: files.pythonhosted.org
    registry.npmjs.org: registry.npmjs.org
    crates.io: crates.io
    static.crates.io: static.crates.io
    proxy.golang.org: proxy.golang.org
    api.first.org: api.first.org
    services.nvd.nist.gov: services.nvd.nist.gov
    toolbox-data.anchore.io: toolbox-data.anchore.io
    grype.anchore.io: grype.anchore.io
    api.osv.dev: api.osv.dev
    semgrep.dev: semgrep.dev
    metrics.semgrep.dev: metrics.semgrep.dev
    ghcr.io: ghcr.io
    pkg-containers.githubusercontent.com: pkg-containers.githubusercontent.com
    vuln.go.dev: vuln.go.dev
    database.clamav.net: database.clamav.net
```

**Note on hostResolver.hosts behavior**: The `hosts` map in Lima's hostResolver defines static name-to-address mappings served by the host-side DNS. The exact filtering behavior (whether unlisted domains still resolve via passthrough or are blocked) needs to be validated during implementation. If `hostResolver` passes through unlisted domains to upstream DNS, this layer serves as a known-good resolution source but does NOT block arbitrary domain lookups on its own — iptables remains the enforcement layer. See [Open Questions](#open-questions).

### Layer 3: Tightened iptables (DNS Pinning to hostResolver)

Modify the firewall rules so the VM can ONLY use the Lima hostResolver for DNS — no external DNS servers.

**Where**: `vm_scripts/firewall.sh`

**Current DNS rules**:
```bash
# Allows DNS to ANY destination
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
```

**New DNS rules**:
```bash
# Lima hostResolver runs on the host gateway (192.168.5.2 for user-mode,
# or the vzNAT gateway). Only allow DNS to that address.
HOST_GW="192.168.5.2"  # Lima's host.lima.internal

sudo iptables -A OUTPUT -p udp --dport 53 -d "$HOST_GW" -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -d "$HOST_GW" -j ACCEPT
# Block DNS to all other destinations (caught by default DROP policy,
# but explicit rule for logging)
sudo iptables -A OUTPUT -p udp --dport 53 -j LOG --log-prefix "BLOCKED_DNS: " --log-level 4
sudo iptables -A OUTPUT -p udp --dport 53 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 53 -j LOG --log-prefix "BLOCKED_DNS: " --log-level 4
sudo iptables -A OUTPUT -p tcp --dport 53 -j DROP
```

**What this prevents**: Malware cannot use an external DNS server (e.g., `8.8.8.8`) to resolve C2 domains. All DNS queries must go through the host-side resolver, which the VM cannot modify.

## How the Layers Work Together

| Attack | Layer 1 (sudoers) | Layer 2 (hostResolver) | Layer 3 (iptables) |
|--------|-------------------|----------------------|-------------------|
| `sudo iptables -F` | Blocked (no sudo for iptables) | N/A | N/A |
| Resolve C2 domain via external DNS | N/A | N/A | Blocked (DNS only to hostResolver) |
| Resolve C2 domain via hostResolver | N/A | Depends on passthrough behavior (see open questions) | Blocked (IP not in whitelist) |
| Connect to C2 by raw IP | N/A | N/A | Blocked (IP not in whitelist) |
| `sudo ip link set` to manipulate interface | Blocked (no sudo for ip) | N/A | N/A |
| Modify `/etc/resolv.conf` to use rogue DNS | N/A | Queries still go to hostResolver gateway | Blocked (DNS to non-gateway dropped) |

Even if any single layer is bypassed, the other two still hold.

## Implementation Order

The changes apply at different points in the lifecycle:

### Base Image Build (`threat-scan-build`)

1. `provision.sh` runs as root — installs all tools (unchanged)
2. `firewall.sh` runs as root — applies whitelist rules with tightened DNS pinning (**modified**)
3. **NEW**: `lockdown.sh` runs as root — writes `/etc/sudoers.d/scanner-lockdown` restricting scan user to Docker-only sudo
4. Base VM stopped and saved

### Scan Runtime (`threat-scan`)

1. Start base VM (firewall + sudoers already baked in)
2. Clean working directories (uses Docker, not raw sudo)
3. Clone repo, download deps (Docker containers, network ON, approved domains only)
4. Run scanners (no network needed for most, iptables allows vuln DB + API domains)
5. Run AI analysis (iptables allows `api.anthropic.com`)
6. Copy report, stop VM

### Lima YAML (`scanner.yaml`)

Updated at project level — takes effect when base image is created.

## Files Modified

| File | Change |
|------|--------|
| `lima/scanner.yaml` | Add `hostResolver` config with approved domain mappings |
| `vm_scripts/firewall.sh` | Pin DNS to Lima hostResolver gateway, block external DNS |
| `vm_scripts/lockdown.sh` (new) | Sudoers restriction — strip scan user's sudo except Docker |
| `src/threat_scanner/vm/lima.py` | Call `lockdown.sh` as final provisioning step |

## Open Questions

1. **hostResolver passthrough**: Does Lima's hostResolver pass through DNS queries for domains NOT listed in `hosts`, or does it only resolve listed entries? If it passes through, the `hosts` map is additive (not a whitelist) and iptables remains the sole egress enforcement. Need to test or read Lima source to confirm.

2. **Lima host gateway IP**: The gateway IP (`192.168.5.2` for user-mode networking) may differ depending on network mode. If we switch to `vzNAT: true`, the gateway address changes. The firewall script should detect the gateway dynamically rather than hardcoding it.

3. **Docker sudo scope**: The sudoers rule `NOPASSWD: /usr/bin/docker` allows arbitrary Docker commands, including `docker run --privileged` or `docker run --network=host`. Consider restricting to specific Docker subcommands or using Docker's `--userns-remap` to limit container privileges.

4. **Base VM reuse**: The sudoers lockdown is baked into the base image. If a future provisioning change requires broader sudo, the base must be rebuilt. This is acceptable since `threat-scan-build` already handles full rebuilds.

## Testing

1. **Sudoers**: SSH into a locked-down VM, verify `sudo iptables -L` is denied, verify `sudo docker ps` works
2. **DNS pinning**: From inside the VM, verify `dig @8.8.8.8 evil.com` is blocked, verify `dig api.anthropic.com` resolves
3. **Egress**: Verify `curl https://api.anthropic.com` succeeds, verify `curl https://evil.com` fails
4. **Full scan**: Run a complete scan against a known-good repo, confirm all scanners and AI analysis still work
5. **Attack simulation**: Place a script in a test repo that attempts `sudo iptables -F`, verify it fails and the scan completes normally
