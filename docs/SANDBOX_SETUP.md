# Sandbox Setup Guide

## Prerequisites

- Linux with systemd (no macOS/Windows support for sandbox mode)
- OpenClaw installed (`~/.openclaw/` exists with a valid `openclaw.json`)
- Root access (sandbox creation requires `CAP_SYS_ADMIN`)
- `openshell-sandbox` binary (auto-installed if missing)

## Step 1: Initialize

```bash
sudo defenseclaw sandbox init
```

What happens:

1. Checks that `openshell-sandbox` is installed; downloads from NVIDIA if not
2. Installs `iptables` if missing (needed for DNS and guardrail forwarding)
3. Creates the `sandbox` system user and group with home at `/home/sandbox`
4. Moves the existing OpenClaw home (`~/.openclaw/`) under sandbox ownership:
   - Backs up original ownership to `openclaw-ownership-backup.json`
   - `chown -R sandbox:sandbox` on the OpenClaw directory
   - Creates a symlink from `/home/sandbox/.openclaw` to the original path
   - Sets POSIX ACLs so the sandbox user has full access
5. Creates `/home/sandbox/.defenseclaw/`
6. Installs the DefenseClaw plugin into `~/.openclaw/extensions/defenseclaw/`
7. Copies default OpenShell policies (Rego + YAML)
8. Automatically runs `defenseclaw sandbox setup` (Step 2)

## Step 2: Configure

```bash
sudo defenseclaw sandbox setup [OPTIONS]
```

Options (all have sensible defaults):

| Flag | Default | Purpose |
|---|---|---|
| `--sandbox-ip` | `10.200.0.2` | IP inside sandbox namespace |
| `--host-ip` | `10.200.0.1` | Host-side veth IP |
| `--sandbox-home` | `/home/sandbox` | Sandbox user's home |
| `--openclaw-port` | `18789` | OpenClaw gateway port |
| `--policy` | `default` | Policy template (default/strict/permissive) |
| `--dns` | `8.8.8.8,1.1.1.1` | DNS servers for the sandbox |

What happens:

1. Validates the `sandbox` user and home directory exist
2. Writes DefenseClaw config (`~/.defenseclaw/config.yaml`):
   - `openshell.mode = "standalone"`
   - Gateway, guardrail, and watcher settings
3. Installs the selected policy template
4. Generates `sandbox-resolv.conf` with the configured DNS servers
5. Patches the sandbox-side `openclaw.json`:
   - Sets gateway port, bind mode, and guardrail baseUrl to point at the host IP
6. Generates systemd unit files → `<data_dir>/systemd/`
7. Generates launcher scripts → `<data_dir>/scripts/`
8. Pre-pairs the sidecar's Ed25519 device key into the sandbox's `paired.json`
9. Detects and stores the gateway auth token
10. Installs the CodeGuard skill into the sandbox
11. Installs/updates the DefenseClaw plugin and registers it in `openclaw.json`
12. Fixes file ownership and directory ACLs
13. Copies units to `/etc/systemd/system/` and scripts to `/usr/local/lib/defenseclaw/`
14. Runs `systemctl daemon-reload`
15. Generates `run-sandbox.sh` for non-systemd environments

## Step 3: Start

```bash
sudo systemctl start defenseclaw-sandbox.target
```

Or without systemd:

```bash
sudo /path/to/data_dir/scripts/run-sandbox.sh
```

This starts the sandbox service, which:
1. Runs `pre-sandbox.sh` — cleans orphan namespaces, fixes ACLs
2. Runs `start-sandbox.sh` — bind-mounts resolv.conf, launches `openshell-sandbox`
3. Runs `post-sandbox.sh` — waits for veth pair, injects iptables rules for
   DNS, sidecar API, and guardrail forwarding

## Step 4: Enable on Boot (optional)

```bash
sudo systemctl enable defenseclaw-sandbox.target
```

## Restart Behavior

The sandbox service uses `Restart=always` with a 30-second delay
(`RestartSec=30`) capped at 2 minutes (`RestartMaxDelaySec=120`). It restarts
on any exit — crash or clean shutdown. Only `systemctl stop` prevents restart.
