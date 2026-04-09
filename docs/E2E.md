# Self-Hosted E2E CI — Setup Guide

Full-stack end-to-end tests for DefenseClaw run on a persistent AWS EC2 instance with a GitHub Actions self-hosted runner. DefenseClaw is rebuilt from scratch on every run. OpenClaw persists and is treated as the long-lived control plane.

## Architecture

```text
GitHub Actions  ──►  .github/workflows/e2e.yml
                           │
                           ├─ core
                           │    push / pull_request / workflow_dispatch
                           │
                           └─ full-live
                                workflow_dispatch / schedule / same-repo pull_request

                                   runs-on: [self-hosted, Linux, ARM64, e2e]
                                                │
                                                ▼
                             ┌──────────────────────────────────────┐
                             │ AWS EC2 runner (Ubuntu 24.04)       │
                             │                                      │
                             │ OpenClaw Gateway       :18789        │
                             │ DefenseClaw Sidecar    :18970        │
                             │ Guardrail Proxy        :4000         │
                             │ Splunk Docker          :8000/:8088   │
                             └──────────────────────────────────────┘
                                                │
                                                ▼
                            ClawHub / Anthropic / Splunk / OpenClaw
```

## Profiles

| Profile | Triggers | Purpose |
|---------|----------|---------|
| `core` | `push`, `pull_request`, `workflow_dispatch` | Deterministic PR-safe path: scanners, enforcement, watcher, CodeGuard, status, AIBOM, policy, skill API, Splunk verification |
| `full-live` | `workflow_dispatch`, `schedule`, same-repo `pull_request` | Agent-first path: live guardrail, real OpenClaw agent actions, plugin lifecycle, recovery, and run-scoped Splunk proof |

## Prerequisites

The EC2 instance needs the following installed. Commands below assume Ubuntu 24.04.

| Dependency | Version | Purpose |
|------------|---------|---------|
| Go | 1.25+ | Build DefenseClaw gateway |
| Node.js | 20+ | Build TypeScript plugin |
| Python | 3.12+ | CLI, tests, E2E helpers |
| uv | latest | Python package management |
| Docker | 24+ | Splunk container |
| jq | any | JSON parsing in shell scripts |
| gh | latest | GitHub CLI for local workflow debugging |

## EC2 Setup

### 1. Launch Instance

- **AMI**: Ubuntu 24.04 LTS
- **Type**: `t4g.small` or larger recommended for ARM64 runner stability
- **Storage**: 20 GB gp3 or larger
- **Security Group**: no inbound required for Actions itself. If you want shell access, add temporary `22/tcp` ingress restricted to your current public IP.
- **IAM Role**: optional for Bedrock-backed OpenClaw usage, but current live guardrail E2E is driven by Anthropic API key auth.

### 2. Install System Dependencies

```bash
# Go
wget -q https://go.dev/dl/go1.25.2.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.25.2.linux-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Python + uv + jq
sudo apt-get install -y python3.12 python3.12-venv jq
curl -LsSf https://astral.sh/uv/install.sh | sh

# Docker
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker

# GitHub CLI
type -p curl >/dev/null || sudo apt-get install -y curl
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
  sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | \
  sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
sudo apt-get update
sudo apt-get install -y gh

# Ensure ~/.local/bin is on PATH
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### 3. Register GitHub Actions Runner

Follow [GitHub's self-hosted runner docs](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners) or use the steps below.

```bash
mkdir ~/actions-runner && cd ~/actions-runner
curl -o actions-runner-linux-arm64-2.322.0.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.322.0/actions-runner-linux-arm64-2.322.0.tar.gz
tar xzf actions-runner-linux-arm64-2.322.0.tar.gz

# Configure
./config.sh --url https://github.com/YOUR_ORG/defenseclaw --token YOUR_TOKEN --labels e2e

# Install and start as systemd service
sudo ./svc.sh install
sudo ./svc.sh start
```

### 4. Install OpenClaw Once

OpenClaw persists across E2E runs. Install it once on the EC2:

```bash
npm install -g @openclaw/gateway
openclaw init
```

DefenseClaw watches both OpenClaw skill locations during E2E runs:

- `~/.openclaw/workspace/skills`
- `~/.openclaw/skills`

### 5. Add GitHub Secrets

Go to **Settings > Secrets and variables > Actions** and add:

| Secret | Required | Source |
|--------|----------|--------|
| `OPENCLAW_GATEWAY_TOKEN` | Yes | `jq -r .token ~/.openclaw/openclaw.json` on the runner |
| `ANTHROPIC_API_KEY` | Yes for `full-live` | Anthropic console |
| `OPENAI_API_KEY` | No | Only needed if you later add OpenAI-backed live checks |
| `SPLUNK_ACCESS_TOKEN` | No | Splunk Observability Cloud |
| `SPLUNK_REALM` | No | Splunk Observability Cloud realm |

## What Gets Reset Every Run

Every E2E run rebuilds DefenseClaw from scratch:

- `~/.defenseclaw/`
- `~/.local/bin/defenseclaw-gateway`
- `~/.openclaw/extensions/defenseclaw*`
- run-scoped temp skills, plugins, and quarantine artifacts

Then the workflow:

1. runs `make install`
2. runs `defenseclaw init`
3. writes fresh secrets into `~/.defenseclaw/.env`
4. configures scanners and Splunk
5. runs unit, TypeScript, Rego, and E2E coverage

## What Persists

OpenClaw remains persistent across runs:

- global OpenClaw install
- `~/.openclaw/openclaw.json`
- auth profiles and device pairing
- non-test skills and plugins

The `full-live` job temporarily rewrites the active OpenClaw model to `anthropic/claude-sonnet-4-5` so guardrail coverage is deterministic, then restores the original config in cleanup.

## Test Coverage

### `core`

`core` runs:

- stack bootstrap and subsystem health
- skill scanner
- deterministic MCP fixture scanning
- skill, MCP, and tool block/allow
- quarantine and restore
- watcher auto-scan
- CodeGuard
- `defenseclaw status`
- `defenseclaw doctor`
- `defenseclaw aibom scan`
- `defenseclaw policy list` and `policy test`
- skill disable/enable API
- run-scoped Splunk verification

### `full-live`

`full-live` runs everything in `core` plus:

- live Anthropic guardrail round-trip
- real OpenClaw agent ping
- agent-driven skill install and cleanup
- agent-driven tool enforcement
- plugin lifecycle
- gateway and sidecar recovery
- live run-scoped Splunk verification for guardrail, agent, plugin, and reconnect events

## Test Phases

| Phase | Coverage |
|------|----------|
| 1 | Start stack |
| 2 | Health assertions |
| 3 | Skill scanner |
| 4 | MCP scanner |
| 4B | Block/allow enforcement |
| 5 | Quarantine |
| 5B | Watcher auto-scan |
| 5C | CodeGuard |
| 5D | Status + doctor |
| 5E | AIBOM |
| 5F | Policy |
| 5G | Skill API |
| 6 | Guardrail (`full-live`) |
| 7 | Agent chat (`full-live`) |
| 7B | Plugin lifecycle (`full-live`) |
| 7C | Recovery (`full-live`) |
| 8 | Splunk verification |
| 9 | Teardown |

## Accessing the Runner

### SSH

If SSH is enabled for your IP, connect directly:

```bash
ssh -i /path/to/openclaw.pem ubuntu@EC2_PUBLIC_IP
```

### SSH Port Forwarding

To access services from your laptop without exposing extra inbound ports:

```bash
ssh -i /path/to/openclaw.pem \
  -L 8000:127.0.0.1:8000 \
  -L 18789:127.0.0.1:18789 \
  -L 18970:127.0.0.1:18970 \
  ubuntu@EC2_PUBLIC_IP
```

Then use:

| URL | Service |
|-----|---------|
| `http://127.0.0.1:8000` | Splunk dashboards |
| `http://127.0.0.1:18789` | OpenClaw gateway |
| `http://127.0.0.1:18970/health` | DefenseClaw health |

### SSM

If you prefer no SSH ingress, AWS SSM works fine for runner maintenance and debugging.

## Running E2E Manually

### From GitHub

Use **Actions > E2E > Run workflow** and select the branch.

### On the Runner

```bash
cd ~/actions-runner/_work/defenseclaw/defenseclaw
git pull
make install
defenseclaw init
bash scripts/test-e2e-full-stack.sh
```

Useful overrides:

```bash
export E2E_PROFILE=core
export DEFENSECLAW_RUN_ID=manual-$(date +%s)
export E2E_TEST_PREFIX=e2e-manual-$(date +%s)
```

## Splunk Observability Cloud

Optional cloud export is still supported through `SPLUNK_ACCESS_TOKEN` and `SPLUNK_REALM`. Local Docker Splunk remains the default proof path for CI.

## Cost

| Item | Cost |
|------|------|
| EC2 ARM64 small instance | roughly `$15-20/month` always-on |
| EBS gp3 20 GB | roughly `$1-2/month` |
| Splunk local Docker | free |
| Anthropic live guardrail calls | low per-run usage |

## Troubleshooting

### Runner Offline

```bash
sudo systemctl status actions.runner.*
sudo systemctl restart actions.runner.*
```

### Splunk Container Won't Start

```bash
docker ps -a --filter name=splunk
docker logs "$(docker ps -aq --filter name=splunk | head -1)"
docker compose -f bundles/splunk_local_bridge/compose/docker-compose.ci.yml down -v
```

### DefenseClaw Health Check Fails

```bash
defenseclaw-gateway status
tail -50 ~/.defenseclaw/gateway.log
pgrep -f "openclaw gateway"
```

### OpenClaw Gateway Won't Start

```bash
jq .token ~/.openclaw/openclaw.json
openclaw gateway stop
openclaw gateway --force
```

### Guardrail Fails in `full-live`

Check:

- `ANTHROPIC_API_KEY` is present in repo secrets
- the job restored and repatched `~/.openclaw/openclaw.json` correctly
- `~/.defenseclaw/config.yaml` has `guardrail.enabled: true`
