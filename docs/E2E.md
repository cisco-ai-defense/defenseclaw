# Self-Hosted E2E CI — Setup Guide

Full-stack end-to-end tests for DefenseClaw running on a persistent AWS EC2 instance with a GitHub Actions self-hosted runner. Every push to `main` or `demo` triggers a nuke-and-rebuild of DefenseClaw while OpenClaw persists.

## Architecture

```
GitHub push  ──►  .github/workflows/e2e.yml
                        │
                        ▼  runs-on: self-hosted
               ┌──────────────────────────────────────┐
               │  AWS EC2 t3.small (Ubuntu 24.04)     │
               │                                       │
               │  OpenClaw Gateway       :18789        │
               │  DefenseClaw Sidecar    :18970        │
               │  Guardrail Proxy        :4000         │
               │  Splunk Docker          :8000/:8088   │
               │  Tailscale              100.x.y.z     │
               └──────────────────────────────────────┘
                        │
                        ▼
               Telegram Bot API  (api.telegram.org)
               Splunk O11y Cloud (optional)
```

## Prerequisites

The EC2 instance needs the following installed. All commands assume Ubuntu 24.04.

| Dependency | Version | Purpose |
|------------|---------|---------|
| Go | 1.25+ | Build DefenseClaw gateway |
| Node.js | 20+ | Build TypeScript plugin |
| Python | 3.12+ | CLI, E2E scripts |
| uv | latest | Python package management |
| Docker | 24+ | Splunk container |
| jq | any | JSON parsing in shell scripts |
| Tailscale | latest | Private mesh network access |

## EC2 Setup

### 1. Launch Instance

- **AMI**: Ubuntu 24.04 LTS (`ami-*` — latest from Canonical)
- **Type**: `t3.small` (2 vCPU, 2 GB RAM)
- **Storage**: 20 GB gp3 EBS
- **Security Group**: SSH restricted to your IP only. No other inbound rules needed — the GitHub Actions runner communicates outbound-only, and Tailscale handles private access.
- **IAM Role**: Attach a role with `bedrock:InvokeModel` permission for LLM access (no API keys needed).

### 2. Install System Dependencies

```bash
# Go
wget -q https://go.dev/dl/go1.25.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.2.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Python + uv
sudo apt-get install -y python3.12 python3.12-venv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Docker
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker

# jq
sudo apt-get install -y jq

# Ensure ~/.local/bin is on PATH
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### 3. Install and Join Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Note your Tailscale IP (`tailscale ip -4`) — you'll use it to access services from your laptop.

On your laptop (macOS):

```bash
brew install tailscale
tailscale up
```

### 4. Register GitHub Actions Runner

Follow [GitHub's self-hosted runner docs](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners) or use the steps below.

```bash
mkdir ~/actions-runner && cd ~/actions-runner
curl -o actions-runner-linux-x64-2.322.0.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.322.0/actions-runner-linux-x64-2.322.0.tar.gz
tar xzf actions-runner-linux-x64-2.322.0.tar.gz

# Configure (get the token from repo Settings > Actions > Runners > New self-hosted runner)
./config.sh --url https://github.com/YOUR_ORG/defenseclaw --token YOUR_TOKEN

# Install and start as systemd service
sudo ./svc.sh install
sudo ./svc.sh start
```

### 5. Add GitHub Secrets

Go to **repo Settings > Secrets and variables > Actions** and add:

| Secret | Required | Source |
|--------|----------|--------|
| `OPENCLAW_GATEWAY_TOKEN` | Yes | `jq -r .token ~/.openclaw/openclaw.json` on the EC2 |
| `SPLUNK_ACCESS_TOKEN` | No | Splunk O11y org settings (for cloud export) |
| `SPLUNK_REALM` | No | e.g., `us1` (for Splunk O11y cloud export) |
| `E2E_TELEGRAM_USER_SESSION` | No | See Telegram section below |

### 6. Install OpenClaw (One-Time)

OpenClaw persists across E2E runs. Install it once on the EC2:

```bash
npm install -g @openclaw/gateway
openclaw init
```

Configure your Telegram channel, agent definitions, and model settings as needed. These persist in `~/.openclaw/` and are not touched by E2E runs.

## Telegram Session Setup (One-Time)

The E2E suite includes a Telegram round-trip test that sends a message as a real Telegram user and verifies the bot responds. This requires a Telethon session string.

### Create Session String

Run this on any machine where you can authenticate with Telegram (your laptop is fine):

```bash
pip install telethon cryptg
```

```python
import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession

API_ID = 12345        # Get from https://my.telegram.org
API_HASH = "abc123"   # Get from https://my.telegram.org

async def main():
    async with TelegramClient(StringSession(), API_ID, API_HASH) as client:
        print("Session string:")
        print(client.session.save())

asyncio.run(main())
```

This will prompt you to log in with your phone number and 2FA code. Copy the resulting session string and store it as the `E2E_TELEGRAM_USER_SESSION` GitHub secret.

**Important**: Use a dedicated test Telegram account, not your personal account. The session string grants full access to the account.

### Required Environment Variables for Telegram Test

The Telegram test also needs `E2E_TELEGRAM_API_ID`, `E2E_TELEGRAM_API_HASH`, and `E2E_TELEGRAM_BOT_USERNAME` as GitHub secrets.

## How CI Works

### What Gets Nuked Every Run

Every E2E run completely destroys and rebuilds DefenseClaw:

- `~/.defenseclaw/` — config, `.env`, policies, audit DB, quarantine, Splunk bridge
- `~/.local/bin/defenseclaw-gateway` — gateway binary
- `~/.openclaw/extensions/defenseclaw/` — TypeScript plugin

Then from the checked-out commit:

1. `make install` builds and installs CLI + gateway + plugin
2. `defenseclaw init` recreates config, DB schema, default policies
3. Secrets are injected into the fresh `.env`

### What Persists

OpenClaw is the only stateful thing:

- OpenClaw install (`npm global`)
- `~/.openclaw/openclaw.json` (config + token)
- `auth-profiles.json` + `models.json`
- Device pairing (`paired.json`)
- Telegram channel login

### Test Phases

| Phase | What It Tests |
|-------|--------------|
| 1. Start stack | OpenClaw gateway + DefenseClaw sidecar startup |
| 2. Health assertions | `/health` JSON, `/status` WebSocket handshake, Telegram channel |
| 3. Agent round-trip | Sidecar -> gateway -> guardrail proxy -> LLM -> back |
| 4. Telegram round-trip | Telegram -> OpenClaw -> guardrail -> LLM -> Telegram |
| 5. Splunk assertions | HEC ingest, event count, guardrail audit events |
| 6. Teardown | Stop services, print summary |

## Accessing Services via Tailscale

Once both your laptop and the EC2 are on the same tailnet, access everything directly:

| URL | Service |
|-----|---------|
| `http://100.x.y.z:8000` | Splunk dashboards (admin / `DefenseClawLocalMode1!`) |
| `http://100.x.y.z:18789` | OpenClaw web UI |
| `http://100.x.y.z:18970/health` | DefenseClaw sidecar health |
| `ssh ubuntu@100.x.y.z` | Shell access |

The Splunk container stays running after E2E tests complete so you can browse dashboards at any time.

## Running E2E Locally

### Via GitHub (workflow_dispatch)

Go to **Actions > E2E > Run workflow** in the GitHub UI. Select the branch and click "Run workflow".

### Directly on the EC2

```bash
cd ~/actions-runner/_work/defenseclaw/defenseclaw
git pull
make install
defenseclaw init --enable-guardrail --yes
scripts/test-e2e-full-stack.sh
```

## Splunk Observability Cloud (Optional)

For persistent cloud-based traces/metrics beyond the local Docker Splunk:

1. Add `SPLUNK_ACCESS_TOKEN` and `SPLUNK_REALM` to GitHub Actions secrets
2. The workflow injects them into `~/.defenseclaw/.env`
3. DefenseClaw's OTEL exporter sends traces and metrics to Splunk O11y
4. Gives you a permanent view of E2E telemetry even when the Docker container is down

## Cost

| Item | Cost |
|------|------|
| EC2 t3.small (always-on) | ~$15/month |
| EBS gp3 20 GB | ~$1.60/month |
| Tailscale (personal) | Free |
| Splunk Docker (local) | Free |
| LLM (Bedrock Haiku, 2-3 prompts/run) | ~$0.01/run |
| Telegram Bot API | Free |

**Tip**: Add a CloudWatch alarm + Lambda to stop the instance after 2 hours of idle CPU, and a second Lambda on the GitHub webhook to start it on push.

## Troubleshooting

### Runner Shows Offline

```bash
# On EC2
sudo systemctl status actions.runner.*
sudo systemctl restart actions.runner.*
```

### Telegram Session Expired

Telegram revokes sessions after extended inactivity (~months). Re-create the session string using the Python snippet above and update the `E2E_TELEGRAM_USER_SESSION` secret.

### Splunk Container Won't Start

```bash
docker logs splunk-claw-bridge-ci-splunk-1
# Common: port conflict — check if another Splunk container is running
docker ps -a --filter name=splunk
docker compose -f bundles/splunk_local_bridge/compose/docker-compose.ci.yml down -v
```

### DefenseClaw Health Check Fails

```bash
# Check if sidecar is actually running
pgrep -f defenseclaw-gateway
# Check logs
tail -50 ~/.defenseclaw/gateway.log
# Check if OpenClaw gateway is running
pgrep -f "openclaw gateway"
```

### OpenClaw Gateway Won't Start

```bash
# Check if already running
pgrep -f "openclaw gateway"
# Check token
jq .token ~/.openclaw/openclaw.json
# Restart manually
openclaw gateway stop
openclaw gateway --force
```
