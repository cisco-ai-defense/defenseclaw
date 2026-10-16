# DefenseClaw Shield — OS-Level Agent Security POC

**Zero connectors. Zero TLS termination. Zero CA certificates. Works on any agent.**

Shield intercepts LLM API calls at the SSL library level using dynamic library
interposition (macOS `DYLD_INSERT_LIBRARIES`, Windows Detours, Linux `LD_PRELOAD`).
It reads plaintext before encryption and after decryption — the TLS connection to
the LLM provider is completely untouched.

## Architecture

```
Agent process (Claude Code, Codex, Cursor, python, anything)
    │
    │ calls SSL_write(plaintext)
    │
    ▼
┌──────────────────────────────────────────────┐
│ Interposition Library (injected into process) │
│                                               │
│ Hooks SSL_write / SSL_read at the C level    │
│ Reads plaintext BEFORE encryption            │
│ Sends to shield daemon via Unix socket / pipe │
│ Gets verdict: ALLOW or BLOCK                  │
│ If BLOCK: SSL_write returns -1 (EPERM)       │
│ If ALLOW: SSL_write proceeds normally         │
└────────────────┬─────────────────────────────┘
                 │ IPC (Unix socket / named pipe)
                 ▼
┌──────────────────────────────────────────────┐
│ Shield Daemon (Go)                            │
│                                               │
│ 1. Identify: is destination an LLM provider? │
│ 2. Inspect: secrets, PII, injection, exfil   │
│ 3. Enforce: allow / block / log              │
│ 4. Discover: which PID / agent is calling    │
│ 5. Audit: JSON log of every LLM interaction  │
└──────────────────────────────────────────────┘
```

## Quick Start (macOS)

```bash
# Build everything
cd internal/shield && make all-darwin

# Terminal 1: start daemon
~/.defenseclaw-shield/defenseclaw-shield start

# Terminal 2: run any agent with protection
~/.defenseclaw-shield/defenseclaw-shield run -- claude "fix the bug"
~/.defenseclaw-shield/defenseclaw-shield run -- python3 my_agent.py
~/.defenseclaw-shield/defenseclaw-shield run -- codex "write tests"

# Check audit log
cat ~/.defenseclaw-shield/audit.jsonl | jq .
```

## Quick Start (Windows)

```powershell
# Build daemon
go build -o %USERPROFILE%\.defenseclaw-shield\defenseclaw-shield.exe .\cmd\defenseclaw-shield

# Build hook DLL (requires MSVC + Detours)
cl /LD /DUSE_DETOURS internal\shield\interpose\windows\shield_hook.c ^
   /I<detours_include> /link detours.lib ws2_32.lib
copy shield_hook.dll %USERPROFILE%\.defenseclaw-shield\

# Terminal 1: start daemon
%USERPROFILE%\.defenseclaw-shield\defenseclaw-shield.exe start

# Terminal 2: run agent with protection
%USERPROFILE%\.defenseclaw-shield\defenseclaw-shield.exe run -- claude "fix the bug"
```

## What Gets Intercepted

Only traffic to known LLM provider domains:

| Provider | Domains |
|----------|---------|
| Anthropic | api.anthropic.com |
| OpenAI | api.openai.com |
| Google | generativelanguage.googleapis.com |
| Azure OpenAI | *.openai.azure.com |
| AWS Bedrock | *.bedrock-runtime.amazonaws.com |
| Mistral | api.mistral.ai |
| Cohere | api.cohere.com |
| Groq | api.groq.com |
| Ollama | localhost:11434 |
| ... | and more |

All other traffic (GitHub, npm, pip, Slack, etc.) passes through untouched
with zero overhead.

## Security Checks

| Category | Rules | Severity |
|----------|-------|----------|
| Secrets | AWS keys, GitHub tokens, API keys, private keys, JWTs, connection strings | HIGH-CRITICAL |
| PII | SSN, credit cards, phone numbers, bulk email addresses | MEDIUM-HIGH |
| Injection | Prompt injection, role override, jailbreak, delimiter injection | MEDIUM-CRITICAL |
| Exfiltration | /etc/passwd, SSH keys, env dumping, webhook exfil, cloud metadata | HIGH-CRITICAL |
| Commands | Destructive commands, reverse shells, credential dumping | HIGH-CRITICAL |

## How It Differs From DefenseClaw v1

| Aspect | v1 (connectors) | Shield (OS-level) |
|--------|-----------------|-------------------|
| Setup | `defenseclaw setup --connector X` per agent | `defenseclaw-shield run -- <any agent>` |
| New agent support | Months of connector work | Day zero |
| Agent update resilience | Hooks break | Agent updates irrelevant |
| Bypass resistance | Config overwrite, hook removal | Can't bypass — SSL_write is hooked in process memory |
| TLS termination | No (uses config patching) | No (reads plaintext before encryption) |
| CA certificate needed | No | No |

## File Structure

```
cmd/defenseclaw-shield/main.go        CLI entry point
internal/shield/
├── daemon.go                          Daemon orchestrator
├── launcher.go                        Process launcher with interposition
├── proxy/ipc.go                       IPC server (Unix socket / named pipe)
├── providers/registry.go              LLM provider domain matching
├── inspect/inspector.go               Content inspection pipeline
├── inspect/detectors.go               Secret/PII/injection/exfil detectors
├── policy/engine.go                   Policy evaluation (allow/block/log)
├── discover/process.go                PID → agent name resolution
├── audit/logger.go                    JSON audit trail
├── interpose/darwin/                  macOS dylib (C)
│   └── libshield_interpose.c
├── interpose/windows/                 Windows DLL (C)
│   └── shield_hook.c
├── Makefile                           Build system
└── README.md                          This file
```
