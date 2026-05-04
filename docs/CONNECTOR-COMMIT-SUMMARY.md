# Connector Architecture v3 — Executive Summary

**Branch**: `feature/connector-architecture-v3`
**Date**: 2026-04-24

---

## Problem

DefenseClaw's guardrail proxy was hardcoded to work only with OpenClaw. Every authentication check, request signal extraction, hook script, and telemetry label assumed a single agent framework. Supporting additional frameworks (Claude Code, Codex, ZeptoClaw, Cursor, OpenCode) required duplicating proxy logic for each one, creating a maintenance and security burden that would grow linearly with each new integration.

Additionally, a code review of the existing connector package uncovered 18 findings — including two critical bugs that could silently break hook teardown and registration — that needed to be addressed before the architecture could be trusted in production.

---

## What Changed

### 1. Pluggable Connector Architecture

DefenseClaw now has a **Connector interface** — a contract that any agent framework adapter implements. Each connector owns five responsibilities for its agent: authentication, LLM traffic routing, tool call inspection mode, subprocess enforcement policy, and setup/teardown lifecycle.

Four built-in connectors ship with this release:
- **OpenClaw** — fetch interceptor plugin (existing, now behind the interface)
- **ZeptoClaw** — `api_base` redirect with `before_tool` hook
- **Claude Code** — environment variable override with PreToolUse/PostToolUse hook scripts
- **Codex** — environment variable override with hook scripts and response scanning

A **connector registry** manages built-in and external connectors. External connectors can be loaded as Go plugin `.so` files from a configurable directory, enabling third-party or enterprise-specific integrations without modifying DefenseClaw core.

### 2. Hook Event Handlers

Two new gateway-level hook handlers process agent lifecycle events:

- **Claude Code hook handler** — Receives events from Claude Code's hook system (PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, Stop, etc.) and dispatches them through the inspection pipeline. In `mode=action`, dangerous tool calls and prompt injections are blocked before execution. In `mode=observe`, findings are logged without blocking.

- **Codex hook handler** — Same capability adapted for the Codex event model.

Both handlers support component scanning on session start, changed-file scanning on session stop, and structured responses that tell the agent whether to proceed or abort.

### 3. Inspection Pipeline Expansion

Three new inspection endpoints complement the existing `/api/v1/inspect/tool`:

- **Pre-request scan** (`/inspect/request`) — Scans user queries for prompt injection and data exfiltration patterns before they reach the LLM
- **Post-response scan** (`/inspect/response`) — Scans LLM output for secret leakage, PII, and harmful content
- **Tool output scan** (`/inspect/tool-response`) — Scans tool execution results before they're fed back to the LLM

These endpoints are called by connector hook scripts, giving every agent framework access to the same security scanning regardless of how it integrates with DefenseClaw.

### 4. Connector Prefix Routing

Agents can now route traffic through the proxy using path-based connector identification: `http://proxy:4000/c/claudecode/v1/messages`. A middleware strips the `/c/<name>/` prefix before routing, so connector-specific traffic reaches the same handlers as fetch-interceptor traffic. This enables agents like Claude Code that use `ANTHROPIC_BASE_URL` to identify themselves without custom headers.

### 5. HTTP CONNECT Tunnel Support

The proxy now handles HTTP CONNECT requests for TLS tunneling. Agents that use `http_proxy` as a forward proxy can tunnel their TLS connections through DefenseClaw. The tunnel is opaque (no decryption) but the target host is logged for audit.

### 6. Proxy Decoupling from OpenClaw

The guardrail proxy no longer contains OpenClaw-specific logic:
- Authentication is delegated to the active connector
- Gateway token configuration renamed from `OPENCLAW_GATEWAY_TOKEN` to `DEFENSECLAW_GATEWAY_TOKEN` (with backward compatibility)
- Telemetry labels use the active connector's name instead of hardcoded "openclaw"
- All OpenClaw-specific comments and variable names replaced with agent-agnostic equivalents

### 7. CLI Multi-Connector Setup

`defenseclaw setup guardrail` now supports a `--agent` flag to select the connector. In interactive mode, a numbered menu presents all available connectors with their tool inspection mode and subprocess policy. Connector-specific setup (plugin install, config patching, hook scripts, shims) is handled automatically by the connector's `Setup()` method when the gateway starts — the CLI no longer contains OpenClaw-specific installation logic.

### 8. Health and Observability

The health endpoint now reports connector state: name, tool inspection mode, subprocess policy, and atomic counters for requests, errors, tool inspections, tool blocks, and subprocess blocks. This gives operators visibility into which connector is active and how it's performing.

### 9. Bug Fixes (12 of 18 findings)

**Critical**:
- Hook teardown silently failed because `removeOwnedHooks` returned a truncated slice that the caller never received (Go interface type assertion limitation). Fixed to return the new slice with caller assignment.
- `UserPromptExpansion` was registered as a hook event but doesn't exist in Claude Code. Removed to prevent silent setup failures.

**High**:
- Non-curl subprocess shims (nc, wget, ssh, pip, npm) recursively called themselves because `curl` was also shimmed. Fixed by resolving `curl` from outside the shim directory.
- Hook scripts used `jq --argjson` on plain-text tool output, causing JSON parse errors. Changed to `--arg` which handles arbitrary strings.
- ZeptoClaw teardown permanently lost the user's original `api_base` configuration. Fixed with proper backup/restore.

**Medium**:
- Teardown deleted the entire `hooks/` directory instead of just DefenseClaw's files
- `IsLoopback` failed on IPv6 and port-suffixed addresses
- Crash-then-re-setup overwrote the clean config backup with the already-patched config
- Shared utility function was trapped in a connector-specific file
- Dead code accumulated in the OpenClaw connector

---

## Outcomes

**Multi-agent support**: DefenseClaw can now protect Claude Code, Codex, ZeptoClaw, and OpenClaw users with a single deployment. Adding a new agent framework requires implementing one Go interface — no proxy changes needed.

**Defense in depth across all surfaces**: Every agent framework gets the same four-layer inspection: prompt scanning, tool call policy enforcement, tool output scanning, and LLM response scanning. Previously only OpenClaw had full coverage.

**Extensibility**: Third-party connectors can be distributed as Go plugins and discovered at runtime without recompiling DefenseClaw.

**Reliability**: The 12 bug fixes eliminate silent failures in hook management, subprocess enforcement, and configuration lifecycle that could have left users unprotected without any visible error.

**Verified end-to-end**: 20 E2E tests pass across all four inspection surfaces (hook endpoint, inspect endpoints, LLM proxy, connector prefix routing) with `mode=action` blocking enabled.

---

## Remaining Work

Six findings from the code review require design decisions before implementation. These are tracked in `docs/CONNECTOR-REMAINING-FIXES.md`:

- **Missing hook events**: Only 8 of 22+ techspec events are registered. Needs a decision on which events to add and at what inspection depth.
- **HandleHookEvent stub**: Connector-level `HandleHookEvent` always returns "allow". Needs an architecture decision on whether inspection stays at the gateway level or moves into connectors.
- **InstallScope + FailClosed**: Config fields specified in the techspec but not yet implemented.
- **Auth header inconsistency**: `X-DC-Auth` accepts both raw tokens and `Bearer`-prefixed tokens ambiguously.
- **No file locking**: Settings.json read-modify-write has no concurrency protection.
- **Exported test globals**: Package-level test overrides are fragile under concurrent test runs.
