# backport: pre-v8 gateway, netguard, and plugin fixes

## Summary

Backports three commits from `main` to the release branch that landed after the branch cut (Jul 13) but before the v8 config overhaul (Jul 16+). None of these carry v8 dependencies.

### 1. Allow operator-configured private upstream IPs (`7544f615`)

Operators running on-prem LLM gateways behind private IPs were blocked by DefenseClaw's SSRF protection. Adds:

- New config field `guardrail.allow_private_upstreams` + env var `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS`
- IP-only allowlist (no CIDR) — forces explicit per-endpoint trust
- Loopback, link-local, and cloud metadata IPs are always denied regardless of allowlist
- Applied at both pre-flight and dial-time checks to prevent DNS rebinding bypass
- Audit event emitted with `reason="private-ip-allowed"` for SOC visibility

### 2. Preserve `extra_content` on streaming tool calls — Gemini `thought_signature` (`9af85c6b`)

Gemini multi-turn tool calls were failing with "missing thought_signature" when traffic flowed through the DC guardrail proxy. Fixes:

- Bumps bifrost/core to v1.7.3 which carries `ExtraContent` on stream deltas and tool calls
- Adds `ExtraContent` field to `ChatMessage` so `thought_signature` passes through the proxy
- Adds `extractExtraParams` to forward `extra_body` (e.g. `google.thinking_config`) to upstream providers via Bifrost

### 3. Plugin egress bypass fixes + test hardening (`603a8cec`)

Three fixes squashed together:

- **Layer 1 shape detection for `http.request`** — Newer OpenClaw versions switched from `globalThis.fetch` to `http.request` for local LLM proxy calls, bypassing the guardrail entirely on non-Ollama ports. Added `hasLLMPathSuffix` detection to `patchedHttpRequest` to match `patchedHttpsRequest` behavior.
- **Close LLM egress bypass — shared state + undici dispatcher** — `LLM_DOMAINS`/`OLLAMA_PORTS` were module-scoped `let` variables causing state splits across V8 contexts, and undici's global dispatcher was unpatched. Fixed by moving state to `globalThis[Symbol.for()]` shared slot, adding idempotent install guards, and intercepting undici's dispatcher.
- **Windows agent version test fix** — Hostile `package.json` fixture was only written to the npm-global candidate path; bun/yarn candidates overwrote the expected failure reason. Now writes to all candidate paths.

## Conflict resolution

`agent_version_windows_test.go` did not exist on the release branch (introduced via the release-26.8.4 forward-port). Resolved by accepting the file as new.

## Test plan

- [ ] `go build ./...` succeeds on the release branch
- [ ] Gateway unit tests pass (`go test ./internal/gateway/...`)
- [ ] Netguard allowlist tests pass (`go test ./internal/netguard/...`)
- [ ] Plugin extension builds and fetch-interceptor tests pass
- [ ] Gemini streaming tool calls with `thought_signature` work through the proxy
- [ ] Private upstream IP allowlisting works with on-prem LLM endpoints
