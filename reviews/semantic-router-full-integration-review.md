# PR Review: semantic-router-full-integration

**Branch:** `feature/semantic-router` → `main`
**Commit:** `9ada9411` feat(routing): full vLLM Semantic Router v0.3 integration
**Date:** 2026-08-19
**Files Changed:** 8 (3,556 insertions, 0 deletions)

---

## PR Summary

Implements Phase 1-3 of full vLLM Semantic Router v0.3 integration: expands config
types to support all 17+ signal types, 16+ selection algorithms, and 12+ plugins;
enriches the classify client to pass session/user/tools/headers/metadata context;
parses SR plugin outputs (cached responses, system prompts, RAG, compression, header
mutations, reasoning control). Includes a 4-file tech spec.

---

## PRS (PR Readiness Score)

| Persona | Score (0-5) | Weight | Weighted |
|---------|:-----------:|:------:|:--------:|
| Principal Engineer | 4 | 19 | 76 |
| DevSecOps | 4 | 19 | 76 |
| QA | 2 | 19 | 38 |
| SRE | 4 | 19 | 76 |
| Support / Operability | 4 | 6 | 24 |
| Migration / Rollout | 4 | 3 | 12 |
| Product / API Contract | 4 | 10 | 40 |
| Spec Guardian | 5 | 5 | 25 |
| **Totals** | | **100** | **367** |

**PRS = (367 / 500) × 100 = 73.4**

### Readiness: CAUTION (70-79)

### Hard Gate Check
No BLOCKERs that prevent merge, but QA flagged critical test gaps. The code is
functionally correct and production-safe (graceful degradation on all error paths),
but insufficient test coverage on new code means regressions could ship undetected.

---

## Human Hotspots (Top 3)

1. **`internal/routing/config_translate_v2.go` — zero test coverage** (1,150 lines).
   The YAML translator has no tests. Invalid configs could produce broken SR YAML
   that fails at container startup.

2. **`internal/gateway/model_router_remote.go:216-263` — plugin output conversion
   untested**. Cached responses, RAG docs, header mutations, and compressed prompts
   are parsed but never tested for malformed input.

3. **`RemoteEndpoint` config bypass** — when set, skips localhost validation,
   creating an SSRF path if config access is not controlled.

---

## Consolidated Findings

### BLOCKER
_(None that prevent merge — the code is behind a feature flag and gracefully degrades)_

### MAJOR
- **No tests for config translator v2** (1,150 lines, 0% coverage) — QA
- **No tests for plugin output parsing** (47 lines of conversion logic) — QA
- **Nil `input` panic in `Route()`** — `input.Messages` accessed without nil check — QA
- **Unvalidated `RemoteEndpoint`** — could enable SSRF in remote mode — DevSecOps
- **`CachedResponse` written directly to client** — SR-controlled bytes bypass sanitization — DevSecOps

### MINOR
- No structured logging (all `fmt.Fprintf(os.Stderr)`) — SRE, Principal
- No metrics/observability on routing decisions — SRE
- No circuit breaker for persistent SR failures — SRE
- No Docker restart policy on SR container — SRE
- No periodic health check after startup — SRE
- Global `modelRouter` var unprotected by sync primitive — Principal, SRE
- Header mutations parsed but not applied (latent risk when wired) — DevSecOps
- Request headers forwarded without allowlist filtering — DevSecOps
- Config translator has no validation pass before YAML emission — Principal, QA
- Duplicate wire types vs. public types without explanatory comment — Principal
- `RoutingConfigV2` reuses V1's `RoutingRemoteConfig` (coupling) — Principal
- No interface compliance assertion (`var _ ModelRouter = ...`) — QA
- `translateConditions` recursion has no depth limit — QA
- HTTP client not injectable (testability) — QA

### NIT
- 764-line types file could be split if it grows — Principal
- `RoutingConfigV2` currently unused (forward declaration) — Principal
- `Model` vs `RequestModel` ambiguity on `ModelRouterInput` — Principal
- Plugin type structs defined but unreferenced — Principal
- Dual default timeout (50ms in sidecar, 100ms in client) — SRE
- `IsRunning()` creates new HTTP client each call — SRE
- Docker image uses `:latest` tag — SRE
- Test ports (9999/9998) could flake — QA
- Error body logging could contain PII — DevSecOps

### PRAISE
- Graceful degradation (nil return on all errors) — all personas
- Bounded response reads (64KB limit) — DevSecOps, SRE
- Connection pooling correctly configured — SRE
- Non-blocking feedback channel with bounded buffer — SRE
- API keys never sent to SR — DevSecOps
- Atomic file write (tmp + rename) — Principal, QA
- Clean V2 suffix backward-compat strategy — Principal
- Minimal interface design (single method) — Principal
- Existing remote client tests cover 10 error scenarios — QA
- Comprehensive tech spec with 34 requirements — Spec Guardian

---

## Individual Persona Reviews

### Principal Engineer (Score: 4/5) — Good with minor issues
Well-structured feature with clean Go practices. V2 suffix strategy preserves
backward compat. Interface design is minimal and correct. Main concerns: unprotected
global var, type duplication without comments, no translator validation. Code is
consistent with existing codebase conventions.

### DevSecOps (Score: 4/5) — Solid with minor gaps
Good trust boundary design for sidecar pattern. API keys never leak to SR, response
reads bounded, localhost default endpoint. Risks: unvalidated RemoteEndpoint in
remote mode (SSRF), cached response passthrough without sanitization, latent header
injection when mutations are wired. Overall well-designed.

### QA (Score: 2/5) — Significant test gaps
1,150-line translator has zero tests. Plugin output conversion has zero tests.
Nil-input panic path exists. Types file has no validation. The existing test suite
(10 cases for remote client) is good but doesn't cover the new functionality.
Non-negotiable: add `config_translate_v2_test.go` and plugin output test cases.

### SRE (Score: 4/5) — Production-ready with operational gaps
Architecture is correct: synchronous sidecar call, strict timeout, graceful fallback.
Missing production affordances: no metrics, no circuit breaker, no restart policy,
no periodic health check, no structured logging. Acceptable for initial feature-flag
rollout; must be addressed before scale.

---

## Recommendations

### Must Fix Before Merge
1. Add nil check for `input` parameter in `Route()` (1 line fix)
2. Add basic `config_translate_v2_test.go` — at minimum test that `TranslateFullConfig`
   produces valid YAML for a representative input

### Should Fix (follow-up PR)
1. Add plugin output parsing tests (cached response, header mutations, RAG, compressed)
2. Validate `RemoteEndpoint` against an allowlist (localhost + configured hosts)
3. Add `var _ ModelRouter = (*RemoteRouterClient)(nil)` compile-time check
4. Add Prometheus histogram for routing latency + counter for fallbacks
5. Add circuit breaker (open after 5 consecutive failures, half-open after 10s)
6. Pin Docker image version instead of `:latest`

### Nice-to-Have
1. Split `routing_types.go` if it grows past 1000 lines
2. Add `sync.Once` or `atomic.Pointer` for `globalModelRouter`
3. Add header denylist for future header mutation application
4. Inject `HTTPDoer` interface for full unit test isolation
5. Add Docker `--restart=on-failure:5` to lifecycle.Start()
