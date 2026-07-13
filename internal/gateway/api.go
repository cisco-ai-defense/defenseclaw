// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// APIServer exposes a local REST API for CLI and plugin communication
// with the running sidecar.
type APIServer struct {
	health        *SidecarHealth
	client        *Client
	store         *audit.Store
	logger        *audit.Logger
	addr          string
	scannerCfg    *config.Config
	hilt          *HILTApprovalManager
	notifier      *notifier.Dispatcher
	aiDiscoveryMu sync.RWMutex
	aiDiscovery   *inventory.ContinuousDiscoveryService

	// inspectToolScanTimeout optionally overrides the synchronous
	// /api/v1/inspect/tool scan budget for this server. Runtime constructors
	// leave it at zero and therefore retain inspectScanTimeout; tests that
	// exercise policy semantics can use a larger budget so race-detector
	// scheduler latency is not mistaken for a scanner verdict.
	inspectToolScanTimeout time.Duration

	// observabilityV8Mu protects the complete process-owned runtime capability
	// set. Sidecar publishes or detaches all four seams atomically.
	observabilityV8Mu sync.RWMutex
	// observabilityV8 is process-owned by Sidecar. When present, inbound OTLP
	// admission is emitted through the canonical collection/redaction/routing
	// graph instead of the legacy audit/sink path.
	observabilityV8 sidecarRuntimeEmitter
	// observabilityV8Canary pins the generated two-span diagnostic to one
	// runtime-graph generation through export acknowledgement. It is separate
	// from log admission so partial test/runtime integrations stay explicit.
	observabilityV8Canary sidecarRuntimeCanaryEmitter
	// observabilityV8LocalOnly persists control-plane evidence through the
	// canonical collection/redaction/SQLite graph without constructing any
	// optional destination projection. It remains deliberately distinct from
	// the ordinary OTLP-ingest emitter so mandatory local evidence cannot be
	// coupled to remote delivery.
	observabilityV8LocalOnly sidecarRuntimeLocalOnlyEmitter
	// observabilityV8Lifecycle is the process-owned request-bounded generated
	// trace seam used by hook and API producers. Binding it with the other seams
	// prevents one request from selecting a different runtime generation later.
	observabilityV8Lifecycle lifecycleV8Runtime

	// cfgMu protects mutable fields in scannerCfg.Guardrail (Mode,
	// ScannerMode) which can be changed at runtime via the PATCH
	// /v1/guardrail/config endpoint while other goroutines read them.
	cfgMu sync.RWMutex

	// configReloader and configSnapshot bind API writes to the same central
	// transaction and immutable snapshot used by live enforcement. The PATCH
	// endpoint refuses to write when this coordination is unavailable.
	configReloader func(context.Context, string) error
	configSnapshot func() *config.Config
	configWriteMu  sync.Mutex

	// otlpPathTokenMu guards otlpPathTokens — the in-memory map of
	// per-source OTLP path tokens loaded from
	// ${data_dir}/hooks/.otlp-<source>.token. Reads happen on every
	// loopback OTLP request that lacks an Authorization header (i.e.
	// the path-token branch in tokenAuth), so the map is held under
	// an RWMutex to keep the hot path lock-free for readers.
	//
	// The map is populated at boot by SetOTLPPathTokens AND refreshed
	// lazily by lookupOTLPPathToken in two cases:
	//
	//  1. Cache miss for a KNOWN scope (F4 fix). Closes the
	//     boot-vs-setup race where the sidecar boots with an empty
	//     or stale map, the operator subsequently runs
	//     `defenseclaw setup geminicli` (which mints a fresh on-disk
	//     token), and the next OTLP request would otherwise 401
	//     because the in-memory snapshot hasn't been refreshed.
	//  2. Bounded secure revalidation for a HIT scope. Closes the rotation
	//     gap where an operator replaces the on-disk token (e.g.
	//     post-rotation policy or a security-incident response)
	//     while the gateway keeps running. Without this check the
	//     in-memory token wins forever and every loopback OTLP
	//     request after the rotation 401s until the gateway is
	//     restarted.
	//
	// Both refreshes are rate-limited per scope by otlpPathTokenLastStatAt
	// so a hostile or noisy caller cannot turn the auth path into a
	// per-request disk stampede. Revalidation opens and reads only the bounded
	// owner-only token file; cached requests inside the interval do no I/O.
	otlpPathTokenMu         sync.RWMutex
	otlpPathTokens          map[connector.OTLPPathTokenScope]otlpPathTokenEntry
	otlpPathTokenLastStatAt map[connector.OTLPPathTokenScope]time.Time

	hookAPITokenMu sync.RWMutex
	hookAPITokens  map[string]string

	// policyReloader, when set, is called by the /policy/reload handler
	// to atomically refresh the shared OPA engine used by the watcher.
	policyReloader func() error

	claudeCodeMu                      sync.Mutex
	claudeCodeLastComponentScan       time.Time
	codexMu                           sync.Mutex
	codexLastComponentScan            time.Time
	rawTelemetryMu                    sync.RWMutex
	rawTelemetryDedupe                *rawTelemetryDeduper
	llmPromptMu                       sync.Mutex
	llmPromptBySourceSession          map[string]string
	llmPromptBySourceSessionOrder     []string
	llmPromptBySourceSessionTurn      map[string]string
	llmPromptBySourceSessionTurnOrder []string
	hookLLMSpanPrompts                map[string]hookLLMSpanPrompt
	hookLLMSpanPromptOrder            []string
	hookLLMSpanCompleted              map[string]struct{}
	hookLLMSpanCompletedOrder         []string
	hookLLMSpanUsage                  map[string]hookLLMSpanUsage
	hookLLMSpanUsageOrder             []string
	hookLifecycleTransitions          map[string]struct{}
	hookLifecycleTransitionOrder      []string
	hookReportedCostTotals            map[string]float64
	hookReportedCostTotalOrder        []string
	hookToolInvocations               map[string][]hookToolInvocation
	hookToolInvocationOrder           []string
	hookSpawnLineageMu                sync.Mutex
	hookSpawnIntents                  map[string]hookSpawnIntent
	hookSpawnIntentOrder              []string
	hookSessionStates                 map[string]hookSessionState
	hookSessionStateOrder             []string
	hookPhaseStates                   map[string]hookPhaseState
	hookPhaseStateOrder               []string
	otlpMetricMu                      sync.Mutex
	otlpMetricCumulative              map[string]otlpCumulativePoint
	otlpMetricCumulativeOrder         []string

	// stepIdxMu guards stepIdxBySession, the per-session 1-indexed
	// turn counter used to populate audit.Event.StepIdx. A "turn" is
	// one prompt-response cycle within a session_id; all hook events
	// emitted during the same turn share one StepIdx. See
	// stepIndexForTurn for the boundary computation. Bounded on both
	// axes so a long-lived process cannot grow memory without limit:
	// maxStepIdxSessions caps the number of sessions, and
	// maxStepIdxTurnsPerSession caps the per-session turn map.
	stepIdxMu        sync.Mutex
	stepIdxBySession map[string]*sessionStepState

	connectorRegistry *connector.Registry

	// ciscoInspector calls the Cisco AI Defense /api/v1/inspect/chat
	// route from the hook lane (inspectToolPolicy +
	// inspectMessageContent). nil when no API key is configured —
	// the lane silently skips AID and falls back to the existing
	// regex + CodeGuard verdict in that case. Wired by the sidecar
	// at boot via SetCiscoInspector. Only the proxy lane held an
	// AID client historically; this field extends coverage to the
	// hook surface (Codex / Claude Code / Cursor / Windsurf /
	// Hermes / Gemini / Copilot) so MCP tool calls and tool results
	// reach AID without per-script changes.
	// Widened from *CiscoInspectClient to the Inspector interface so
	// managed_enterprise installs can inject the token-authenticated
	// *CiscoDefenseClawInspectClient instead. Callers still hold the
	// same nil-guard semantics: only assign non-nil concrete values to
	// this field (see inspector.go for the nil-interface trap).
	ciscoInspector Inspector

	// hookJudge forwards hook-lane message content (prompts + tool
	// results delivered by hook connectors) to the LLM judge — the
	// same judge instance the proxy lane uses, so a custom provider
	// configured via guardrail.judge.llm sees live hook content too.
	// nil unless guardrail.judge.enabled; wired by the sidecar at
	// boot via SetHookJudge. Per-connector gating happens in
	// hookJudgeInspect via guardrail.judge.hook_connectors.
	hookJudge *LLMJudge
	// hookJudgeSem bounds concurrent hook-lane judge executions,
	// mirroring EventRouter.judgeSem on the proxy lane. At capacity
	// the judge is skipped (fail-open to the regex/AID verdict)
	// rather than queued — a queued hook would stall the agent past
	// the hook scripts' curl --max-time budget.
	hookJudgeSem chan struct{}
}

// SetCiscoInspector wires the Cisco AI Defense client onto the API
// server. Accepts any Inspector implementation — opensource installs
// pass *CiscoInspectClient, managed_enterprise installs pass
// *CiscoDefenseClawInspectClient. Pass a nil INTERFACE (not a typed-nil
// concrete pointer) to disable the hook-lane AID call. Callers should
// only invoke this when their concrete constructor returned a non-nil
// value.
func (a *APIServer) SetCiscoInspector(c Inspector) {
	if c != nil {
		a.observabilityV8Mu.RLock()
		metricRuntime, _ := a.observabilityV8Lifecycle.(hookLifecycleMetricV8Runtime)
		a.observabilityV8Mu.RUnlock()
		c.bindObservabilityV8(metricRuntime)
	}
	a.ciscoInspector = c
}

// SetHookJudge wires the LLM judge onto the API server so the hook
// content lane (inspectMessageContent) can adjudicate prompts and
// tool results for connectors listed in
// guardrail.judge.hook_connectors. Pass nil to disable (the default
// when guardrail.judge is off).
func (a *APIServer) SetHookJudge(j *LLMJudge) {
	a.hookJudge = j
	if j != nil && a.hookJudgeSem == nil {
		a.hookJudgeSem = make(chan struct{}, maxConcurrentHookJudges)
	}
}

// otlpPathTokenEntry holds only the last securely loaded value. Once the
// bounded stat interval expires, lookupOTLPPathToken reopens and validates the
// owner-only regular file and reloads its content. File mtime is deliberately
// not trusted as identity: atomic replacement can preserve timestamps.
type otlpPathTokenEntry struct {
	token string
}

// SetOTLPPathTokens replaces the in-memory snapshot of per-source
// OTLP path-tokens. Called by the sidecar at boot once
// ${data_dir}/hooks/.otlp-<source>.token files have been minted.
//
// Passing nil clears the table — useful for tests and for operators
// that explicitly disable the scoped-token path. Passing a partial
// map (a subset of OTLPPathTokenScopes()) is supported: scopes
// missing from the map fall back to the master-token comparison in
// tokenAuth so we do not break legacy deployments.
func (a *APIServer) SetOTLPPathTokens(tokens map[connector.OTLPPathTokenScope]string) {
	a.otlpPathTokenMu.Lock()
	defer a.otlpPathTokenMu.Unlock()
	if tokens == nil {
		a.otlpPathTokens = nil
		return
	}
	cp := make(map[connector.OTLPPathTokenScope]otlpPathTokenEntry, len(tokens))
	for k, v := range tokens {
		cp[k] = otlpPathTokenEntry{token: v}
	}
	a.otlpPathTokens = cp
}

// SetHookAPITokens replaces the in-memory snapshot of connector-scoped hook
// API tokens. These tokens are narrower than gateway.token: tokenAuth accepts
// them only for the matching connector hook/notify routes.
func (a *APIServer) SetHookAPITokens(tokens map[string]string) {
	a.hookAPITokenMu.Lock()
	defer a.hookAPITokenMu.Unlock()
	if tokens == nil {
		a.hookAPITokens = nil
		return
	}
	cp := make(map[string]string, len(tokens))
	for k, v := range tokens {
		name := strings.ToLower(strings.TrimSpace(k))
		tok := strings.TrimSpace(v)
		if name != "" && tok != "" {
			cp[name] = tok
		}
	}
	a.hookAPITokens = cp
}

// otlpPathTokenStatMinInterval bounds secure file revalidation on the hot
// auth-check path. We reopen the token at most once per scope per this
// interval; in between, every request reuses the cached entry
// without any system call. 1s is short enough that a rotated token
// is picked up within the human-perceptible window (operators don't
// expect "rotate then immediately retry" to succeed without a brief
// delay) and long enough to keep the per-request cost on the hot
// path effectively free.
const otlpPathTokenStatMinInterval = 1 * time.Second

// lookupOTLPPathToken returns the per-source scoped OTLP path-token
// for *source*, or "" when no token has been provisioned for that
// source. *source* is the URL segment from
// /otlp/<source>/<token>/v1/<signal>; it is matched against the
// closed allow-list of known OTLPPathTokenScope values so an
// attacker cannot trigger a map lookup against arbitrary scopes.
//
// Three refresh triggers:
//
//   - F4 boot-race: empty in-memory map, on-disk file exists →
//     lazy load on miss.
//   - Rotation/replacement: bounded secure reload observes current content,
//     including same-mtime atomic replacement and delete+recreate.
//   - Reload error / disappearance: file removed → drop the
//     in-memory entry so the next request 401s instead of
//     authenticating a stale token forever.
//
// All three refreshes share the same per-scope validation deadline
// (otlpPathTokenLastStatAt) so a hostile or noisy caller cannot turn the auth
// path into a disk-stampede primitive. A second, independent reload deadline
// must not override a due validation and return a credential that has been
// removed from disk.
// Unknown scopes never trigger disk I/O.
func (a *APIServer) lookupOTLPPathToken(source string) string {
	scope := connector.OTLPPathTokenScope(source)

	// Fast path: read under RLock and decide whether validation is due.
	// The validation throttle (otlpPathTokenLastStatAt) is checked for
	// BOTH cache-hit and cache-miss cases — a missing token file
	// for a known scope must not turn into one file open per request,
	// or a hostile caller probing /otlp/geminicli/<random>/v1/*
	// before any operator-side setup mints the on-disk token can
	// weaponise the auth check into a per-request disk syscall.
	a.otlpPathTokenMu.RLock()
	var (
		cached       otlpPathTokenEntry
		haveCached   bool
		statDueScope bool
	)
	if a.otlpPathTokens != nil {
		cached, haveCached = a.otlpPathTokens[scope]
	}
	lastStat := a.otlpPathTokenLastStatAt[scope]
	statDueScope = lastStat.IsZero() || time.Since(lastStat) >= otlpPathTokenStatMinInterval
	a.otlpPathTokenMu.RUnlock()

	// Steady-state hot path: cached, fresh-enough, no stat due.
	if haveCached && cached.token != "" && !statDueScope {
		return cached.token
	}

	// Throttled miss path: we statted this exact scope recently
	// and the cache is still empty (or never seen). Another stat
	// inside the refractory window would return the same "no
	// file" answer, so skip the syscall entirely and serve the
	// equivalent empty result. !statDueScope implies !lastStat.IsZero(),
	// and lastStat is only populated below AFTER IsValidOTLPScope
	// passes, so this branch cannot be reached for an unknown
	// scope — keeping the closed-allow-list discipline intact.
	if !statDueScope && (!haveCached || cached.token == "") {
		return ""
	}

	if !connector.IsValidOTLPScope(scope) {
		return ""
	}
	dataDir := a.configDataDir()
	if dataDir == "" {
		// No data dir wired (early-boot / test). Return whatever
		// was set via SetOTLPPathTokens; we cannot stat the disk.
		if haveCached {
			return cached.token
		}
		return ""
	}

	a.otlpPathTokenMu.Lock()
	defer a.otlpPathTokenMu.Unlock()

	// Re-read cache after upgrading the lock — another goroutine
	// may have already done the work we were about to do.
	cached = otlpPathTokenEntry{}
	haveCached = false
	if a.otlpPathTokens != nil {
		if e, ok := a.otlpPathTokens[scope]; ok {
			cached = e
			haveCached = e.token != ""
		}
	}
	// Re-check the authoritative validation deadline after upgrading the lock.
	// Another goroutine may have securely refreshed (or revoked) this scope while
	// we waited. In that case its cache result is current and no second disk read
	// is needed. If validation is still due, no independent throttle may return a
	// cached credential before the secure load below.
	if last := a.otlpPathTokenLastStatAt[scope]; !last.IsZero() &&
		time.Since(last) < otlpPathTokenStatMinInterval {
		if haveCached {
			return cached.token
		}
		return ""
	}

	// Securely reopen and reload the file whenever the bounded stat interval
	// expires. LoadOTLPPathToken uses Lstat, rejects symlinks/non-regular files,
	// validates ownership/permissions, verifies the opened file is the same
	// inode, and validates the complete token content. This intentionally does
	// not use mtime as identity: same-mtime atomic replacement and
	// delete+recreate must rotate the cached credential.
	if a.otlpPathTokenLastStatAt == nil {
		a.otlpPathTokenLastStatAt = make(map[connector.OTLPPathTokenScope]time.Time)
	}
	a.otlpPathTokenLastStatAt[scope] = time.Now()

	tok, err := connector.LoadOTLPPathToken(dataDir, scope)
	if err != nil || tok == "" {
		// Read failed after a successful stat: race with rotation
		// rename, or unreadable file. Drop the cache so we don't
		// keep authenticating a token that can no longer be
		// verified against disk.
		if a.otlpPathTokens != nil {
			delete(a.otlpPathTokens, scope)
		}
		return ""
	}
	if a.otlpPathTokens == nil {
		a.otlpPathTokens = make(map[connector.OTLPPathTokenScope]otlpPathTokenEntry)
	}
	a.otlpPathTokens[scope] = otlpPathTokenEntry{token: tok}
	return tok
}

func (a *APIServer) hookAPITokenMatches(connectorName, presented string) bool {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	presented = strings.TrimSpace(presented)
	if name == "" || presented == "" {
		return false
	}

	dataDir := a.configDataDir()
	if dataDir == "" {
		a.hookAPITokenMu.RLock()
		cached := ""
		if a.hookAPITokens != nil {
			cached = a.hookAPITokens[name]
		}
		a.hookAPITokenMu.RUnlock()
		return cached != "" && constantTimeStringMatch(presented, cached)
	}
	tok, err := connector.LoadHookAPIToken(dataDir, name)
	if err != nil || tok == "" {
		a.hookAPITokenMu.Lock()
		if a.hookAPITokens != nil {
			delete(a.hookAPITokens, name)
		}
		a.hookAPITokenMu.Unlock()
		return false
	}
	a.hookAPITokenMu.Lock()
	if a.hookAPITokens == nil {
		a.hookAPITokens = map[string]string{}
	}
	a.hookAPITokens[name] = tok
	a.hookAPITokenMu.Unlock()
	return constantTimeStringMatch(presented, tok)
}

func (a *APIServer) hookTokenScopeForPath(path string) (string, bool) {
	if path == "/api/v1/codex/notify" {
		return "codex", true
	}
	if a.connectorRegistry != nil {
		for _, name := range a.connectorRegistry.Names() {
			conn, ok := a.connectorRegistry.Get(name)
			if !ok {
				continue
			}
			he, ok := conn.(connector.HookEndpoint)
			if ok && he.HookAPIPath() == path {
				return strings.ToLower(name), true
			}
		}
		return "", false
	}
	switch path {
	case "/api/v1/codex/hook":
		return "codex", true
	case "/api/v1/claude-code/hook":
		return "claudecode", true
	}
	return "", false
}

func (a *APIServer) SetHILTApprovalManager(m *HILTApprovalManager) {
	a.hilt = m
}

// SetAIDiscoveryService wires the continuous AI discovery service so
// the API can answer /v1/ai/* endpoints from a live store. Safe to
// call with nil — endpoint handlers short-circuit on a nil service.
func (a *APIServer) SetAIDiscoveryService(svc *inventory.ContinuousDiscoveryService) {
	if a == nil {
		return
	}
	a.aiDiscoveryMu.Lock()
	a.aiDiscovery = svc
	a.aiDiscoveryMu.Unlock()
}

// leaseAIDiscovery pins the current discovery service for one complete API
// handler. Config reload publishes the replacement with the write lock, so it
// waits for handlers using the old service/store before canceling that service
// and allowing its Run defer to close inventory.db.
func (a *APIServer) leaseAIDiscovery() (*inventory.ContinuousDiscoveryService, func()) {
	if a == nil {
		return nil, func() {}
	}
	a.aiDiscoveryMu.RLock()
	return a.aiDiscovery, a.aiDiscoveryMu.RUnlock
}

// SetNotifier wires the user-session OS notifier dispatcher used by
// the hook handlers to surface block / would-block / approval-pending
// events. Safe to call with nil — the dispatcher's methods short-
// circuit on nil so callers do not need to guard each emission site.
func (a *APIServer) SetNotifier(n *notifier.Dispatcher) {
	a.notifier = n
}

func (a *APIServer) connectorName() string {
	if a.scannerCfg != nil {
		if c := strings.TrimSpace(a.scannerCfg.Guardrail.Connector); c != "" {
			return strings.ToLower(c)
		}
		if c := strings.TrimSpace(string(a.scannerCfg.Claw.Mode)); c != "" {
			return strings.ToLower(c)
		}
	}
	return "unknown"
}

// SetPolicyReloader registers a callback that atomically reloads the
// shared OPA policy engine.  It is called by the /policy/reload handler.
func (a *APIServer) SetPolicyReloader(fn func() error) {
	a.policyReloader = fn
}

// SetConnectorRegistry attaches the connector registry so the
// /v1/connectors endpoint can list available connectors.
func (a *APIServer) SetConnectorRegistry(reg *connector.Registry) {
	a.connectorRegistry = reg
}

// hookHandlers maps connector names to their gateway-side HTTP handlers.
// connectorHookHandlerByName is the registry that lets api.go map a
// connector name to the http.HandlerFunc that owns its hook endpoint.
// Plan C1 / S2.4: registration is data-driven so adding a new
// connector no longer requires editing the switch in
// registerConnectorHookRoutes; the gateway package populates this
// map in api.go's init() (see the bottom of this file).
//
// The handler bodies still live in the gateway package because they
// reach into APIServer state (logger, otel, config, redactor). The
// HookEndpoint interface in the connector package supplies the path;
// the map below supplies the handler. Together they encode the
// "what" (route) on the connector side and the "how" (gateway-level
// state plumbing) on this side, with no name-cased switch in either.
var connectorHookHandlerByName = map[string]func(*APIServer) http.HandlerFunc{}

// registerHookHandler is the registration entry point used by
// gateway-package init() blocks. Idempotent — duplicate registration
// for the same name overwrites; the last-writer-wins semantics keeps
// test fixtures hermetic when they swap a stub handler in.
func registerHookHandler(name string, factory func(*APIServer) http.HandlerFunc) {
	connectorHookHandlerByName[name] = factory
}

// registerConnectorHookRoutes dynamically registers hook endpoints for
// connectors that implement the HookEndpoint interface and have a
// matching gateway-side handler factory in connectorHookHandlerByName.
//
// Plan C1: when a connector is in the registry but has no factory,
// we log and skip rather than fall back to a hardcoded path — that
// way an out-of-tree connector can ship without forcing a gateway
// rebuild, and a misnamed factory fails loud (logged) rather than
// silent (a 404 at request time).
//
// The optional wrap argument lets callers wrap each registered handler
// in middleware (e.g. perIPRateLimiter) so a compromised remote caller
// can't blast the connector hook surface. Loopback is exempt inside
// perIPRateLimiter, so legitimate local agent traffic is unaffected.
func (a *APIServer) registerConnectorHookRoutes(mux *http.ServeMux, wrap ...func(http.Handler) http.Handler) {
	register := func(path string, h http.Handler) {
		for _, mw := range wrap {
			if mw != nil {
				h = mw(h)
			}
		}
		mux.Handle(path, h)
	}

	if a.connectorRegistry == nil {
		// No registry plumbed (legacy boot path, tests). Fall back
		// to the previous hardcoded routes so existing flows keep
		// working — we never unconditionally register a route the
		// connector didn't ask for.
		if f, ok := connectorHookHandlerByName["claudecode"]; ok {
			register("/api/v1/claude-code/hook", http.HandlerFunc(f(a)))
		}
		if f, ok := connectorHookHandlerByName["codex"]; ok {
			register("/api/v1/codex/hook", http.HandlerFunc(f(a)))
		}
		for _, name := range []string{"hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent"} {
			if f, ok := connectorHookHandlerByName[name]; ok {
				register("/api/v1/"+name+"/hook", http.HandlerFunc(f(a)))
			}
		}
		return
	}

	for _, name := range a.connectorRegistry.Names() {
		conn, ok := a.connectorRegistry.Get(name)
		if !ok {
			continue
		}
		he, ok := conn.(connector.HookEndpoint)
		if !ok {
			continue
		}
		factory, ok := connectorHookHandlerByName[name]
		if !ok {
			fmt.Fprintf(os.Stderr,
				"[api] connector %q implements HookEndpoint but no gateway handler is registered; skipping route %s\n",
				name, he.HookAPIPath())
			continue
		}
		path := he.HookAPIPath()
		register(path, http.HandlerFunc(factory(a)))
		fmt.Fprintf(os.Stderr, "[api] registered hook endpoint: %s → %s\n", name, path)
	}
}

// NewAPIServer creates the REST API server bound to the given address.
func NewAPIServer(addr string, health *SidecarHealth, client *Client, store *audit.Store, logger *audit.Logger, cfg ...*config.Config) *APIServer {
	s := &APIServer{
		addr:   addr,
		health: health,
		client: client,
		store:  store,
		logger: logger,
	}
	if len(cfg) > 0 {
		s.scannerCfg = cfg[0]
	}
	return s
}

// SetConfigRuntime connects configuration mutations to ConfigManager and the
// authoritative live sidecar snapshot.
func (a *APIServer) SetConfigRuntime(reload func(context.Context, string) error, snapshot func() *config.Config) {
	if a == nil {
		return
	}
	a.configReloader = reload
	a.configSnapshot = snapshot
}

func (a *APIServer) runtimeConfigSnapshot() *config.Config {
	if a == nil {
		return nil
	}
	if a.configSnapshot != nil {
		return a.configSnapshot()
	}
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return cloneConfig(a.scannerCfg)
}

// Run starts the HTTP server and blocks until ctx is cancelled.
// listenWithRetry binds a TCP listener on addr, retrying briefly while the
// address is still in use. It exists for the `setup --restart` window: the old
// gateway is terminated and a fresh one is spawned immediately, and the OS can
// hold the previous listening socket for a short interval after the process
// exits (most visibly on Windows, where the bind fails with "Only one usage of
// each socket address ... permitted"). Retrying within a bounded budget lets the
// kernel reclaim the port so the restarted gateway can bind it. Non-address-in-use
// errors and context cancellation return immediately.
func listenWithRetry(ctx context.Context, addr string, budget time.Duration) (net.Listener, error) {
	var lc net.ListenConfig
	deadline := time.Now().Add(budget)
	for attempt := 1; ; attempt++ {
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err == nil {
			return ln, nil
		}
		if !isAddrInUse(err) || time.Now().After(deadline) || ctx.Err() != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[sidecar-api] %s still in use after restart, retrying bind (attempt %d)\n", addr, attempt)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// isAddrInUse reports whether err is an "address already in use" bind failure on
// any platform. Modern Go maps Windows WSAEADDRINUSE (10048) to syscall.EADDRINUSE,
// but the human-readable text is matched too as a cross-version guard.
func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address")
}

func (a *APIServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/skill/disable", a.handleSkillDisable)
	mux.HandleFunc("/skill/enable", a.handleSkillEnable)
	mux.HandleFunc("/plugin/disable", a.handlePluginDisable)
	mux.HandleFunc("/plugin/enable", a.handlePluginEnable)
	mux.HandleFunc("/config/patch", a.handleConfigPatch)
	mux.HandleFunc("/scan/result", a.handleScanResult)
	mux.HandleFunc("/enforce/block", a.handleEnforceBlock)
	mux.HandleFunc("/enforce/allow", a.handleEnforceAllow)
	mux.HandleFunc("/enforce/blocked", a.handleEnforceBlocked)
	mux.HandleFunc("/enforce/allowed", a.handleEnforceAllowed)
	mux.HandleFunc("/alerts", a.handleAlerts)
	mux.HandleFunc("/audit/event", a.handleAuditEvent)
	mux.HandleFunc("/policy/evaluate", a.handlePolicyEvaluate)
	mux.HandleFunc("/policy/evaluate/firewall", a.handlePolicyEvaluateFirewall)
	mux.HandleFunc("/policy/evaluate/audit", a.handlePolicyEvaluateAudit)
	mux.HandleFunc("/policy/evaluate/skill-actions", a.handlePolicyEvaluateSkillActions)
	mux.HandleFunc("/policy/reload", a.handlePolicyReload)
	mux.HandleFunc("/skills", a.handleSkills)
	mux.HandleFunc("/mcps", a.handleMCPs)
	mux.HandleFunc("/tools/catalog", a.handleToolsCatalog)
	mux.HandleFunc("/v1/skill/scan", a.handleSkillScan)
	mux.HandleFunc("/v1/plugin/scan", a.handlePluginScan)
	mux.HandleFunc("/v1/mcp/scan", a.handleMCPScan)
	mux.HandleFunc("/v1/skill/fetch", a.handleSkillFetch)
	mux.HandleFunc("/v1/guardrail/event", a.handleGuardrailEvent)
	mux.HandleFunc("/v1/guardrail/evaluate", a.handleGuardrailEvaluate)
	mux.HandleFunc("/v1/guardrail/config", a.handleGuardrailConfig)
	// /api/v1/inspect/* and /api/v1/{connector}/hook are both in the
	// agent's critical path: every connector hook (claude-code-hook,
	// codex-hook, cursor-hook, ...) hits one of them. Wrap them in a
	// shared per-IP token bucket so a misbehaving or compromised
	// REMOTE caller can never blast the path. Loopback callers
	// (the gateway's own hooks) are exempt inside perIPRateLimiter,
	// so a legitimate local agent doesn't self-throttle.
	hookLimiter := perIPRateLimiter(20, 40)
	inspectMux := http.NewServeMux()
	inspectMux.HandleFunc("/api/v1/inspect/tool", a.handleInspectTool)
	inspectMux.HandleFunc("/api/v1/inspect/request", a.handleInspectRequest)
	inspectMux.HandleFunc("/api/v1/inspect/response", a.handleInspectResponse)
	inspectMux.HandleFunc("/api/v1/inspect/tool-response", a.handleInspectToolResponse)
	mux.Handle("/api/v1/inspect/", hookLimiter(inspectMux))
	mux.HandleFunc("/api/v1/scan/code", a.handleCodeScan)
	mux.HandleFunc("/api/v1/network-egress", a.handleNetworkEgress)
	mux.HandleFunc("/api/v1/telemetry/canary", a.handleTelemetryCanary)
	mux.HandleFunc("/api/v1/watchdog/recovery", a.handleWatchdogRecovery)
	mux.HandleFunc(destinationtest.EndpointPath, a.handleObservabilityDestinationTestActivity)
	mux.HandleFunc(cliObservabilityV8Path, a.handleCLIObservabilityV8)
	mux.HandleFunc(alertAcknowledgementV8Path, a.handleAlertAcknowledgementV8)
	a.registerConnectorHookRoutes(mux, hookLimiter)
	// OTLP-HTTP receiver for the three signal types codex
	// (via [otel.exporter.otlp-http]) and Claude Code (via
	// OTEL_EXPORTER_OTLP_ENDPOINT) post telemetry to. Body shape is
	// OTLP-JSON; tokenAuth + apiCSRFProtect protect the endpoints
	// the same way they protect /api/v1/codex/hook. See
	// internal/gateway/otel_ingest.go.
	mux.HandleFunc("/v1/logs", a.handleOTLPLogs)
	mux.HandleFunc("/v1/metrics", a.handleOTLPMetrics)
	mux.HandleFunc("/v1/traces", a.handleOTLPTraces)
	mux.HandleFunc("/otlp/", a.handleOTLPPathToken)
	mux.HandleFunc("/api/v1/agents/discovery", a.handleAgentDiscovery)
	mux.HandleFunc("/api/v1/ai-usage", a.handleAIUsage)
	mux.HandleFunc("/api/v1/ai-usage/scan", a.handleAIUsageScan)
	mux.HandleFunc("/api/v1/ai-usage/discovery", a.handleAIUsageDiscovery)
	mux.HandleFunc("/api/v1/ai-usage/components", a.handleAIUsageComponents)
	// Locations + history endpoints share the /api/v1/ai-usage/components/
	// prefix; the handlers parse {ecosystem}/{name}/{leaf} themselves.
	// Net/http's mux uses longest-prefix routing, so registering
	// /api/v1/ai-usage/components/ catches the deeper paths without
	// shadowing the bare /components endpoint above.
	mux.HandleFunc("/api/v1/ai-usage/components/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/locations"):
			a.handleAIUsageComponentLocations(w, r)
		case strings.HasSuffix(r.URL.Path, "/history"):
			a.handleAIUsageComponentHistory(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	// Confidence policy inspection + dry-run validate. Lets the
	// CLI ship `agent confidence policy {show, default, validate}`
	// without shelling into the sidecar host.
	mux.HandleFunc("/api/v1/ai-usage/confidence/policy", a.handleAIUsageConfidencePolicy)
	mux.HandleFunc("/api/v1/ai-usage/confidence/policy/validate", a.handleAIUsageConfidencePolicyValidate)
	// Codex agent-turn-complete notifier. The notify-bridge.sh shim
	// installed by the codex connector POSTs codex's JSON arg here
	// after every turn (see https://developers.openai.com/codex/
	// config-advanced). Audited as a structured event so the SIEM
	// can roll up turn counts + completion reasons per session.
	mux.HandleFunc("/api/v1/codex/notify", a.handleCodexNotify)
	mux.HandleFunc("/v1/connectors", a.handleConnectors)

	handler := maxBodyMiddleware(mux, 1<<20)
	handler = a.apiCSRFProtect(handler)
	handler = a.tokenAuth(handler)
	handler = a.metricsMiddleware(handler)
	var reg *AgentRegistry
	if a.scannerCfg != nil {
		reg = InstallSharedAgentRegistry(a.scannerCfg.Agent.ID, a.scannerCfg.Agent.Name)
	} else {
		reg = InstallSharedAgentRegistry("", "")
	}
	handler = CorrelationMiddleware(reg)(handler)
	// request-ID then scoped W3C extraction so generated hook spans retain the
	// agent parent without creating an unregistered SDK server span.
	handler = requestIDMiddleware(handler)
	handler = inboundTraceContextMiddleware(handler)

	srv := &http.Server{
		Addr:    a.addr,
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Bind with a short retry instead of a bare ListenAndServe. During
	// `defenseclaw setup --restart` the previous gateway is terminated and a
	// fresh, guardrail-enabled gateway is spawned immediately. On Windows the
	// kernel can keep the old listening socket reserved for a brief interval
	// after the process exits ("Only one usage of each socket address ...
	// permitted"), so a naive bind in the new process loses the race, the hook
	// API never comes up, and every connector hook posting to this port fails.
	// Retrying for a few seconds lets the OS reclaim the port so the restarted
	// gateway binds the same address the agent's hooks call.
	ln, lnErr := listenWithRetry(ctx, a.addr, 30*time.Second)
	if lnErr != nil {
		a.health.SetAPI(StateError, lnErr.Error(), nil)
		return fmt.Errorf("api: listen %s: %w", a.addr, lnErr)
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[sidecar-api] listening on %s\n", a.addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	a.health.SetAPI(StateRunning, "", map[string]interface{}{"addr": a.addr})

	select {
	case err := <-errCh:
		a.health.SetAPI(StateError, err.Error(), nil)
		return fmt.Errorf("api: listen %s: %w", a.addr, err)
	case <-ctx.Done():
		a.health.SetAPI(StateStopped, "", nil)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// handleTelemetryCanary exercises the real runtime trace pipeline. The global
// token/CSRF middleware protects this diagnostic endpoint like every other
// mutating API route.
func (a *APIServer) handleTelemetryCanary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	canary := a.observabilityV8CanaryRuntime()
	if canary == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability v8 traces are not available"})
		return
	}
	var request struct {
		Destination string `json:"destination"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(request.Destination) == "" {
		request.Destination = "galileo"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := canary.EmitTraceCanary(ctx, request.Destination)
	destination := result.Destination
	if destination == "" {
		destination = request.Destination
	}
	payload := map[string]interface{}{
		"trace_id": result.TraceID, "destination": destination,
		"generation": result.Generation, "acknowledged": result.Acknowledged,
	}
	if err != nil {
		payload["error"] = err.Error()
	}
	status := http.StatusOK
	if err != nil || !result.Acknowledged {
		status = http.StatusBadGateway
	}
	a.writeJSON(w, status, payload)
}

// handleWatchdogRecovery is the narrow, authenticated bridge used by the
// standalone watchdog after the sidecar becomes reachable again. The sidecar
// owns the observability graph, so the watchdog never constructs a second OTel
// provider or exports outside canonical v8 routing. The global auth and CSRF
// middleware protect this POST; the additional loopback check prevents a
// remote authenticated client from manufacturing recovery counts.
func (a *APIServer) handleWatchdogRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !connector.IsLoopback(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "watchdog recovery is loopback-only"})
		return
	}
	runtime, _ := a.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	if runtime == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability v8 metrics are not available"})
		return
	}
	if err := recordWatcherRestartV8(r.Context(), runtime); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "watchdog recovery metric was not recorded"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]bool{"recorded": true})
}

func (a *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := a.health.Snapshot()
	raw, err := json.Marshal(snap)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	body["provenance"] = version.Current()
	a.writeJSON(w, http.StatusOK, body)
}

func (a *APIServer) handleConnectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reg := a.connectorRegistry
	if reg == nil {
		// Reuse the lazy singleton instead of paying a fresh
		// NewDefaultRegistry() build (ten builtin
		// registrations) on every /connectors GET.
		reg = getFallbackConnectorRegistry()
	}
	type connectorEntry struct {
		Name               string `json:"name"`
		Description        string `json:"description"`
		Source             string `json:"source"`
		ToolInspectionMode string `json:"tool_inspection_mode"`
		SubprocessPolicy   string `json:"subprocess_policy"`
		// LLMTrafficMode ("proxy" | "hooks-only") tells the CLI whether a
		// custom provider bound to this connector is enforced on the
		// agent's own model traffic or only configures DefenseClaw's
		// judge/aux model. Set for every connector (proxy connectors do
		// not emit the ConnectorCapabilities struct, so it cannot live
		// solely there).
		LLMTrafficMode   string                           `json:"llm_traffic_mode"`
		HookCapabilities *connector.HookCapability        `json:"hook_capabilities,omitempty"`
		Capabilities     *connector.ConnectorCapabilities `json:"capabilities,omitempty"`
		Locations        *connector.ConnectorLocations    `json:"locations,omitempty"`
	}
	avail := reg.Available()
	entries := make([]connectorEntry, len(avail))
	for i, info := range avail {
		entry := connectorEntry{
			Name:               info.Name,
			Description:        info.Description,
			Source:             info.Source,
			ToolInspectionMode: string(info.ToolInspectionMode),
			SubprocessPolicy:   string(info.SubprocessPolicy),
			LLMTrafficMode:     connector.LLMTrafficModeForConnector(info.Name),
		}
		if conn, ok := reg.Get(info.Name); ok {
			opts := connector.SetupOpts{
				DataDir:      a.configDataDir(),
				APIAddr:      a.apiAddrForCapabilities(),
				WorkspaceDir: a.connectorWorkspaceDir(),
			}
			loc := connector.ResolvedConnectorLocations(opts, conn)
			entry.Locations = &loc
			if cp, ok := conn.(connector.ConnectorCapabilityProvider); ok {
				caps := cp.Capabilities(opts)
				entry.Capabilities = &caps
				entry.HookCapabilities = &caps.Hooks
			}
			if hp, ok := conn.(connector.HookCapabilityProvider); ok {
				if entry.HookCapabilities == nil {
					caps := hp.HookCapabilities(opts)
					entry.HookCapabilities = &caps
				}
			}
		}
		entries[i] = entry
	}
	resp := map[string]interface{}{
		"active":     a.connectorName(),
		"connectors": entries,
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snap := a.health.Snapshot()

	status := map[string]interface{}{
		"health":     snap,
		"provenance": version.Current(),
		// connector_mode reports which guardrail surface the active
		// connector is running. The TUI uses this to render the
		// "Observability mode" banner with the right copy and to
		// hide proxy-related panels (proxy_addr, openai_base_url
		// override) when enforcement is off. This is the single
		// source of truth: the proxy's "running / observability-only"
		// summary in health.proxy mirrors this but the structured
		// field below is what programmatic consumers (CLI status,
		// dashboards) should read.
		//
		// connector_mode is the active-connector view (back-compat).
		// connector_modes fans the same shape out across every active
		// connector so multi-connector status can show each one's
		// enforcement/observability posture, not just the primary's.
		"connector_mode":  a.connectorModeSummary(),
		"connector_modes": a.connectorModesSummary(),
	}

	if a.client != nil && a.client.Hello() != nil {
		hello := a.client.Hello()
		status["gateway_hello"] = hello
	}

	a.writeJSON(w, http.StatusOK, status)
}

// connectorModeSummary returns the per-connector runtime summary for the
// active connector. The shape is:
//
//	{
//	  "connector":  "codex" | "claudecode" | "openclaw" | "zeptoclaw",
//	  "mode":       "guardrail" | "observability", // legacy data-path field
//	  "policy_mode": "observe" | "action",
//	  "enforcement_surface": "llm_proxy" | "agent_lifecycle_hooks" | "omnigent_policy_api",
//	  "telemetry":  ["hooks", "otel", "notify"],   // active channels
//	  "proxy_intercept": true | false,
//	}
//
// "guardrail" means the proxy listener is bound; "observability" is the
// legacy name for a direct-to-upstream data path. Enforcement on that direct
// path is described separately by policy_mode and enforcement_surface.
//
// This is the singular (active-connector) view kept for back-compat;
// connectorModesSummary fans the same shape out across every active
// connector for the multi-connector status surface.
func (a *APIServer) connectorModeSummary() map[string]interface{} {
	if a.scannerCfg != nil && !a.scannerCfg.HasConnectorConfigured() {
		return map[string]interface{}{
			"connector":           "",
			"mode":                "unconfigured",
			"policy_mode":         "",
			"enforcement_surface": "",
			"telemetry":           []string{},
			"proxy_intercept":     false,
		}
	}
	return connectorModeForConfig(a.scannerCfg, a.connectorName())
}

// connectorModesSummary returns one connectorModeFor entry per active
// connector so multi-connector status output can show every connector's
// enforcement/observability posture rather than only the primary's. The
// roster is sourced from the config's ActiveConnectors() (sorted), which
// returns a single name on a single-connector install — so the shape is
// identical regardless of count. Falls back to the singular active
// connector when the config is unavailable.
func (a *APIServer) connectorModesSummary() []map[string]interface{} {
	var names []string
	if a.scannerCfg != nil {
		names = a.scannerCfg.ActiveConnectors()
		if !a.scannerCfg.HasConnectorConfigured() {
			return []map[string]interface{}{}
		}
	}
	if len(names) == 0 {
		names = []string{a.connectorName()}
	}
	out := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		out = append(out, connectorModeForConfig(a.scannerCfg, strings.ToLower(strings.TrimSpace(name))))
	}
	return out
}

// connectorModeFor derives the enforcement/observability mode summary for a
// single connector name. Pure function of the name so it can be mapped over
// the whole active set (connectorModesSummary) or applied to just the
// primary (connectorModeSummary).
func connectorModeFor(name, policyMode string) map[string]interface{} {
	mode := "guardrail"
	intercept := true
	surface := "llm_proxy"
	var telemetry []string
	policyMode = strings.ToLower(strings.TrimSpace(policyMode))
	if policyMode != "action" {
		policyMode = "observe"
	}

	switch name {
	case "codex":
		mode = "observability"
		intercept = false
		surface = "agent_lifecycle_hooks"
		// codex telemetry always wires all three channels (hooks,
		// the [otel.exporter.otlp-http] block, the notify bridge).
		telemetry = []string{"hooks", "otel", "notify"}
	case "claudecode":
		mode = "observability"
		intercept = false
		surface = "agent_lifecycle_hooks"
		// Claude Code uses hooks + the OTel env-block; no notify
		// equivalent (Anthropic doesn't ship a turn-complete shim).
		telemetry = []string{"hooks", "otel"}
	case "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode":
		mode = "observability"
		intercept = false
		surface = "agent_lifecycle_hooks"
		telemetry = []string{"hooks"}
		if name == "geminicli" || name == "copilot" {
			telemetry = append(telemetry, "otel")
		}
	case "omnigent":
		mode = "observability"
		intercept = false
		surface = "omnigent_policy_api"
		telemetry = []string{"policy-api"}
	default:
		// openclaw / zeptoclaw / unknown: enforcement is the only
		// supported mode today. Hooks are wired by the connector;
		// no native OTel surface from those agents.
		telemetry = []string{"hooks"}
	}

	return map[string]interface{}{
		"connector":           name,
		"mode":                mode,
		"policy_mode":         policyMode,
		"enforcement_surface": surface,
		"telemetry":           telemetry,
		"proxy_intercept":     intercept,
	}
}

func connectorModeForConfig(cfg *config.Config, name string) map[string]interface{} {
	guardrailMode := "observe"
	if cfg != nil {
		guardrailMode = cfg.EffectiveGuardrailModeForConnector(name)
	}
	out := connectorModeFor(name, guardrailMode)
	if guardrailMode != "" {
		out["guardrail_mode"] = guardrailMode
	}
	proxyIntercept, _ := out["proxy_intercept"].(bool)
	out["hook_enforcement"] = !proxyIntercept && strings.EqualFold(guardrailMode, "action")
	return out
}

type skillActionRequest struct {
	SkillKey string `json:"skillKey"`
}

func (a *APIServer) handleSkillDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SkillKey == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skillKey is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.DisableSkill(ctx, req.SkillKey); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPISkillDisable), req.SkillKey, "disabled via REST API")
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "skillKey": req.SkillKey})
}

func (a *APIServer) handleSkillEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SkillKey == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skillKey is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.EnableSkill(ctx, req.SkillKey); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPISkillEnable), req.SkillKey, "enabled via REST API")
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "skillKey": req.SkillKey})
}

type pluginActionRequest struct {
	PluginName string `json:"pluginName"`
}

func (a *APIServer) handlePluginDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req pluginActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.PluginName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pluginName is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), pluginGatewayMutationTimeout)
	defer cancel()

	if err := a.retryGatewayMutation(ctx, func(callCtx context.Context) error {
		return a.client.DisablePlugin(callCtx, req.PluginName)
	}); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIPluginDisable), req.PluginName, "disabled via REST API")
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "pluginName": req.PluginName})
}

func (a *APIServer) handlePluginEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req pluginActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.PluginName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pluginName is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), pluginGatewayMutationTimeout)
	defer cancel()

	if err := a.retryGatewayMutation(ctx, func(callCtx context.Context) error {
		return a.client.EnablePlugin(callCtx, req.PluginName)
	}); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIPluginEnable), req.PluginName, "enabled via REST API")
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "pluginName": req.PluginName})
}

const gatewayMutationRetryDelay = 2 * time.Second
const gatewayMutationMaxAttempts = 45
const pluginGatewayMutationTimeout = 90 * time.Second
const gatewayMutationPerAttemptTimeout = 10 * time.Second

func isRetryableGatewayMutationError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "gateway: not connected") ||
		strings.Contains(msg, "websocket: close sent") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "context deadline exceeded")
}

func (a *APIServer) retryGatewayMutation(ctx context.Context, fn func(context.Context) error) error {
	var lastErr error
	for attempt := 1; attempt <= gatewayMutationMaxAttempts; attempt++ {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, gatewayMutationPerAttemptTimeout)
		lastErr = fn(attemptCtx)
		attemptCancel()
		if lastErr == nil {
			return nil
		}
		if !isRetryableGatewayMutationError(lastErr) || attempt == gatewayMutationMaxAttempts {
			return lastErr
		}
		fmt.Fprintf(os.Stderr, "[api] gateway mutation attempt %d/%d failed: %v (retrying in %s)\n",
			attempt, gatewayMutationMaxAttempts, lastErr, gatewayMutationRetryDelay)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(gatewayMutationRetryDelay):
		}
	}
	return lastErr
}

type configPatchRequest struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type enforcementRequest struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
}

type enforcementEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type policyEvaluateRequest struct {
	Domain string              `json:"domain"`
	Input  policyEvaluateInput `json:"input"`
}

type policyEvaluateInput struct {
	TargetType string                    `json:"target_type"`
	TargetName string                    `json:"target_name"`
	Path       string                    `json:"path"`
	ScanResult *policyEvaluateScanResult `json:"scan_result,omitempty"`
}

type policyEvaluateScanResult struct {
	MaxSeverity   string `json:"max_severity"`
	TotalFindings int    `json:"total_findings"`
	// DeepSec hardening (S2.scanners): expose the scanner failure
	// signal so callers driving this debug endpoint can reproduce
	// the post-scan admission decision a non-zero scanner exit
	// would yield. Mirrors policy.ScanResultInput.
	ExitCode  int    `json:"exit_code,omitempty"`
	ScanError string `json:"scan_error,omitempty"`
}

func (a *APIServer) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req configPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Path == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.PatchConfig(ctx, req.Path, req.Value); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIConfigPatch), req.Path, fmt.Sprintf("patched via REST API value_type=%T", req.Value))
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "patched", "path": req.Path})
}

func (a *APIServer) handleScanResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := a.logger
	if logger == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "v8 observability runtime not configured"})
		return
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if result.Scanner == "" || result.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanner and target are required"})
		return
	}
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now().UTC()
	}

	if err := logger.LogScan(&result); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *APIServer) handleEnforceBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	var req enforcementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.TargetType == "" || req.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_type and target_name are required"})
		return
	}

	pe := enforce.NewPolicyEngine(a.store)
	switch r.Method {
	case http.MethodPost:
		reason := req.Reason
		if reason == "" {
			reason = "blocked via REST API"
		}
		if err := pe.Block(req.TargetType, req.TargetName, reason); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIEnforceBlock), req.TargetName, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(reason, 120)))
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "blocked"})
	case http.MethodDelete:
		if err := pe.Unblock(req.TargetType, req.TargetName); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIEnforceUnblock), req.TargetName, fmt.Sprintf("type=%s", req.TargetType))
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked"})
	}
}

func (a *APIServer) handleEnforceAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	var req enforcementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.TargetType == "" || req.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_type and target_name are required"})
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "allowed via REST API"
	}

	pe := enforce.NewPolicyEngine(a.store)
	policyName := req.TargetName
	runtimeName := req.TargetName
	if req.TargetType == "plugin" {
		policyName = normalizePluginPolicyName(req.TargetName)
		runtimeName = resolvePluginRuntimeActionName(pe, req.TargetName, policyName)
	}

	entry, err := pe.GetAction(req.TargetType, runtimeName)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entry != nil && entry.Actions.Runtime == "disable" {
		if a.client == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway client not configured"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), pluginGatewayMutationTimeout)
		defer cancel()
		switch req.TargetType {
		case "skill":
			if err := a.retryGatewayMutation(ctx, func(callCtx context.Context) error {
				return a.client.EnableSkill(callCtx, req.TargetName)
			}); err != nil {
				a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
		case "plugin":
			if err := a.retryGatewayMutation(ctx, func(callCtx context.Context) error {
				return a.client.EnablePlugin(callCtx, runtimeName)
			}); err != nil {
				a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if runtimeName != policyName {
				if err := pe.Enable("plugin", runtimeName); err != nil {
					a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
					return
				}
			}
		}
	}
	if err := pe.Allow(req.TargetType, policyName, reason); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIEnforceAllow), policyName, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(reason, 120)))
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "allowed"})
}

func normalizePluginPolicyName(name string) string {
	if name == "" {
		return ""
	}
	base := filepath.Base(name)
	if base == "." || base == string(filepath.Separator) {
		return name
	}
	return base
}

func resolvePluginRuntimeActionName(pe *enforce.PolicyEngine, rawName, policyName string) string {
	candidates := []string{policyName}
	for _, suffix := range []string{"-plugin", "-provider"} {
		if strings.HasSuffix(policyName, suffix) {
			candidates = append(candidates, strings.TrimSuffix(policyName, suffix))
		}
	}
	if rawName != "" && rawName != policyName {
		candidates = append(candidates, rawName)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		entry, err := pe.GetAction("plugin", candidate)
		if err == nil && entry != nil && entry.Actions.Runtime == "disable" {
			return candidate
		}
	}
	return policyName
}

func (a *APIServer) handleEnforceBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	entries, err := enforce.NewPolicyEngine(a.store).ListBlocked()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, toEnforcementEntries(entries))
}

func (a *APIServer) handleEnforceAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	entries, err := enforce.NewPolicyEngine(a.store).ListAllowed()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, toEnforcementEntries(entries))
}

func (a *APIServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = parsed
	}
	if limit > 500 {
		limit = 500
	}

	alerts, err := a.store.ListAlerts(limit)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, alerts)
}

func (a *APIServer) handleAuditEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	var event audit.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if event.Action == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action is required"})
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Severity == "" {
		event.Severity = "INFO"
	}
	if err := persistAuditEvent(a.logger, event); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *APIServer) handlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policyEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Domain != "" && req.Domain != "admission" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported policy domain"})
		return
	}
	if req.Input.TargetType == "" || req.Input.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "input.target_type and input.target_name are required"})
		return
	}

	input := policy.AdmissionInput{
		TargetType: req.Input.TargetType,
		TargetName: req.Input.TargetName,
		Path:       req.Input.Path,
		BlockList:  a.blockListEntries(),
		AllowList:  a.allowListEntries(),
	}
	if req.Input.ScanResult != nil {
		input.ScanResult = &policy.ScanResultInput{
			MaxSeverity:   req.Input.ScanResult.MaxSeverity,
			TotalFindings: req.Input.ScanResult.TotalFindings,
			ExitCode:      req.Input.ScanResult.ExitCode,
			ScanError:     req.Input.ScanResult.ScanError,
		}
	}
	ctx, observation, err := a.startAPIPolicyEvaluationV8(
		r.Context(), "admission", req.Input.TargetType, req.Input.TargetName,
	)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := a.evaluateAdmissionPolicy(ctx, input)
	if err != nil {
		_ = observation.complete("error", "", "", err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	severity := ""
	if req.Input.ScanResult != nil {
		severity = req.Input.ScanResult.MaxSeverity
	}
	if err := observation.complete(out.Verdict, out.Reason, severity, nil); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": out})
}

func (a *APIServer) handleSkills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := a.client.GetSkillsStatus(ctx)
	if err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *APIServer) handleMCPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusOK, []config.MCPServerEntry{})
		return
	}

	servers, err := a.scannerCfg.ReadMCPServers()
	if err != nil {
		a.writeJSON(w, http.StatusOK, []config.MCPServerEntry{})
		return
	}

	a.writeJSON(w, http.StatusOK, servers)
}

func (a *APIServer) handleToolsCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := a.client.GetToolsCatalog(ctx)
	if err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func scanAPIResponseEnvelope(result *scanner.ScanResult) map[string]interface{} {
	bySev := make(map[string]int)
	for _, f := range result.Findings {
		bySev[string(f.Severity)]++
	}
	return map[string]interface{}{
		"scan_id":                    uuid.New().String(),
		"verdict":                    string(result.MaxSeverity()),
		"provenance":                 version.Current(),
		"findings_count_by_severity": bySev,
		"result":                     result,
	}
}

// ---------------------------------------------------------------------------
// POST /v1/skill/scan — run skill scanner on a local path (Option 2: remote scan)
// ---------------------------------------------------------------------------

type skillScanRequest struct {
	Target string `json:"target"`
	Name   string `json:"name"`
}

func (a *APIServer) handleSkillScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	// Verify target exists on this host.
	// If the path doesn't exist locally, the scanner will fail with a clear
	// error — we still attempt the scan so that when the sidecar runs on the
	// same host as OpenClaw (the intended remote deployment), it works.
	if info, err := os.Stat(req.Target); err != nil || !info.IsDir() {
		// Log a warning but proceed — the scanner will produce the definitive error.
		fmt.Fprintf(os.Stderr, "[api] warning: target directory not found locally: %s\n", req.Target)
	}

	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scanner not configured"})
		return
	}

	// Route through the unified resolver so top-level ``llm:`` defaults
	// flow into the skill scanner with ``scanners.skill.llm:`` overrides
	// applied on top. ``NewSkillScannerFromLLM`` is the post-v5
	// constructor; the legacy ``NewSkillScanner`` path is kept alive
	// only for tests that still pass ``InspectLLMConfig``.
	ss := scanner.NewSkillScannerFromLLM(
		a.scannerCfg.Scanners.SkillScanner,
		a.scannerCfg.ResolveLLM("scanners.skill"),
		a.scannerCfg.CiscoAIDefense,
	)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	result, err := ss.Scan(ctx, req.Target)
	if err != nil {
		a.recordAPIScanErrorV8(r.Context(), "skill-scanner", "skill", classifyScanError(err))
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPISkillScan), req.Target, fmt.Sprintf("findings=%d max=%s", len(result.Findings), result.MaxSeverity()))
		_ = a.logger.LogScanWithCorrelation(r.Context(), result, "", ScanCorrelationFromContext(r.Context()))
	}

	a.writeJSON(w, http.StatusOK, scanAPIResponseEnvelope(result))
}

func (a *APIServer) handlePluginScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	if info, err := os.Stat(req.Target); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "[api] warning: plugin target directory not found locally: %s\n", req.Target)
	}

	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scanner not configured"})
		return
	}

	ps := scanner.NewPluginScanner(a.scannerCfg.Scanners.PluginScanner)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	result, err := ps.Scan(ctx, req.Target)
	if err != nil {
		a.recordAPIScanErrorV8(r.Context(), "plugin-scanner", "plugin", classifyScanError(err))
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIPluginScan), req.Target, fmt.Sprintf("findings=%d max=%s", len(result.Findings), result.MaxSeverity()))
		_ = a.logger.LogScanWithCorrelation(r.Context(), result, "", ScanCorrelationFromContext(r.Context()))
	}

	a.writeJSON(w, http.StatusOK, scanAPIResponseEnvelope(result))
}

// ---------------------------------------------------------------------------
// POST /v1/mcp/scan — run MCP scanner on a target (URL or local path)
// ---------------------------------------------------------------------------

type mcpScanRequest struct {
	Target string `json:"target"`
	Name   string `json:"name"`
}

func (a *APIServer) handleMCPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mcpScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scanner not configured"})
		return
	}

	ms := scanner.NewMCPScannerFromLLM(
		a.scannerCfg.Scanners.MCPScanner,
		a.scannerCfg.ResolveLLM("scanners.mcp"),
		a.scannerCfg.CiscoAIDefense,
	)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	result, err := ms.Scan(ctx, req.Target)
	if err != nil {
		a.recordAPIScanErrorV8(r.Context(), "mcp-scanner", "mcp", classifyScanError(err))
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIMCPScan), req.Target, fmt.Sprintf("findings=%d max=%s", len(result.Findings), result.MaxSeverity()))
		_ = a.logger.LogScanWithCorrelation(r.Context(), result, "", ScanCorrelationFromContext(r.Context()))
	}

	a.writeJSON(w, http.StatusOK, scanAPIResponseEnvelope(result))
}

// ---------------------------------------------------------------------------
// POST /v1/skill/fetch — tar.gz a skill directory and stream it back
// ---------------------------------------------------------------------------

type skillFetchRequest struct {
	Target string `json:"target"`
}

func (a *APIServer) handleSkillFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillFetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	// Avarice F-3287: the legacy handler accepted any directory the
	// gateway process could read and streamed every regular file
	// inside it. A caller with the sidecar bearer token could ask
	// for ~/.defenseclaw, ~/.ssh, /etc, /private/etc/ssh, etc., and
	// receive a tarball of readable host files. Constrain req.Target
	// to a directory under one of the configured skill or plugin
	// roots, after fully resolving symlinks on both sides.
	resolvedTarget, err := filepath.EvalSymlinks(req.Target)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("target directory not found: %s", req.Target),
		})
		return
	}
	resolvedAbs, err := filepath.Abs(resolvedTarget)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("target directory not resolvable: %s", req.Target),
		})
		return
	}
	a.cfgMu.RLock()
	cfgSnap := a.scannerCfg
	a.cfgMu.RUnlock()
	var allowedRoots []string
	if cfgSnap != nil {
		allowedRoots = append(allowedRoots, cfgSnap.SkillDirs()...)
		allowedRoots = append(allowedRoots, cfgSnap.PluginDirs()...)
	}
	rootOK := false
	for _, root := range allowedRoots {
		if root == "" {
			continue
		}
		rr, rerr := filepath.EvalSymlinks(root)
		if rerr != nil {
			continue
		}
		rrAbs, aerr := filepath.Abs(rr)
		if aerr != nil {
			continue
		}
		if resolvedAbs == rrAbs {
			rootOK = true
			break
		}
		if strings.HasPrefix(resolvedAbs, rrAbs+string(os.PathSeparator)) {
			rootOK = true
			break
		}
	}
	if !rootOK {
		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), "api-skill-fetch-rejected", req.Target,
				"reason=outside-skill-roots (F-3287)")
		}
		a.writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "target is not under a configured skill or plugin root (F-3287)",
		})
		return
	}

	info, err := os.Stat(req.Target)
	if err != nil || !info.IsDir() {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("target directory not found: %s", req.Target),
		})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPISkillFetch), req.Target, "streaming skill tar.gz")
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(req.Target)+".tar.gz"))
	w.WriteHeader(http.StatusOK)

	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	base := req.Target
	_ = filepath.Walk(base, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}

		// Skip node_modules and .git
		name := fi.Name()
		if fi.IsDir() && (name == "node_modules" || name == ".git") {
			return filepath.SkipDir
		}

		rel, _ := filepath.Rel(base, path)
		if rel == "." {
			return nil
		}

		// Sanitise: prevent path traversal in archive
		if strings.Contains(rel, "..") {
			return nil
		}

		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return nil
		}
		header.Name = rel

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			_, _ = io.Copy(tw, f)
		}

		return nil
	})
}

// ---------------------------------------------------------------------------
// POST /v1/guardrail/event — receive verdict telemetry from the guardrail proxy
// ---------------------------------------------------------------------------

type guardrailEventRequest struct {
	EvaluationID   string   `json:"evaluation_id"`
	Direction      string   `json:"direction"`
	Model          string   `json:"model"`
	Action         string   `json:"action"`
	Severity       string   `json:"severity"`
	Reason         string   `json:"reason"`
	Findings       []string `json:"findings"`
	ElapsedMs      float64  `json:"elapsed_ms"`
	CiscoElapsedMs float64  `json:"cisco_elapsed_ms"`
	TokensIn       *int64   `json:"tokens_in,omitempty"`
	TokensOut      *int64   `json:"tokens_out,omitempty"`
}

func (a *APIServer) handleGuardrailEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req guardrailEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.EvaluationID == "" || req.Direction == "" || req.Action == "" || req.Severity == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "evaluation_id, direction, action, and severity are required"})
		return
	}
	facts, err := newAPIGuardrailEventV8Facts(r.Context(), a.connectorName(), req)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// The local stderr diagnostic remains redacted. Canonical telemetry keeps
	// the source reason until the central per-destination redaction stage.
	redactedReason := redaction.Reason(req.Reason)
	redactedFindings := make([]string, len(req.Findings))
	for i, f := range req.Findings {
		redactedFindings[i] = redaction.Reason(f)
	}
	switch req.Action {
	case "block":
		fmt.Fprintf(os.Stderr, "[guardrail] BLOCKED %s: model=%s severity=%s reason=%q findings=%v\n",
			req.Direction, req.Model, req.Severity, redactedReason, redactedFindings)
	case "alert":
		fmt.Fprintf(os.Stderr, "[guardrail] ALERT %s: model=%s severity=%s reason=%q findings=%v\n",
			req.Direction, req.Model, req.Severity, redactedReason, redactedFindings)
	default:
		fmt.Fprintf(os.Stderr, "[guardrail] OK %s: model=%s severity=%s elapsed=%.0fms\n",
			req.Direction, req.Model, req.Severity, req.ElapsedMs)
	}
	if err := a.emitGuardrailEventV8(r.Context(), facts); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type guardrailEvaluateRequest struct {
	EvaluationID  string                      `json:"evaluation_id"`
	Direction     string                      `json:"direction"`
	Model         string                      `json:"model"`
	Mode          string                      `json:"mode"`
	ScannerMode   string                      `json:"scanner_mode"`
	LocalResult   *policy.GuardrailScanResult `json:"local_result"`
	CiscoResult   *policy.GuardrailScanResult `json:"cisco_result"`
	ContentLength int                         `json:"content_length"`
	ElapsedMs     float64                     `json:"elapsed_ms"`
}

func (a *APIServer) handleGuardrailEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req guardrailEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.EvaluationID == "" || req.Direction == "" || req.Mode == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "evaluation_id, direction, and mode are required"})
		return
	}
	facts, err := newAPIGuardrailEvaluateV8RequestFacts(r.Context(), a, req)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req = facts.request

	fmt.Fprintf(os.Stderr, "[guardrail] evaluate >>> direction=%s model=%s mode=%s scanner_mode=%s content_len=%d\n",
		req.Direction, req.Model, req.Mode, req.ScannerMode, req.ContentLength)

	input := policy.GuardrailInput{
		Direction:     req.Direction,
		Model:         req.Model,
		Mode:          req.Mode,
		ScannerMode:   req.ScannerMode,
		LocalResult:   req.LocalResult,
		CiscoResult:   req.CiscoResult,
		ContentLength: req.ContentLength,
	}

	// Inject the live HILT configuration so the Rego policy reads
	// `input.hilt.*` and config.yaml stays the single source of truth.
	// Without this, the policy would fall back to `data.guardrail.hilt`
	// in policies/rego/data.json, which historically drifted out of sync
	// with config.yaml and surfaced HIGH-severity findings as `alert`
	// instead of `confirm`. See cmd_setup.py:_sync_guardrail_hilt_to_opa
	// for the legacy mirror — preserved as a fallback for non-gateway
	// callers (e.g. direct `opa eval`) but no longer authoritative for
	// requests routed through this endpoint.
	if a.scannerCfg != nil {
		a.cfgMu.RLock()
		hilt := a.scannerCfg.Guardrail.HILT
		a.cfgMu.RUnlock()
		minSev := strings.ToUpper(strings.TrimSpace(hilt.MinSeverity))
		if minSev == "" {
			minSev = "HIGH"
		}
		input.HILT = &policy.GuardrailHILTInput{
			Enabled:     hilt.Enabled,
			MinSeverity: minSev,
		}
	}

	startedAt := time.Now().UTC()
	out, err := a.evaluateGuardrailPolicy(r.Context(), input)
	completedAt := time.Now().UTC()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] evaluate error: %v\n", err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	facts, err = facts.complete(out, startedAt, completedAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] evaluate invalid output: %v\n", err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "guardrail output is invalid"})
		return
	}

	fmt.Fprintf(os.Stderr, "[guardrail] evaluate <<< action=%s severity=%s sources=%v reason=%q\n",
		out.Action, out.Severity, out.ScannerSources,
		redaction.Reason(truncate(out.Reason, 120)))

	runtime, ok := a.observabilityV8RuntimeEmitter().(apiGuardrailEvaluateV8Runtime)
	if !ok || runtime == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}
	if err := facts.emit(r.Context(), runtime); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}

	a.writeJSON(w, http.StatusOK, out)
}

func (a *APIServer) handleGuardrailConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := map[string]interface{}{
			"mode":         "observe",
			"scanner_mode": "local",
		}
		if live := a.runtimeConfigSnapshot(); live != nil {
			cfg["mode"] = live.Guardrail.Mode
			cfg["scanner_mode"] = live.Guardrail.ScannerMode
			cfg["block_message"] = live.Guardrail.BlockMessage
			cfg["connector"] = live.Guardrail.Connector
			cfg["hilt_enabled"] = live.Guardrail.HILT.Enabled
			cfg["hilt_min_severity"] = live.Guardrail.HILT.MinSeverity
		}
		a.writeJSON(w, http.StatusOK, cfg)

	case http.MethodPatch:
		current := a.runtimeConfigSnapshot()
		// PR #141 audit C1: defense-in-depth gate. tokenAuth already
		// fail-closes when no gateway token is configured, but mode
		// changes are too security-sensitive to depend on a single
		// middleware layer. A future refactor that exposes this
		// handler outside the tokenAuth chain (or a misconfigured
		// custom mux) must not silently downgrade `action` → `observe`
		// without an authenticated caller. Re-validate here with the
		// same constant-time compare tokenAuth uses.
		if status, authErr := guardrailConfigPatchAuthorization(r, current); authErr != "" {
			a.writeJSON(w, status, map[string]string{"error": authErr})
			return
		}

		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		if current == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
			return
		}
		if a.configReloader == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "central config reload is unavailable; refusing an uncoordinated config write",
			})
			return
		}

		changed := []string{}
		updates := map[string]any{}
		if raw, ok := req["mode"]; ok {
			mode, ok := raw.(string)
			if !ok || (mode != "observe" && mode != "action") {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be observe or action"})
				return
			}
			updates["guardrail.mode"] = mode
			changed = append(changed, "mode="+mode)
		}
		if raw, ok := req["scanner_mode"]; ok {
			sm, ok := raw.(string)
			if !ok || (sm != "local" && sm != "remote" && sm != "both") {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanner_mode must be local, remote, or both"})
				return
			}
			updates["guardrail.scanner_mode"] = sm
			changed = append(changed, "scanner_mode="+sm)
		}
		if raw, ok := req["block_message"]; ok {
			bm, ok := raw.(string)
			if !ok {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "block_message must be a string"})
				return
			}
			updates["guardrail.block_message"] = bm
			changed = append(changed, "block_message")
		}
		if raw, ok := req["connector"]; ok {
			conn, ok := raw.(string)
			if !ok || strings.TrimSpace(conn) == "" {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connector must be a non-empty string"})
				return
			}
			conn = strings.ToLower(strings.TrimSpace(conn))
			updates["guardrail.connector"] = conn
			changed = append(changed, "connector="+conn)
		}
		if raw, ok := req["hilt_enabled"]; ok {
			enabled, ok := raw.(bool)
			if !ok {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hilt_enabled must be a boolean"})
				return
			}
			updates["guardrail.hilt.enabled"] = enabled
			changed = append(changed, fmt.Sprintf("hilt_enabled=%v", enabled))
		}
		if raw, ok := req["hilt_min_severity"]; ok {
			minSev, ok := raw.(string)
			if !ok || strings.TrimSpace(minSev) == "" {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hilt_min_severity must be a non-empty string"})
				return
			}
			minSev = strings.ToUpper(strings.TrimSpace(minSev))
			updates["guardrail.hilt.min_severity"] = minSev
			changed = append(changed, "hilt_min_severity="+minSev)
		}

		if len(updates) == 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid fields to update"})
			return
		}
		a.configWriteMu.Lock()
		defer a.configWriteMu.Unlock()

		// Re-snapshot after entering the write transaction. An administrator
		// may have switched the gateway into managed mode, rotated the token,
		// or changed the authoritative config path while this request body was
		// being decoded or waiting behind another PATCH.
		current = a.runtimeConfigSnapshot()
		if current == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
			return
		}
		if status, authErr := guardrailConfigPatchAuthorization(r, current); authErr != "" {
			a.writeJSON(w, status, map[string]string{"error": authErr})
			return
		}

		configPath := configFilePathForSnapshot(current)
		original, err := captureConfigFileState(configPath)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := a.patchGuardrailConfigFile(configPath, updates); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		candidate, err := config.LoadRuntimeV8File(configPath)
		if err != nil {
			_ = restoreConfigFileState(configPath, original)
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		diff := diffConfigs(current, candidate)
		if configReloadMode(candidate) == "hot" && len(diff.RestartRequired) > 0 {
			if err := restoreConfigFileState(configPath, original); err != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			a.writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error":            "guardrail config change requires gateway restart",
				"restart_required": diff.RestartRequired,
				"changed":          changed,
			})
			return
		}

		if err := a.configReloader(r.Context(), "guardrail_api"); err != nil {
			rollbackErr := restoreConfigFileState(configPath, original)
			if rollbackErr == nil {
				rollbackErr = a.configReloader(r.Context(), "guardrail_api_rollback")
			}
			if rollbackErr != nil {
				err = fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		statusCode := http.StatusOK
		status := "updated"
		live := true
		responseCfg := a.runtimeConfigSnapshot()
		if configReloadMode(candidate) == "restart" && !onlyConfigReloadModeChanged(current, candidate) {
			statusCode = http.StatusAccepted
			status = "restart_requested"
			live = false
			responseCfg = candidate
		} else if !guardrailConfigContainsUpdates(responseCfg, updates) {
			rollbackErr := restoreConfigFileState(configPath, original)
			if rollbackErr == nil {
				rollbackErr = a.configReloader(r.Context(), "guardrail_api_rollback")
			}
			err := fmt.Errorf("central config reload returned without applying the guardrail update")
			if rollbackErr != nil {
				err = fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		resp := guardrailConfigResponse(responseCfg)
		resp["status"] = status
		resp["live"] = live
		resp["changed"] = changed

		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionGuardrailConfigReload), "", strings.Join(changed, " "))
		}

		a.writeJSON(w, statusCode, resp)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func guardrailConfigPatchAuthorization(r *http.Request, current *config.Config) (int, string) {
	if current == nil {
		return 0, ""
	}
	if managed.IsManagedEnterprise(current.DeploymentMode) {
		return http.StatusForbidden, "managed_enterprise config changes require operating-system administrator privileges; edit the managed config file or use the enterprise guardian"
	}
	token := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	}
	if token == "" {
		token = r.Header.Get("X-DefenseClaw-Token")
	}
	expected := current.Gateway.Token
	if expected == "" || token == "" || !constantTimeStringMatch(token, expected) {
		return http.StatusForbidden, "guardrail config changes require a valid gateway token — set DEFENSECLAW_GATEWAY_TOKEN"
	}
	return 0, ""
}

func (a *APIServer) configFilePath() string {
	return configFilePathForSnapshot(a.runtimeConfigSnapshot())
}

func configFilePathForSnapshot(cfg *config.Config) string {
	if cfg != nil {
		if p := strings.TrimSpace(cfg.ConfigFilePath); p != "" {
			return p
		}
		if d := strings.TrimSpace(cfg.DataDir); d != "" {
			return filepath.Join(d, config.DefaultConfigName)
		}
	}
	return config.ConfigPath()
}

type configFileState struct {
	data    []byte
	mode    os.FileMode
	existed bool
}

func captureConfigFileState(path string) (configFileState, error) {
	state := configFileState{mode: 0o600}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, fmt.Errorf("api: read config before patch: %w", err)
	}
	state.data = data
	state.existed = true
	if info, statErr := os.Stat(path); statErr == nil {
		state.mode = info.Mode().Perm()
	}
	return state, nil
}

func restoreConfigFileState(path string, state configFileState) error {
	if state.existed {
		if err := config.WriteFileAtomic(path, state.data, state.mode); err != nil {
			return fmt.Errorf("api: restore config after failed live apply: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("api: remove config after failed live apply: %w", err)
	}
	return nil
}

func (a *APIServer) patchGuardrailConfigFile(path string, updates map[string]any) error {
	original, err := captureConfigFileState(path)
	if err != nil {
		return err
	}
	if err := config.PatchYAMLFile(path, updates); err != nil {
		return err
	}
	if _, err := config.LoadRuntimeV8File(path); err != nil {
		if restoreErr := restoreConfigFileState(path, original); restoreErr != nil {
			return fmt.Errorf("api: patched config invalid: %w; restore failed: %v", err, restoreErr)
		}
		return fmt.Errorf("api: patched config invalid: %w", err)
	}
	return nil
}

func guardrailConfigContainsUpdates(cfg *config.Config, updates map[string]any) bool {
	if cfg == nil {
		return false
	}
	for key, value := range updates {
		switch key {
		case "guardrail.mode":
			want, ok := value.(string)
			if !ok || cfg.Guardrail.Mode != want {
				return false
			}
		case "guardrail.scanner_mode":
			want, ok := value.(string)
			if !ok || cfg.Guardrail.ScannerMode != want {
				return false
			}
		case "guardrail.block_message":
			want, ok := value.(string)
			if !ok || cfg.Guardrail.BlockMessage != want {
				return false
			}
		case "guardrail.connector":
			want, ok := value.(string)
			if !ok || cfg.Guardrail.Connector != want {
				return false
			}
		case "guardrail.hilt.enabled":
			want, ok := value.(bool)
			if !ok || cfg.Guardrail.HILT.Enabled != want {
				return false
			}
		case "guardrail.hilt.min_severity":
			want, ok := value.(string)
			if !ok || cfg.Guardrail.HILT.MinSeverity != want {
				return false
			}
		}
	}
	return true
}

func guardrailConfigResponse(cfg *config.Config) map[string]interface{} {
	resp := map[string]interface{}{}
	if cfg == nil {
		return resp
	}
	resp["mode"] = cfg.Guardrail.Mode
	resp["scanner_mode"] = cfg.Guardrail.ScannerMode
	resp["block_message"] = cfg.Guardrail.BlockMessage
	resp["connector"] = cfg.Guardrail.Connector
	resp["hilt_enabled"] = cfg.Guardrail.HILT.Enabled
	resp["hilt_min_severity"] = cfg.Guardrail.HILT.MinSeverity
	return resp
}

func (a *APIServer) evaluateGuardrailPolicy(ctx context.Context, input policy.GuardrailInput) (*policy.GuardrailOutput, error) {
	// Avarice F-3288: when a policy bundle is configured but
	// either the engine constructor or evaluation fails, the
	// previous code silently fell back to a built-in
	// severity-derived decision that allows clean/missing scanner
	// results and downgrades MEDIUM/HIGH to alert. That converted
	// every policy outage into a quiet enforcement bypass for
	// action-mode prompts. We now fail closed: any configured
	// policy directory whose engine/eval fails returns block in
	// action mode (and an explicit alert in observe mode for
	// audit visibility).
	if a.scannerCfg != nil && a.scannerCfg.PolicyDir != "" {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err != nil {
			return policyOutageVerdict(input,
				fmt.Sprintf("policy engine load failed: %v", err)), nil
		}
		out, evalErr := engine.EvaluateGuardrail(ctx, input)
		if evalErr != nil {
			return policyOutageVerdict(input,
				fmt.Sprintf("policy evaluation failed: %v", evalErr)), nil
		}
		return out, nil
	}

	// No policy directory configured at all — keep the legacy
	// severity-derived fallback. Operators that want strict
	// fail-closed behavior on missing policy must configure a
	// PolicyDir; the absence of one is treated as "no policy"
	// rather than "policy outage".
	sev := "NONE"
	var sources []string
	for _, res := range []*policy.GuardrailScanResult{input.LocalResult, input.CiscoResult} {
		if res == nil {
			continue
		}
		rank := map[string]int{"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
		if rank[res.Severity] > rank[sev] {
			sev = res.Severity
		}
		if res.Severity != "NONE" {
			sources = append(sources, "scanner")
		}
	}

	action := guardrailFallbackActionForSeverity(sev)
	if input.Mode == "observe" && action == "block" {
		action = "alert"
	}

	return &policy.GuardrailOutput{
		Action:         action,
		Severity:       sev,
		Reason:         "built-in fallback (no policy configured)",
		ScannerSources: sources,
	}, nil
}

// policyOutageVerdict builds a fail-closed verdict for guardrail
// evaluations when a configured policy bundle cannot be loaded or
// evaluated. Action mode blocks; observe mode keeps the request
// flowing but loud-flags it via alert + would_block-style telemetry.
func policyOutageVerdict(input policy.GuardrailInput, reason string) *policy.GuardrailOutput {
	action := "block"
	if input.Mode == "observe" {
		action = "alert"
	}
	return &policy.GuardrailOutput{
		Action:         action,
		Severity:       "HIGH",
		Reason:         "guardrail failing closed: " + reason,
		ScannerSources: []string{"policy-outage"},
	}
}

// metricsMiddleware records generated HTTP request count and duration.
//
// SECURITY (Plan B5): only the matched ServeMux pattern may become a route
// label. Raw paths can contain the scoped OTLP path token and are
// attacker-controlled, so unmatched requests collapse to one bounded token.
func (a *APIServer) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtime := a.apiOperationalV8Runtime()
		if runtime == nil {
			next.ServeHTTP(w, r)
			return
		}
		t0 := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if route == "" {
			// An empty ServeMux pattern is an unmatched path. Never use the raw
			// path here: it may contain a path token and is attacker-controlled,
			// which would leak secrets and create unbounded metric cardinality.
			route = "unmatched"
		}
		recordAPIRequestV8(r.Context(), runtime, r.Method, route, sw.status, time.Since(t0))
	})
}

// statusWriter captures the HTTP status code for metrics.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// tokenAuth wraps a handler with Bearer token authentication.
// GET /health is exempt to allow unauthenticated health checks.
func (a *APIServer) tokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		route := r.Pattern
		if route == "" {
			// Sanitize so the OTLP path-token is never recorded as a
			// route attribute on auth-failure telemetry.
			route = sanitizeRouteForTelemetry(r.URL.Path)
		}
		ctx := r.Context()

		token := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
		if token == "" {
			token = r.Header.Get("X-DefenseClaw-Token")
		}

		expected := ""
		if a.scannerCfg != nil {
			expected = a.scannerCfg.Gateway.Token
		}
		if expected == "" {
			// Fail closed when no token is configured. EnsureGatewayToken
			// synthesizes one at boot, so this branch
			// is unreachable in production. Treat it as a misconfiguration
			// (503) rather than silently allowing loopback — the previous
			// "no token, trust loopback" path was a local-IDOR risk.
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthMissingToken, "no_token_configured")
			http.Error(w, `{"error":"sidecar misconfigured: no gateway token"}`, http.StatusServiceUnavailable)
			return
		}
		if pathToken, source, ok := parseOTLPPathToken(r.URL.Path); ok && connector.IsLoopback(r) {
			scoped := a.lookupOTLPPathToken(source)
			if scoped != "" {
				if token != "" {
					a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "scoped_otlp_rejects_header_token")
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
				if constantTimeStringMatch(pathToken, scoped) {
					next.ServeHTTP(w, r)
					return
				}
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_scoped_path_token")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			// Legacy compatibility only for deployments that have not
			// minted a scoped token for this source yet. Once a scoped
			// token exists, the master gateway bearer must not
			// authenticate /otlp/<source>/<token> paths because that
			// would turn a single connector settings-file leak into
			// full gateway authority.
			if token == "" && constantTimeStringMatch(pathToken, expected) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if hookScope, ok := a.hookTokenScopeForPath(r.URL.Path); ok && connector.IsLoopback(r) && token != "" {
			if a.hookAPITokenMatches(hookScope, token) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/inspect/") && connector.IsLoopback(r) && token != "" {
			hookScope := strings.ToLower(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")))
			registered := false
			if a.connectorRegistry != nil {
				_, registered = a.connectorRegistry.Get(hookScope)
			}
			if registered && a.hookAPITokenMatches(hookScope, token) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if token == "" {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthMissingToken, "missing_token")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if !constantTimeStringMatch(token, expected) {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_token")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// DeepSec S2.MEDIUM ("CorrelationMiddleware mints
		// unauthenticated agent sessions"): now that auth has
		// succeeded, upgrade the previously peeked agent identity
		// to a fully minted entry so authenticated traffic still
		// gets a stable agent_instance_id on its emissions.
		r = r.WithContext(PromoteSessionIfAuthenticated(r.Context()))
		next.ServeHTTP(w, r)
	})
}

// constantTimeStringMatch returns true iff a == b without leaking
// the timing of WHERE the strings diverge, AND without leaking the
// length of `expected` to a probing caller.
//
// Background (L6 hardening): subtle.ConstantTimeCompare(a, b) is
// constant-time WITHIN equal-length inputs, but it short-circuits
// with zero on a length mismatch. All gateway tokens today are
// 64-char hex (EnsureGatewayToken + EnsureOTLPPathToken both write
// 32 bytes hex-encoded), so the practical leak is bounded by that
// invariant. However:
//
//  1. A future caller (operator-provided token, plugin-supplied
//     scope) could feed a different-length value, regressing the
//     invariant silently.
//  2. The codeguard rule for constant-time crypto explicitly calls
//     out length-leak risk; defence in depth is cheap here.
//
// The fix is to hash both inputs with SHA-256 first, then compare
// the fixed-width 32-byte digests in constant time. The hash
// adds ≈microseconds to the auth path (negligible vs. socket I/O)
// and removes any timing observability of length differences.
//
// We deliberately do NOT use HMAC + a process-local key: the
// inputs are themselves high-entropy CSPRNG tokens and we're
// comparing for equality, not protecting against precomputation
// of "what's the token?" — the digest never leaves this comparison.
func constantTimeStringMatch(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func (a *APIServer) emitHTTPAuthFailure(ctx context.Context, r *http.Request, _ string, _ gatewaylog.ErrorCode, metricReason string) {
	// Ordinary sidecar authentication failures use the canonical compliance
	// event plus its generated platform-health metric. OTLP receivers own the
	// more specific telemetry.authentication.failed event, including the inbound
	// signal and connector when those facts are known, and share the same
	// generated metric family. Both paths use fixed route labels and never fall
	// back to the legacy gateway event or Provider metric.
	if r != nil && !isOTLPEndpointPath(r.URL.Path) {
		// Target runtime startup guarantees the v8 graph. Missing capability,
		// collection disablement, or persistence failure cannot revive a legacy
		// gateway event or Provider metric.
		a.emitAPIAuthenticationFailureV8(ctx, metricReason)
		return
	}
	if r != nil {
		a.emitOTLPAuthenticationFailureV8(ctx, r, metricReason)
		metricRoute := "otlp"
		if signal, ok := otlpSignalFromRequestPath(r.URL.Path); ok {
			metricRoute += "-" + string(signal)
		}
		a.recordAPIAuthenticationFailureMetricV8(ctx, metricRoute, metricReason)
	}
}

// apiCSRFProtect is the CSRF gate for the REST API with structured auth telemetry.
//
// Plan A3 (S0.13): GET/HEAD remain exempt because the inspect handlers (and
// every state-changing endpoint) reject non-POST. OPTIONS is no longer a
// blanket exemption — CORS preflight is rejected via the same Sec-Fetch-Site
// gate that protects POST. There is no legitimate cross-origin caller of
// the sidecar API today; if one is added, it must explicitly bypass this
// gate by setting Sec-Fetch-Site to same-origin or none in a non-browser
// caller (where the header is absent).
func (a *APIServer) apiCSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		route := r.Pattern
		if route == "" {
			// SECURITY (Plan B5): never let the path-token reach a metric label.
			route = sanitizeRouteForTelemetry(r.URL.Path)
		}
		ctx := r.Context()

		// Sec-Fetch-Site is a browser-enforced header that cannot be spoofed
		// by JavaScript. When present, reject cross-site requests outright.
		// For OPTIONS (CORS preflight), this is the primary signal.
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
			if sfs != "same-origin" && sfs != "none" {
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "sec_fetch_site_rejected")
				http.Error(w, `{"error":"cross-site request rejected"}`, http.StatusForbidden)
				return
			}
		}
		if _, _, ok := parseOTLPPathToken(r.URL.Path); ok && connector.IsLoopback(r) {
			// SECURITY (Plan B5 follow-up): the X-DefenseClaw-Client header
			// CANNOT be enforced here because OTLP exporters (Gemini CLI's
			// settings.json, etc.) cannot set arbitrary HTTP headers — only
			// path / Content-Type / body. We do however enforce:
			//   1. Loopback (the conditional above; a non-loopback request
			//      bypasses this branch entirely and falls into the standard
			//      CSRF gate).
			//   2. localhost Origin if the browser supplied one (prevents
			//      non-loopback DNS rebinding from sneaking through).
			//   3. An OTLP Content-Type, mirroring the unparameterized
			//      /v1/logs|metrics|traces gate below, so a browser cannot
			//      smuggle a CSRF POST with default text/plain or
			//      application/x-www-form-urlencoded.
			if origin := r.Header.Get("Origin"); origin != "" && !isLocalhostOrigin(origin) {
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthOriginBlocked, "origin_blocked")
				http.Error(w, `{"error":"non-localhost Origin rejected"}`, http.StatusForbidden)
				return
			}
			if !isOTLPContentType(r.Header.Get("Content-Type")) {
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "bad_content_type")
				http.Error(w, `{"error":"Content-Type must be application/json or application/x-protobuf"}`, http.StatusUnsupportedMediaType)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// CORS preflights legitimately have no body / Content-Type but
		// browsers always set Origin and Sec-Fetch-Site=cross-site for them.
		// If an OPTIONS reaches here with same-origin / no Sec-Fetch-Site
		// (curl, internal callers) it must still present the CSRF tag.
		if r.Method == http.MethodOptions {
			if r.Header.Get("X-DefenseClaw-Client") == "" {
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "csrf_mismatch_options")
				http.Error(w, `{"error":"missing X-DefenseClaw-Client header"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("X-DefenseClaw-Client") == "" {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "csrf_mismatch")
			http.Error(w, `{"error":"missing X-DefenseClaw-Client header"}`, http.StatusForbidden)
			return
		}

		ct := r.Header.Get("Content-Type")
		if isOTLPEndpointPath(r.URL.Path) {
			if !isOTLPContentType(ct) {
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "bad_content_type")
				http.Error(w, `{"error":"Content-Type must be application/json or application/x-protobuf"}`, http.StatusUnsupportedMediaType)
				return
			}
		} else if !strings.Contains(ct, "application/json") {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "bad_content_type")
			http.Error(w, `{"error":"Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			if !isLocalhostOrigin(origin) {
				a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthOriginBlocked, "origin_blocked")
				http.Error(w, `{"error":"non-localhost Origin rejected"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// csrfProtect wraps a handler with localhost CSRF defenses. Mutating methods
// (POST, PUT, PATCH, DELETE) require:
//  1. X-DefenseClaw-Client header (blocks simple/no-cors browser requests)
//  2. Content-Type containing "application/json"
//  3. Origin, if present, must be a localhost address
//
// maxBodyMiddleware caps the request body size for state-changing methods
// to prevent memory exhaustion from oversized payloads.
func maxBodyMiddleware(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// Read-only requests (GET, HEAD, OPTIONS) are exempt.
func csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
			if sfs != "same-origin" && sfs != "none" {
				http.Error(w, `{"error":"cross-site request rejected"}`, http.StatusForbidden)
				return
			}
		}

		if r.Header.Get("X-DefenseClaw-Client") == "" {
			http.Error(w, `{"error":"missing X-DefenseClaw-Client header"}`, http.StatusForbidden)
			return
		}

		ct := r.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			http.Error(w, `{"error":"Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			if !isLocalhostOrigin(origin) {
				http.Error(w, `{"error":"non-localhost Origin rejected"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isLocalhostOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (a *APIServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func toEnforcementEntries(entries []audit.ActionEntry) []enforcementEntry {
	out := make([]enforcementEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, enforcementEntry{
			ID:         entry.ID,
			TargetType: entry.TargetType,
			TargetName: entry.TargetName,
			Reason:     entry.Reason,
			UpdatedAt:  entry.UpdatedAt,
		})
	}
	return out
}

func (a *APIServer) blockListEntries() []policy.ListEntry {
	return a.policyListEntries(true)
}

func (a *APIServer) allowListEntries() []policy.ListEntry {
	return a.policyListEntries(false)
}

func (a *APIServer) policyListEntries(blocked bool) []policy.ListEntry {
	if a.store == nil {
		return nil
	}

	pe := enforce.NewPolicyEngine(a.store)
	var (
		actions []audit.ActionEntry
		err     error
	)
	if blocked {
		actions, err = pe.ListBlocked()
	} else {
		actions, err = pe.ListAllowed()
	}
	if err != nil {
		return nil
	}

	entries := make([]policy.ListEntry, 0, len(actions))
	for _, action := range actions {
		entries = append(entries, policy.ListEntry{
			TargetType: action.TargetType,
			TargetName: action.TargetName,
			Reason:     action.Reason,
		})
	}
	return entries
}

func (a *APIServer) evaluateAdmissionPolicy(ctx context.Context, input policy.AdmissionInput) (*policy.AdmissionOutput, error) {
	if a.scannerCfg != nil && a.scannerCfg.PolicyDir != "" {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err == nil {
			out, evalErr := engine.Evaluate(ctx, input)
			if evalErr == nil {
				return out, nil
			}
		}
	}

	regoDir := ""
	if a.scannerCfg != nil {
		regoDir = a.scannerCfg.PolicyDir
	}
	return policy.EvaluateAdmissionFallback(input, policy.LoadFallbackProfile(regoDir)), nil
}

func classifyScanError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "no such file") || strings.Contains(msg, "executable file not found"):
		return "not_found"
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "parse") || strings.Contains(msg, "unmarshal") || strings.Contains(msg, "json"):
		return "parse"
	default:
		return "crash"
	}
}

// ---------------------------------------------------------------------------
// POST /policy/evaluate/firewall
// ---------------------------------------------------------------------------

func (a *APIServer) handlePolicyEvaluateFirewall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input policy.FirewallInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if input.Destination == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "destination is required"})
		return
	}

	ctx, observation, err := a.startAPIPolicyEvaluationV8(
		r.Context(), "firewall", "network", input.Destination,
	)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	engine, err := a.loadPolicyEngine()
	if err != nil {
		_ = observation.complete("error", "", "", err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := engine.EvaluateFirewall(ctx, input)
	if err != nil {
		_ = observation.complete("error", "", "", err)
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := observation.complete(out.Action, out.RuleName, "", nil); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}

	a.writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// POST /policy/evaluate/audit
// ---------------------------------------------------------------------------

func (a *APIServer) handlePolicyEvaluateAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input policy.AuditInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	ctx, observation, err := a.startAPIPolicyEvaluationV8(
		r.Context(), "audit", firstNonEmpty(input.EventType, "audit-event"), input.EventType,
	)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	engine, err := a.loadPolicyEngine()
	if err != nil {
		_ = observation.complete("error", "", input.Severity, err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := engine.EvaluateAudit(ctx, input)
	if err != nil {
		_ = observation.complete("error", "", input.Severity, err)
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	verdict := "expire"
	if out.Retain {
		verdict = "retain"
	}
	if err := observation.complete(verdict, out.RetainReason, input.Severity, nil); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}

	a.writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// POST /policy/evaluate/skill-actions
// ---------------------------------------------------------------------------

func (a *APIServer) handlePolicyEvaluateSkillActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input policy.SkillActionsInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if input.Severity == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "severity is required"})
		return
	}

	ctx, observation, err := a.startAPIPolicyEvaluationV8(
		r.Context(), "skill-actions", firstNonEmpty(input.TargetType, "skill"), "",
	)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	engine, err := a.loadPolicyEngine()
	if err != nil {
		_ = observation.complete("error", "", input.Severity, err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := engine.EvaluateSkillActions(ctx, input)
	if err != nil {
		_ = observation.complete("error", "", input.Severity, err)
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	verdict := out.RuntimeAction
	if out.ShouldBlock {
		verdict = "block"
	}
	if err := observation.complete(verdict, "", input.Severity, nil); err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}

	a.writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// POST /policy/reload — hot-reload OPA engine from disk
// ---------------------------------------------------------------------------

func (a *APIServer) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.scannerCfg == nil || a.scannerCfg.PolicyDir == "" {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy_dir not configured"})
		return
	}
	if a.observabilityV8RuntimeEmitter() == nil || a.logger == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "observability runtime unavailable"})
		return
	}
	recordFailure := func(reason string) {
		_ = a.recordAPIPolicyReloadMetricV8(r.Context(), "failed")
		_ = a.emitAPIPolicyReloadRejectedV8(r.Context(), reason)
	}

	// If a shared OPA engine is wired, use its atomic Reload(); otherwise
	// validate by constructing a throwaway engine (backward-compatible).
	if a.policyReloader != nil {
		if err := a.policyReloader(); err != nil {
			recordFailure(err.Error())
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "reload failed: " + err.Error(),
				"status": "failed",
			})
			return
		}
	} else {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err != nil {
			recordFailure(err.Error())
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "reload failed: " + err.Error(),
				"status": "failed",
			})
			return
		}
		if err := engine.Compile(); err != nil {
			recordFailure(err.Error())
			a.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":  "compilation failed: " + err.Error(),
				"status": "failed",
			})
			return
		}
	}

	// Any cached LLM-judge verdict was rendered under the previous
	// policy; drop it in O(1) so the next call re-evaluates under
	// the fresh rulepack. Safe no-op when the cache is unset.
	InvalidateJudgeVerdictCache()

	if err := a.logger.LogActionCtx(r.Context(), string(audit.ActionPolicyReload), a.scannerCfg.PolicyDir, "OPA policy reloaded via API"); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy reloaded but compliance logging failed"})
		return
	}
	if err := a.recordAPIPolicyReloadMetricV8(r.Context(), "success"); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy reloaded but observability metric failed"})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{
		"status":     "reloaded",
		"policy_dir": a.scannerCfg.PolicyDir,
	})
}

// loadPolicyEngine creates a fresh policy engine from the configured policy_dir.
func (a *APIServer) loadPolicyEngine() (*policy.Engine, error) {
	if a.scannerCfg == nil || a.scannerCfg.PolicyDir == "" {
		return nil, fmt.Errorf("policy_dir not configured")
	}
	return policy.New(a.scannerCfg.PolicyDir)
}

// codeScanRequest is the payload for POST /api/v1/scan/code.
type codeScanRequest struct {
	Path string `json:"path"`
}

// handleCodeScan runs the built-in source-code scanner suite on the given
// filesystem path and returns the ScanResult with OTel signals emitted via
// the shared audit logger.
func (a *APIServer) handleCodeScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req codeScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Path == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is required"})
		return
	}

	rulesDir := ""
	if a.scannerCfg != nil {
		rulesDir = a.scannerCfg.Scanners.CodeGuard
	}

	result, err := scanner.ScanCode(r.Context(), req.Path, rulesDir)
	if err != nil {
		a.recordAPIScanErrorV8(r.Context(), "codeguard", "code", classifyScanError(err))
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(r.Context(), result, "", ScanCorrelationFromContext(r.Context()))
	}

	// Keep the authenticated REST response conservative by default. Canonical
	// persistence above already retained the source facts so each configured
	// destination can independently apply `none`, `detect`, or `whole`
	// redaction. This in-place copy change affects only the response body.
	// Title remains an operator-searchable rule summary.
	for i := range result.Findings {
		f := &result.Findings[i]
		f.Description = redaction.ForSinkString(f.Description)
		f.Location = redaction.ForSinkString(f.Location)
		f.Remediation = redaction.ForSinkString(f.Remediation)
	}

	a.writeJSON(w, http.StatusOK, result)
}

// handleNetworkEgress serves GET /api/v1/network-egress and
// POST /api/v1/network-egress.
//
// GET  — list structured outbound network call records from the audit DB.
//
//	Query params:
//	  limit=N    (default 50, max 500)
//	  hostname=H (filter to exact hostname)
//
// POST — ingest a single egress event from an external observer (e.g. a
//
//	runtime hook running inside the agent process) so that it is
//	persisted alongside tool-lifecycle events.
func (a *APIServer) handleNetworkEgress(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		a.handleNetworkEgressList(w, r)
	case http.MethodPost:
		a.handleNetworkEgressIngest(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleNetworkEgressList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 50
	if raw := q.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 500 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1–500"})
			return
		}
		limit = parsed
	}

	f := audit.NetworkEgressFilter{
		Hostname:    q.Get("hostname"),
		SessionID:   q.Get("session_id"),
		AgentID:     q.Get("agent_id"),
		RootAgentID: q.Get("root_agent_id"),
		UserID:      q.Get("user_id"),
		Limit:       limit,
	}

	// ?blocked=true|false — optional boolean filter
	if raw := q.Get("blocked"); raw != "" {
		var b bool
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true", "1":
			b = true
		case "false", "0":
			b = false
		default:
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "blocked must be true, false, 1, or 0"})
			return
		}
		f.Blocked = &b
	}

	// ?since=<RFC3339> — optional time lower-bound filter
	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be RFC3339 (e.g. 2026-01-02T15:04:05Z)"})
			return
		}
		f.Since = t
	}

	events, err := a.store.QueryNetworkEgressEvents(f)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type response struct {
		Events []audit.NetworkEgressRow `json:"events"`
		Count  int                      `json:"count"`
	}
	if events == nil {
		events = []audit.NetworkEgressRow{}
	}
	a.writeJSON(w, http.StatusOK, response{Events: events, Count: len(events)})
}

func (a *APIServer) handleNetworkEgressIngest(w http.ResponseWriter, r *http.Request) {
	var evt audit.NetworkEgressEvent
	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := evt.Validate(); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	env := audit.EnvelopeFromContext(r.Context())
	identity := AgentIdentityFromContext(r.Context())
	evt.SessionID = firstNonEmpty(SessionIDFromContext(r.Context()), env.SessionID, evt.SessionID)
	evt.Connector = firstNonEmpty(env.Connector, evt.Connector)
	evt.AgentID = firstNonEmpty(identity.AgentID, env.AgentID, evt.AgentID)
	evt.ToolID = firstNonEmpty(env.ToolID, evt.ToolID)
	userID, _ := userFromHTTPRequest(r, nil)
	evt.UserID = firstNonEmpty(userID, evt.UserID)
	if evt.AgentLifecycleID == "" && evt.Connector != "" && evt.SessionID != "" && evt.AgentID != "" {
		evt.AgentLifecycleID = stableLLMEventID("lifecycle", evt.Connector, evt.SessionID, evt.AgentID)
	}
	if snapshot, ok := a.hookLifecycleSnapshot(evt.Connector, evt.SessionID, evt.AgentID); ok {
		evt.RootAgentID = firstNonEmpty(evt.RootAgentID, snapshot.RootAgentID, snapshot.AgentID)
		evt.ParentAgentID = firstNonEmpty(evt.ParentAgentID, snapshot.ParentAgentID)
		evt.RootSessionID = firstNonEmpty(evt.RootSessionID, snapshot.RootSessionID, snapshot.SessionID)
		if snapshot.LifecycleID != "" {
			evt.AgentLifecycleID = snapshot.LifecycleID
		}
		if snapshot.ExecutionID != "" {
			evt.AgentExecutionID = snapshot.ExecutionID
		}
	}
	evt.RootAgentID = firstNonEmpty(evt.RootAgentID, evt.AgentID)
	evt.RootSessionID = firstNonEmpty(evt.RootSessionID, evt.SessionID)

	if a.logger == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit logger not configured"})
		return
	}
	if err := a.logger.LogNetworkEgress(r.Context(), evt); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
