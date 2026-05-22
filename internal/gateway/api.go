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
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// APIServer exposes a local REST API for CLI and plugin communication
// with the running sidecar.
type APIServer struct {
	health      *SidecarHealth
	client      *Client
	store       *audit.Store
	logger      *audit.Logger
	addr        string
	scannerCfg  *config.Config
	otel        *telemetry.Provider
	hilt        *HILTApprovalManager
	notifier    *notifier.Dispatcher
	aiDiscovery *inventory.ContinuousDiscoveryService

	// cfgMu protects mutable fields in scannerCfg.Guardrail (Mode,
	// ScannerMode) which can be changed at runtime via the PATCH
	// /v1/guardrail/config endpoint while other goroutines read them.
	cfgMu sync.RWMutex

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
	//  2. Mtime drift for a HIT scope (M1 fix). Closes the rotation
	//     gap where an operator regenerates the on-disk token (e.g.
	//     post-rotation policy or a security-incident response)
	//     while the gateway keeps running. Without this check the
	//     in-memory token wins forever and every loopback OTLP
	//     request after the rotation 401s until the gateway is
	//     restarted.
	//
	// Both refreshes are rate-limited per scope by otlpPathTokenReloadAt
	// so a hostile or noisy caller cannot turn the auth path into a
	// per-request disk stampede. Values are kept as a small
	// otlpPathTokenEntry struct that carries the token AND the mtime
	// observed when it was loaded, so rotation detection is a single
	// os.Stat (no full read on the steady-state path).
	otlpPathTokenMu         sync.RWMutex
	otlpPathTokens          map[connector.OTLPPathTokenScope]otlpPathTokenEntry
	otlpPathTokenReloadAt   map[connector.OTLPPathTokenScope]time.Time
	otlpPathTokenLastStatAt map[connector.OTLPPathTokenScope]time.Time

	// policyReloader, when set, is called by the /policy/reload handler
	// to atomically refresh the shared OPA engine used by the watcher.
	policyReloader func() error

	claudeCodeMu                 sync.Mutex
	claudeCodeLastComponentScan  time.Time
	codexMu                      sync.Mutex
	codexLastComponentScan       time.Time
	rawTelemetryMu               sync.RWMutex
	rawTelemetryDedupe           *rawTelemetryDeduper
	llmPromptMu                  sync.Mutex
	llmPromptBySourceSession     map[string]string
	llmPromptBySourceSessionTurn map[string]string

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
	ciscoInspector *CiscoInspectClient
}

// SetCiscoInspector wires the Cisco AI Defense client onto the API
// server. Pass nil to disable the hook-lane AID call (e.g. when the
// operator did not configure cisco_ai_defense.api_key_env).
func (a *APIServer) SetCiscoInspector(c *CiscoInspectClient) {
	a.ciscoInspector = c
}

// SetOTelProvider attaches the OTel provider so guardrail events
// can be recorded as metrics.
func (a *APIServer) SetOTelProvider(p *telemetry.Provider) {
	a.otel = p
}

// otlpPathTokenEntry bundles the cached path-token with the mtime of
// the on-disk file when it was last loaded. Rotation detection
// compares the live mtime against this value via a cheap os.Stat.
type otlpPathTokenEntry struct {
	token string
	mtime time.Time
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
//
// Mtime is sampled from the on-disk file when available so the
// rotation-detection path in lookupOTLPPathToken can avoid an
// immediate reload on the first request after boot. If stat fails
// (the boot caller may pass values not yet on disk in test
// environments) the mtime is left as the zero value, which forces
// the first lookup to reload — strictly safer than caching a token
// we can't compare against the file system.
func (a *APIServer) SetOTLPPathTokens(tokens map[connector.OTLPPathTokenScope]string) {
	a.otlpPathTokenMu.Lock()
	defer a.otlpPathTokenMu.Unlock()
	if tokens == nil {
		a.otlpPathTokens = nil
		return
	}
	dataDir := a.configDataDir()
	cp := make(map[connector.OTLPPathTokenScope]otlpPathTokenEntry, len(tokens))
	for k, v := range tokens {
		entry := otlpPathTokenEntry{token: v}
		if dataDir != "" {
			if path, err := connector.OTLPPathTokenFilePath(dataDir, k); err == nil {
				if info, err := os.Stat(path); err == nil {
					entry.mtime = info.ModTime()
				}
			}
		}
		cp[k] = entry
	}
	a.otlpPathTokens = cp
}

// otlpPathTokenReloadMinInterval bounds disk I/O on the loopback OTLP auth
// path. After a cache miss OR a rotation-suspected hit for a known scope
// we re-read the on-disk token file at most once per scope per this
// interval; subsequent requests before the interval elapses use the
// in-memory value (or "" on miss) without touching disk. 500ms is short
// enough that the very next OTLP retry after `defenseclaw setup geminicli`
// or a token rotation succeeds in real operator workflows, and long enough
// that an attacker probing /otlp/geminicli/<random>/v1/* cannot weaponise
// the reload into a disk DoS.
const otlpPathTokenReloadMinInterval = 500 * time.Millisecond

// otlpPathTokenStatMinInterval bounds os.Stat calls on the hot
// auth-check path. We only check the on-disk mtime once per scope per
// this interval; in between, every request reuses the cached entry
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
//   - M1 rotation: on-disk mtime moved past the cached mtime →
//     evict + reload.
//   - Reload error / disappearance: file removed → drop the
//     in-memory entry so the next request 401s instead of
//     authenticating a stale token forever.
//
// All three refreshes share the same per-scope rate limiter
// (otlpPathTokenReloadAt) so a hostile or noisy caller cannot
// turn the auth path into a disk-stampede primitive. Stat calls
// for rotation detection are gated by otlpPathTokenLastStatAt
// to keep the steady-state per-request cost effectively zero.
// Unknown scopes never trigger disk I/O.
func (a *APIServer) lookupOTLPPathToken(source string) string {
	scope := connector.OTLPPathTokenScope(source)

	// Fast path: read under RLock and decide whether a stat is due.
	// The stat throttle (otlpPathTokenLastStatAt) is checked for
	// BOTH cache-hit and cache-miss cases — a missing token file
	// for a known scope must not turn into one os.Stat per request,
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
	if a.otlpPathTokens != nil {
		if e, ok := a.otlpPathTokens[scope]; ok {
			cached = e
			haveCached = ok && e.token != ""
		}
	}

	// Rate-limit reloads so a flood of misses or rotation probes
	// can't issue one disk read per request.
	if a.otlpPathTokenReloadAt != nil {
		if last, ok := a.otlpPathTokenReloadAt[scope]; ok &&
			time.Since(last) < otlpPathTokenReloadMinInterval {
			if haveCached {
				return cached.token
			}
			return ""
		}
	}

	// Stat the on-disk file. We do this regardless of whether we
	// have a cached entry: a missing file means the operator has
	// torn down the connector, in which case authenticating the
	// stale in-memory token would be a regression. A present file
	// with an unchanged mtime is the steady-state path and avoids
	// the read+parse cost.
	tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return ""
	}
	if a.otlpPathTokenLastStatAt == nil {
		a.otlpPathTokenLastStatAt = make(map[connector.OTLPPathTokenScope]time.Time)
	}
	a.otlpPathTokenLastStatAt[scope] = time.Now()

	info, statErr := os.Stat(tokenPath)
	if statErr != nil {
		if !os.IsNotExist(statErr) {
			// Permission flips and other stat failures are treated as
			// fail-closed. Returning a cached token here would keep a
			// revoked/hidden token valid until restart.
			return ""
		}
		// File is gone — drop any stale cached entry and fail
		// closed so the next OTLP request 401s rather than
		// authenticating a removed token.
		if a.otlpPathTokens != nil {
			delete(a.otlpPathTokens, scope)
		}
		return ""
	}

	// Cached entry is still current — refresh the stat timestamp
	// (already done above) and return without disk-read cost.
	if haveCached && cached.mtime.Equal(info.ModTime()) {
		return cached.token
	}

	// Either no cache yet or mtime moved → reload from disk.
	if a.otlpPathTokenReloadAt == nil {
		a.otlpPathTokenReloadAt = make(map[connector.OTLPPathTokenScope]time.Time)
	}
	a.otlpPathTokenReloadAt[scope] = time.Now()

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
	a.otlpPathTokens[scope] = otlpPathTokenEntry{token: tok, mtime: info.ModTime()}
	return tok
}

func (a *APIServer) SetHILTApprovalManager(m *HILTApprovalManager) {
	a.hilt = m
}

// SetAIDiscoveryService wires the continuous AI discovery service so
// the API can answer /v1/ai/* endpoints from a live store. Safe to
// call with nil — endpoint handlers short-circuit on a nil service.
func (a *APIServer) SetAIDiscoveryService(svc *inventory.ContinuousDiscoveryService) {
	a.aiDiscovery = svc
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
		for _, name := range []string{"hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity"} {
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

// Run starts the HTTP server and blocks until ctx is cancelled.
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
	// request-ID then OTel so the HTTP server span includes the full chain.
	handler = requestIDMiddleware(handler)
	handler = otelHTTPServerMiddleware("sidecar-api", handler)

	srv := &http.Server{
		Addr:    a.addr,
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[sidecar-api] listening on %s\n", a.addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
		Name               string                           `json:"name"`
		Description        string                           `json:"description"`
		Source             string                           `json:"source"`
		ToolInspectionMode string                           `json:"tool_inspection_mode"`
		SubprocessPolicy   string                           `json:"subprocess_policy"`
		HookCapabilities   *connector.HookCapability        `json:"hook_capabilities,omitempty"`
		Capabilities       *connector.ConnectorCapabilities `json:"capabilities,omitempty"`
		Locations          *connector.ConnectorLocations    `json:"locations,omitempty"`
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
		"connector_mode": a.connectorModeSummary(),
	}

	if a.client != nil && a.client.Hello() != nil {
		hello := a.client.Hello()
		status["gateway_hello"] = hello
	}

	a.writeJSON(w, http.StatusOK, status)
}

// connectorModeSummary returns the per-connector enforcement /
// observability mode for the active connector. The shape is:
//
//	{
//	  "connector":  "codex" | "claudecode" | "openclaw" | "zeptoclaw",
//	  "mode":       "guardrail" | "observability",
//	  "telemetry":  ["hooks", "otel", "notify"],   // active channels
//	  "proxy_intercept": true | false,
//	}
//
// "guardrail" means the proxy listener is bound and inline blocking
// is active; "observability" means traffic is NOT intercepted and
// the gateway only ingests telemetry. Telemetry channels reflect
// what Setup() actually wired (hooks always on; otel + notify are
// codex/claude-only; openclaw/zeptoclaw enumerate "hooks" alone).
func (a *APIServer) connectorModeSummary() map[string]interface{} {
	name := a.connectorName()
	mode := "guardrail"
	intercept := true
	var telemetry []string

	switch name {
	case "codex":
		mode = "observability"
		intercept = false
		// codex telemetry always wires all three channels (hooks,
		// the [otel.exporter.otlp-http] block, the notify bridge).
		telemetry = []string{"hooks", "otel", "notify"}
	case "claudecode":
		mode = "observability"
		intercept = false
		// Claude Code uses hooks + the OTel env-block; no notify
		// equivalent (Anthropic doesn't ship a turn-complete shim).
		telemetry = []string{"hooks", "otel"}
	case "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity":
		mode = "observability"
		intercept = false
		telemetry = []string{"hooks"}
		if name == "geminicli" || name == "copilot" {
			telemetry = append(telemetry, "otel")
		}
	default:
		// openclaw / zeptoclaw / unknown: enforcement is the only
		// supported mode today. Hooks are wired by the connector;
		// no native OTel surface from those agents.
		telemetry = []string{"hooks"}
	}

	return map[string]interface{}{
		"connector":       name,
		"mode":            mode,
		"telemetry":       telemetry,
		"proxy_intercept": intercept,
	}
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
		if a.store == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
			return
		}
		logger = audit.NewLogger(a.store)
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
	if err := persistAuditEvent(a.logger, a.store, event); err != nil {
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

	start := time.Now()
	ctx := r.Context()
	var span trace.Span
	if a.otel != nil {
		ctx, span = a.otel.StartPolicySpan(ctx, "admission", req.Input.TargetType, req.Input.TargetName)
	}
	endAdmission := func(verdict, reason string) {
		if a.otel != nil && span != nil {
			a.otel.EndPolicySpan(span, "admission", verdict, reason, start)
		}
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
		}
	}

	out, err := a.evaluateAdmissionPolicy(ctx, input)
	if err != nil {
		endAdmission("error", err.Error())
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	if a.otel != nil {
		endAdmission(out.Verdict, out.Reason)
		a.otel.RecordAdmissionDecision(ctx, out.Verdict, req.Input.TargetType, "api")
		a.otel.RecordPolicyEvaluation(ctx, "admission", out.Verdict)
		latencyMs := float64(time.Since(start).Milliseconds())
		a.otel.RecordPolicyLatency(ctx, "admission", latencyMs)
		// Feed the <2000ms block SLO histogram for every admission
		// decision so the dashboard can compare blocked vs allowed
		// latency distributions.
		a.otel.RecordBlockSLO(ctx, req.Input.TargetType, latencyMs)
		if out.Verdict == "blocked" || out.Verdict == "rejected" {
			a.otel.EmitPolicyDecision("admission", out.Verdict, req.Input.TargetName, req.Input.TargetType, out.Reason, nil)
		}
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
		if a.otel != nil {
			a.otel.RecordScanError(r.Context(), "skill-scanner", "skill", classifyScanError(err))
		}
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
		if a.otel != nil {
			a.otel.RecordScanError(r.Context(), "plugin-scanner", "plugin", classifyScanError(err))
		}
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
		if a.otel != nil {
			a.otel.RecordScanError(r.Context(), "mcp-scanner", "mcp", classifyScanError(err))
		}
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
	if req.Direction == "" || req.Action == "" || req.Severity == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "direction, action, and severity are required"})
		return
	}

	// PR #141 audit M6: compute the redacted reason BEFORE the details
	// string is composed so the audit-store row, the gateway.log line,
	// and any sink-forwarded copy all carry the redacted form. The
	// upstream rule-id literal is still preserved on stderr (see
	// switch-block below) for operator-facing visibility, but every
	// persisted surface now matches the rest of the v7 redaction
	// contract.
	redactedReason := redaction.Reason(req.Reason)
	details := fmt.Sprintf("direction=%s action=%s severity=%s findings=%d elapsed_ms=%.1f",
		req.Direction, req.Action, req.Severity, len(req.Findings), req.ElapsedMs)
	if req.Reason != "" {
		details += fmt.Sprintf(" reason=%s", truncate(redactedReason, 120))
	}

	if nfs := NormalizeScanVerdict(&ScanVerdict{
		Severity: req.Severity,
		Findings: req.Findings,
	}); len(nfs) > 0 {
		ids := make([]string, 0, len(nfs))
		seen := make(map[string]bool, len(nfs))
		for _, nf := range nfs {
			if seen[nf.CanonicalID] {
				continue
			}
			seen[nf.CanonicalID] = true
			ids = append(ids, nf.CanonicalID)
			if len(ids) >= 8 {
				break
			}
		}
		details += fmt.Sprintf(" canonical=%s", strings.Join(ids, ","))
	}

	// Both Reason and Findings are composed upstream by the
	// guardrail proxy and routinely embed the matched literal
	// in RULE-ID:description form. redactedReason is computed
	// above (see audit M6); the same Reveal-aware redaction is
	// applied to each finding for parity with the persisted
	// `details` string. Rule IDs survive intact in either form.
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

	requestID := RequestIDFromContext(r.Context())
	if requestID != "" {
		// Append the correlation key so the human-readable
		// gateway.log line (which still routes through LogAction
		// and does not carry structured fields) is also searchable
		// by request_id. Structured sinks pick it up from the
		// dedicated Event.RequestID column below.
		details += fmt.Sprintf(" request_id=%s", requestID)
	}
	if a.logger != nil {
		// v7 envelope threading: see review finding C1. The previous
		// LogActionWithCorrelation carried only trace_id + request_id
		// onto the guardrail-verdict audit row — every other
		// dimension (session_id, agent_*, policy_id, destination_app,
		// tool_*) was silently dropped before the row reached
		// SQLite/sinks/OTel. LogActionCtx routes through the same
		// ctx envelope the middleware already stamped for this
		// request so all five surfaces agree.
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionGuardrailVerdict), req.Model, details)
	}
	if a.store != nil {
		evt := audit.Event{
			Action:    string(audit.ActionGuardrailInspection),
			Target:    req.Model,
			Severity:  req.Severity,
			Details:   details,
			Timestamp: time.Now().UTC(),
			RequestID: requestID,
		}
		// Store-level twin row (TUI-only surface) — ApplyEnvelope
		// keeps it in lockstep with the logger row above.
		audit.ApplyEnvelope(&evt, audit.EnvelopeFromContext(r.Context()))
		_ = a.store.LogEvent(evt)
	}
	_ = persistAuditEvent(a.logger, a.store, audit.Event{
		Action:    string(audit.ActionGuardrailInspection),
		Target:    req.Model,
		Severity:  req.Severity,
		Details:   details,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
	})

	if a.otel != nil {
		ctx := r.Context()
		a.otel.RecordGuardrailEvaluation(ctx, "guardrail-proxy", req.Action)
		a.otel.RecordGuardrailLatency(ctx, "guardrail-proxy", req.ElapsedMs)
		if req.CiscoElapsedMs > 0 {
			a.otel.RecordGuardrailLatency(ctx, "cisco-ai-defense", req.CiscoElapsedMs)
			a.otel.RecordGuardrailEvaluation(ctx, "cisco-ai-defense", req.Action)
		}
		if req.TokensIn != nil || req.TokensOut != nil {
			var tIn, tOut int64
			if req.TokensIn != nil {
				tIn = *req.TokensIn
			}
			if req.TokensOut != nil {
				tOut = *req.TokensOut
			}
			agentName := a.connectorName()
			if reg := SharedAgentRegistry(); reg != nil && reg.AgentName() != "" {
				agentName = reg.AgentName()
			}
			a.otel.RecordLLMTokens(ctx, "chat", "defenseclaw", req.Model, agentName, SharedAgentRegistry().AgentID(), tIn, tOut)
		}
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type guardrailEvaluateRequest struct {
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
	if req.Direction == "" || req.Mode == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "direction and mode are required"})
		return
	}

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

	out, err := a.evaluateGuardrailPolicy(r.Context(), input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] evaluate error: %v\n", err)
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	details := fmt.Sprintf("direction=%s action=%s severity=%s scanner_mode=%s sources=%v elapsed_ms=%.1f",
		req.Direction, out.Action, out.Severity, req.ScannerMode, out.ScannerSources, req.ElapsedMs)
	if out.Reason != "" {
		details += fmt.Sprintf(" reason=%s", truncate(out.Reason, 120))
	}

	fmt.Fprintf(os.Stderr, "[guardrail] evaluate <<< action=%s severity=%s sources=%v reason=%q\n",
		out.Action, out.Severity, out.ScannerSources,
		redaction.Reason(truncate(out.Reason, 120)))

	requestID := RequestIDFromContext(r.Context())
	if requestID != "" {
		details += fmt.Sprintf(" request_id=%s", requestID)
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionGuardrailOPAVerdict), req.Model, details)
	}
	if a.store != nil {
		evt := audit.Event{
			Action:    string(audit.ActionGuardrailOPAInspection),
			Target:    req.Model,
			Severity:  out.Severity,
			Details:   details,
			Timestamp: time.Now().UTC(),
			RequestID: requestID,
		}
		audit.ApplyEnvelope(&evt, audit.EnvelopeFromContext(r.Context()))
		_ = a.store.LogEvent(evt)
	}
	_ = persistAuditEvent(a.logger, a.store, audit.Event{
		Action:    string(audit.ActionGuardrailOPAInspection),
		Target:    req.Model,
		Severity:  out.Severity,
		Details:   details,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
	})

	if a.otel != nil {
		ctx := r.Context()
		for _, src := range out.ScannerSources {
			a.otel.RecordGuardrailEvaluation(ctx, src, out.Action)
		}
		a.otel.RecordGuardrailLatency(ctx, "opa-guardrail", req.ElapsedMs)
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
		if a.scannerCfg != nil {
			a.cfgMu.RLock()
			cfg["mode"] = a.scannerCfg.Guardrail.Mode
			cfg["scanner_mode"] = a.scannerCfg.Guardrail.ScannerMode
			a.cfgMu.RUnlock()
		}
		a.writeJSON(w, http.StatusOK, cfg)

	case http.MethodPatch:
		// PR #141 audit C1: defense-in-depth gate. tokenAuth already
		// fail-closes when no gateway token is configured, but mode
		// changes are too security-sensitive to depend on a single
		// middleware layer. A future refactor that exposes this
		// handler outside the tokenAuth chain (or a misconfigured
		// custom mux) must not silently downgrade `action` → `observe`
		// without an authenticated caller. Re-validate here with the
		// same constant-time compare tokenAuth uses.
		if a.scannerCfg != nil {
			token := ""
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
			if token == "" {
				token = r.Header.Get("X-DefenseClaw-Token")
			}
			expected := a.scannerCfg.Gateway.Token
			if expected == "" || token == "" || !constantTimeStringMatch(token, expected) {
				a.writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "guardrail config changes require a valid gateway token — set DEFENSECLAW_GATEWAY_TOKEN",
				})
				return
			}
		}

		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		if a.scannerCfg == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
			return
		}

		a.cfgMu.Lock()

		oldMode := a.scannerCfg.Guardrail.Mode
		oldScannerMode := a.scannerCfg.Guardrail.ScannerMode

		changed := []string{}
		if mode, ok := req["mode"]; ok && (mode == "observe" || mode == "action") {
			a.scannerCfg.Guardrail.Mode = mode
			changed = append(changed, "mode="+mode)
		}
		if sm, ok := req["scanner_mode"]; ok && (sm == "local" || sm == "remote" || sm == "both") {
			a.scannerCfg.Guardrail.ScannerMode = sm
			changed = append(changed, "scanner_mode="+sm)
		}

		if len(changed) == 0 {
			a.cfgMu.Unlock()
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid fields to update"})
			return
		}

		if err := a.writeGuardrailRuntime(); err != nil {
			a.scannerCfg.Guardrail.Mode = oldMode
			a.scannerCfg.Guardrail.ScannerMode = oldScannerMode
			a.cfgMu.Unlock()
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		resp := map[string]interface{}{
			"status":       "updated",
			"changed":      changed,
			"mode":         a.scannerCfg.Guardrail.Mode,
			"scanner_mode": a.scannerCfg.Guardrail.ScannerMode,
		}

		a.cfgMu.Unlock()

		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionGuardrailConfigReload), "", strings.Join(changed, " "))
		}

		a.writeJSON(w, http.StatusOK, resp)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) writeGuardrailRuntime() error {
	if a.scannerCfg == nil {
		return fmt.Errorf("api: no config available")
	}
	runtimeFile := filepath.Join(a.scannerCfg.DataDir, "guardrail_runtime.json")
	data, err := json.Marshal(map[string]string{
		"mode":          a.scannerCfg.Guardrail.Mode,
		"scanner_mode":  a.scannerCfg.Guardrail.ScannerMode,
		"block_message": a.scannerCfg.Guardrail.BlockMessage,
	})
	if err != nil {
		return fmt.Errorf("api: marshal runtime config: %w", err)
	}
	return os.WriteFile(runtimeFile, data, 0o600)
}

func (a *APIServer) evaluateGuardrailPolicy(ctx context.Context, input policy.GuardrailInput) (*policy.GuardrailOutput, error) {
	if a.scannerCfg != nil && a.scannerCfg.PolicyDir != "" {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err == nil {
			out, evalErr := engine.EvaluateGuardrail(ctx, input)
			if evalErr == nil {
				return out, nil
			}
		}
	}

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
		Reason:         "built-in fallback (OPA unavailable)",
		ScannerSources: sources,
	}, nil
}

// metricsMiddleware records HTTP request count and duration via OTel.
//
// SECURITY (Plan B5): the path-token OTLP endpoint encodes the master gateway
// bearer token as a URL segment, so we MUST sanitize r.URL.Path before any
// telemetry sink sees it — otherwise the token would leak to any backend the
// gateway exports OTel metrics to. We also prefer r.Pattern when set so
// parametric routes don't blow up label cardinality.
func (a *APIServer) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.otel == nil {
			next.ServeHTTP(w, r)
			return
		}
		t0 := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		durationMs := float64(time.Since(t0).Milliseconds())
		route := r.Pattern
		if route == "" {
			route = sanitizeRouteForTelemetry(r.URL.Path)
		}
		a.otel.RecordHTTPRequest(r.Context(), r.Method, route, sw.status, durationMs)
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

func (a *APIServer) emitHTTPAuthFailure(ctx context.Context, r *http.Request, route string, code gatewaylog.ErrorCode, metricReason string) {
	actor := "anonymous"
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" || r.Header.Get("X-DefenseClaw-Token") != "" {
		actor = "claimed"
	}
	msg := fmt.Sprintf("sidecar API auth failure (actor=%s client_ip=%s ua=%q)",
		actor, ClientIPRedacted(r), TruncateUserAgent256(r.UserAgent()))
	emitGatewayError(ctx, gatewaylog.SubsystemAuth, code, msg, nil)
	if a.otel != nil {
		a.otel.RecordHTTPAuthFailure(ctx, route, metricReason)
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
	case strings.Contains(msg, "not found") || strings.Contains(msg, "executable file not found"):
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

	start := time.Now()
	ctx := r.Context()
	var span trace.Span
	if a.otel != nil {
		ctx, span = a.otel.StartPolicySpan(ctx, "firewall", "network", input.Destination)
	}
	endFw := func(verdict, detail string) {
		if a.otel != nil && span != nil {
			a.otel.EndPolicySpan(span, "firewall", verdict, detail, start)
		}
	}

	engine, err := a.loadPolicyEngine()
	if err != nil {
		endFw("error", err.Error())
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := engine.EvaluateFirewall(ctx, input)
	if err != nil {
		endFw("error", err.Error())
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.otel != nil {
		endFw(out.Action, out.RuleName)
		a.otel.RecordPolicyEvaluation(ctx, "firewall", out.Action)
		if out.Action == "deny" || out.Action == "block" {
			a.otel.EmitPolicyDecision("firewall", out.Action, input.Destination, "network", out.RuleName, nil)
		}
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

	start := time.Now()
	ctx := r.Context()
	var span trace.Span
	if a.otel != nil {
		ctx, span = a.otel.StartPolicySpan(ctx, "audit", input.EventType, input.Severity)
	}
	endAud := func(verdict, detail string) {
		if a.otel != nil && span != nil {
			a.otel.EndPolicySpan(span, "audit", verdict, detail, start)
		}
	}

	engine, err := a.loadPolicyEngine()
	if err != nil {
		endAud("error", err.Error())
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := engine.EvaluateAudit(ctx, input)
	if err != nil {
		endAud("error", err.Error())
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.otel != nil {
		verdict := "expire"
		if out.Retain {
			verdict = "retain"
		}
		endAud(verdict, out.RetainReason)
		a.otel.RecordPolicyEvaluation(ctx, "audit", verdict)
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

	start := time.Now()
	ctx := r.Context()
	var span trace.Span
	if a.otel != nil {
		ctx, span = a.otel.StartPolicySpan(ctx, "skill-actions", input.TargetType, input.Severity)
	}
	endSkill := func(verdict, detail string) {
		if a.otel != nil && span != nil {
			a.otel.EndPolicySpan(span, "skill-actions", verdict, detail, start)
		}
	}

	engine, err := a.loadPolicyEngine()
	if err != nil {
		endSkill("error", err.Error())
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	out, err := engine.EvaluateSkillActions(ctx, input)
	if err != nil {
		endSkill("error", err.Error())
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.otel != nil {
		verdict := out.RuntimeAction
		if out.ShouldBlock {
			verdict = "block"
		}
		endSkill(verdict, "")
		a.otel.RecordPolicyEvaluation(ctx, "skill-actions", verdict)
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

	// If a shared OPA engine is wired, use its atomic Reload(); otherwise
	// validate by constructing a throwaway engine (backward-compatible).
	if a.policyReloader != nil {
		if err := a.policyReloader(); err != nil {
			if a.otel != nil {
				a.otel.RecordPolicyReload(r.Context(), "failed")
			}
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "reload failed: " + err.Error(),
				"status": "failed",
			})
			return
		}
	} else {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err != nil {
			if a.otel != nil {
				a.otel.RecordPolicyReload(r.Context(), "failed")
			}
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "reload failed: " + err.Error(),
				"status": "failed",
			})
			return
		}
		if err := engine.Compile(); err != nil {
			if a.otel != nil {
				a.otel.RecordPolicyReload(r.Context(), "failed")
			}
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

	if a.otel != nil {
		a.otel.RecordPolicyReload(r.Context(), "success")
		a.otel.EmitPolicyDecision("reload", "success", a.scannerCfg.PolicyDir, "", "OPA policy reloaded via API", nil)
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionPolicyReload), a.scannerCfg.PolicyDir, "OPA policy reloaded via API")
	}
	emitLifecycle(r.Context(), "policy", "reload", map[string]string{
		"policy_dir": a.scannerCfg.PolicyDir,
		"source":     "api",
	})

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

// handleCodeScan runs CodeGuard on the given filesystem path and returns
// the ScanResult with OTel signals emitted via the shared audit logger.
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
	cg := scanner.NewCodeGuardScanner(rulesDir)

	result, err := cg.Scan(r.Context(), req.Path)
	if err != nil {
		if a.otel != nil {
			a.otel.RecordScanError(r.Context(), "codeguard", "code", classifyScanError(err))
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(r.Context(), result, "", ScanCorrelationFromContext(r.Context()))
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
		Hostname:  q.Get("hostname"),
		SessionID: q.Get("session_id"),
		Limit:     limit,
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
