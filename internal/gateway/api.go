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
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/scanoutput"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/systemd"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// APIServer exposes a local REST API for CLI and plugin communication
// with the running sidecar.
type APIServer struct {
	health *SidecarHealth
	client *Client
	store  *audit.Store
	logger *audit.Logger
	// exemptAuditAt is when each exempt account and connector last got an
	// enterprise-exempt-user audit row (auditEnterpriseExemptUser).
	exemptAuditMu sync.Mutex
	exemptAuditAt map[string]time.Time
	// foreignHookSessionLocks serializes foreign-hook session exchanges per
	// caller identity: each identity has its own session store, so callers
	// never wait on each other's exchanges.
	foreignHookSessionLocks keyedMutex
	// foreignHookRemovals caches the hook guardian foreign-hook removal
	// ledger the session exchanges check.
	foreignHookRemovals foreignHookRemovalCache
	// hookCallerLimits bounds each verified caller identity's requests on a
	// standalone gateway (hook socket and per-user credentials).
	hookCallerLimits hookCallerLimiter
	// managedRefusalLimits bounds the managed refusal rows per account.
	managedRefusalLimits managedRefusalLimiter
	// copilotDedupe answers the second delivery of one Copilot tool call
	// with the first delivery's verdict.
	copilotDedupe copilotHookDedupe
	// hermesTasks gives a Hermes hook that names only its task the session
	// of that task.
	hermesTasks hermesTaskSessions

	// shutdownRequester cancels the owning Sidecar run context after an
	// authenticated, loopback-only management request has proven the expected
	// process and data-home identity. shutdownOnce keeps retries idempotent.
	shutdownRequester func()
	shutdownOnce      sync.Once
	addr              string
	scannerCfg        *config.Config
	hilt              *HILTApprovalManager
	notifier          *notifier.Dispatcher
	webhookSource     func() *WebhookDispatcher
	aiDiscoveryMu     sync.RWMutex
	aiDiscovery       *inventory.ContinuousDiscoveryService
	aiRuntimeMu       sync.RWMutex
	aiRuntime         *sensor.Service
	// scanOutputRedactor is initialized only if the code-scan response path is
	// used. Failed loads are deliberately not cached: repairing key-store
	// permissions must restore useful protected output without a restart.
	scanOutputRedactionMu sync.Mutex
	scanOutputRedactor    *scanoutput.Redactor
	// codeScanner is a hermetic test seam. Production leaves it nil and always
	// executes scanner.ScanCode.
	codeScanner func(context.Context, string, string) (*scanner.ScanResult, error)

	// inspectToolScanTimeout optionally overrides the synchronous
	// /api/v1/inspect/tool scan budget for this server. Runtime constructors
	// leave it at zero and therefore retain inspectScanTimeout; tests that
	// exercise policy semantics can use a larger budget so race-detector
	// scheduler latency is not mistaken for a scanner verdict.
	inspectToolScanTimeout time.Duration
	// inspectToolWorkerDone is a test-only completion barrier for the detached
	// scan worker. Production constructors leave it nil. It lets timeout tests
	// prove that post-cancellation worker completion cannot record a fail-open
	// decision after the handler has already returned 504.
	inspectToolWorkerDone func()
	// ACP readiness is surfaced on unauthenticated /health. Cache the bounded
	// custody probe briefly so health polling cannot force repeated protected-
	// directory traversal. Authentication never uses this cache.
	acpReadinessMu        sync.Mutex
	acpReadinessCheckedAt time.Time
	acpReadinessKey       string
	acpReadinessValue     bool
	acpReadinessWindow    time.Duration

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

	// cfgMu protects scannerCfg, which a config reload replaces while
	// request goroutines read it.
	cfgMu sync.RWMutex

	// configReloader and configSnapshot bind API writes (the sandbox
	// decision persister) to the same central reload transaction and
	// immutable snapshot used by live enforcement; writes go through
	// internal/config/configwrite. The sandbox decision write refuses to
	// run when this coordination is unavailable.
	configReloader func(context.Context, string) error
	configSnapshot func() *config.Config
	configWriteMu  sync.Mutex

	// guardrailProfiles holds the identity-based guardrail profiles derived
	// at load and on every reload (guardrail_profile.go).
	guardrailProfiles guardrailProfileHolder

	// otlpPathTokenMu guards otlpPathTokens — the in-memory map of
	// per-source OTLP credentials loaded from
	// ${data_dir}/hooks/.otlp-<source>.token. Reads happen on every
	// loopback OTLP request authenticated by either a scoped Authorization
	// header (Codex and Claude Code) or the path-token transport for
	// exporters that cannot set headers, so the map is held under an RWMutex to keep the hot
	// path lock-free for readers.
	//
	// The map is populated at boot by SetOTLPPathTokens AND refreshed
	// lazily by lookupOTLPPathToken in two cases:
	//
	//  1. Cache miss for a KNOWN scope (F4 fix). Closes the
	//     boot-vs-setup race where the sidecar boots with an empty
	//     or stale map, the operator subsequently runs
	//     `defenseclaw setup <connector>` (which mints a fresh on-disk
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

	// userScopedCredentials authenticates the standalone profile's per-user
	// connector credentials on the TCP API (user_scoped_credentials.go).
	userScopedCredentialsOnce sync.Once
	userScopedCredentials     *userScopedCredentialStore

	// hookRegistrationRepair is the narrow authenticated bridge from a fresh
	// connector SessionStart to the Sidecar-owned hook guard. The Sidecar owns
	// connector selection and SetupOpts; the API never resolves an ambient
	// profile or constructs a second registration writer.
	hookRegistrationRepairMu sync.RWMutex
	hookRegistrationRepair   func(context.Context, string) error

	// policyReloader, when set, is called by the /policy/reload handler to
	// rebuild the configuration generation now.
	policyReloader func() error
	// configApply is the config.yaml writer /enforce/* uses; nil is
	// configwrite.Apply (tests substitute a recorder).
	configApply func(context.Context, string, []configwrite.Change, configwrite.Options) (configwrite.Result, error)

	// generationSource returns the sidecar's live configuration generation;
	// decisions and policy evaluation read it. Nil for an API server the
	// sidecar does not own (tests, embedders), which decides with its
	// start-time configuration and prepares its policy once.
	generationSource func() *Generation
	ownPolicyOnce    sync.Once
	ownPolicy        *policy.Prepared
	ownPolicyErr     error

	claudeCodeMu                sync.Mutex
	claudeCodeLastComponentScan time.Time
	// activeAgentContext is process-local, authenticated connector context. It
	// is deliberately separate from hook payloads so tool arguments and generic
	// request fields cannot assert which agent instruction files are active.
	activeAgentContext     activeAgentContextCache
	codexMu                sync.Mutex
	codexLastComponentScan time.Time
	// codexAdditionalContextMu protects the bounded, process-local cache used
	// only to suppress repeated in-chat Observe warnings. Canonical detection,
	// audit, and notification emission happen before this cache is consulted.
	codexAdditionalContextMu    sync.Mutex
	codexAdditionalContextSeen  map[[sha256.Size]byte]time.Time
	codexAdditionalContextOrder []codexAdditionalContextEntry
	// claudeCodePreActionEvals lets a Claude Code PermissionRequest reuse
	// the evaluation of its PreToolUse instead of alerting twice.
	claudeCodePreActionEvals          claudeCodePreActionEvalCache
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
	hookChildThreads                  map[string]hookChildThread
	hookChildThreadOrder              []string
	copilotSubagents                  []copilotPendingSubagent
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
	// hook surface (Codex / Claude Code / Cursor / Devin /
	// Hermes / Copilot) so MCP tool calls and tool results
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
	hookJudge atomic.Pointer[LLMJudge]
	// hookJudgeSem bounds concurrent hook-lane judge executions,
	// mirroring EventRouter.judgeSem on the proxy lane. At capacity
	// the judge is skipped (fail-open to the regex/AID verdict)
	// rather than queued — a queued hook would stall the agent past
	// the hook scripts' curl --max-time budget.
	hookJudgeSem     chan struct{}
	hookJudgeSemOnce sync.Once

	// sandboxIngress is the OpenShell sandbox hook listener configured by
	// SetSandboxIngress (api_sandbox_ingress.go); nil when sandboxes are off.
	sandboxIngressMu sync.RWMutex
	sandboxIngress   *sandboxIngressState

	// sandboxCtl is the OpenShell sandbox manager behind /api/v1/sandbox/
	// (api_sandbox.go); nil when sandboxes are off.
	sandboxCtlMu sync.RWMutex
	sandboxCtl   SandboxController
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

// judgeFor is the hook-lane judge of the generation ctx pinned, else the
// server's own (an API server outside a gateway).
func (a *APIServer) judgeFor(ctx context.Context) *LLMJudge {
	if a == nil {
		return nil
	}
	return judgeOf(pinnedGeneration(ctx), a.hookJudge.Load())
}

// SetHookJudge wires the LLM judge onto the API server so the hook
// content lane (inspectMessageContent) can adjudicate prompts and
// tool results for connectors listed in
// guardrail.judge.hook_connectors. Pass nil to disable (the default
// when guardrail.judge is off).
func (a *APIServer) SetHookJudge(j *LLMJudge) {
	a.hookJudge.Store(j)
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

// SetHookRegistrationRepair wires the active Sidecar hook-guard registry into
// authenticated hook handling. Passing nil detaches the retiring API server
// before its guards stop, so a stale request cannot write through an old
// connector generation.
func (a *APIServer) SetHookRegistrationRepair(repair func(context.Context, string) error) {
	if a == nil {
		return
	}
	a.hookRegistrationRepairMu.Lock()
	a.hookRegistrationRepair = repair
	a.hookRegistrationRepairMu.Unlock()
}

func (a *APIServer) ensureHookRegistration(ctx context.Context, connectorName string) error {
	if a == nil {
		return nil
	}
	a.hookRegistrationRepairMu.RLock()
	repair := a.hookRegistrationRepair
	a.hookRegistrationRepairMu.RUnlock()
	if repair == nil {
		return nil
	}
	return repair(ctx, connectorName)
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
	// or a hostile caller probing /otlp/<scope>/<random>/v1/*
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
	if name, ok := strings.CutPrefix(path, enterprisepolicy.ForeignHookSessionPathPrefix); ok && name != "" && !strings.Contains(name, "/") {
		if a.connectorRegistry != nil {
			_, found := a.connectorRegistry.Get(name)
			return name, found
		}
		_, found := sharedDefaultRegistry().Get(name)
		return name, found
	}
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
	// Legacy/test boot still registers every built-in HookEndpoint. Resolve
	// authentication from that same reviewed built-in roster so a newly added
	// connector route cannot silently accept only the master token.
	registry := sharedDefaultRegistry()
	for _, name := range registry.Names() {
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		if endpoint, ok := conn.(connector.HookEndpoint); ok && endpoint.HookAPIPath() == path {
			return strings.ToLower(name), true
		}
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
// SetAIRuntimeService wires the runtime planes into the API. Safe to call
// with nil: the planes are opt-in, and a nil service is the disabled state the
// handler reports rather than an error.
func (a *APIServer) SetAIRuntimeService(svc *sensor.Service) {
	if a == nil {
		return
	}
	a.aiRuntimeMu.Lock()
	a.aiRuntime = svc
	a.aiRuntimeMu.Unlock()
}

func (a *APIServer) leaseAIRuntime() (*sensor.Service, func()) {
	if a == nil {
		return nil, func() {}
	}
	a.aiRuntimeMu.RLock()
	return a.aiRuntime, a.aiRuntimeMu.RUnlock
}

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

// SetWebhookSource wires the gateway's current webhook dispatcher into the
// connector-hook handlers. A func is stored because a config reload swaps
// the dispatcher.
func (a *APIServer) SetWebhookSource(source func() *WebhookDispatcher) {
	a.webhookSource = source
}

// dispatchHookBlockWebhook sends an enforced connector-hook block to the
// configured webhooks. Only the LLM proxy, watcher and health paths used to
// dispatch, so blocks on the per-user hook connectors reached no webhook
// (GAP-1145). Dispatch redacts the reason and applies severity, event and
// cooldown filters. The redacted reason alone did not say which rule fired
// (GAP-1351), so the details also carry rule=<ids> and the generic payload
// names the rules the way the agent message does ("rule ID: Title", titles
// only from the compiled-in catalog or a loaded rule pack). The payload also
// names the account, agent identity and profile of the request (GAP-0144). A
// managed deployment keeps the historical payload.
func (a *APIServer) dispatchHookBlockWebhook(ctx context.Context, connectorName, toolName, hookEvent, severity, reason string, ruleIDs []string) {
	if a == nil || a.webhookSource == nil {
		return
	}
	webhooks := a.webhookSource()
	if webhooks == nil {
		return
	}
	target := strings.TrimSpace(toolName)
	if target == "" {
		target = hookEvent
	}
	event := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    string(audit.ActionBlock),
		Target:    target,
		Actor:     "defenseclaw-hook",
		Details:   fmt.Sprintf("connector=%s event=%s reason=%s", connectorName, hookEvent, reason),
		Severity:  severity,
		Connector: connectorName,
	}
	if !managedEnterpriseActive.Load() {
		if ids := webhookRuleIDs(ruleIDs); ids != "" {
			event.Details = fmt.Sprintf("connector=%s event=%s rule=%s reason=%s", connectorName, hookEvent, ids, reason)
		}
		event.Structured = map[string]any{webhookAttributionKey: webhookAttributionFor(ctx)}
		if rules := agentMatchedRules(reason); rules != "" {
			event.Structured[webhookRuleKey] = rules
		}
	}
	webhooks.Dispatch(event)
}

// webhookRuleIDs joins the rule IDs of a hook verdict for the webhook
// details; anything that is not a plain rule identifier is dropped.
func webhookRuleIDs(ruleIDs []string) string {
	var ids []string
	for _, id := range ruleIDs {
		id = strings.TrimSpace(id)
		if agentRuleIDPattern.MatchString(id) && len(ids) < 5 {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

func (a *APIServer) connectorName() string {
	return connectorNameForConfig(a.runtimeConfigSnapshot())
}

func connectorNameForConfig(cfg *config.Config) string {
	if cfg != nil {
		if c := strings.TrimSpace(cfg.Guardrail.Connector); c != "" {
			return strings.ToLower(c)
		}
		if c := strings.TrimSpace(string(cfg.Claw.Mode)); c != "" {
			return strings.ToLower(c)
		}
	}
	return "unknown"
}

// SetGenerationSource connects the API server to the sidecar's live
// configuration generation.
func (a *APIServer) SetGenerationSource(source func() *Generation) {
	if a == nil {
		return
	}
	a.generationSource = source
}

func (a *APIServer) generation() *Generation {
	if a == nil || a.generationSource == nil {
		return nil
	}
	return a.generationSource()
}

// preparedPolicy returns the OPA queries decisions evaluate: the live
// generation's, or for an API server without one, queries prepared once
// from its start-time policy_dir.
func (a *APIServer) preparedPolicy(ctx context.Context) (*policy.Prepared, error) {
	g := pinnedGeneration(ctx)
	if g == nil {
		g = a.generation()
	}
	return a.preparedPolicyForGeneration(ctx, g)
}

// pinRequestGeneration pins the API server's published generation on r for
// a request no profile resolution pinned (GAP-0455).
func (a *APIServer) pinRequestGeneration(r *http.Request) *http.Request {
	if g := a.generation(); g.published() {
		return r.WithContext(withPinnedGeneration(r.Context(), g))
	}
	return r
}

func (a *APIServer) preparedPolicyForGeneration(ctx context.Context, g *Generation) (*policy.Prepared, error) {
	if a.generationSource != nil {
		if g == nil {
			return nil, errors.New("policy is not loaded")
		}
		if g.OPA == nil {
			if g.opaError != "" {
				return nil, errors.New(g.opaError)
			}
			if a.scannerCfg != nil && !a.scannerCfg.SecureClientIntegration() {
				return nil, policy.ErrNoModules
			}
			return nil, errors.New("policy is not loaded")
		}
		return g.OPA, nil
	}
	a.ownPolicyOnce.Do(func() {
		a.ownPolicy, a.ownPolicyErr = policy.Prepare(ctx, a.scannerCfg.PolicyDir)
	})
	return a.ownPolicy, a.ownPolicyErr
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
		// The sidecar always plumbs the registry (SetConnectorRegistry);
		// without one there is no connector to serve a hook route for.
		return
	}

	for _, name := range a.connectorRegistry.Names() {
		if connector.ConnectorSupportOnHostOS(name).Status == connector.PlatformUnsupported {
			continue
		}
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
	return newAPIServer(nil, addr, health, client, store, logger, cfg...)
}

// newAPIServer is NewAPIServer with the rule packs the sidecar already loaded
// and validated for its guardrail profile set; nil loads them again.
func newAPIServer(rulePacks *guardrail.RulePackCache, addr string, health *SidecarHealth, client *Client, store *audit.Store, logger *audit.Logger, cfg ...*config.Config) *APIServer {
	s := &APIServer{
		addr:   addr,
		health: health,
		client: client,
		store:  store,
		logger: logger,
	}
	if len(cfg) > 0 {
		s.scannerCfg = cfg[0]
		s.initGuardrailProfiles(s.scannerCfg, rulePacks)
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

// SetShutdownRequester wires the local management shutdown endpoint to the
// owning Sidecar. The callback must be non-blocking; Sidecar supplies its
// context cancel function so every subsystem gets its normal drain path.
func (a *APIServer) SetShutdownRequester(request func()) {
	if a == nil {
		return
	}
	a.shutdownRequester = request
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

// servesOpenClawRoutes reports whether Run registers the routes that proxy
// the OpenClaw gateway RPCs (/skill/*, /plugin/*, /skills, /mcps,
// /tools/catalog): only when openclaw is an active connector, and never on a
// standalone enterprise deployment, which does not run OpenClaw. The Secure
// Client path keeps its route set unchanged. A connector change restarts the
// gateway, so the route set is fixed for the process.
func (a *APIServer) servesOpenClawRoutes() bool {
	cfg := a.runtimeConfigSnapshot()
	switch {
	case cfg == nil || cfg.StandaloneEnterprise():
		return false
	case cfg.SecureClientIntegration():
		return true
	}
	return slices.Contains(cfg.ActiveConnectors(), "openclaw")
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
	deadline := time.Now().Add(budget)
	for attempt := 1; ; attempt++ {
		ln, err := apiListenTCP(ctx, addr)
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

// retriesHeldAPIPortWithoutHookSocket reports whether this gateway keeps
// retrying a held API port although it serves no hook socket: only the
// standalone profile on a platform without the socket (Windows). Secure
// Client and per-user gateways keep ending Run after the bind budget.
func (a *APIServer) retriesHeldAPIPortWithoutHookSocket() bool {
	return heldAPIPortRetriedWithoutHookSocket && a.scannerCfg != nil && a.scannerCfg.StandaloneEnterprise()
}

// apiPortHeld reports whether the first bind failed because another process
// holds the API port, so Run keeps retrying the bind instead of returning.
// Beside "address in use", a Windows standalone gateway also retries the
// "forbidden by its access permissions" failure (WSAEACCES) that Windows
// returns when another account holds the port on the wildcard address
// (0.0.0.0 or [::]): the gateway service account cannot bind 127.0.0.1
// under another account's wildcard listener, so that is a held port too.
func (a *APIServer) apiPortHeld(hasHookSocket bool, err error) bool {
	if hasHookSocket {
		return isAddrInUse(err)
	}
	if !a.retriesHeldAPIPortWithoutHookSocket() {
		return false
	}
	return isAddrInUse(err) || isAPIPortHeldByAnotherAccount(err)
}

func (a *APIServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(enterprisepolicy.ForeignHookSessionPathPrefix+"{connector}", a.handleForeignHookSession)
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/api/v1/admin/shutdown", a.handleShutdown)
	if a.servesOpenClawRoutes() {
		// These routes proxy the OpenClaw gateway RPCs.
		mux.HandleFunc("/skill/disable", a.handleSkillDisable)
		mux.HandleFunc("/skill/enable", a.handleSkillEnable)
		mux.HandleFunc("/plugin/disable", a.handlePluginDisable)
		mux.HandleFunc("/plugin/enable", a.handlePluginEnable)
		// Secure Client keeps the config.patch bridge (issue #1092).
		if a.managedAIDOnly() {
			mux.HandleFunc("/config/patch", a.handleConfigPatch)
		}
		mux.HandleFunc("/skills", a.handleSkills)
		mux.HandleFunc("/mcps", a.handleMCPs)
		mux.HandleFunc("/tools/catalog", a.handleToolsCatalog)
	}
	mux.HandleFunc("/scan/result", a.handleScanResult)
	mux.HandleFunc("/enforce/block", a.handleEnforceBlock)
	mux.HandleFunc("/enforce/allow", a.handleEnforceAllow)
	mux.HandleFunc("/enforce/blocked", a.handleEnforceBlocked)
	mux.HandleFunc("/enforce/allowed", a.handleEnforceAllowed)
	mux.HandleFunc("/alerts", a.handleAlerts)
	mux.HandleFunc("/audit/event", a.handleAuditEvent)
	mux.HandleFunc("/policy/evaluate", a.handlePolicyEvaluate)
	mux.HandleFunc("/policy/reload", a.handlePolicyReload)
	mux.HandleFunc("/v1/skill/scan", a.handleSkillScan)
	mux.HandleFunc("/v1/plugin/scan", a.handlePluginScan)
	mux.HandleFunc("/v1/mcp/scan", a.handleMCPScan)
	mux.HandleFunc("/v1/skill/fetch", a.handleSkillFetch)
	mux.HandleFunc("/v1/guardrail/event", a.handleGuardrailEvent)
	mux.HandleFunc("/v1/guardrail/evaluate", a.handleGuardrailEvaluate)
	mux.HandleFunc("/v1/guardrail/config", a.handleGuardrailConfig)
	// Secure Client serves none of the identity routes (issue #1092).
	if !a.managedAIDOnly() {
		mux.HandleFunc("/api/v1/guardrail/profiles/resolve", a.handleGuardrailProfileResolve)
	}
	mux.HandleFunc("/api/v1/acp/challenge", a.handleACPChallenge)
	mux.HandleFunc("/api/v1/acp/evaluate", a.handleACPEvaluate)
	mux.HandleFunc("/v1/acp/catalog", a.handleACPCatalog)
	mux.HandleFunc("/v1/acp/profiles", a.handleACPProfiles)
	// Provider configuration belongs to the management API so hook-only
	// deployments can inspect and reload it without enabling the proxy listener.
	a.registerProviderRoutes(mux)
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
	mux.Handle("/api/v1/inspect/", hookLimiter(a.guardrailProfileInspectMiddleware(inspectMux)))
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
	if !a.managedAIDOnly() {
		mux.HandleFunc("/api/v1/agents/identities", a.handleAgentIdentities)
	}
	mux.HandleFunc("/api/v1/ai-usage", a.handleAIUsage)
	mux.HandleFunc("/api/v1/ai-usage/scan", a.handleAIUsageScan)
	mux.HandleFunc("/api/v1/ai-usage/discovery", a.handleAIUsageDiscovery)
	mux.HandleFunc("/api/v1/ai-usage/components", a.handleAIUsageComponents)
	if !a.managedAIDOnly() {
		mux.HandleFunc("/api/v1/ai-usage/ide-plugins", a.handleAIUsageIDEPlugins)
	}
	// Runtime planes. Registered under the ai-usage prefix so the whole of AI
	// discovery -- presence and behaviour -- reads as one surface.
	mux.HandleFunc("/api/v1/ai-usage/runtime", a.handleAIRuntime)
	mux.HandleFunc("/api/v1/ai-usage/runtime/scan", a.handleAIRuntimeScan)
	// Correlation graph endpoints expose the durable, evidence-backed identity
	// ledger. They remain behind the same bearer-token and CSRF middleware as
	// every other API route; handlers are read-only and accept exactly one
	// canonical anchor per request.
	mux.HandleFunc("/api/v1/correlation/graph", a.handleCorrelationGraphV8)
	mux.HandleFunc("/api/v1/correlation/explain", a.handleCorrelationExplainV8)
	mux.HandleFunc("/api/v1/correlation/timeline", a.handleCorrelationTimelineV8)
	mux.HandleFunc("/api/v1/correlation/conflicts", a.handleCorrelationConflictsV8)
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
	a.registerSandboxRoutes(mux)

	handler := apiBodyLimitMiddleware(mux, apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes)
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

	baseCtx := ctx
	if managedHookSocketEnabled(a.scannerCfg) {
		// Off the verified hook socket a standalone gateway has no trusted
		// caller identity, so "~" must not resolve to its service account.
		baseCtx = withServiceAccountGateway(ctx)
	}
	srv := &http.Server{
		Addr:    a.addr,
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return baseCtx
		},
		ConnContext: acpPeerConnContext,
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
	//
	// Under systemd socket activation the listener is inherited instead: PID 1
	// holds 127.0.0.1:<port> across gateway restarts, so there is no window in
	// which a local user could bind it (acquireAPIListener).
	//
	// The standalone managed profile additionally serves the agent-facing
	// routes on a unix socket where each caller is identified by its
	// kernel-verified uid (see managed_hook_peer.go). A failure here leaves
	// the TCP API up; hooks that require the socket fail closed on their own.
	// The socket is bound and served before the TCP listener and does not
	// depend on it: without socket activation (macOS) a local user can hold
	// the TCP port while the gateway restarts, and that must not take the
	// socket — whose directory no standard user can write — down with it
	// for every user on the host. newManagedHookSocketServer returns no
	// server outside the standalone profile, so there the TCP bind below
	// behaves exactly as before.
	hookSrv, hookLn, hookErr := a.newManagedHookSocketServer(ctx, func(h http.Handler) http.Handler {
		h = a.metricsMiddleware(h)
		h = CorrelationMiddleware(reg)(h)
		h = requestIDMiddleware(h)
		return inboundTraceContextMiddleware(h)
	})
	apiDetails := map[string]interface{}{"addr": a.addr}
	if hookErr != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] standalone hook socket unavailable: %v\n", hookErr)
		apiDetails["hook_socket_error"] = hookErr.Error()
	}

	errCh := make(chan error, 2)
	if hookSrv != nil {
		apiDetails["hook_socket"] = hookLn.Addr().String()
		go func() {
			fmt.Fprintf(os.Stderr, "[sidecar-api] standalone hook socket listening on %s\n", hookLn.Addr())
			if err := hookSrv.Serve(hookLn); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("hook socket: %w", err)
			}
		}()
	}

	serveTCP := func(ln net.Listener) {
		go func() {
			fmt.Fprintf(os.Stderr, "[sidecar-api] listening on %s\n", a.addr)
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}
	// tcpBound delivers a listener the standalone bind retry below won; it
	// stays nil (never ready) when the first bind succeeded.
	var tcpBound chan net.Listener
	retryCtx, stopRetry := context.WithCancel(ctx)
	defer stopRetry()
	ln, lnErr := a.acquireAPIListener(ctx)
	switch {
	case lnErr == nil:
		serveTCP(ln)
		a.health.SetAPI(StateRunning, "", apiDetails)
	case a.apiPortHeld(hookSrv != nil, lnErr) && ctx.Err() == nil:
		// Another process holds the TCP port. Keep serving the hook socket
		// (where there is one), report the API as failed, and take the port
		// when it is released instead of exiting into a restart loop that
		// also drops the socket, or (Windows standalone) leaving the service
		// running without its API.
		switch {
		case hookSrv != nil:
			fmt.Fprintf(os.Stderr, "[sidecar-api] %s is held by another process; the hook socket stays up while the API bind is retried: %v\n", a.addr, lnErr)
		case isAPIPortHeldByAnotherAccount(lnErr):
			fmt.Fprintf(os.Stderr, "[sidecar-api] another account holds the port of %s on its wildcard address; hooks fail closed while the API bind is retried until the port is released: %v\n", a.addr, lnErr)
		default:
			fmt.Fprintf(os.Stderr, "[sidecar-api] %s is held by another process; hooks fail closed while the API bind is retried until the port is released: %v\n", a.addr, lnErr)
		}
		retryDetails := make(map[string]interface{}, len(apiDetails)+1)
		for key, value := range apiDetails {
			retryDetails[key] = value
		}
		retryDetails["tcp_bind_retrying"] = true
		a.health.SetAPI(StateError, lnErr.Error(), retryDetails)
		tcpBound = make(chan net.Listener)
		go a.retryAPIListenerBind(retryCtx, tcpBound)
	default:
		a.health.SetAPI(StateError, lnErr.Error(), nil)
		if hookSrv != nil {
			_ = hookSrv.Close()
			_ = hookLn.Close()
		}
		return fmt.Errorf("api: listen %s: %w", a.addr, lnErr)
	}

	// Readiness and watchdog for Type=notify units; both are no-ops outside
	// systemd (NOTIFY_SOCKET / WATCHDOG_USEC unset).
	if _, err := systemd.Notify(systemd.StateReady); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] systemd readiness notification failed: %v\n", err)
	}
	watchdogCtx, stopWatchdog := context.WithCancel(ctx)
	defer stopWatchdog()
	go systemd.RunWatchdog(watchdogCtx, nil)

	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var hookShutdownErr error
		if hookSrv != nil {
			hookShutdownErr = hookSrv.Shutdown(shutdownCtx)
		}
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return hookShutdownErr
	}

	for {
		select {
		case ln := <-tcpBound:
			tcpBound = nil
			fmt.Fprintf(os.Stderr, "[sidecar-api] %s was released; the API is bound again\n", a.addr)
			serveTCP(ln)
			a.health.SetAPI(StateRunning, "", apiDetails)
		case err := <-errCh:
			a.health.SetAPI(StateError, err.Error(), nil)
			_ = shutdown()
			return fmt.Errorf("api: listen %s: %w", a.addr, err)
		case <-ctx.Done():
			a.health.SetAPI(StateStopped, "", nil)
			_, _ = systemd.Notify(systemd.StateStopping)
			return shutdown()
		}
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
	if cfg := a.runtimeConfigSnapshot(); (cfg == nil || !cfg.SecureClientIntegration()) && a.store.DatabaseFileReplaced() {
		// Present only when it happened, so the usual body is unchanged;
		// Secure Client keeps its health body (issue #1092).
		body["audit_store"] = map[string]interface{}{
			"state":  "replaced",
			"detail": "audit.db was deleted or replaced after the gateway opened it, so new audit records are lost; restart the gateway: defenseclaw-gateway restart",
		}
	}
	if policy, ok := CurrentPolicyHealth(); ok {
		body["policy"] = policy
	}
	if ledger := agentIdentityLedgerHealth(); ledger != nil {
		body["agent_identities"] = ledger
	}
	if cfg := a.runtimeConfigSnapshot(); cfg != nil {
		if !cfg.SecureClientIntegration() {
			if set := a.guardrailProfileSet(); set != nil {
				body["profile_assignment_warnings"] = set.assignmentWarnings(true)
			}
		}
		body["acp"] = map[string]interface{}{
			"enabled": cfg.ACP.Enabled, "mode": effectiveACPMode(cfg.ACP, ""),
			"schema_version": acp.SchemaVersion, "schema_sha256": acp.SchemaSHA256,
			"configured_clients": len(cfg.ACP.Clients), "configured_agents": len(cfg.ACP.Agents),
			"scoped_token_ready": a.acpScopedTokenReady(),
		}
		if cfg.StandaloneEnterprise() {
			body["inspection"] = standaloneInspectionPosture(cfg, snap.Guardrail)
			peer, viaHookSocket := managedHookPeerFromContext(r.Context())
			if directory := directoryHealthSummary(directoryCacheHealth(), viaHookSocket && peer.UID == 0); directory != nil {
				body["directory"] = directory
			}
			// An assignment group the host does not know (renamed, deleted,
			// or spelled another way after an SSSD naming switch) selects
			// nobody, and the whole team falls to the default profile:
			// status and verify report it (GAP-0704). The last check is
			// served; a stale one is refreshed in the background.
			if warnings := liveGuardrailProfiles.Load().unknownGroupWarnings(0); len(warnings) > 0 {
				body["profile_warnings"] = warnings
			}
			// Non-secret fingerprints of the per-user credential keys that
			// authenticate right now (a rotation's staged key included).
			body["user_scoped_credentials"] = map[string]interface{}{
				"key_ids": a.userScopedCredentialStore().keyFingerprints(),
			}
		}
	}
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
		PlatformStatus     string `json:"platform_status"`
		PlatformReason     string `json:"platform_reason,omitempty"`
		// LLMTrafficMode ("proxy" | "hooks-only") tells the CLI whether a
		// custom provider bound to this connector is enforced on the
		// agent's own model traffic or only configures DefenseClaw's
		// judge/aux model. Set for every connector (proxy connectors do
		// not emit the ConnectorCapabilities struct, so it cannot live
		// solely there).
		LLMTrafficMode   string                           `json:"llm_traffic_mode"`
		HookCapabilities *connector.HookCapability        `json:"hook_capabilities,omitempty"`
		Capabilities     *connector.ConnectorCapabilities `json:"capabilities,omitempty"`
		ACP              *connector.ACPCapability         `json:"acp,omitempty"`
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
			PlatformStatus:     string(info.PlatformStatus),
			PlatformReason:     info.PlatformReason,
			LLMTrafficMode:     connector.LLMTrafficModeForConnector(info.Name),
		}
		if conn, ok := reg.Get(info.Name); ok {
			if capability := connector.ACPAgentCapabilityForConnector(info.Name); capability.Agent || capability.Client {
				entry.ACP = &capability
			}
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
				if caps.ACP.Agent || caps.ACP.Client {
					entry.ACP = &caps.ACP
				}
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
	runtimeEnvironment := ""
	if cfg := a.runtimeConfigSnapshot(); cfg != nil {
		runtimeEnvironment = cfg.Environment
	}

	status := map[string]interface{}{
		"health":     snap,
		"provenance": version.Current(),
		// Runtime identity is intentionally available only through this
		// authenticated endpoint. Doctor uses it to bind the live listener to
		// the managed process and configured data home without reading another
		// process's memory or environment. Never add authentication material to
		// this object.
		"runtime": map[string]interface{}{
			"pid":         os.Getpid(),
			"data_dir":    a.configDataDir(),
			"environment": runtimeEnvironment,
		},
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
		"connector_mode":  a.connectorModeSummary(r.Context()),
		"connector_modes": a.connectorModesSummary(r.Context()),
	}
	if cfg := a.runtimeConfigSnapshot(); cfg != nil && !cfg.SecureClientIntegration() {
		if set := a.guardrailProfileSet(); set != nil {
			status["profile_assignment_warnings"] = set.assignmentWarnings(true)
		}
	}

	if policy, ok := CurrentPolicyHealth(); ok {
		status["policy"] = policy
	}

	if a.client != nil && a.client.Hello() != nil {
		hello := a.client.Hello()
		status["gateway_hello"] = hello
	}

	a.writeJSON(w, http.StatusOK, status)
}

type gatewayShutdownRequest struct {
	PID     int    `json:"pid"`
	DataDir string `json:"data_dir"`
}

// handleShutdown is the authenticated control plane used by the detached
// Windows gateway (and, for parity, other daemon platforms). A signal cannot
// reach a DETACHED_PROCESS reliably, so the CLI proves both the target PID and
// configured data home over the already-authenticated loopback API, then this
// handler cancels the Sidecar run context. That preserves normal subsystem,
// audit, SQLite, webhook, and telemetry drains before process exit.
func (a *APIServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !connector.IsLoopback(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "shutdown is restricted to loopback clients"})
		return
	}
	if a.shutdownRequester == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "graceful shutdown is unavailable"})
		return
	}

	var request gatewayShutdownRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must contain one JSON object"})
		return
	}
	if request.PID != os.Getpid() || !sameRuntimeDataDir(request.DataDir, a.configDataDir()) {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "gateway runtime identity mismatch"})
		return
	}

	requested := false
	a.shutdownOnce.Do(func() {
		requested = true
	})
	status := "already_requested"
	if requested {
		status = "accepted"
	}
	a.writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
	if requested {
		// Start cancellation only after the response has been written. The
		// HTTP server's graceful Shutdown waits for this handler to return,
		// ensuring the caller receives the acknowledgement before teardown.
		go a.shutdownRequester()
	}
}

func sameRuntimeDataDir(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbs, rightAbs)
	}
	return leftAbs == rightAbs
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
func (a *APIServer) connectorModeSummary(ctx context.Context) map[string]interface{} {
	cfg := a.runtimeConfigSnapshot()
	if cfg != nil && !cfg.HasConnectorConfigured() {
		return map[string]interface{}{
			"connector":           "",
			"mode":                "unconfigured",
			"policy_mode":         "",
			"enforcement_surface": "",
			"telemetry":           []string{},
			"proxy_intercept":     false,
		}
	}
	return connectorModeForDecision(cfg, a.decisionConfigFrom(ctx, cfg), connectorNameForConfig(cfg))
}

// connectorModesSummary returns one connectorModeFor entry per active
// connector so multi-connector status output can show every connector's
// enforcement/observability posture rather than only the primary's. The
// roster is sourced from the config's ActiveConnectors() (sorted), which
// returns a single name on a single-connector install — so the shape is
// identical regardless of count. Falls back to the singular active
// connector when the config is unavailable.
func (a *APIServer) connectorModesSummary(ctx context.Context) []map[string]interface{} {
	cfg := a.runtimeConfigSnapshot()
	decisionCfg := a.decisionConfigFrom(ctx, cfg)
	var names []string
	if cfg != nil {
		names = cfg.ActiveConnectors()
		if !cfg.HasConnectorConfigured() {
			return []map[string]interface{}{}
		}
	}
	if len(names) == 0 {
		names = []string{connectorNameForConfig(cfg)}
	}
	out := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		out = append(out, connectorModeForDecision(cfg, decisionCfg, strings.ToLower(strings.TrimSpace(name))))
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

	// Derive the data-path trio from the connector's declared traffic mode,
	// through the same predicate the sidecar uses to decide whether to bind
	// the proxy listener. It used to come from the name list below, and a
	// connector missing from that list was reported as proxy-intercepted with
	// enforcement_surface llm_proxy -- which is how Kiro, a hooks-only
	// connector, showed up in `defenseclaw-gateway status` as "Data path:
	// DefenseClaw proxy" in the same output whose Guardrail subsystem said
	// "proxy_port: closed" and "the local guardrail proxy is not in the LLM
	// data path". The list below now contributes only the telemetry channels
	// and OmniGent's policy-API surface, which are genuinely per-connector.
	if !connectorProxyBindsByName(name) {
		mode = "observability"
		intercept = false
		surface = "agent_lifecycle_hooks"
	}

	switch name {
	case "codex":
		// codex telemetry always wires all three channels (hooks,
		// the [otel.exporter.otlp-http] block, the notify bridge).
		telemetry = []string{"hooks", "otel", "notify"}
	case "claudecode":
		// Claude Code uses hooks + the OTel env-block; no notify
		// equivalent (Anthropic doesn't ship a turn-complete shim).
		telemetry = []string{"hooks", "otel"}
	case "hermes", "cursor", "devin", "copilot", "openhands",
		"antigravity", "opencode", "amp", "kiro":
		telemetry = []string{"hooks"}
	case "omnigent":
		// OmniGent enforces through its own policy API rather than the
		// shared lifecycle-hook bridge, so it keeps a distinct surface.
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
	return connectorModeForDecision(cfg, cfg, name)
}

// connectorModeForDecision reports the guardrail mode decisionCfg (the
// caller's guardrail profile, or cfg) applies, while the hook fail mode and
// enablement, which are baked into the installed hooks, stay cfg's.
func connectorModeForDecision(cfg, decisionCfg *config.Config, name string) map[string]interface{} {
	guardrailMode := "observe"
	hookFailMode := "closed"
	enabled := false
	if cfg != nil {
		guardrailMode = cfg.EffectiveGuardrailModeForConnector(name)
		if decisionCfg != nil {
			guardrailMode = decisionCfg.EffectiveGuardrailModeForConnector(name)
		}
		hookFailMode = cfg.EffectiveHookFailModeForConnector(name)
		enabled = cfg.Guardrail.EffectiveEnabled(name)
	}
	out := connectorModeFor(name, guardrailMode)
	if guardrailMode != "" {
		out["guardrail_mode"] = guardrailMode
	}
	out["hook_fail_mode"] = hookFailMode
	out["enabled"] = enabled
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

type enforcementRequest struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
	// Connector scopes a config change to one connector; empty is global.
	Connector string `json:"connector,omitempty"`
	// SourcePath pins an allow to one install path (source_path_contains).
	SourcePath string `json:"source_path,omitempty"`
}

type enforcementEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	UpdatedAt  time.Time `json:"updated_at"`
	Connector  string    `json:"connector,omitempty"`
}

type policyEvaluateRequest struct {
	Domain string              `json:"domain"`
	Input  policyEvaluateInput `json:"input"`
}

type policyEvaluateInput struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Path       string `json:"path"`
	// Connector is the connector asking (the OpenClaw plugin sends
	// "openclaw"); asset_policy rules scoped to a connector match only it.
	Connector  string                    `json:"connector,omitempty"`
	ScanResult *policyEvaluateScanResult `json:"scan_result,omitempty"`
}

type policyEvaluateScanResult struct {
	MaxSeverity   string `json:"max_severity"`
	TotalFindings int    `json:"total_findings"`
	// ScannerName keys admission.<type>.scanner_overrides.
	ScannerName string `json:"scanner_name,omitempty"`
	// DeepSec hardening (S2.scanners): expose the scanner failure
	// signal so callers driving this debug endpoint can reproduce
	// the post-scan admission decision a non-zero scanner exit
	// would yield. Mirrors policy.ScanResultInput.
	ExitCode  int    `json:"exit_code,omitempty"`
	ScanError string `json:"scan_error,omitempty"`
}

type configPatchRequest struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// handleConfigPatch is POST /config/patch, served on Secure Client only.
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
	blockAction := audit.ActionAPIEnforceBlock
	if r.Method == http.MethodDelete {
		blockAction = audit.ActionAPIEnforceUnblock
	}
	if a.refuseManagedPolicyWrite(w, r, blockAction) {
		return
	}
	req, ok := a.decodeEnforcementRequest(w, r)
	if !ok {
		return
	}
	if a.legacyEnforcementRows() {
		a.handleLegacyEnforceBlock(w, r, req)
		return
	}

	edit := assetListEdit{Op: assetListOpBlock, TargetType: req.TargetType, Name: req.TargetName, Connector: req.Connector, Reason: req.Reason}
	if edit.Reason == "" {
		edit.Reason = "blocked via REST API"
	}
	status, action, details := "blocked", audit.ActionAPIEnforceBlock, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(edit.Reason, 120))
	if r.Method == http.MethodDelete {
		edit.Op, edit.Reason = assetListOpUnblock, ""
		status, action, details = "unblocked", audit.ActionAPIEnforceUnblock, fmt.Sprintf("type=%s", req.TargetType)
	}
	result, err := a.applyAssetListEdit(r.Context(), edit, apiConfigActor(r.Context()))
	if err != nil {
		a.writeAssetListError(w, r, action, err)
		return
	}
	if r.Method == http.MethodDelete && a.store != nil {
		// The watcher's own install block is journal state; an operator
		// unblock clears it too, so a restore no longer keeps it (GAP-1971).
		_ = a.store.ClearActionField(req.TargetType, req.TargetName, "install")
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(action), req.TargetName, details)
	}
	a.writeJSON(w, http.StatusOK, a.enforceWriteResponse(status, result))
}

func (a *APIServer) handleEnforceAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.refuseManagedPolicyWrite(w, r, audit.ActionAPIEnforceAllow) {
		return
	}
	req, ok := a.decodeEnforcementRequest(w, r)
	if !ok {
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "allowed via REST API"
	}

	legacy := a.legacyEnforcementRows()
	actionConnector := ""
	if !legacy {
		req.Connector = config.NormalizeConnectorName(req.Connector)
		actionConnector = req.Connector
	}
	policyName := req.TargetName
	runtimeName := req.TargetName
	if req.TargetType == "plugin" {
		policyName = normalizePluginPolicyName(req.TargetName)
		runtimeName = resolvePluginRuntimeActionName(a.store, req.TargetName, policyName, actionConnector)
	}
	var result assetListResult
	if legacy {
		// Secure Client keeps its pre-1.0 mutation order and response bytes.
		if status, err := a.enableAllowedRuntime(r.Context(), req, runtimeName, policyName, ""); err != nil {
			a.writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		if err := a.legacyAllow(req.TargetType, policyName, reason); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	} else {
		var err error
		result, err = a.applyAssetListEdit(r.Context(), assetListEdit{
			Op: assetListOpAllow, TargetType: req.TargetType, Name: policyName,
			Connector: req.Connector, Reason: reason, SourcePath: req.SourcePath,
		}, apiConfigActor(r.Context()))
		if err != nil {
			a.writeAssetListError(w, r, audit.ActionAPIEnforceAllow, err)
			return
		}
		if result.reloadErr == nil {
			// Only activate an asset after the allow rule is committed and applied.
			if status, err := a.enableAllowedRuntime(r.Context(), req, runtimeName, policyName, req.Connector); err != nil {
				a.writeJSON(w, status, map[string]any{
					"error": err.Error(), "policy_written": true, "generation": result.Generation,
				})
				return
			}
			// An operator allow lifts the automatic quarantine/disable journal
			// state, as it always did.
			if a.store != nil {
				_ = a.store.ClearActionFieldForConnector(req.TargetType, policyName, req.Connector, "file")
				_ = a.store.ClearActionFieldForConnector(req.TargetType, policyName, req.Connector, "runtime")
			}
		}
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIEnforceAllow), policyName, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(reason, 120)))
	}
	if legacy {
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "allowed"})
		return
	}
	a.writeJSON(w, http.StatusOK, a.enforceWriteResponse("allowed", result))
}

// enableAllowedRuntime restores a disabled skill or plugin in OpenClaw. The
// caller chooses the mutation order: Secure Client retains the legacy flow;
// config-driven policy commits before this is called.
func (a *APIServer) enableAllowedRuntime(ctx context.Context, req enforcementRequest, runtimeName, policyName, actionConnector string) (int, error) {
	if a.store == nil {
		return 0, nil
	}
	entry, err := a.store.GetActionForConnector(req.TargetType, runtimeName, actionConnector)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if entry == nil || entry.Actions.Runtime != "disable" {
		return 0, nil
	}
	if a.client == nil {
		return http.StatusServiceUnavailable, fmt.Errorf("gateway client not configured")
	}
	callCtx, cancel := context.WithTimeout(ctx, pluginGatewayMutationTimeout)
	defer cancel()
	switch req.TargetType {
	case "skill":
		if err := a.retryGatewayMutation(callCtx, func(ctx context.Context) error {
			return a.client.EnableSkill(ctx, req.TargetName)
		}); err != nil {
			return http.StatusBadGateway, err
		}
	case "plugin":
		if err := a.retryGatewayMutation(callCtx, func(ctx context.Context) error {
			return a.client.EnablePlugin(ctx, runtimeName)
		}); err != nil {
			return http.StatusBadGateway, err
		}
		if runtimeName != policyName {
			if err := a.store.ClearActionFieldForConnector("plugin", runtimeName, actionConnector, "runtime"); err != nil {
				return http.StatusInternalServerError, err
			}
		}
	}
	return 0, nil
}

// decodeEnforcementRequest reads and validates an /enforce/* body.
func (a *APIServer) decodeEnforcementRequest(w http.ResponseWriter, r *http.Request) (enforcementRequest, bool) {
	var req enforcementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return req, false
	}
	if req.TargetType == "" || req.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_type and target_name are required"})
		return req, false
	}
	if !a.legacyEnforcementRows() && !assetListTargetTypes[req.TargetType] {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_type must be skill, mcp, plugin or tool"})
		return req, false
	}
	return req, true
}

// legacyEnforcementRows reports a Secure Client host, which keeps operator
// rows in the audit.db actions table unchanged.
func (a *APIServer) legacyEnforcementRows() bool {
	cfg := a.liveConfig()
	return cfg != nil && cfg.SecureClientIntegration()
}

// handleLegacyEnforceBlock is the Secure Client /enforce/block, unchanged.
func (a *APIServer) handleLegacyEnforceBlock(w http.ResponseWriter, r *http.Request, req enforcementRequest) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}
	switch r.Method {
	case http.MethodPost:
		reason := req.Reason
		if reason == "" {
			reason = "blocked via REST API"
		}
		if err := a.store.SetActionField(req.TargetType, req.TargetName, "install", "block", reason); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIEnforceBlock), req.TargetName, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(reason, 120)))
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "blocked"})
	case http.MethodDelete:
		if err := a.store.ClearActionField(req.TargetType, req.TargetName, "install"); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPIEnforceUnblock), req.TargetName, fmt.Sprintf("type=%s", req.TargetType))
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked"})
	}
}

// legacyAllow is the Secure Client allow row write, unchanged.
func (a *APIServer) legacyAllow(targetType, name, reason string) error {
	if a.store == nil {
		return nil
	}
	if err := a.store.SetActionField(targetType, name, "install", "allow", reason); err != nil {
		return err
	}
	var errs []error
	if err := a.store.ClearActionField(targetType, name, "file"); err != nil {
		errs = append(errs, fmt.Errorf("clear file action: %w", err))
	}
	if err := a.store.ClearActionField(targetType, name, "runtime"); err != nil {
		errs = append(errs, fmt.Errorf("clear runtime action: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("enforce: allow %s %q: partial cleanup: %v", targetType, name, errs)
	}
	return nil
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

func resolvePluginRuntimeActionName(store *audit.Store, rawName, policyName, actionConnector string) string {
	if store == nil {
		return policyName
	}
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
		entry, err := store.GetActionForConnector("plugin", candidate, actionConnector)
		if err == nil && entry != nil && entry.Actions.Runtime == "disable" {
			return candidate
		}
	}
	return policyName
}

func (a *APIServer) handleEnforceBlocked(w http.ResponseWriter, r *http.Request) {
	a.writeEnforcementList(w, r, true)
}

func (a *APIServer) handleEnforceAllowed(w http.ResponseWriter, r *http.Request) {
	a.writeEnforcementList(w, r, false)
}

// writeEnforcementList answers GET /enforce/blocked|allowed from the live
// config's asset_policy lists (the actions table on Secure Client hosts).
func (a *APIServer) writeEnforcementList(w http.ResponseWriter, r *http.Request, blocked bool) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.legacyEnforcementRows() {
		a.writeJSON(w, http.StatusOK, configListEntries(a.liveConfig(), blocked))
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}
	value := "allow"
	if blocked {
		value = "block"
	}
	entries, err := a.store.ListByAction("install", value)
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
	// Sandbox attribution comes only from an authenticated sandbox binding
	// (audit.CorrelationEnvelope), never from a request body.
	event.SandboxID, event.SandboxName = "", ""
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
	r = a.pinRequestGeneration(r)

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
	}
	if req.Input.ScanResult != nil {
		input.ScanResult = &policy.ScanResultInput{
			MaxSeverity:   req.Input.ScanResult.MaxSeverity,
			TotalFindings: req.Input.ScanResult.TotalFindings,
			ScannerName:   req.Input.ScanResult.ScannerName,
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

	out, err := a.evaluateAdmissionPolicy(ctx, input, config.NormalizeConnectorName(req.Input.Connector))
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

// withScannerSettings adds the scanner settings a scan ran with (policy,
// analyzers and judge model, never a key) so `defenseclaw scan skill|mcp`
// reports them as the per-user `skill scan` does. The Secure Client
// integration keeps its response unchanged.
func withScannerSettings(cfg *config.Config, kind string, envelope map[string]interface{}) map[string]interface{} {
	if cfg == nil || cfg.SecureClientIntegration() {
		return envelope
	}
	settings := map[string]interface{}{}
	switch kind {
	case "skill":
		settings["policy"] = cfg.Scanners.SkillScanner.EffectivePolicy()
		if cfg.Scanners.SkillScanner.UseLLM {
			settings["judge_model"] = cfg.ResolveLLM("scanners.skill").Model
		}
	case "mcp":
		settings["analyzers"] = cfg.Scanners.MCPScanner.AnalyzersArg()
		settings["judge_model"] = cfg.ResolveLLM("scanners.mcp").Model
	}
	envelope["scanner_settings"] = settings
	return envelope
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
	if isBundledSkillScanPath(req.Target) {
		a.writeJSON(w, http.StatusConflict, map[string]string{
			"error": "vendor-bundled skills are discovery-only and are not scanned or blocked",
		})
		return
	}

	if a.rejectUnreadableScanTarget(w, "target directory", req.Target, "SKILL.md") {
		return
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
	// The live config: scanner and llm edits reload hot.
	cfg := a.liveConfig()
	// The rule pack an install-time scan applies to a skill (none under the
	// Secure Client integration), so a scan reports what admission sees.
	skillScanner := scanner.NewSkillScannerFromLLM(
		cfg.Scanners.SkillScanner,
		cfg.ResolveLLM("scanners.skill"),
		cfg.CiscoAIDefense,
	)
	skillScanner.SecureClient = cfg.SecureClientIntegration()
	ss := guardrail.NewArtifactOverlay(skillScanner, installScanRulePack(""))

	ctx, cancel := context.WithTimeout(r.Context(), componentScanTimeout(cfg, "skill"))
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

	a.writeJSON(w, http.StatusOK, withScannerSettings(cfg, "skill", scanAPIResponseEnvelope(result)))
}

// rejectUnreadableScanTarget answers with one plain line when the folder to
// scan is not there (404) or the account the gateway runs as is not allowed to
// read it, or a file the scanner must read in it (403): the scanner subprocess
// would otherwise die on the same error and the caller would get its process
// name, its exit code or its Python traceback (GAP-0229, GAP-0256). A path that
// exists but is not a directory is only logged: the scanner reports it.
func (a *APIServer) rejectUnreadableScanTarget(w http.ResponseWriter, what, target string, mustRead ...string) bool {
	info, err := os.Stat(target)
	// Secure Client keeps the scan of main, which the scanner fails on
	// (issue #1092): nothing below applies to it.
	if a.managedAIDOnly() {
		if err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "[api] warning: %s not found locally: %s\n", what, target)
		}
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("the gateway's service account cannot read %s: copy the folder somewhere it can read, or grant that account read access", target),
		})
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		a.writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("the folder does not exist: %s", target),
		})
		return true
	}
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "[api] warning: %s not found locally: %s\n", what, target)
		return false
	}
	for _, name := range mustRead {
		file := filepath.Join(target, name)
		handle, openErr := os.Open(file)
		if errors.Is(openErr, fs.ErrPermission) {
			a.writeJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("the gateway's service account cannot read %s: grant that account read access to the file", file),
			})
			return true
		}
		if openErr == nil {
			_ = handle.Close()
		}
	}
	return false
}

func (a *APIServer) isBundledMCPScanRequest(req mcpScanRequest) bool {
	if a == nil || a.scannerCfg == nil {
		return false
	}
	servers, err := a.scannerCfg.ReadMCPServersForConnector("codex")
	if err != nil {
		return false
	}
	for _, server := range servers {
		if !server.Bundled {
			continue
		}
		if req.Target == server.Name {
			return true
		}
		if req.Name == server.Name && (req.Target == server.Name || req.Target == server.URL) {
			return true
		}
	}
	return false
}

func isBundledSkillScanPath(path string) bool {
	if enforce.IsBundledSkillPath(path) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && enforce.IsBundledSkillPath(resolved)
}

func (a *APIServer) isManagedPluginScanTarget(target string) bool {
	if a == nil || a.scannerCfg == nil || strings.TrimSpace(target) == "" {
		return false
	}
	reg := connector.NewDefaultRegistry()
	opts := connector.SetupOpts{WorkspaceDir: a.scannerCfg.ConnectorWorkspaceDir()}
	for _, name := range a.scannerCfg.ActiveConnectors() {
		conn, ok := reg.Get(name)
		if !ok {
			continue
		}
		for _, managedPath := range connector.ManagedPluginArtifacts(conn, opts) {
			if sameAPIScanPath(target, managedPath) {
				return true
			}
		}
	}
	return false
}

func sameAPIScanPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbs, rightAbs)
	}
	return leftAbs == rightAbs
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
	if a.isManagedPluginScanTarget(req.Target) {
		a.writeJSON(w, http.StatusConflict, map[string]string{
			"error": "connector-managed plugins are lifecycle-owned and are not scanned",
		})
		return
	}

	if a.rejectUnreadableScanTarget(w, "plugin target directory", req.Target) {
		return
	}

	cfg := a.liveConfig()
	if cfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scanner not configured"})
		return
	}

	ps := scanner.NewPluginScanner(cfg.Scanners.PluginScanner)

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
	if a.isBundledMCPScanRequest(req) {
		a.writeJSON(w, http.StatusConflict, map[string]string{
			"error": "vendor-bundled MCP servers are discovery-only and are not scanned",
		})
		return
	}

	// The live config: scanner and llm edits reload hot.
	cfg := a.liveConfig()
	ms := scanner.NewMCPScannerFromLLM(
		cfg.Scanners.MCPScanner,
		cfg.ResolveLLM("scanners.mcp"),
		cfg.CiscoAIDefense,
	)
	ms.RulePack = scanner.MCPRulePackFor(cfg, "")

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

	a.writeJSON(w, http.StatusOK, withScannerSettings(cfg, "mcp", scanAPIResponseEnvelope(result)))
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
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionAPISkillFetch), req.Target,
				"result=rejected reason=outside-skill-roots (F-3287)")
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
	RawAction      string   `json:"raw_action,omitempty"`
	WouldBlock     bool     `json:"would_block,omitempty"`
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
	r = a.pinRequestGeneration(r)

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
		hilt := a.decisionConfig(r.Context()).Guardrail.HILT
		a.cfgMu.RUnlock()
		minSev := strings.ToUpper(strings.TrimSpace(hilt.MinSeverity))
		if minSev == "" {
			minSev = "HIGH"
		}
		input.HILT = &policy.GuardrailHILTInput{
			Enabled:     hilt.Enabled,
			MinSeverity: minSev,
		}
		decisionCfg := a.decisionConfig(r.Context())
		block, alert := guardrailThresholdRanks(resolveThresholds(decisionCfg, profileRequestConnector(r.Context())))
		input.Thresholds = &policy.ThresholdsInput{
			Block:           block,
			Alert:           alert,
			CiscoTrustLevel: decisionCfg.Guardrail.EffectiveCiscoTrustLevel(),
		}
		if decisionCfg.SecureClientIntegration() {
			// The 1.0 verdict of this route read the data.json levels.
			thresholds := policy.SecureClientGuardrailThresholds(decisionCfg.PolicyDir)
			input.Thresholds = &thresholds
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

	default:
		if r.Method == http.MethodPatch && a.managedAIDOnly() {
			// Secure Client keeps the managed refusal of main (issue #1092).
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "managed_enterprise config changes require operating-system administrator privileges; edit the managed config file or use the enterprise guardian"})
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

// policyConfigSnapshot keeps Secure Client on its start-time policy, while
// standalone and per-user requests follow the published generation.
func (a *APIServer) policyConfigSnapshot(g *Generation) *config.Config {
	if a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration() {
		return a.scannerCfg
	}
	if g != nil && g.Config != nil {
		return g.Config
	}
	return a.runtimeConfigSnapshot()
}

func (a *APIServer) evaluateGuardrailPolicy(ctx context.Context, input policy.GuardrailInput) (*policy.GuardrailOutput, error) {
	generation := a.generation()
	policyCfg := a.policyConfigSnapshot(generation)
	// Avarice F-3288: when a policy bundle is configured but
	// either the engine constructor or evaluation fails, the
	// previous code silently fell back to a built-in
	// severity-derived decision that allows clean/missing scanner
	// results and downgrades MEDIUM/HIGH to alert. That converted
	// every policy outage into a quiet enforcement bypass for
	// action-mode prompts. Load and evaluation failures still
	// fail closed. An empty Rego directory is config-only mode,
	// matching generation loading, so it uses the fallback below.
	if policyCfg != nil && policyCfg.PolicyDir != "" {
		if policyCfg.SecureClientIntegration() {
			// Secure Client keeps the engine load error of main (issue #1092).
			if err := policy.SecureClientPolicyLoadError(policyCfg.PolicyDir); err != nil {
				return policyOutageVerdict(input,
					fmt.Sprintf("policy engine load failed: %v", err)), nil
			}
		}
		prepared, err := a.preparedPolicyForGeneration(ctx, generation)
		if err == nil {
			out, evalErr := prepared.EvaluateGuardrail(ctx, input)
			if evalErr != nil {
				return policyOutageVerdict(input,
					fmt.Sprintf("policy evaluation failed: %v", evalErr)), nil
			}
			return out, nil
		}
		if policyCfg.SecureClientIntegration() || !errors.Is(err, policy.ErrNoModules) {
			return policyOutageVerdict(input,
				fmt.Sprintf("policy engine load failed: %v", err)), nil
		}
		// No Rego is config-only mode, as it is during generation loading.
	}

	// No Rego modules (or no policy directory): use the config-driven
	// severity fallback. Other load and evaluation errors fail closed.
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
	if thresholds := input.Thresholds; thresholds != nil && policyCfg != nil && !policyCfg.SecureClientIntegration() {
		// The request carries the resolved thresholds (config levels, pack
		// posture, Cisco trust level, HILT): apply them as the inspector
		// fallback does, so both no-OPA paths decide alike. Secure Client
		// keeps the default-posture answer of main (issue #1092).
		var local, cisco *ScanVerdict
		if input.LocalResult != nil {
			local = &ScanVerdict{Severity: input.LocalResult.Severity}
		}
		if input.CiscoResult != nil {
			cisco = &ScanVerdict{Severity: input.CiscoResult.Severity}
		}
		action = fallbackGuardrailVerdictForThresholds(local, cisco, *thresholds, input.Mode, input.HILT).Action
	}
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

type authenticatedInspectConnectorKey struct{}

func withAuthenticatedInspectConnector(ctx context.Context, connectorName string) context.Context {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	if connectorName == "" {
		return ctx
	}
	return context.WithValue(ctx, authenticatedInspectConnectorKey{}, connectorName)
}

func authenticatedInspectConnector(ctx context.Context) string {
	connectorName, _ := ctx.Value(authenticatedInspectConnectorKey{}).(string)
	return canonicalConnectorRulePackKey(connectorName)
}

// tokenAuth wraps a handler with Bearer token authentication. Management
// clients may use Authorization, X-DefenseClaw-Token, or the proxy-compatible
// X-DC-Auth header; all are compared against the same gateway token.
// GET /health is exempt to allow unauthenticated health checks. In the
// standalone profile the listener proof route answers before authentication
// and never reaches next.
func (a *APIServer) tokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == connector.UserScopedListenerProofPath && a.userScopedCredentialsRequired() {
			// A standalone in-agent plugin on loopback TCP makes the
			// listener prove it is the gateway before it sends its per-user
			// credential (user_scoped_listener_proof.go). Every other
			// profile keeps the ordinary authentication below.
			a.serveUserScopedListenerProof(w, r)
			return
		}
		route := r.Pattern
		if route == "" {
			// Sanitize so the OTLP path-token is never recorded as a
			// route attribute on auth-failure telemetry.
			route = sanitizeRouteForTelemetry(r.URL.Path)
		}
		ctx := r.Context()
		// Sandbox binding credentials are valid only on the sandbox ingress
		// listener. Refuse them before any other comparison so that no
		// loopback carve-out below (hook, OTLP, inspect, ACP) can ever be
		// reached with one, whatever header or path carries it.
		if requestCarriesSandboxCredential(r) {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_token")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if (r.URL.Path == "/api/v1/acp/challenge" || r.URL.Path == "/api/v1/acp/evaluate") &&
			connector.IsLoopback(r) && r.Header.Get(acp.AuthKeyIDHeader) != "" {
			authenticated, token, nonce, ok := a.authenticateACPSignedRequest(r)
			if !ok {
				a.emitHTTPAuthFailure(a.withRevokedACPCredential(a.withACPCallerAccount(ctx, r), r), r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_acp_signed_request")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if reason := a.acpCallerAccountRefusal(authenticated); reason != "" {
				a.emitHTTPAuthFailure(a.withACPCallerAccount(ctx, r), r, route, gatewaylog.ErrCodeAuthInvalidToken, reason)
				if reason == acpCallerAccountMismatchReason {
					// The caller holds the credential, so the refusal can be
					// signed and the guard can tell the borrower whose it is
					// instead of "revoked" (GAP-0690).
					writeACPSignedOtherAccountRefusal(w, r, token, nonce)
					return
				}
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			// The ACP credential that signed the request names who sent it:
			// the principal it was enrolled for on a managed gateway, the
			// gateway's own account on a per-user one. Identity headers the
			// caller sent stay claims.
			authenticated = authenticated.WithContext(a.attachACPSubject(authenticated.Context()))
			serveACPSignedResponse(w, authenticated, next, token, nonce)
			return
		}
		if r.URL.Path == "/api/v1/acp/challenge" || r.URL.Path == "/api/v1/acp/evaluate" {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "missing_acp_authenticated_transport")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		token := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
		if token == "" {
			token = r.Header.Get("X-DefenseClaw-Token")
		}
		if token == "" {
			if dcAuth := r.Header.Get("X-DC-Auth"); strings.HasPrefix(dcAuth, "Bearer ") {
				token = strings.TrimPrefix(dcAuth, "Bearer ")
			}
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
		// Codex and Claude Code support arbitrary OTLP headers. Bind their
		// connector-scoped bearer to the authenticated source while keeping the
		// credential out of the URL. Once a scoped credential exists, refuse the
		// master gateway bearer for that source exactly as the path-token route
		// does; a leaked connector configuration must never grant management API
		// authority. Exporters that cannot set an authorization header use the
		// path form below.
		// The standalone profile accepts connector credentials only when they
		// are bound to one user (user_scoped_credentials.go): a request that
		// presents one is attributed to that user, and a connector-wide
		// credential, which every user of the connector used to hold, no
		// longer authenticates.
		userScoped := a.userScopedCredentialsRequired()
		if isUnscopedOTLPEndpointPath(r.URL.Path) && connector.IsLoopback(r) {
			source := normalizeConnectorTelemetrySource(r.Header.Get(otelSourceHeader))
			if scope, validSource := connector.OTLPPathTokenScopeForConnector(source); validSource {
				if identity, ok := a.lookupUserScopedCredential(connector.UserScopedOTLPCredential, string(scope), token); ok {
					r.Header.Set(otelSourceHeader, string(scope))
					a.serveUserScoped(w, r, route, identity, next, nil)
					return
				}
				scoped := a.lookupOTLPPathToken(string(scope))
				if scoped != "" {
					if !userScoped && token != "" && constantTimeStringMatch(token, scoped) {
						// Preserve only the canonical source name used to select the
						// credential so attribution cannot drift through an alias.
						r.Header.Set(otelSourceHeader, string(scope))
						r = r.WithContext(PromoteSessionIfAuthenticated(r.Context()))
						next.ServeHTTP(w, r)
						return
					}
					a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_scoped_header_token")
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
			}
		}
		if pathToken, source, ok := parseOTLPPathToken(r.URL.Path); ok && connector.IsLoopback(r) {
			if token == "" {
				if identity, ok := a.lookupUserScopedCredential(connector.UserScopedOTLPCredential, source, pathToken); ok {
					a.serveUserScoped(w, r, route, identity, next, nil)
					return
				}
			}
			scoped := a.lookupOTLPPathToken(source)
			if scoped != "" {
				if token != "" {
					a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "scoped_otlp_rejects_header_token")
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
				if !userScoped && constantTimeStringMatch(pathToken, scoped) {
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
			if identity, ok := a.lookupUserScopedCredential(connector.UserScopedHookCredential, hookScope, token); ok {
				if a.refuseUnverifiedSurface(w, r, route, hookScope) {
					return
				}
				a.serveUserScoped(w, r, route, identity, next, func(ctx context.Context) context.Context {
					return withAuthenticatedHookConnector(ctx, hookScope)
				})
				return
			}
			if !userScoped && a.hookAPITokenMatches(hookScope, token) {
				r = r.WithContext(withAuthenticatedHookConnector(
					a.attachProcessOwnerSubject(PromoteSessionIfAuthenticated(r.Context())),
					hookScope,
				))
				next.ServeHTTP(w, r)
				return
			}
		}
		if isACPAPIPath(r.URL.Path) && connector.IsLoopback(r) {
			if authenticated, ok := a.authenticateACPToken(r, token); ok {
				r = authenticated.WithContext(a.attachACPSubject(authenticated.Context()))
				next.ServeHTTP(w, r)
				return
			}
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_acp_scoped_token")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/inspect/") && connector.IsLoopback(r) && token != "" {
			hookScope := strings.ToLower(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")))
			registered := false
			if a.connectorRegistry != nil {
				_, registered = a.connectorRegistry.Get(hookScope)
			}
			if registered {
				if identity, ok := a.lookupUserScopedCredential(connector.UserScopedHookCredential, hookScope, token); ok {
					if a.refuseUnverifiedSurface(w, r, route, hookScope) {
						return
					}
					a.serveUserScoped(w, r, route, identity, next, func(ctx context.Context) context.Context {
						return withAuthenticatedInspectConnector(ctx, hookScope)
					})
					return
				}
			}
			if registered && !userScoped && a.hookAPITokenMatches(hookScope, token) {
				r = r.WithContext(withAuthenticatedInspectConnector(
					a.attachProcessOwnerSubject(PromoteSessionIfAuthenticated(r.Context())),
					hookScope,
				))
				next.ServeHTTP(w, r)
				return
			}
		}
		if token == "" {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthMissingToken, "missing_token")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if !constantTimeStringMatch(token, expected) && !a.matchesRefreshedGatewayToken(token) {
			a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, "invalid_token")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// DeepSec S2.MEDIUM ("CorrelationMiddleware mints
		// unauthenticated agent sessions"): now that auth has
		// succeeded, upgrade the previously peeked agent identity
		// to a fully minted entry so authenticated traffic still
		// gets a stable agent_instance_id on its emissions.
		ctx = a.attachProcessOwnerSubject(PromoteSessionIfAuthenticated(r.Context()))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// matchesRefreshedGatewayToken accepts the gateway token the OpenClaw
// client adopted from openclaw.json after boot. Auth repair persists that
// token to .env and hooks/.token, so the CLI (for example the graceful
// shutdown during 'setup openclaw') presents it before this process
// restarts (GAP-2259). The boot token stays valid until the restart.
func (a *APIServer) matchesRefreshedGatewayToken(token string) bool {
	refreshed := a.client.RefreshedToken()
	return refreshed != "" && constantTimeStringMatch(token, refreshed)
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
	a.emitHTTPAuthFailureForConnector(ctx, r, route, code, metricReason, "")
}

// emitHTTPAuthFailureForConnector is emitHTTPAuthFailure for a refusal that
// knows the connector route the caller asked for.
func (a *APIServer) emitHTTPAuthFailureForConnector(ctx context.Context, r *http.Request, route string, _ gatewaylog.ErrorCode, metricReason, connectorName string) {
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
		a.emitAPIAuthenticationFailureV8(ctx, metricReason, apiAuthenticationFailureFactsFor(ctx, route, connectorName))
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
			// CANNOT be enforced here because some OTLP exporters cannot set
			// arbitrary HTTP headers — only
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

const (
	apiRequestBodyMaxBytes  int64 = 1 << 20
	otlpRequestBodyMaxBytes int64 = 64 << 20
)

// apiBodyLimitMiddleware preserves the ordinary API mutation ceiling while
// allowing exact OTLP-HTTP ingest routes to receive exporter batches. The
// 64 MiB OTLP limit follows the protocol's recommended receiver default and
// matches the observability pipeline's supported maximum export batch size.
func apiBodyLimitMiddleware(next http.Handler, maxBytes, otlpMaxBytes int64) http.Handler {
	return bodyLimitMiddleware(next, func(r *http.Request) int64 {
		if isOTLPEndpointPath(r.URL.Path) {
			return otlpMaxBytes
		}
		return maxBytes
	})
}

// maxBodyMiddleware applies one uniform cap to all state-changing methods.
func maxBodyMiddleware(next http.Handler, maxBytes int64) http.Handler {
	return bodyLimitMiddleware(next, func(*http.Request) int64 { return maxBytes })
}

func bodyLimitMiddleware(next http.Handler, maxBytes func(*http.Request) int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes(r))
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

// componentScanTimeout bounds one REST or hook scan of component. A skill
// scan follows scanners.skill_scanner.timeouts.scan_s, as the install watcher
// does, so a judge-on scan of a large skill is not cut at two minutes while
// the watcher waits for it (GAP-0301). Plugin and MCP scans keep two minutes,
// and so does a Secure Client host, as on main (issue #1092).
func componentScanTimeout(cfg *config.Config, component string) time.Duration {
	if component == "skill" && cfg != nil && !cfg.SecureClientIntegration() {
		return time.Duration(cfg.Scanners.SkillScanner.ScanTimeoutSeconds()) * time.Second
	}
	return 120 * time.Second
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

// evaluateAdmissionPolicy evaluates admission with the input built from the
// live config: the compiled admission: and the asset_policy lists. The
// built-in Go twin runs only when OPA fails. OPA is the live generation's
// prepared query (prepared once for an API server without a generation).
func (a *APIServer) evaluateAdmissionPolicy(ctx context.Context, input policy.AdmissionInput, connector string) (*policy.AdmissionOutput, error) {
	cfg := a.liveConfig()
	input.BlockList, input.AllowList = policy.AssetPolicyListsFor(cfg, config.AssetPolicyInput{
		TargetType: input.TargetType, Name: input.TargetName, Connector: connector, SourcePath: input.Path,
	})
	input.Admission = policy.AdmissionFor(policy.CompileAdmission(cfg), input.TargetType)
	secureClient := cfg != nil && cfg.SecureClientIntegration()
	if !secureClient {
		input.VerifyFirstParty()
	}
	if secureClient {
		input.BlockList, input.AllowList = a.legacyPolicyListEntries(true), a.legacyPolicyListEntries(false)
		// The engine of main needed data.json: without it, main answered from
		// its fallback even when policy_dir held Rego modules (issue #1092).
		if policy.SecureClientPolicyLoadError(a.startPolicyDir()) != nil {
			return policy.EvaluateSecureClientAdmission(input, a.startPolicyDir()), nil
		}
	}
	if a.generationSource != nil || (a.scannerCfg != nil && a.scannerCfg.PolicyDir != "") {
		if prepared, err := a.preparedPolicy(ctx); err == nil {
			if out, err := prepared.EvaluateAdmission(ctx, input); err == nil && out != nil {
				return out, nil
			}
		}
	}
	if secureClient {
		// Secure Client keeps the admission fallback of main (issue #1092).
		return policy.EvaluateSecureClientAdmission(input, a.startPolicyDir()), nil
	}
	return policy.EvaluateAdmissionFallback(input), nil
}

// startPolicyDir is the policy_dir of the start-time configuration.
func (a *APIServer) startPolicyDir() string {
	if a.scannerCfg == nil {
		return ""
	}
	return a.scannerCfg.PolicyDir
}

// legacyPolicyListEntries is the Secure Client block/allow list read from
// the actions table, unchanged.
func (a *APIServer) legacyPolicyListEntries(blocked bool) []policy.ListEntry {
	if a.store == nil {
		return nil
	}
	value := "allow"
	if blocked {
		value = "block"
	}
	actions, err := a.store.ListByAction("install", value)
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

func classifyScanError(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "not_found"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "cannot find the file specified") ||
		strings.Contains(msg, "cannot find the path specified"):
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
// POST /policy/reload — hot-reload OPA engine from disk
// ---------------------------------------------------------------------------

func (a *APIServer) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyCfg := a.policyConfigSnapshot(a.generation())
	if policyCfg == nil || policyCfg.PolicyDir == "" {
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

	// Secure Client keeps the reload check of main (issue #1092): it fails
	// while the policy directory has no data.json.
	if policyCfg.SecureClientIntegration() {
		if err := policy.SecureClientPolicyLoadError(policyCfg.PolicyDir); err != nil {
			recordFailure(err.Error())
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "reload failed: " + err.Error(),
				"status": "failed",
			})
			return
		}
	}

	// Rebuild the configuration generation now: Rego modules and rule packs
	// are prepared once and swapped atomically, or the live generation stays.
	if a.policyReloader == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy reload is not available"})
		return
	}
	if err := a.policyReloader(); err != nil {
		recordFailure(err.Error())
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "reload failed: " + err.Error(),
			"status": "failed",
		})
		return
	}

	// Any cached LLM-judge verdict was rendered under the previous
	// policy; drop it in O(1) so the next call re-evaluates under
	// the fresh rulepack. Safe no-op when the cache is unset.
	InvalidateJudgeVerdictCache()

	if err := a.logger.LogActionCtx(r.Context(), string(audit.ActionPolicyReload), policyCfg.PolicyDir, "OPA policy reloaded via API"); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy reloaded but compliance logging failed"})
		return
	}
	if err := a.recordAPIPolicyReloadMetricV8(r.Context(), "success"); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy reloaded but observability metric failed"})
		return
	}

	reloaded := map[string]any{
		"status":     "reloaded",
		"policy_dir": policyCfg.PolicyDir,
	}
	// The live generation after the rebuild, so a caller can say which policy is enforcing now.
	if g := livePolicyGeneration(); g != nil {
		reloaded["generation"] = g.N
		reloaded["digest"] = g.Digest
	}
	a.writeJSON(w, http.StatusOK, reloaded)
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

	codeScanner := scanner.ScanCode
	if a.codeScanner != nil {
		codeScanner = a.codeScanner
	}
	result, err := codeScanner(r.Context(), req.Path, rulesDir)
	if err != nil {
		a.recordAPIScanErrorV8(r.Context(), "codeguard", "code", classifyScanError(err))
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// The canonical logger intentionally neutralizes sensitive findings in
	// place before persistence. Snapshot scanner-owned response facts first so
	// the detached output projector can preserve safe location/remediation
	// context while independently removing detected spans.
	responseSource := scanoutput.Clone(result)
	if a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(r.Context(), result, "", ScanCorrelationFromContext(r.Context()))
	}

	// Canonical persistence above owns the raw local facts. Project a detached
	// response copy so detector-recognized spans are protected while ordinary
	// file/line and remediation context remains useful. The REST contract has
	// no raw-output switch; only the local CLI can make that explicit choice.
	a.writeJSON(w, http.StatusOK, a.codeScanOutputProjector().Project(responseSource))
}

func (a *APIServer) codeScanOutputProjector() *scanoutput.Redactor {
	if a == nil {
		return scanoutput.NewUnavailableRedactor()
	}
	a.scanOutputRedactionMu.Lock()
	defer a.scanOutputRedactionMu.Unlock()
	if a.scanOutputRedactor != nil {
		return a.scanOutputRedactor
	}
	cfg := a.runtimeConfigSnapshot()
	dataDir := ""
	if cfg != nil {
		dataDir = strings.TrimSpace(cfg.DataDir)
	}
	var (
		redactor *scanoutput.Redactor
		err      error
	)
	if dataDir == "" {
		redactor, err = scanoutput.NewEphemeralRedactor()
	} else {
		redactor, err = scanoutput.LoadRedactor(dataDir)
	}
	if err != nil || redactor == nil {
		// Fail closed for this response, but retry after an operator repairs
		// key custody instead of pinning degraded output for process lifetime.
		return scanoutput.NewUnavailableRedactor()
	}
	a.scanOutputRedactor = redactor
	return redactor
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
	requestUser := resolveHTTPUserIdentity(r, nil)
	evt.UserID = firstNonEmpty(requestUser.ID, evt.UserID)
	evt.UserIDKind = ""
	if evt.UserID == requestUser.ID {
		evt.UserIDKind = requestUser.IDKind
	}
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

// connectorProxyBindsByName reports whether the named connector puts the
// DefenseClaw proxy in its LLM data path, resolved through the connector
// registry so status can never disagree with what the sidecar actually binds.
// An unknown or unregistered name keeps the conservative proxy default that
// plugin connectors have always had.
func connectorProxyBindsByName(name string) bool {
	conn, ok := sharedDefaultRegistry().Get(strings.ToLower(strings.TrimSpace(name)))
	if !ok {
		return true
	}
	return proxyShouldBindForConnector(conn, nil)
}
