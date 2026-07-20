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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/notify"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
	"github.com/google/uuid"
)

var launchConfigRestartHelper = defaultLaunchConfigRestartHelper
var validateManagedGuardianAuthorization = managed.ValidateTrustedFilePath

// Sidecar is the long-running process that connects to the agent gateway,
// watches for skill installs, and exposes a local REST API.
type Sidecar struct {
	startedAt     time.Time
	cfg           *config.Config
	cfgCurrent    atomic.Pointer[config.Config]
	client        *Client
	router        *EventRouter
	store         *audit.Store
	logger        *audit.Logger
	health        *SidecarHealth
	shell         *sandbox.OpenShell
	notify        *NotificationQueue
	opa           *policy.Engine
	hilt          *HILTApprovalManager
	webhooks      *WebhookDispatcher
	aiDiscovery   *inventory.ContinuousDiscoveryService
	appProtection *applicationProtectionController
	osNotifier    *notifier.Dispatcher
	configMgr     *ConfigManager

	// ipcRunner is injected by the CLI layer to avoid a gateway/ipc import
	// cycle. A nil runner disables the managed UDS server.
	ipcRunner IPCRunner

	webhooksMu               sync.RWMutex
	aiDiscoveryMu            sync.RWMutex
	apiMu                    sync.RWMutex
	apiServer                *APIServer
	hookGuardsMu             sync.RWMutex
	hookGuards               map[*HookConfigGuard]struct{}
	hookGuardsChanged        chan struct{}
	proxyMu                  sync.RWMutex
	guardrailProxy           *GuardrailProxy
	apiRestartCh             chan struct{}
	watcherRestartCh         chan struct{}
	guardrailRestartCh       chan struct{}
	aiRestartCh              chan struct{}
	runCancelMu              sync.Mutex
	runCancel                context.CancelFunc
	observabilityV8Mu        sync.Mutex
	observabilityV8          sidecarRuntimeEmitter
	observabilityV8Lifecycle lifecycleV8Runtime
	// observabilityV8ConsumersDetached prevents a consumer constructed during
	// shutdown from republishing capabilities for the retiring owned runtime.
	observabilityV8ConsumersDetached bool
	observabilityV8Run               bool
	// exporterHealthMetric* retains only monotonic, content-free delivery
	// counters for the active graph generation. It converts runtime health
	// snapshots into delta exporter-error metrics without resurrecting a global
	// OTel provider or double-counting the same failed delivery on every tick.
	exporterHealthMetricMu         sync.Mutex
	exporterHealthMetricGeneration uint64
	exporterHealthMetricCounters   map[exporterHealthMetricKey]uint64

	alertCtx    context.Context
	alertCancel context.CancelFunc
	alertWg     sync.WaitGroup

	// judge is the LLM judge instance shared between the proxy lane
	// (EventRouter.SetJudge) and the hook lane (APIServer.SetHookJudge
	// in runAPI) so both lanes use one Bifrost client cache and one
	// verdict cache. nil when guardrail.judge.enabled is false.
	judgeMu sync.RWMutex
	judge   *LLMJudge

	// judgeStore is the async judge completion queue. It remains active when
	// guardrail.retain_judge_bodies is off so canonical allow/block/error logs
	// are policy-independent; its optional body inserter is enabled only when
	// retention is on. Sidecar.Run drains it on shutdown.
	judgeStore *JudgeStore

	// judgeBodyStore is the Phase 4 split-out SQLite database
	// dedicated to judge_responses. Held here so Sidecar.Run can
	// close it after the queue drains; the audit.Store keeps
	// audit_events / activity_events on its own file.
	judgeBodyStore *audit.JudgeBodyStore

	// Schema-v8 construction opens the forensic store before the canonical
	// observability runtime can be bound. Retain the content-free readiness
	// occurrence until the CLI completes that binding; v7 continues to emit it
	// synchronously from NewSidecar.
	judgeBodiesReadyMu      sync.Mutex
	judgeBodiesReadyPending bool
	judgeBodiesReadyDetails string

	// cmidProviderMu guards cmidProviderInst. The provider is lazily
	// constructed on first request via ensureCMIDProvider and reused
	// for the sidecar's lifetime. Managed-mode wiring only.
	cmidProviderMu   sync.Mutex
	cmidProviderInst cloudreg.Provider
}

// osToastSenderFor returns the sender the OS-toast lane of the
// notifier should use. In managed_enterprise the Secure Client GUI
// is the intended surface for user-visible notifications (routed
// via the internal/ipc UDS observer), so the daemon's own
// osascript / notify-send calls would double-deliver. This helper
// swaps in a silent no-op for that lane; the observer lane
// (feeding IPC subscribers) is unaffected because notifier.dispatch
// fires observers independently of whether the sender was invoked.
func osToastSenderFor(cfg *config.Config) func(notify.Notification) error {
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return func(notify.Notification) error { return nil }
	}
	return notify.SendNotification
}

// NewSidecar creates a sidecar instance ready to connect.
func NewSidecar(cfg *config.Config, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell) (*Sidecar, error) {
	if cfg == nil || cfg.ConfigVersion != config.ObservabilityV8ConfigVersion {
		return nil, fmt.Errorf("sidecar: schema v8 is required; run 'defenseclaw upgrade' first")
	}
	fmt.Fprintf(os.Stderr, "[sidecar] initializing client (host=%s port=%d device_key=%s)\n",
		cfg.Gateway.Host, cfg.Gateway.Port, cfg.Gateway.DeviceKeyFile)

	// Mint a per-process agent instance id immediately so every
	// audit row that fires during sidecar boot (device-identity
	// load, guardrail init, WS client dial) carries the same
	// stable id we later advertise on tool/approval events. The
	// router also stamps a per-session id on conversation-scoped
	// events; this one is the process-lifetime fallback.
	agentInstanceID := uuid.New().String()
	audit.SetProcessAgentInstanceID(agentInstanceID)
	// Keep the compatibility identity registry aligned because correlation
	// helpers and imported event adapters still read it; production delivery is
	// owned by the v8 runtime rather than the compatibility identity registry.
	gatewaylog.SetSidecarInstanceID(agentInstanceID)
	gatewaylog.SetAgentWatchContext(gatewaylog.AgentWatchContext{
		TenantID:        cfg.TenantID,
		WorkspaceID:     cfg.WorkspaceID,
		Environment:     cfg.Environment,
		DeploymentMode:  cfg.DeploymentMode,
		DiscoverySource: cfg.DiscoverySource,
	})

	// Seed run_id so every audit row and generated observability record
	// record in this sidecar run carries a non-empty correlation
	// key. Precedence:
	//   1. DEFENSECLAW_RUN_ID from the env (set by the daemon
	//      launcher or an operator pinning a specific run id).
	//   2. Newly minted UUID — covers `go run`, direct
	//      `defenseclaw-gateway` invocations, and test harnesses
	//      that never exported the env var.
	// We mirror the resolved value back into the env so legacy
	// readers (Python scanners, subprocess judges) and future
	// child processes still pick it up transparently, and install
	// the atomic copy for in-process readers that now prefer
	// gatewaylog.ProcessRunID().
	runID := strings.TrimSpace(os.Getenv("DEFENSECLAW_RUN_ID"))
	if runID == "" {
		runID = uuid.NewString()
		_ = os.Setenv("DEFENSECLAW_RUN_ID", runID)
	}
	gatewaylog.SetProcessRunID(runID)
	// Persist the retention flag before any goroutines start so the
	// very first judge invocation sees the operator-configured value
	// (otherwise the default atomic would race with early traffic).
	//
	// Upgrade has already materialized any legacy environment override. Runtime
	// retention is controlled only by committed v8 policy.
	retainJudge := cfg.Guardrail.RetainJudgeBodies
	SetRetainJudgeBodies(retainJudge)

	// In standalone sandbox mode the veth link is point-to-point;
	// TLS is not needed and the gateway serves plain WS.
	if !cfg.Gateway.RequiresTLSWithMode(&cfg.OpenShell) {
		cfg.Gateway.NoTLS = true
	}

	client, err := NewClient(&cfg.Gateway)
	if err != nil {
		return nil, fmt.Errorf("sidecar: create client: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[sidecar] device identity loaded (id=%s)\n", client.device.DeviceID)

	// Plan B6 / S0.10: install the per-boot HMAC seed for telemetry
	// payload integrity. We feed the ed25519 device-key seed to HKDF
	// inside SetTelemetryHMACSeed so the HMAC key is derived (not
	// reused) — the device key never ends up on the wire even
	// indirectly. Done as early as possible so every event emitted
	// after this point is HMAC-stamped at the writer choke point.
	gatewaylog.SetTelemetryHMACSeed(client.device.PrivateKey.Seed())

	notify := NewNotificationQueue()

	// User-session OS notifier dispatcher. Constructed unconditionally
	// so every block / approval site can call into it without nil
	// checks; the dispatcher's master Enabled gate keeps it silent
	// when the operator hasn't opted in (or is on a platform without
	// a display server). The setup wizard flips Enabled=true after
	// asking the user — see cli/defenseclaw/commands/cmd_setup.py.
	//
	// managed_enterprise routes user-visible notifications through
	// the local UDS IPC surface (Cisco Secure Client GUI is the
	// presentation layer) so we suppress the daemon's own OS toasts
	// to avoid double-delivery. Observers (the IPC bridge) keep
	// firing regardless — see osToastSenderFor.
	osNotifier := notifier.NewWithSender(cfg.Notifications, osToastSenderFor(cfg))

	router := NewEventRouter(client, store, logger, cfg.Gateway.AutoApprove)
	router.notify = notify
	router.SetGuardrailConfig(&cfg.Guardrail)
	hilt := NewHILTApprovalManager(client)
	hilt.SetNotifier(osNotifier)
	router.SetHILTApprovalManager(hilt)
	// Seed defaults for the observability contract so every span /
	// audit row knows which agent (framework mode) and policy
	// signed off on the event even when the incoming stream does
	// not carry a hint.
	router.SetDefaultAgentName(string(cfg.Claw.Mode))
	// We use Guardrail.Mode ("default" | "strict" | "permissive") as
	// the policy identifier because it is the only operator-selected,
	// version-controlled handle on the guardrail configuration today.
	// When a richer policy catalog exists (rule-pack id, Rego bundle
	// digest) callers can override this via SetDefaultPolicyID.
	router.SetDefaultPolicyID(cfg.Guardrail.Mode)

	// Load guardrail rule pack for judge prompts, suppressions, etc.
	rp := loadSidecarRulePack(cfg)
	router.SetRulePack(rp)
	ApplyRulePackOverrides(rp)
	// local-patterns.yaml replaces the compiled-in local pattern set
	// per-profile when present in the rule pack. Calling with nil
	// LocalPatterns is a no-op (keeps the defaults), so this is safe
	// even when an operator hasn't customized the file.
	ApplyLocalPatternsOverride(rp.LocalPatterns)

	// Seed custom-providers overlay from llm.base_url so a custom LLM
	// gateway domain is recognized by isKnownProviderDomain(). Must run
	// before providerRegistrySnapshot() calls below.
	if err := SeedCustomProvidersFromLLMBaseURL(cfg.LLM.BaseURL); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] custom-providers seed warning: %v\n", err)
	}

	// Wire LLM judge when enabled. The judge handles tool-call injection
	// detection AND tool-result PII inspection (via inspectToolResult),
	// so it must be initialized whenever judge is enabled — not only when
	// tool_injection is on.
	hookJudge := buildSharedJudge(cfg, rp)
	if hookJudge != nil {
		router.SetJudge(hookJudge)
	}

	previousClientOnEvent := client.OnEvent
	client.OnEvent = router.Route

	alertCtx, alertCancel := context.WithCancel(context.Background())

	var webhooks *WebhookDispatcher
	// Construct when there are global webhooks OR any per-connector
	// observability override (D5b); NewWebhookDispatcher returns nil when
	// neither yields an endpoint, and the nil-checks below tolerate that.
	if len(cfg.Webhooks) > 0 || len(cfg.Observability.Connectors) > 0 {
		webhooks = NewWebhookDispatcher(cfg.Webhooks, cfg.Observability)
		if webhooks != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] webhook dispatcher initialized (%d global endpoints, %d per-connector overrides)\n",
				len(webhooks.endpoints), len(webhooks.connectorOverride))
		}
	}
	if shell != nil && logger != nil {
		shell.BindObservabilityV8(logger)
	}

	var (
		judgeStore              *JudgeStore
		judgeBodyStore          *audit.JudgeBodyStore
		judgeBodiesReadyPending bool
		judgeBodiesReadyDetails string
	)
	cleanupFailedConstruction := func() {
		alertCancel()
		client.OnEvent = previousClientOnEvent
		if shell != nil {
			shell.BindObservabilityV8(nil)
		}
		if webhooks != nil {
			webhooks.Close()
		}
		SetJudgeResponseStore(nil)
		if judgeStore != nil {
			_ = shutdownJudgeStore(judgeStore)
		}
		if judgeBodyStore != nil {
			_ = judgeBodyStore.Close()
		}
	}

	// Phase 3: always enqueue structured judge completions so every configured
	// sink sees the canonical summary. Raw body persistence is a separate,
	// optional side effect controlled by retain_judge_bodies.
	//
	// Retention defaults to on (see viper.SetDefault); operators who opt out via
	// config or DEFENSECLAW_PERSIST_JUDGE=0 get no judge_responses body row but
	// retain the canonical completion. The raw body is only touched inside this
	// process; route-specific central projection owns export redaction, and the
	// InsertJudgeResponse body stays on disk under the data-directory ACLs.
	queueDepth := cfg.Guardrail.JudgePersistQueueDepth
	if v := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_PERSIST_QUEUE_SIZE")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			queueDepth = parsed
		}
	}
	legacyJudgeBodies := false
	if store != nil {
		var legacyErr error
		legacyJudgeBodies, legacyErr = audit.HasLegacyJudgeBodies(context.Background(), store)
		if legacyErr != nil {
			cleanupFailedConstruction()
			return nil, fmt.Errorf("inspect legacy judge-body cutover work: %w", legacyErr)
		}
	}
	if (retainJudge || legacyJudgeBodies) && store != nil {
		// V8 cutover: judge bodies live exclusively in the dedicated
		// SQLite file. The cutover constructor blocks reads/writes until
		// every legacy row has committed and verified by stable ID. Any
		// open/copy/verification failure aborts startup; audit.db is never
		// used as a raw-body fallback.
		bodyDBPath := strings.TrimSpace(cfg.JudgeBodiesDB)
		if bodyDBPath == "" {
			bodyDBPath = filepath.Join(cfg.DataDir, config.DefaultJudgeBodiesDBName)
		}
		bs, openErr := openAuthoritativeJudgeBodyStore(context.Background(), bodyDBPath, store)
		if openErr != nil {
			cleanupFailedConstruction()
			return nil, openErr
		}
		judgeBodyStore = bs
		judgeBodyStore.BindSQLiteBusyObservabilityV8(logger)
		judgeBodiesReadyDetails = "path=" + bodyDBPath
		judgeBodiesReadyPending = deferJudgeBodiesReady(logger)
	}
	var bodyInserter JudgeBodyInserter
	if retainJudge && judgeBodyStore != nil {
		bodyInserter = &judgeBodyStoreInserter{s: judgeBodyStore}
	}
	// One bounded queue owns completion ordering in both retention modes. With
	// bodyInserter nil it emits canonical summaries only; with an inserter it
	// attempts the body transaction first and then emits the same summary.
	judgeStore = NewJudgeStore(bodyInserter, logger, queueDepth)
	SetJudgeResponseStore(judgeStore)

	aiDiscovery, err := inventory.NewContinuousDiscoveryService(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] ai discovery init failed: %v\n", err)
	}
	sidecar := &Sidecar{
		startedAt:               time.Now(),
		cfg:                     cfg,
		client:                  client,
		store:                   store,
		logger:                  logger,
		health:                  NewSidecarHealth(),
		shell:                   shell,
		notify:                  notify,
		webhooks:                webhooks,
		hilt:                    hilt,
		aiDiscovery:             aiDiscovery,
		osNotifier:              osNotifier,
		apiRestartCh:            make(chan struct{}, 1),
		watcherRestartCh:        make(chan struct{}, 1),
		guardrailRestartCh:      make(chan struct{}, 1),
		aiRestartCh:             make(chan struct{}, 1),
		alertCtx:                alertCtx,
		alertCancel:             alertCancel,
		judge:                   hookJudge,
		judgeStore:              judgeStore,
		judgeBodyStore:          judgeBodyStore,
		judgeBodiesReadyPending: judgeBodiesReadyPending,
		judgeBodiesReadyDetails: judgeBodiesReadyDetails,
	}
	sidecar.setEventRouter(router)
	sidecar.publishConfig(cfg)
	// Publish the process-global managed carve-out only after every fallible
	// constructor has succeeded. A rejected Sidecar candidate must not change
	// redaction behavior for an already-running embedder or a later retry.
	setManagedEnterpriseRedactionPosture(managed.IsManagedEnterprise(cfg.DeploymentMode))
	return sidecar, nil
}

func deferJudgeBodiesReady(logger *audit.Logger) bool {
	return logger != nil
}

// EmitPostBootstrapPlatformHealth publishes construction-time health facts
// that schema v8 must not emit before its canonical runtime is authoritative.
// It is idempotent and clears the pending occurrence only after persistence.
func (s *Sidecar) EmitPostBootstrapPlatformHealth() error {
	if s == nil {
		return fmt.Errorf("sidecar: post-bootstrap platform health is unavailable")
	}
	s.judgeBodiesReadyMu.Lock()
	defer s.judgeBodiesReadyMu.Unlock()
	if !s.judgeBodiesReadyPending {
		return nil
	}
	if s.logger == nil || s.observabilityV8Emitter() == nil {
		return fmt.Errorf("sidecar: post-bootstrap platform health runtime is unavailable")
	}
	if err := s.logger.LogEvent(audit.Event{
		Action:   string(audit.ActionGatewayJudgeBodiesReady),
		Actor:    "defenseclaw-gateway",
		Severity: "INFO",
		Details:  s.judgeBodiesReadyDetails,
	}); err != nil {
		return err
	}
	s.judgeBodiesReadyPending = false
	s.judgeBodiesReadyDetails = ""
	return nil
}

func (s *Sidecar) currentConfig() *config.Config {
	if s == nil {
		return nil
	}
	if cfg := s.cfgCurrent.Load(); cfg != nil {
		return cfg
	}
	return s.cfg
}

func (s *Sidecar) sharedJudge() *LLMJudge {
	if s == nil {
		return nil
	}
	s.judgeMu.RLock()
	defer s.judgeMu.RUnlock()
	return s.judge
}

func (s *Sidecar) setSharedJudge(judge *LLMJudge) {
	if s == nil {
		return
	}
	s.judgeMu.Lock()
	s.judge = judge
	s.judgeMu.Unlock()
}

func (s *Sidecar) publishConfig(cfg *config.Config) *config.Config {
	if s == nil || cfg == nil {
		return nil
	}
	snapshot := cloneConfig(cfg)
	s.cfgCurrent.Store(snapshot)
	return snapshot
}

func (s *Sidecar) webhooksSnapshot() *WebhookDispatcher {
	if s == nil {
		return nil
	}
	s.webhooksMu.RLock()
	defer s.webhooksMu.RUnlock()
	return s.webhooks
}

func (s *Sidecar) swapWebhooks(next *WebhookDispatcher) *WebhookDispatcher {
	if s == nil {
		return nil
	}
	s.webhooksMu.Lock()
	defer s.webhooksMu.Unlock()
	previous := s.webhooks
	s.webhooks = next
	return previous
}

func (s *Sidecar) aiDiscoverySnapshot() *inventory.ContinuousDiscoveryService {
	if s == nil {
		return nil
	}
	s.aiDiscoveryMu.RLock()
	defer s.aiDiscoveryMu.RUnlock()
	return s.aiDiscovery
}

func (s *Sidecar) swapAIDiscovery(next *inventory.ContinuousDiscoveryService) *inventory.ContinuousDiscoveryService {
	if s == nil {
		return nil
	}
	s.aiDiscoveryMu.Lock()
	defer s.aiDiscoveryMu.Unlock()
	previous := s.aiDiscovery
	s.aiDiscovery = next
	return previous
}

// claimAIDiscoveryRun snapshots and claims the current service under the same
// lock used by swapAIDiscovery. A coalesced reload therefore cannot strand an
// intermediate generation between the pointer snapshot and ClaimRun.
func (s *Sidecar) claimAIDiscoveryRun() (*inventory.ContinuousDiscoveryService, func(context.Context) error, bool) {
	if s == nil {
		return nil, nil, false
	}
	s.aiDiscoveryMu.Lock()
	defer s.aiDiscoveryMu.Unlock()
	service := s.aiDiscovery
	if service == nil {
		return nil, nil, false
	}
	runner, ok := service.ClaimRun()
	return service, runner, ok
}

// Run starts all subsystems as independent goroutines. Each subsystem runs
// in its own goroutine so that a gateway disconnect does not stop the watcher
// or API server. Run blocks until ctx is cancelled, then shuts everything down.
func (s *Sidecar) Run(ctx context.Context) (runErr error) {
	if err := s.beginObservabilityV8Run(); err != nil {
		return err
	}
	// Bootstrap-owned workers must retire on every return path, including
	// failures before the normal shutdown block is reached. The explicit normal
	// close below preserves close-before-store ordering; this deferred call is
	// idempotent and covers startup lifecycle/token/watcher failures.
	defer func() {
		if err := s.closeOwnedObservabilityV8Runtime(); err != nil && runErr == nil {
			runErr = err
		}
	}()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	s.setRunCancel(runCancel)
	defer s.setRunCancel(nil)
	// The endpoint inventory cannot be emitted from NewSidecar: schema v8
	// deliberately binds its generation-owned runtime afterward. Publish the
	// first complete connector/MCP snapshot immediately after that binding, then
	// retain the same callback for each managed discovery scan.
	if managed.IsManagedEnterprise(s.currentConfig().DeploymentMode) {
		inventoryEmit := makeEndpointInventoryEmitter(s.currentConfig(), s.observabilityV8Emitter())
		if discovery := s.aiDiscoverySnapshot(); discovery != nil {
			discovery.SetManagedInventoryEmitHook(inventoryEmit)
		}
		inventoryEmit(runCtx)
	}

	runID := gatewaylog.ProcessRunID()
	fmt.Fprintf(os.Stderr, "[sidecar] starting subsystems (auto_approve=%v watcher=%v api_port=%d guardrail=%v run_id=%s)\n",
		s.currentConfig().Gateway.AutoApprove, s.currentConfig().Gateway.Watcher.Enabled, s.currentConfig().Gateway.APIPort, s.currentConfig().Guardrail.Enabled, runID)
	if err := s.recordSidecarLifecycle(runCtx, audit.ActionSidecarStart); err != nil {
		return err
	}

	if s.currentConfig().Guardrail.Enabled && s.currentConfig().Guardrail.Model == "" &&
		proxyShouldBindForConfiguredConnector(s.currentConfig()) {
		fmt.Fprintf(os.Stderr, "[sidecar] WARNING: guardrail.enabled is true but guardrail.model is empty — relying on fetch-interceptor routing.\n")
		fmt.Fprintf(os.Stderr, "[sidecar]          Set guardrail.model in ~/.defenseclaw/config.yaml only if you need a fixed advertised model name.\n")
	}

	if strings.EqualFold(s.currentConfig().Guardrail.Host, "localhost") {
		fmt.Fprintf(os.Stderr, "[sidecar] WARNING: guardrail.host is set to \"localhost\" which may resolve to IPv6 (::1) on macOS.\n")
		fmt.Fprintf(os.Stderr, "[sidecar]          The proxy binds 127.0.0.1 only. Set guardrail.host to \"127.0.0.1\" to avoid silent connection failures.\n")
	}

	// Initialize private-upstream allowlist from config + env var.
	// Always call SetAllowedPrivateIPs so config removals clear stale entries.
	allowedIPs := netguard.ParseAllowedPrivateUpstreams(s.currentConfig().Guardrail.AllowPrivateUpstreams)
	netguard.SetAllowedPrivateIPs(allowedIPs)
	if len(allowedIPs) > 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] private-upstream allowlist: %d IPs configured\n", len(allowedIPs))
	}

	// Initialize OPA engine before goroutines so both the watcher and the
	// API reload handler share the same instance.
	if s.currentConfig().PolicyDir != "" {
		if engine, err := policy.New(s.currentConfig().PolicyDir); err == nil {
			if compileErr := engine.Compile(); compileErr == nil {
				s.opa = engine
				fmt.Fprintf(os.Stderr, "[sidecar] OPA policy engine loaded from %s\n", s.currentConfig().PolicyDir)
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] OPA compile error (falling back to built-in): %v\n", compileErr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[sidecar] OPA init skipped (falling back to built-in): %v\n", err)
		}
	}

	// ("Redacted AI discovery events expose reversible
	// path fingerprints"): the AI-discovery service runs in goroutine 5
	// below and calls runScan(..., "startup") immediately, so it can
	// produce path digests BEFORE any code inside runGuardrail
	// executes. If we delay installing the keyed HMAC path-hash key
	// until runGuardrail (which is goroutine 4 and may even error out
	// on bad connector config), the first round of AI-discovery payloads
	// will leak the legacy reversible `sha256:` digests — exactly the
	// regression flagged.
	//
	// Solve this by resolving (and persisting if needed) the gateway
	// token SYNCHRONOUSLY here, then installing the inventory hash key
	// before any goroutine starts. ensureGatewayTokenSynthesis is
	// idempotent: runGuardrail later calls the same helper and gets the
	// cached value, so the existing Setup() / connector wiring is
	// unchanged. SetPathHashKey is also idempotent (mutex-protected),
	// so re-derivation in tests or restart paths stays safe.
	//
	// If token synthesis fails here we cannot proceed — the API server
	// authenticates inbound hook calls with this token. Fail loudly.
	apiToken, tokErr := s.ensureGatewayTokenSynthesis()
	if tokErr != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] FATAL: failed to synthesize gateway token: %v\n", tokErr)
		return fmt.Errorf("sidecar: gateway token synthesis: %w", tokErr)
	}
	inventory.SetPathHashKey(deriveAIInventoryHashKey(apiToken))

	s.attachApplicationProtectionObserver(runCtx, apiToken)

	var wg sync.WaitGroup
	errCh := make(chan error, 7)

	configPath := s.currentConfig().ConfigFilePath
	if strings.TrimSpace(configPath) == "" {
		configPath = config.ConfigPath()
	}
	s.configMgr = newConfigManagerWithSnapshot(
		configPath,
		s.currentConfig(),
		s.logger,
		s.health,
		s.observabilityV8ActivePlanDigest(),
		s.applyConfigReloadSnapshot,
	)
	s.configMgr.bindInitialObservabilityV8Plan(s.observabilityV8ActivePlan())
	metricRuntime, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	s.configMgr.bindObservabilityV8(metricRuntime)
	configStartupReady := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.configMgr.runWithStartupReconcile(runCtx, configStartupReady)
		if err != nil && runCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] config manager exited with error: %v\n", err)
			errCh <- err
		}
	}()
	if err := <-configStartupReady; err != nil {
		runCancel()
		wg.Wait()
		return fmt.Errorf("sidecar: reconcile observability v8 config: %w", err)
	}

	// The updater cannot instantiate the target release's logger. It leaves a
	// private, terminal receipt after health verification; this worker waits for
	// API/config/telemetry readiness and admits that receipt through the one
	// canonical mandatory compliance pipeline. Pending receipts are never
	// interpreted as success.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runUpgradeReceiptConsumer(runCtx)
	}()

	// Process and mandatory-SQLite capacity metrics are generated lazily under
	// the active v8 graph. If every corresponding family is disabled, neither
	// runtime.ReadMemStats nor SQLite PRAGMA work occurs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runCapacityObservabilityV8(runCtx, sidecarCapacityInterval)
	}()

	// Goroutine 1: Gateway connection loop. Runs only when an OpenClaw
	// fleet is configured (see gatewayShouldConnectForConfiguredConnector).
	// In standalone hook-connector mode (no fleet, local hooks/native OTLP)
	// runGatewayLoop short-circuits to StateDisabled and parks on ctx.Done()
	// instead of spinning ConnectWithRetry against a port nothing is bound
	// to. The goroutine is still spawned in both cases so shutdown / wg
	// accounting / health snapshots stay symmetric across modes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runGatewayLoop(runCtx); err != nil && runCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] gateway loop exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 2: Skill/MCP watcher (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runRestartable(runCtx, "watcher", s.watcherRestartCh, s.runWatcher); err != nil && runCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 3: REST API server (always runs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runRestartable(runCtx, "api", s.apiRestartCh, s.runAPI); err != nil && runCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] api server exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 4: guardrail proxy (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runRestartable(runCtx, "guardrail", s.guardrailRestartCh, s.runActiveGuardrail); err != nil && runCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] guardrail exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 5: continuous AI discovery (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runRestartable(runCtx, "ai discovery", s.aiRestartCh, s.runAIDiscovery); err != nil && runCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] ai discovery exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 6: local UDS gRPC IPC server for AVC (opt-in via
	// managed.enabled or deployment_mode=managed_enterprise). No-op
	// when no IPCRunner has been installed by the CLI wiring layer.
	if s.ipcRunner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.ipcRunner.Run(runCtx); err != nil && runCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[sidecar] ipc server exited with error: %v\n", err)
				errCh <- err
			}
		}()
	}
	// Report sandbox health — only present when standalone mode is active
	s.reportSandboxHealth(runCtx)

	// Wait for context cancellation (signal handler in CLI layer)
	<-runCtx.Done()
	fmt.Fprintf(os.Stderr, "[sidecar] context cancelled, waiting for subsystems to stop ...\n")
	wg.Wait()

	s.alertCancel()
	s.alertWg.Wait()

	// Shutdown — ctx is already Done, but still carries correlation values.
	stopObservabilityErr := s.recordSidecarLifecycle(runCtx, audit.ActionSidecarStop)
	if webhooks := s.webhooksSnapshot(); webhooks != nil {
		webhooks.Close()
	}
	// Drain the async judge completion queue BEFORE the audit DB handle is
	// closed: canonical summaries and any enabled body rows still buffered after
	// SIGTERM must be processed. Shutdown
	// bounds the wait to judgePersistShutdownTimeout (5s) so a
	// pathological DB doesn't wedge the process; drops still
	// surface as defenseclaw.judge.persist.drops with
	// reason="shutdown" if we run out of time.
	judgeStoreClosed := true
	if s.judgeStore != nil {
		// Detach from the global so any post-drain emit path sees a
		// nil store instead of racing the worker.
		SetJudgeResponseStore(nil)
		if err := shutdownJudgeStore(s.judgeStore); err != nil {
			if s.logger != nil {
				_ = s.logger.LogEvent(audit.Event{
					Action:   string(audit.ActionGatewayJudgeStoreDrainTimeout),
					Actor:    "defenseclaw-gateway",
					Severity: "ERROR",
					Details:  "error=" + err.Error(),
				})
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] judge-store drain: %v\n", err)
			}
		}
		// Even on a returned error, the worker eventually drains. We
		// MUST NOT close the underlying DB until IsClosed() is true,
		// otherwise the worker hits a use-after-close on tx.Commit /
		// tx.Insert and either panics or corrupts the connection
		// pool. IsClosed becomes true the instant doneCh is closed
		// (the worker's only defer).
		judgeStoreClosed = s.judgeStore.IsClosed()
	}
	// Close the dedicated judge-bodies DB AFTER the queue has drained
	// so the worker's final batch lands on disk before we drop the
	// connection. If Shutdown timed out and the worker is still
	// inside a tx, skipping Close is the only safe option — the OS
	// reclaims the file handle on process exit (which is imminent
	// for a SIGTERM-driven Stop path) and the alternative is a
	// guaranteed panic on the writer goroutine. audit.Logger.Close()
	// below still flushes audit.db.
	if s.judgeBodyStore != nil {
		if !judgeStoreClosed {
			if s.logger != nil {
				_ = s.logger.LogEvent(audit.Event{
					Action:   string(audit.ActionGatewayJudgeBodiesCloseSkipped),
					Actor:    "defenseclaw-gateway",
					Severity: "ERROR",
					Details:  "reason=worker_still_running",
				})
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] judge-bodies db close skipped: worker still running\n")
			}
		} else if err := s.judgeBodyStore.Close(); err != nil {
			if s.logger != nil {
				_ = s.logger.LogEvent(audit.Event{
					Action:   string(audit.ActionGatewayJudgeBodiesCloseError),
					Actor:    "defenseclaw-gateway",
					Severity: "ERROR",
					Details:  "error=" + err.Error(),
				})
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] judge-bodies db close: %v\n", err)
			}
		}
	}
	// Keep the canonical runtime authoritative through judge-queue drain and
	// forensic-store close so their terminal health failures can persist without
	// a legacy fallback. Retire it immediately afterward, while audit.db is still
	// open; the deferred close above remains the abnormal-return safety net.
	if err := s.closeOwnedObservabilityV8Runtime(); err != nil {
		return err
	}
	s.logger.Close()
	_ = s.client.Close()
	// Return the first non-nil error if any subsystem failed before shutdown
	select {
	case err := <-errCh:
		return err
	default:
		return stopObservabilityErr
	}
}

// shutdownJudgeStore gives the persistence worker its own bounded drain
// budget. Sidecar.Run reaches this point only after runCtx has been cancelled;
// passing that lifecycle context to Shutdown would therefore abort the drain
// immediately and could lose queued raw judge bodies during normal shutdown.
func shutdownJudgeStore(store *JudgeStore) error {
	if store == nil {
		return nil
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), judgePersistShutdownTimeout)
	defer cancel()
	return store.Shutdown(drainCtx)
}

func (s *Sidecar) attachApplicationProtectionObserver(ctx context.Context, apiToken string) {
	if s == nil || s.currentConfig() == nil || s.health == nil {
		return
	}
	aiDiscovery := s.aiDiscoverySnapshot()
	if aiDiscovery == nil {
		s.health.SetApplicationProtection(StateDisabled, "ai discovery disabled", map[string]interface{}{
			"enabled": s.currentConfig().ApplicationProtection.Enabled,
		})
		return
	}
	// Token synthesis is deliberately completed before this method is called.
	// Keeping observer attachment infallible prevents a reload from publishing
	// new configuration and then reporting failure after old resources closed.
	if strings.TrimSpace(apiToken) == "" {
		s.health.SetApplicationProtection(StateError, "gateway token unavailable", nil)
		return
	}

	registry := connector.NewDefaultRegistry()
	if s.currentConfig().PluginDir != "" {
		if err := registry.DiscoverPlugins(s.currentConfig().PluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "[application-protection] plugin discovery: %v\n", err)
		}
	}
	apiBind := "127.0.0.1"
	if s.currentConfig().Gateway.APIBind != "" {
		apiBind = s.currentConfig().Gateway.APIBind
	} else if s.currentConfig().OpenShell.IsStandalone() && s.currentConfig().Guardrail.Host != "" && s.currentConfig().Guardrail.Host != "localhost" {
		apiBind = s.currentConfig().Guardrail.Host
	}
	apiAddr := fmt.Sprintf("%s:%d", apiBind, s.currentConfig().Gateway.APIPort)
	proxyAddr := guardrailListenAddr(s.currentConfig().Guardrail.Port, s.currentConfig().Guardrail.Host)
	masterKey := deriveMasterKey(s.currentConfig().DataDir)
	if s.appProtection == nil {
		s.appProtection = newApplicationProtectionController(s, registry, apiToken, proxyAddr, apiAddr, masterKey)
	} else {
		s.appProtection.UpdateRuntime(registry, apiToken, proxyAddr, apiAddr, masterKey)
	}
	controller := s.appProtection
	aiDiscovery.AddReportObserver(func(reportCtx context.Context, report inventory.AIDiscoveryReport) {
		controller.OnDiscoveryReport(reportCtx, report)
	})
	s.health.SetApplicationProtection(StateStarting, "", map[string]interface{}{
		"enabled":    s.currentConfig().ApplicationProtection.Enabled,
		"state_file": filepath.Join(s.currentConfig().DataDir, applicationProtectionStateFile),
	})
}

func (s *Sidecar) runActiveGuardrail(ctx context.Context) error {
	runGuardrailFn := s.runGuardrail
	if len(s.currentConfig().ActiveConnectors()) > 1 {
		runGuardrailFn = s.runGuardrailMulti
	}
	err := runGuardrailFn(ctx)
	if err != nil && ctx.Err() == nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
	}
	return err
}

func (s *Sidecar) runRestartable(ctx context.Context, name string, restart <-chan struct{}, run func(context.Context) error) error {
	for {
		childCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			done <- run(childCtx)
		}()
		select {
		case <-ctx.Done():
			cancel()
			if err := <-done; err != nil && !isContextTermination(err) {
				return err
			}
			return ctx.Err()
		case <-restart:
			fmt.Fprintf(os.Stderr, "[sidecar] restarting %s after config reload\n", name)
			cancel()
			if err := <-done; err != nil && !isContextTermination(err) {
				return err
			}
			continue
		case err := <-done:
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
}

func isContextTermination(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func signalRestart(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *Sidecar) setRunCancel(cancel context.CancelFunc) {
	if s == nil {
		return
	}
	s.runCancelMu.Lock()
	defer s.runCancelMu.Unlock()
	s.runCancel = cancel
}

func (s *Sidecar) requestProcessRestart() {
	if s == nil {
		return
	}
	s.runCancelMu.Lock()
	cancel := s.runCancel
	s.runCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// requestProcessShutdown cancels the complete Sidecar run context. It is kept
// separate from requestProcessRestart at the API boundary so a local graceful
// stop cannot accidentally acquire restart-helper semantics later.
func (s *Sidecar) requestProcessShutdown() {
	if s == nil {
		return
	}
	s.runCancelMu.Lock()
	cancel := s.runCancel
	s.runCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func configReloadMode(cfg *config.Config) string {
	if cfg == nil {
		return "hot"
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Gateway.ConfigReload.Mode))
	if mode == "" {
		return "hot"
	}
	return mode
}

func onlyConfigReloadModeChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	oldCopy := *oldCfg
	oldCopy.Gateway.ConfigReload = newCfg.Gateway.ConfigReload
	return reflect.DeepEqual(&oldCopy, newCfg)
}

func defaultLaunchConfigRestartHelper() error {
	if !daemon.IsDaemonChild() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("config reload restart: resolve executable: %w", err)
	}
	cmd := exec.Command(exe, configRestartHelperArgs(os.Args)...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("config reload restart: launch helper: %w", err)
	}
	return nil
}

func configRestartHelperArgs(argv []string) []string {
	args := []string{"restart"}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--host" && i+1 < len(argv):
			args = append(args, "--host", argv[i+1])
			i++
		case strings.HasPrefix(arg, "--host="):
			args = append(args, arg)
		case arg == "--port" && i+1 < len(argv):
			args = append(args, "--port", argv[i+1])
			i++
		case strings.HasPrefix(arg, "--port="):
			args = append(args, arg)
		}
	}
	return args
}

func loadSidecarRulePack(cfg *config.Config) *guardrail.RulePack {
	rp := guardrail.LoadRulePack(cfg.Guardrail.RulePackDir)
	rp.Validate()
	fmt.Fprintf(os.Stderr, "[sidecar] guardrail rule pack loaded: %s\n", rp)
	return rp
}

func buildSharedJudge(cfg *config.Config, rp *guardrail.RulePack) *LLMJudge {
	if cfg == nil || !cfg.Guardrail.Judge.Enabled {
		return nil
	}
	if rp == nil {
		rp = loadSidecarRulePack(cfg)
	}
	dotenvPath := filepath.Join(cfg.DataDir, ".env")
	judgeLLM := cfg.ResolveLLM("guardrail.judge")
	providers, _, _ := providerRegistrySnapshot()
	judge := NewLLMJudge(&cfg.Guardrail.Judge, judgeLLM, dotenvPath, rp, providers)
	if judge == nil {
		return nil
	}

	features := "tool-result-pii"
	if cfg.Guardrail.Judge.ToolInjection {
		features += ", tool-injection"
	}
	fmt.Fprintf(os.Stderr, "[sidecar] LLM judge enabled (%s) (model=%s)\n", features, judgeLLM.Model)
	if hooks := cfg.Guardrail.Judge.HookConnectors; len(hooks) > 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] LLM judge hook lane enabled for: %s\n", strings.Join(hooks, ", "))
	}
	return judge
}

func (s *Sidecar) applyConfigReloadSnapshot(
	ctx context.Context,
	oldCfg, newCfg *config.Config,
	diff ConfigDiff,
	source configReloadSource,
) error {
	if oldCfg == nil || newCfg == nil || oldCfg.ConfigVersion != config.ObservabilityV8ConfigVersion ||
		newCfg.ConfigVersion != config.ObservabilityV8ConfigVersion {
		return fmt.Errorf("config reload requires schema v8; run 'defenseclaw upgrade' first")
	}
	v8PlanChanged := false
	if strings.TrimSpace(source.sourceName) == "" || len(source.raw) == 0 ||
		source.compiledV8 == nil || source.compiledV8.Plan == nil {
		return fmt.Errorf("config reload schema v8 requires the validated source snapshot")
	}
	compiledLocal := source.compiledV8.Plan.Snapshot().Local
	if source.compiledV8.DataDir != newCfg.DataDir ||
		compiledLocal.Path != newCfg.AuditDB ||
		compiledLocal.JudgeBodiesPath != newCfg.JudgeBodiesDB {
		return fmt.Errorf("config reload schema v8 candidate does not match its compiled local paths")
	}
	activePlan := s.observabilityV8ActivePlan()
	if activePlan == nil {
		return fmt.Errorf("config reload schema v8 has no active owned runtime graph")
	}
	candidatePlan, candidateChanged, err := sidecarObservabilityV8ManagedReloadCandidate(
		source.compiledV8, newCfg, activePlan, source.raw,
	)
	if err != nil {
		return fmt.Errorf("config reload observability v8 managed destination: %w", err)
	}
	v8PlanChanged = candidateChanged
	onlyReloadModeChange := onlyConfigReloadModeChanged(oldCfg, newCfg) &&
		len(diff.Changed) == 1 && diff.Changed[0] == "gateway"
	if configReloadMode(newCfg) == "restart" && !onlyReloadModeChange {
		if s == nil || s.currentConfig() == nil || newCfg == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "[sidecar] config reload mode=restart: validated config change; requesting process restart\n")
		if launchConfigRestartHelper != nil {
			if err := launchConfigRestartHelper(); err != nil {
				return err
			}
		}
		if s.health != nil {
			s.health.SetConfig(StateStopped, "restart requested by config reload", map[string]interface{}{
				"changed": diff.Changed,
			})
		}
		s.requestProcessRestart()
		return nil
	}
	if len(diff.RestartRequired) > 0 {
		return fmt.Errorf("config reload requires gateway restart for: %s", strings.Join(diff.RestartRequired, ", "))
	}
	if s == nil || s.currentConfig() == nil || newCfg == nil {
		return nil
	}
	current := s.currentConfig()

	guardrailRestart := guardrailNeedsRestart(oldCfg, newCfg)
	apiRestart := apiNeedsRestart(oldCfg, newCfg)
	watcherRestart := watcherNeedsRestart(oldCfg, newCfg)
	aiRestart := aiDiscoveryNeedsRestart(oldCfg, newCfg)
	rulePackReload := rulePackNeedsReload(oldCfg, newCfg)
	judgeReload := judgeNeedsReload(oldCfg, newCfg)
	privateUpstreamsReload := !reflect.DeepEqual(
		oldCfg.Guardrail.AllowPrivateUpstreams,
		newCfg.Guardrail.AllowPrivateUpstreams,
	)

	next := *newCfg
	if next.Gateway.Token == "" && current.Gateway.Token != "" {
		next.Gateway.Token = current.Gateway.Token
	}

	var nextAIDiscovery *inventory.ContinuousDiscoveryService
	preparedCommitted := false
	defer func() {
		if preparedCommitted {
			return
		}
		if nextAIDiscovery != nil {
			_, _ = nextAIDiscovery.CloseIfNeverStarted()
		}
	}()

	if aiRestart {
		svc, err := inventory.NewContinuousDiscoveryService(&next)
		if err != nil {
			return fmt.Errorf("config reload ai_discovery: %w", err)
		}
		nextAIDiscovery = svc
	}

	var nextRulePack *guardrail.RulePack
	if rulePackReload || judgeReload {
		nextRulePack = loadSidecarRulePack(&next)
	}

	var nextJudge *LLMJudge
	if judgeReload {
		if strings.TrimSpace(next.LLM.BaseURL) != "" {
			if err := SeedCustomProvidersFromLLMBaseURL(next.LLM.BaseURL); err != nil {
				fmt.Fprintf(os.Stderr, "[sidecar] custom-providers seed warning: %v\n", err)
			}
		}
		nextJudge = buildSharedJudge(&next, nextRulePack)
	}

	// Application-protection observer attachment must be infallible after the
	// commit point below. Resolve the only fallible dependency (the gateway
	// token) while all old resources and the published config are still live.
	if aiRestart && nextAIDiscovery != nil && strings.TrimSpace(next.Gateway.Token) == "" {
		apiToken, err := s.ensureGatewayTokenSynthesis()
		if err != nil {
			return fmt.Errorf("config reload application protection gateway token: %w", err)
		}
		next.Gateway.Token = apiToken
	}

	// Resolve the managed posture before the v8 commit boundary without
	// mutating process-global state. The actual toggles are applied only after
	// the candidate runtime graph has passed its canaries and committed.
	nextManagedEnterprise := managed.IsManagedEnterprise(next.DeploymentMode)
	// The v8 runtime graph is the first mutation and the commit boundary. Its
	// reload builds and canary-validates the complete candidate off-path, then
	// atomically publishes it. Everything below is deliberately infallible, so
	// a rejected graph leaves both the prior graph and Config authoritative.
	if v8PlanChanged {
		s.observabilityV8Mu.Lock()
		owner, ok := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
		s.observabilityV8Mu.Unlock()
		if !ok || owner == nil {
			return fmt.Errorf("config reload observability v8: active runtime is unavailable")
		}
		if _, err := owner.reload(ctx, candidatePlan, owner.retainJudgeBodies); err != nil {
			return newSidecarObservabilityV8BootstrapError(
				sidecarObservabilityV8BootstrapReload,
				err,
			)
		}
	}

	// Canonical v8 redaction is selected per destination, so there is no
	// process-wide privacy kill switch to mutate on reload. Keep only the
	// managed-enterprise local-agent carve-out and cloud-controlled
	// per-inspection redaction gate in sync with the committed deployment mode.
	setManagedEnterpriseRedactionPosture(nextManagedEnterprise)

	appliedCfg := current
	if !onlyReloadModeChange {
		appliedCfg = s.publishConfig(&next)
	}
	if privateUpstreamsReload {
		// Replace, rather than merge, so removing the last entry takes effect.
		// Drop pooled transports as well: an already-idle connection otherwise
		// bypasses DialContext and could survive an allowlist revocation.
		netguard.SetAllowedPrivateIPs(netguard.ParseAllowedPrivateUpstreams(appliedCfg.Guardrail.AllowPrivateUpstreams))
		providerHTTPClient.CloseIdleConnections()
	}

	if s.router != nil {
		if nextRulePack != nil {
			s.router.SetRulePack(nextRulePack)
			ApplyRulePackOverrides(nextRulePack)
			ApplyLocalPatternsOverride(nextRulePack.LocalPatterns)
		}
		s.router.SetGuardrailConfig(&appliedCfg.Guardrail)
		s.router.SetDefaultAgentName(string(appliedCfg.Claw.Mode))
		s.router.SetDefaultPolicyID(appliedCfg.Guardrail.Mode)
	}

	if judgeReload {
		if nextJudge != nil {
			s.observabilityV8Mu.Lock()
			judgeRuntime, _ := s.observabilityV8.(judgeTraceV8Runtime)
			if s.observabilityV8ConsumersDetached {
				judgeRuntime = nil
			}
			nextJudge.bindJudgeTraceV8(judgeRuntime)
			s.observabilityV8Mu.Unlock()
		}
		s.setSharedJudge(nextJudge)
		if s.router != nil {
			s.router.SetJudge(nextJudge)
		}
		if api := s.apiSnapshot(); api != nil {
			api.SetHookJudge(nextJudge)
		}
	}

	if notifierChanged(oldCfg, newCfg) {
		s.osNotifier = notifier.NewWithSender(appliedCfg.Notifications, osToastSenderFor(appliedCfg))
		if s.hilt != nil {
			s.hilt.SetNotifier(s.osNotifier)
		}
		if api := s.apiSnapshot(); api != nil {
			api.SetNotifier(s.osNotifier)
		}
		if proxy := s.proxySnapshot(); proxy != nil {
			proxy.SetNotifier(s.osNotifier)
		}
	}

	if webhooksChanged(oldCfg, newCfg) {
		nextWebhooks := NewWebhookDispatcher(appliedCfg.Webhooks, appliedCfg.Observability)
		if nextWebhooks != nil {
			metricRuntime, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
			nextWebhooks.BindObservabilityV8(metricRuntime)
		}
		oldWebhooks := s.swapWebhooks(nextWebhooks)
		if proxy := s.proxySnapshot(); proxy != nil {
			proxy.SetWebhookDispatcher(nextWebhooks)
		}
		if oldWebhooks != nil {
			oldWebhooks.Close()
		}
	}

	if !guardrailRestart {
		if proxy := s.proxySnapshot(); proxy != nil {
			proxy.ApplyGuardrailConfig(&appliedCfg.Guardrail)
			proxy.SetDefaultAgentName(string(appliedCfg.Claw.Mode))
			proxy.SetDefaultPolicyID(appliedCfg.Guardrail.Mode)
		}
	}

	if aiRestart {
		if nextAIDiscovery != nil {
			nextAIDiscovery.BindObservabilityV8(newAIDiscoveryV8Adapter(s.observabilityV8Emitter()))
		}
		oldDiscovery := s.swapAIDiscovery(nextAIDiscovery)
		if oldDiscovery != nil && oldDiscovery != nextAIDiscovery {
			oldDiscovery.BindObservabilityV8(nil)
		}
		if api := s.apiSnapshot(); api != nil {
			api.SetAIDiscoveryService(nextAIDiscovery)
		}
		// The API setter waits for leases using the old service before it
		// publishes the replacement. A coalesced intermediate that the restart
		// worker never claimed can now be retired without racing a query;
		// claimed/running services close from their Run defer.
		if oldDiscovery != nil && oldDiscovery != nextAIDiscovery {
			if _, err := oldDiscovery.CloseIfNeverStarted(); err != nil {
				fmt.Fprintf(os.Stderr, "[sidecar] close superseded ai discovery service: %v\n", err)
			}
		}
		s.attachApplicationProtectionObserver(ctx, next.Gateway.Token)
	}

	// managed_enterprise: refresh the connector / MCP endpoint inventory
	// on every reload — MCP servers and connectors can change via config
	// without restarting the discovery scanner. Rebuild the emitter from
	// the just-published config, re-arm the scan-cadence hook (the
	// discovery service may have been recreated above), and emit an
	// immediate snapshot so AI Defense sees the change without waiting
	// for the next scan tick.
	if nextManagedEnterprise {
		inventoryEmit := makeEndpointInventoryEmitter(s.currentConfig(), s.observabilityV8Emitter())
		if svc := s.aiDiscoverySnapshot(); svc != nil {
			svc.SetManagedInventoryEmitHook(inventoryEmit)
		}
		inventoryEmit(ctx)
	} else if svc := s.aiDiscoverySnapshot(); svc != nil {
		// The discovery service can survive a deployment-mode-only reload.
		// Clear the generation-owned callback so later scan cadences cannot
		// retain managed endpoint inventory behavior.
		svc.SetManagedInventoryEmitHook(nil)
	}

	if watcherRestart {
		signalRestart(s.watcherRestartCh)
	}
	if apiRestart {
		signalRestart(s.apiRestartCh)
	}
	if guardrailRestart {
		signalRestart(s.guardrailRestartCh)
	}
	if aiRestart {
		signalRestart(s.aiRestartCh)
	}
	preparedCommitted = true
	return nil
}

func rulePackNeedsReload(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return oldCfg.Guardrail.RulePackDir != newCfg.Guardrail.RulePackDir
}

func judgeNeedsReload(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.LLM, newCfg.LLM) ||
		rulePackNeedsReload(oldCfg, newCfg) ||
		!reflect.DeepEqual(oldCfg.Guardrail.Judge, newCfg.Guardrail.Judge)
}

func guardrailNeedsRestart(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	oldG, newG := oldCfg.Guardrail, newCfg.Guardrail
	if oldG.Host != newG.Host || oldG.Port != newG.Port || oldG.Enabled != newG.Enabled ||
		oldG.Connector != newG.Connector ||
		oldG.RetainJudgeBodies != newG.RetainJudgeBodies ||
		!reflect.DeepEqual(oldCfg.LLM, newCfg.LLM) ||
		!reflect.DeepEqual(oldG.Connectors, newG.Connectors) ||
		oldG.RulePackDir != newG.RulePackDir || oldG.HookSelfHeal != newG.HookSelfHeal ||
		oldG.HookSelfHealDebounceMs != newG.HookSelfHealDebounceMs ||
		oldG.Judge.Enabled != newG.Judge.Enabled || !reflect.DeepEqual(oldG.Judge, newG.Judge) {
		return true
	}
	return false
}

func apiNeedsRestart(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return oldCfg.Gateway.APIPort != newCfg.Gateway.APIPort ||
		oldCfg.Gateway.APIBind != newCfg.Gateway.APIBind ||
		!reflect.DeepEqual(oldCfg.OpenShell, newCfg.OpenShell) ||
		oldCfg.Guardrail.Host != newCfg.Guardrail.Host
}

func watcherNeedsRestart(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.Gateway.Watcher, newCfg.Gateway.Watcher) ||
		!reflect.DeepEqual(oldCfg.LLM, newCfg.LLM) ||
		!reflect.DeepEqual(oldCfg.Watch, newCfg.Watch) ||
		!reflect.DeepEqual(oldCfg.Scanners, newCfg.Scanners) ||
		!reflect.DeepEqual(oldCfg.SkillActions, newCfg.SkillActions) ||
		!reflect.DeepEqual(oldCfg.MCPActions, newCfg.MCPActions) ||
		!reflect.DeepEqual(oldCfg.PluginActions, newCfg.PluginActions) ||
		!reflect.DeepEqual(oldCfg.AssetPolicy, newCfg.AssetPolicy) ||
		oldCfg.Claw != newCfg.Claw
}

func aiDiscoveryNeedsRestart(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.AIDiscovery, newCfg.AIDiscovery) ||
		managed.IsManagedEnterprise(oldCfg.DeploymentMode) != managed.IsManagedEnterprise(newCfg.DeploymentMode)
}

func notifierChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.Notifications, newCfg.Notifications)
}

func webhooksChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.Webhooks, newCfg.Webhooks) ||
		!reflect.DeepEqual(oldCfg.Observability, newCfg.Observability)
}

func (s *Sidecar) setAPIServer(api *APIServer) {
	if s == nil {
		return
	}
	// Lock order: observabilityV8Mu before apiMu. Runtime publication,
	// shutdown detach, and API construction therefore cannot pass each other.
	s.observabilityV8Mu.Lock()
	s.apiMu.Lock()
	previous := s.apiServer
	if previous != nil && previous != api {
		previous.SetHookRegistrationRepair(nil)
		previous.bindObservabilityV8Runtimes(nil, nil, nil, nil)
	}
	if api != nil {
		s.bindAPIServerObservabilityV8Locked(api)
		api.SetHookRegistrationRepair(s.ensureActiveHookRegistration)
	}
	s.apiServer = api
	s.apiMu.Unlock()
	s.observabilityV8Mu.Unlock()
}

func (s *Sidecar) registerHookConfigGuard(guard *HookConfigGuard) {
	if s == nil || guard == nil {
		return
	}
	s.hookGuardsMu.Lock()
	if s.hookGuards == nil {
		s.hookGuards = make(map[*HookConfigGuard]struct{})
	}
	s.hookGuards[guard] = struct{}{}
	s.signalHookGuardsChangedLocked()
	s.hookGuardsMu.Unlock()
	guard.SetDeactivationNotifier(s.unregisterHookConfigGuard)
}

func (s *Sidecar) unregisterHookConfigGuard(guard *HookConfigGuard) {
	if s == nil || guard == nil {
		return
	}
	s.hookGuardsMu.Lock()
	delete(s.hookGuards, guard)
	s.signalHookGuardsChangedLocked()
	s.hookGuardsMu.Unlock()
}

func (s *Sidecar) signalHookGuardsChangedLocked() {
	if s.hookGuardsChanged != nil {
		close(s.hookGuardsChanged)
	}
	s.hookGuardsChanged = make(chan struct{})
}

const hookRegistrationOwnerWaitTimeout = 10 * time.Second

func (s *Sidecar) ensureActiveHookRegistration(ctx context.Context, connectorName string) error {
	if s == nil {
		return errors.New("hook registration repair owner is unavailable")
	}
	cfg := s.currentConfig()
	if cfg == nil {
		return errors.New("hook registration repair owner is unavailable")
	}
	// Respect intentional lifecycle ownership boundaries. A disabled guardrail
	// or self-heal setting must not be turned back into a writer by cached hook
	// traffic, and managed-enterprise hook files belong exclusively to the
	// privileged guardian.
	if !cfg.Guardrail.Enabled || !cfg.Guardrail.HookSelfHeal || managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if name != "codex" {
		return fmt.Errorf("hook registration repair is unsupported for connector %q", name)
	}
	if !cfg.EffectiveGuardrailEnabledForConnector(name) {
		return nil
	}
	dataDir := cfg.DataDir
	configured := false
	for _, active := range cfg.ActiveConnectors() {
		if strings.EqualFold(strings.TrimSpace(active), name) {
			configured = true
			break
		}
	}
	if !configured {
		return fmt.Errorf("no configured hook registration owner exists for connector %s", name)
	}
	if connector.ConnectorExplicitlyInactive(dataDir, name) {
		return fmt.Errorf("connector %s is explicitly inactive", name)
	}

	waitCtx := ctx
	if waitCtx == nil {
		waitCtx = context.Background()
	}
	waitCtx, cancel := context.WithTimeout(waitCtx, hookRegistrationOwnerWaitTimeout)
	defer cancel()
	for {
		s.hookGuardsMu.Lock()
		if s.hookGuardsChanged == nil {
			s.hookGuardsChanged = make(chan struct{})
		}
		changed := s.hookGuardsChanged
		guards := make([]*HookConfigGuard, 0, len(s.hookGuards))
		for guard := range s.hookGuards {
			guards = append(guards, guard)
		}
		s.hookGuardsMu.Unlock()

		var owner *HookConfigGuard
		for _, guard := range guards {
			if guard.MatchesActiveConnector(name, dataDir) {
				if owner != nil {
					return fmt.Errorf("multiple active hook registration guards claim connector %s in the configured data home", name)
				}
				owner = guard
			}
		}
		if owner != nil {
			return owner.EnsurePresent(ctx, name, dataDir, "authenticated SessionStart")
		}
		if connector.ConnectorExplicitlyInactive(dataDir, name) {
			return fmt.Errorf("connector %s is explicitly inactive", name)
		}
		select {
		case <-changed:
			continue
		case <-waitCtx.Done():
			return fmt.Errorf("no active hook registration guard owns connector %s in the configured data home: %w", name, waitCtx.Err())
		}
	}
}

// pickInspector selects the AID inspector implementation based on
// deployment_mode. Returns a non-nil Inspector interface only when the
// concrete constructor produced a non-nil value; the returned
// interface's nil-status is the sole signal the caller should trust.
//
// Managed-mode fail-closed behavior: when deployment_mode =
// managed_enterprise but ensureCMIDProvider errors (unsupported OS,
// no managed cloud auth provider registered, agent unavailable), this
// returns nil AND logs an ERROR — remote inspection is disabled
// entirely rather than silently falling back to API-key auth.
func (s *Sidecar) pickInspector(ctx context.Context) Inspector {
	cfg := s.currentConfig()
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return s.newManagedInspector(ctx, "remote inspection disabled")
	}
	// Opensource path — unchanged from before the picker was added.
	if c := NewCiscoInspectClient(&cfg.CiscoAIDefense, filepath.Join(cfg.DataDir, ".env")); c != nil {
		metricRuntime, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
		c.bindObservabilityV8(metricRuntime)
		return c
	}
	return nil
}

// newManagedInspector constructs the managed_enterprise Inspector:
// ensure the cloud auth provider is available, then build a
// CiscoDefenseClawInspectClient and wire telemetry. Returns nil (and
// logs a Cisco error using siteLabel) when the provider or client
// can't be constructed — callers rely on that nil to take the
// fail-closed path (see pickInspector's caller contract at
// [Sidecar.pickInspector] and the proxy-swap block in runGuardrail).
// Both call sites always read a fresh cfg snapshot, so this helper does
// too.
func (s *Sidecar) newManagedInspector(ctx context.Context, siteLabel string) Inspector {
	cfg := s.currentConfig()
	metricRuntime, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	prov, err := s.ensureCMIDProvider(ctx)
	if err != nil {
		EmitCiscoError(ctx, gatewaylog.ErrCodeUpstreamError,
			"managed_enterprise + managed cloud auth unavailable — "+siteLabel+": "+err.Error())
		recordCiscoInspectV8(ctx, metricRuntime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeUpstreamError)
		return nil
	}
	m := NewCiscoDefenseClawInspectClient(&cfg.CiscoAIDefense, prov)
	if m == nil {
		EmitCiscoError(ctx, gatewaylog.ErrCodeInvalidResponse,
			"managed_enterprise inspector unavailable — "+siteLabel)
		recordCiscoInspectV8(ctx, metricRuntime, -1, observability.OutcomeFailed, gatewaylog.ErrCodeInvalidResponse)
		return nil
	}
	m.bindObservabilityV8(metricRuntime)
	return m
}

// ensureCMIDProvider lazily constructs the managed cloud auth provider
// on first use and caches it for the sidecar's lifetime.
// Managed_enterprise only. Returns an error when the underlying
// provider cannot Refresh (unsupported OS, no provider registered,
// agent unavailable after the retry ladder). The error is surfaced so
// the caller can take the fail-closed path.
func (s *Sidecar) ensureCMIDProvider(ctx context.Context) (cloudreg.Provider, error) {
	s.cmidProviderMu.Lock()
	defer s.cmidProviderMu.Unlock()
	if s.cmidProviderInst != nil {
		return s.cmidProviderInst, nil
	}
	cfg := s.currentConfig()
	prov, err := cloudreg.New(cloudreg.Config{LibPath: cfg.CloudAuth.LibPath})
	if err != nil {
		return nil, err
	}
	if err := prov.Refresh(ctx); err != nil {
		return nil, err
	}
	s.cmidProviderInst = prov
	return prov, nil
}

func (s *Sidecar) apiSnapshot() *APIServer {
	s.apiMu.RLock()
	defer s.apiMu.RUnlock()
	return s.apiServer
}

func (s *Sidecar) setGuardrailProxy(proxy *GuardrailProxy) {
	if s == nil {
		return
	}
	// Lock order: observabilityV8Mu before proxyMu and the proxy runtime lock.
	s.observabilityV8Mu.Lock()
	s.proxyMu.Lock()
	previous := s.guardrailProxy
	if previous != nil && previous != proxy {
		previous.bindObservabilityV8TraceMode(nil, true)
	}
	if proxy != nil {
		lifecycle := s.observabilityV8Lifecycle
		if s.observabilityV8ConsumersDetached {
			lifecycle = nil
		}
		proxy.bindObservabilityV8TraceMode(lifecycle, true)
	}
	s.guardrailProxy = proxy
	s.proxyMu.Unlock()
	s.observabilityV8Mu.Unlock()
}

// setEventRouter is construction-time wiring. Keeping the lifecycle binding in
// this seam makes runtime-first and router-first assembly equivalent.
func (s *Sidecar) setEventRouter(router *EventRouter) {
	if s == nil {
		return
	}
	// Lock order: observabilityV8Mu before the router lifecycle lock.
	s.observabilityV8Mu.Lock()
	previous := s.router
	if previous != nil && previous != router {
		previous.bindObservabilityV8Capabilities(nil, nil)
	}
	if router != nil {
		emitter := s.observabilityV8
		lifecycle := s.observabilityV8Lifecycle
		if s.observabilityV8ConsumersDetached {
			emitter = nil
			lifecycle = nil
		}
		router.bindObservabilityV8Capabilities(emitter, lifecycle)
	}
	s.router = router
	s.observabilityV8Mu.Unlock()
}

func (s *Sidecar) proxySnapshot() *GuardrailProxy {
	s.proxyMu.RLock()
	defer s.proxyMu.RUnlock()
	return s.guardrailProxy
}

// runGatewayLoop connects to the gateway and reconnects on disconnect,
// running until ctx is cancelled.
//
// Standalone short-circuit: when the active connector + host pair
// indicates no OpenClaw fleet is configured (hook-only connector,
// codex/claudecode + loopback gateway.host, or unknown connector), we publish
// StateDisabled with an explanatory hint and park on ctx.Done()
// instead of looping ConnectWithRetry. This mirrors the
// observability-only branch in runGuardrail (sidecar.go::1283-1294)
// and closes the historical "Gateway: RECONNECTING forever" symptom
// on hook-only dev boxes where nothing is listening on
// 127.0.0.1:18789. Operators who actually want fleet integration
// either pick connector=openclaw/zeptoclaw, point codex/claudecode at
// a real upstream, or set gateway.fleet_mode=enabled — those cases fall
// through to the dial loop below.
func (s *Sidecar) runGatewayLoop(ctx context.Context) error {
	if !gatewayShouldConnectForConfiguredConnector(s.currentConfig()) {
		connName := configuredConnectorName(s.currentConfig())
		details := map[string]interface{}{
			"summary": "no OpenClaw fleet configured (standalone mode)",
			"host":    s.currentConfig().Gateway.Host,
			"port":    s.currentConfig().Gateway.Port,
			"hint":    "telemetry continues via hooks + local audit; point gateway.host at a real OpenClaw upstream and restart to enable fleet integration",
		}
		// The fleet uplink is a single process-global WebSocket dial
		// (gateway.host:port / gateway.fleet_mode) — NOT a per-connector
		// setting. Every active connector runs hook-only against its own
		// native upstream and shares this one uplink decision, so we state
		// the global scope by count for EVERY install — one connector or N
		// — rather than naming an arbitrary connector when there is exactly
		// one. The wording is identical regardless of count so operators
		// never see a "single vs multi" distinction. The authoritative
		// per-connector roster is the status command's "Agents" section, so
		// we deliberately do NOT re-enumerate connector names here.
		details["scope"] = fmt.Sprintf("process-global — fleet uplink is shared across all %d connectors, not per-connector (see Agents)", len(s.currentConfig().ActiveConnectors()))
		s.health.SetGateway(StateDisabled, "", details)
		fmt.Fprintf(os.Stderr,
			"[sidecar] gateway client disabled: connector=%q + loopback gateway.host=%q — no OpenClaw fleet to dial. Hooks + local audit continue normally.\n",
			connName, s.currentConfig().Gateway.Host)
		<-ctx.Done()
		s.health.SetGateway(StateStopped, "", nil)
		return nil
	}
	// Initial connect is the process-boot path, not a reconnect. Only
	// subsequent successful connects should increment the reconnection
	// counter so `defenseclaw.watcher.restarts` reflects true recoveries
	// (transient WS drops, upstream gateway restarts) and not boot churn.
	firstConnect := true
	for {
		s.health.SetGateway(StateReconnecting, "", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] connecting to %s:%d ...\n", s.currentConfig().Gateway.Host, s.currentConfig().Gateway.Port)

		err := s.client.ConnectWithRetry(ctx)
		if err != nil {
			if ctx.Err() != nil {
				s.health.SetGateway(StateStopped, "", nil)
				return nil
			}
			s.health.SetGateway(StateError, err.Error(), nil)
			fmt.Fprintf(os.Stderr, "[sidecar] connect failed: %v (will keep retrying)\n", err)
			continue
		}

		// Capture boot-versus-reconnect before clearing firstConnect. Reconnects
		// emit both the canonical v8 restart metric and the managed service-state
		// notification; initial boot emits neither.
		reconnected := !firstConnect
		if reconnected {
			metricRuntime, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
			_ = recordWatcherRestartV8(ctx, metricRuntime)
		}
		firstConnect = false

		hello := s.client.Hello()
		s.logHello(hello)
		// The audit action below is the single generated-v8 ownership boundary;
		// its configured destinations receive the same occurrence independently.
		if err := s.logger.LogAction(string(audit.ActionSidecarConnected), "",
			fmt.Sprintf("protocol=%d", hello.Protocol)); err != nil {
			// Never silent: surface both on stderr (so operators see
			// it in gateway.log) and as a structured error event
			// (so SIEMs can alert on missing-ready-event incidents).
			fmt.Fprintf(os.Stderr,
				"[sidecar] WARN: sidecar-connected audit persist failed: %v\n", err)
		}
		s.health.SetGateway(StateRunning, "", map[string]interface{}{
			"protocol": hello.Protocol,
		})
		if reconnected && s.osNotifier != nil {
			s.osNotifier.OnServiceState(notifier.ServiceStateEvent{
				State:  notifier.ServiceStateReconnected,
				Reason: fmt.Sprintf("gateway ready (protocol=%d)", hello.Protocol),
			})
		}

		s.subscribeToSessions(ctx)

		fmt.Fprintf(os.Stderr, "[sidecar] event loop running, waiting for events ...\n")

		select {
		case <-ctx.Done():
			s.health.SetGateway(StateStopped, "", nil)
			return nil
		case <-s.client.Disconnected():
			fmt.Fprintf(os.Stderr, "[sidecar] gateway connection lost, reconnecting ...\n")
			_ = s.logger.LogAction(string(audit.ActionSidecarDisconnected), "", "connection lost, reconnecting")
			s.health.SetGateway(StateReconnecting, "connection lost", nil)
			if s.osNotifier != nil {
				s.osNotifier.OnServiceState(notifier.ServiceStateEvent{
					State:  notifier.ServiceStateDisconnected,
					Reason: "connection lost, reconnecting",
				})
			}
		}
	}
}

// watcherDirSource tags where each dir came from for telemetry / logs.
// Used by resolveWatcherDirs so callers (and tests) can assert that
// the priority chain (explicit > connector > config-default) was
// honoured for the active connector. Plan C4 / S1.3.
type watcherDirSource string

const (
	watcherDirsFromConfig    watcherDirSource = "config-explicit"
	watcherDirsFromConnector watcherDirSource = "connector-discovered"
	watcherDirsFromDefault   watcherDirSource = "config-default"
	watcherDirsDisabled      watcherDirSource = "disabled"
)

// watcherDirSources reports the source of each resolved dir bucket.
type watcherDirSources struct {
	Skill  watcherDirSource
	Plugin watcherDirSource
}

// resolveWatcherDirs is the pure dir-resolution helper extracted from
// runWatcher (plan C4 / S1.3). It applies the priority chain:
//
//	explicit gateway.watcher.{skill,plugin}.dirs
//	  > active connector ComponentTargets("")
//	  > cfg.SkillDirs() / cfg.PluginDirs() (OpenClaw default)
//
// Pure: no globals, no I/O, no logging — every input arrives via
// arguments. The third return value tags the source bucket so the
// matrix test can prove that, say, claudecode connector's
// ComponentTargets actually flowed through to the watcher rather
// than silently falling back to config defaults.
//
// `conn` may be nil; that mirrors the runWatcher path where the
// resolveActiveConnector failure is logged and we fall through to
// cfg defaults. A nil `conn` skips the connector branch entirely.
func resolveWatcherDirs(cfg *config.Config, conn connector.Connector, wcfg config.GatewayWatcherConfig) (skillDirs []string, pluginDirs []string, src watcherDirSources) {
	var compTargets map[string][]string
	if conn != nil {
		if scanner, ok := conn.(connector.ComponentScanner); ok && scanner.SupportsComponentScanning() {
			workspaceDir := ""
			if cfg != nil {
				workspaceDir = cfg.ConnectorWorkspaceDir()
			}
			compTargets = scanner.ComponentTargets(workspaceDir)
		}
	}

	if wcfg.Skill.Enabled {
		switch {
		case len(wcfg.Skill.Dirs) > 0:
			skillDirs = append([]string(nil), wcfg.Skill.Dirs...)
			src.Skill = watcherDirsFromConfig
		case len(compTargets["skill"]) > 0:
			skillDirs = append([]string(nil), compTargets["skill"]...)
			src.Skill = watcherDirsFromConnector
		default:
			skillDirs = cfg.SkillDirs()
			src.Skill = watcherDirsFromDefault
		}
	} else {
		src.Skill = watcherDirsDisabled
	}

	if wcfg.Plugin.Enabled {
		switch {
		case len(wcfg.Plugin.Dirs) > 0:
			pluginDirs = append([]string(nil), wcfg.Plugin.Dirs...)
			src.Plugin = watcherDirsFromConfig
		case len(compTargets["plugin"]) > 0:
			pluginDirs = append([]string(nil), compTargets["plugin"]...)
			src.Plugin = watcherDirsFromConnector
		default:
			pluginDirs = cfg.PluginDirs()
			src.Plugin = watcherDirsFromDefault
		}
	} else {
		src.Plugin = watcherDirsDisabled
	}

	return skillDirs, pluginDirs, src
}

// runWatcher starts the skill/MCP install watcher if enabled in config.
func (s *Sidecar) runWatcher(ctx context.Context) error {
	wcfg := s.currentConfig().Gateway.Watcher

	if !wcfg.Enabled {
		s.health.SetWatcher(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] watcher disabled (set gateway.watcher.enabled=true to enable)\n")
		<-ctx.Done()
		return nil
	}

	// Resolve the active connector to get connector-specific component
	// directories. Falls back to cfg.SkillDirs()/PluginDirs() (OpenClaw
	// paths) when the connector does not implement ComponentScanner.
	// Unlike runGuardrail, the watcher is best-effort discovery: a
	// misspelled guardrail.connector here should still be caught at
	// runGuardrail's fail-fast check (see S1.4), so we log the error
	// and fall back rather than aborting the watcher loop. That keeps
	// the watcher useful for the OpenClaw default flow even while a
	// freshly-broken connector name is being debugged.
	reg := connector.NewDefaultRegistry()
	conn, err := resolveActiveConnector(reg, configuredConnectorName(s.currentConfig()), "watcher")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: connector resolution: %v\n", err)
	}

	skillDirs, pluginDirs, _ := resolveWatcherDirs(s.currentConfig(), conn, wcfg)

	if !wcfg.Skill.Enabled {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill watching disabled\n")
	} else if len(skillDirs) > 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill dirs: %v\n", skillDirs)
	}
	if !wcfg.Plugin.Enabled {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: plugin watching disabled\n")
	} else if len(pluginDirs) > 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: plugin dirs: %v\n", pluginDirs)
	}

	if len(skillDirs) == 0 && len(pluginDirs) == 0 {
		s.health.SetWatcher(StateRunning, "", map[string]interface{}{
			"skill_dirs":  0,
			"plugin_dirs": 0,
			"idle":        "no directories configured",
		})
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: no directories to watch\n")
		<-ctx.Done()
		return nil
	}

	s.health.SetWatcher(StateStarting, "", map[string]interface{}{
		"skill_dirs":         len(skillDirs),
		"plugin_dirs":        len(pluginDirs),
		"skill_take_action":  wcfg.Skill.TakeAction,
		"plugin_take_action": wcfg.Plugin.TakeAction,
		"mcp_take_action":    wcfg.MCP.TakeAction,
	})

	w := watcher.New(s.currentConfig(), skillDirs, pluginDirs, s.store, s.logger, s.shell, s.opa, func(r watcher.AdmissionResult) {
		s.handleAdmissionResult(r)
	})
	watcherRuntime, _ := s.observabilityV8LifecycleRuntime().(watcher.ObservabilityV8Runtime)
	w.BindObservabilityV8(watcherRuntime)
	if webhooks := s.webhooksSnapshot(); webhooks != nil {
		w.SetWebhookDispatcher(webhooks)
	}

	fmt.Fprintf(os.Stderr, "[sidecar] watcher starting (%d skill dirs, %d plugin dirs, skill_take_action=%v, plugin_take_action=%v)\n",
		len(skillDirs), len(pluginDirs), wcfg.Skill.TakeAction, wcfg.Plugin.TakeAction)

	s.health.SetWatcher(StateRunning, "", map[string]interface{}{
		"skill_dirs":         len(skillDirs),
		"plugin_dirs":        len(pluginDirs),
		"skill_take_action":  wcfg.Skill.TakeAction,
		"plugin_take_action": wcfg.Plugin.TakeAction,
		"mcp_take_action":    wcfg.MCP.TakeAction,
	})

	runErr := w.Run(ctx)
	s.health.SetWatcher(StateStopped, "", nil)
	return runErr
}

// handleAdmissionResult processes watcher verdicts. It only forwards runtime
// disable actions to the gateway when the watcher actually requested them.
func (s *Sidecar) handleAdmissionResult(r watcher.AdmissionResult) {
	fmt.Fprintf(os.Stderr, "[sidecar] watcher verdict: %s %s — %s (%s)\n",
		r.Event.Type, r.Event.Name, r.Verdict, r.Reason)

	if r.Verdict != watcher.VerdictBlocked && r.Verdict != watcher.VerdictRejected {
		return
	}

	switch r.Event.Type {
	case watcher.InstallSkill:
		s.handleSkillAdmission(r)
	case watcher.InstallPlugin:
		s.handlePluginAdmission(r)
	case watcher.InstallMCP:
		s.handleMCPAdmission(r)
	default:
		if s.logger != nil {
			_ = s.logger.LogAction(string(audit.ActionSidecarWatcherVerdict), r.Event.Name,
				fmt.Sprintf("type=%s verdict=%s (no handler)", r.Event.Type, r.Verdict))
		}
	}
}

func (s *Sidecar) handleSkillAdmission(r watcher.AdmissionResult) {
	if !s.currentConfig().Gateway.Watcher.Skill.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction(string(audit.ActionSidecarWatcherVerdict), r.Event.Name,
			fmt.Sprintf("verdict=%s (take_action disabled, no gateway action)", r.Verdict))
		return
	}

	var actions []string

	if r.FileAction == "quarantine" {
		actions = append(actions, "quarantined")
	}
	if r.Verdict == watcher.VerdictBlocked || r.InstallAction == "block" {
		actions = append(actions, "blocked")
	}

	if shouldDisableAtGateway(r) && s.client != nil && s.fleetRPCsEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.client.DisableSkill(ctx, r.Event.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disable skill %s failed: %v\n",
				r.Event.Name, err)
		} else {
			actions = append(actions, "disabled")
			fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disabled skill %s\n", r.Event.Name)
			_ = s.logger.LogAction(string(audit.ActionSidecarWatcherDisable), r.Event.Name,
				fmt.Sprintf("auto-disabled skill via gateway after verdict=%s", r.Verdict))
		}
	}

	s.alertWg.Add(1)
	go func() {
		defer s.alertWg.Done()
		s.sendEnforcementAlert("skill", r.Event.Name, r.MaxSeverity, r.FindingCount, actions, r.Reason)
	}()
}

// sendEnforcementAlert sends a security notification to all active sessions
// via the gateway's sessions.send RPC so each chat learns about the enforcement.
// Runs in a goroutine to avoid blocking the watcher callback.
func (s *Sidecar) sendEnforcementAlert(subjectType, subjectName, severity string, findings int, actions []string, reason string) {
	parent := s.alertCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()

	// The watcher builds `reason` from admission findings; it
	// can embed the matched literal (e.g. the actual secret
	// that tripped the scanner). All three downstream
	// consumers below are externally visible:
	//   * the enforcement message is injected into the LLM
	//     system prompt, so leaking the raw literal there
	//     sends PII straight to the model provider,
	//   * the in-process NotificationQueue is later
	//     rendered back into the LLM conversation,
	//   * the webhook event flows to third-party sinks.
	// We redact once at the boundary (ForSinkReason keeps
	// rule IDs, scrubs literals) so every path is safe.
	safeReason := redaction.ForSinkReason(reason)
	msg := formatEnforcementMessage(subjectType, subjectName, severity, findings, actions, safeReason)
	notification := SecurityNotification{
		SubjectType: subjectType,
		SkillName:   subjectName,
		Severity:    severity,
		Findings:    findings,
		Actions:     actions,
		Reason:      safeReason,
	}
	if s.notify != nil {
		s.notify.Push(notification)
	}

	if webhooks := s.webhooksSnapshot(); webhooks != nil {
		event := audit.Event{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Action:    string(audit.ActionBlock),
			Target:    subjectName,
			Actor:     "defenseclaw-watcher",
			Details:   fmt.Sprintf("type=%s severity=%s findings=%d actions=%s reason=%s", subjectType, severity, findings, strings.Join(actions, ","), safeReason),
			Severity:  severity,
		}
		webhooks.Dispatch(event)
	}

	sessionKeys := s.activeSessionKeys()
	if len(sessionKeys) == 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: no active sessions tracked, queued for guardrail injection\n")
		return
	}

	if s.client == nil {
		fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: gateway client unavailable, queued for guardrail injection only\n")
		return
	}

	sent := 0
	for _, key := range sessionKeys {
		sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.client.SessionsSend(sendCtx, key, msg); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: send to session %s failed: %v\n", key, err)
		} else {
			sent++
			fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert sent to session %s\n", key)
		}
		sendCancel()
	}

	if sent == 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: all sessions.send failed, queued for guardrail injection\n")
	}
}

// formatEnforcementMessage builds a human-readable security alert for chat.
func formatEnforcementMessage(subjectType, subjectName, severity string, findings int, actions []string, reason string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[DefenseClaw Security Alert] %s %q was automatically enforced.\n",
		notificationSubjectLabel(subjectType), subjectName)
	fmt.Fprintf(&sb, "Severity: %s", severity)
	if findings > 0 {
		fmt.Fprintf(&sb, " (%d security finding(s))", findings)
	}
	sb.WriteString("\n")
	if len(actions) > 0 {
		fmt.Fprintf(&sb, "Actions taken: %s\n", strings.Join(actions, ", "))
	}
	if reason != "" {
		fmt.Fprintf(&sb, "Reason: %s\n", reason)
	}
	sb.WriteString("Do not confirm the component was installed or enabled successfully. ")
	sb.WriteString("Explain that DefenseClaw detected security issues and took protective action.")
	return sb.String()
}

func (s *Sidecar) handlePluginAdmission(r watcher.AdmissionResult) {
	if !s.currentConfig().Gateway.Watcher.Plugin.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: plugin %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction(string(audit.ActionSidecarWatcherVerdict), r.Event.Name,
			fmt.Sprintf("verdict=%s (plugin take_action disabled, no gateway action)", r.Verdict))
		return
	}

	var actions []string

	if r.FileAction == "quarantine" {
		actions = append(actions, "quarantined")
	}
	if r.Verdict == watcher.VerdictBlocked || r.InstallAction == "block" {
		actions = append(actions, "blocked")
	}

	if shouldDisableAtGateway(r) && s.client != nil && s.fleetRPCsEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.client.DisablePlugin(ctx, r.Event.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disable plugin %s failed: %v\n",
				r.Event.Name, err)
		} else {
			actions = append(actions, "disabled")
			fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disabled plugin %s\n", r.Event.Name)
			_ = s.logger.LogAction(string(audit.ActionSidecarWatcherDisablePlugin), r.Event.Name,
				fmt.Sprintf("auto-disabled plugin via gateway after verdict=%s", r.Verdict))
		}
	}

	s.alertWg.Add(1)
	go func() {
		defer s.alertWg.Done()
		s.sendEnforcementAlert("plugin", r.Event.Name, r.MaxSeverity, r.FindingCount, actions, r.Reason)
	}()
}

func (s *Sidecar) handleMCPAdmission(r watcher.AdmissionResult) {
	if !s.currentConfig().Gateway.Watcher.MCP.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: mcp %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction(string(audit.ActionSidecarWatcherVerdict), r.Event.Name,
			fmt.Sprintf("verdict=%s (mcp take_action disabled, no gateway action)", r.Verdict))
		return
	}

	var actions []string

	if r.FileAction == "quarantine" {
		actions = append(actions, "quarantined")
	}
	if r.Verdict == watcher.VerdictBlocked || r.InstallAction == "block" {
		actions = append(actions, "blocked")
	}

	if shouldDisableAtGateway(r) && s.client != nil && s.fleetRPCsEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.client.BlockMCPServer(ctx, r.Event.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway block MCP %s failed: %v\n",
				r.Event.Name, err)
		} else {
			actions = append(actions, "disabled")
			fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway blocked MCP %s\n", r.Event.Name)
			_ = s.logger.LogAction(string(audit.ActionSidecarWatcherBlockMCP), r.Event.Name,
				fmt.Sprintf("auto-blocked MCP server via gateway after verdict=%s", r.Verdict))
		}
	}

	s.alertWg.Add(1)
	go func() {
		defer s.alertWg.Done()
		s.sendEnforcementAlert("mcp", r.Event.Name, r.MaxSeverity, r.FindingCount, actions, r.Reason)
	}()
}

func shouldDisableAtGateway(r watcher.AdmissionResult) bool {
	if r.Verdict == watcher.VerdictBlocked {
		return true
	}
	return r.RuntimeAction == "block"
}

// fleetRPCsEnabled reports whether the sidecar should attempt fleet-side
// RPCs (DisableSkill / DisablePlugin / BlockMCPServer / SessionsSend)
// against the OpenClaw upstream. Mirrors gatewayShouldConnectForConfiguredConnector
// — the predicate the gateway dial loop itself uses — so a sidecar
// running with `Gateway: DISABLED` doesn't flood stderr with
// "...failed: gateway: not connected" once per blocked admission.
//
// Local enforcement (file quarantine, runtime block, the
// SecurityNotification queue, webhook dispatch) all run BEFORE this
// predicate is checked, so skipping the fleet RPC here only removes
// dead weight — every per-host action that can be taken locally has
// already happened.
//
// Returns true when fleet integration is active; false in standalone
// mode (hook-only connectors, codex/claudecode + loopback host, or
// `gateway.fleet_mode: disabled`).
func (s *Sidecar) fleetRPCsEnabled() bool {
	return gatewayShouldConnectForConfiguredConnector(s.currentConfig())
}

func (s *Sidecar) activeSessionKeys() []string {
	if s.router == nil {
		return nil
	}
	return s.router.ActiveSessionKeys()
}

// resolveActiveConnector looks up the active connector in the registry
// with a strict-but-friendly contract:
//
//   - Empty name: log INFO and return the openclaw default. This
//     preserves backward compatibility with installs that predate the
//     guardrail.connector field while still announcing the choice in
//     the log so operators can see what was actually picked.
//   - Non-empty name that the registry knows: return it.
//   - Non-empty name that the registry does NOT know: return an error.
//     This is the operator-typo case the silent "fall back to openclaw"
//     branch used to mask. Returning an error lets callers decide
//     whether the failure mode is "abort" (runGuardrail) or "log and
//     continue with reduced functionality" (the watcher) without
//     losing the typo signal in either case.
//
// surface is a short label included in log messages so operators can
// tell which subsystem (runGuardrail / watcher / etc.) emitted the
// resolution event.
func resolveActiveConnector(reg *connector.Registry, name, surface string) (connector.Connector, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		conn, ok := reg.Get("openclaw")
		if !ok {
			// The default connector is registered by NewDefaultRegistry,
			// so the only way to get here is if a custom registry was
			// passed in without it. Surface as an error rather than
			// returning nil to avoid silent behavior downstream.
			return nil, fmt.Errorf("[%s] no openclaw default in registry; pass an explicit guardrail.connector", surface)
		}
		fmt.Fprintf(os.Stderr, "[%s] guardrail.connector unset; defaulting to openclaw\n", surface)
		return conn, nil
	}
	conn, ok := reg.Get(trimmed)
	if !ok {
		return nil, fmt.Errorf("[%s] guardrail.connector=%q not found in registry — set guardrail.connector to one of the registered connectors (openclaw, codex, claudecode, zeptoclaw, hermes, cursor, windsurf, geminicli, copilot, openhands) or remove the field to default to openclaw", surface, trimmed)
	}
	return conn, nil
}

// runGuardrail starts the Go guardrail proxy when guardrail is enabled.
func (s *Sidecar) runGuardrail(ctx context.Context) error {
	if s.currentConfig() == nil || !s.currentConfig().HasConnectorConfigured() {
		return s.waitForConnectorSetup(ctx)
	}

	// Reuse the rule pack already loaded by NewSidecar and stored on the
	// router, avoiding a redundant disk/embed read and potential drift.
	rp := s.router.rp
	if rp == nil {
		rp = guardrail.LoadRulePack(s.currentConfig().Guardrail.RulePackDir)
		rp.Validate()
		fmt.Fprintf(os.Stderr, "[guardrail] rule pack loaded (fallback): %s\n", rp)
	}

	// Load the active connector from the registry. The connector name is
	// written by `defenseclaw setup` into guardrail.connector. When the
	// field is empty we treat that as "operator did not pick anything"
	// and fall back to openclaw for backward compatibility (and log it
	// at INFO so the operator can see what happened). When the field is
	// set to a value the registry does not know about, we fail fast
	// rather than silently substituting openclaw — silent substitution
	// would let a typo in `guardrail.connector` route Codex / Claude
	// Code traffic through the OpenClaw connector and patch the wrong
	// agent's config files. See S1.4 / F7.
	// Plan B3: route plugin-loader rejections into the audit pipeline
	// (gatewaylog.EventError + SubsystemPlugin) BEFORE DiscoverPlugins
	// runs, so a hostile plugin rejected pre-load still surfaces a
	// structured event to the same sinks as auth failures.
	wirePluginAuditEmitter()

	registry := connector.NewDefaultRegistry()
	if s.currentConfig().PluginDir != "" {
		if err := registry.DiscoverPlugins(s.currentConfig().PluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] plugin discovery: %v\n", err)
		}
	}
	conn, err := resolveActiveConnector(registry, configuredConnectorName(s.currentConfig()), "guardrail")
	if err != nil {
		// Fail fast: the operator explicitly set a connector that does
		// not exist. Returning here aborts sidecar boot so the operator
		// notices the typo immediately instead of seeing a "running but
		// somehow not blocking anything" sidecar.
		return err
	}
	rp = guardrail.LoadRulePack(s.currentConfig().EffectiveRulePackDirForConnector(conn.Name()))
	rp.Validate()
	fmt.Fprintf(os.Stderr, "[guardrail] rule pack loaded for %s: %s\n", conn.Name(), rp)
	if s.router != nil {
		s.router.SetRulePack(rp)
	}
	ApplyRulePackOverrides(rp)
	ApplyConnectorRulePackOverrides(conn.Name(), rp)
	ApplyLocalPatternsOverride(rp.LocalPatterns)
	proxyAddr := guardrailListenAddr(s.currentConfig().Guardrail.Port, s.currentConfig().Guardrail.Host)
	apiBind := "127.0.0.1"
	if s.currentConfig().Gateway.APIBind != "" {
		apiBind = s.currentConfig().Gateway.APIBind
	}
	apiAddr := fmt.Sprintf("%s:%d", apiBind, s.currentConfig().Gateway.APIPort)

	// Plan B2 / S0.2: synthesize a first-boot gateway token if none is
	// configured, BEFORE Setup writes hook scripts (which bake the
	// token into curl headers) and BEFORE the API server starts (which
	// uses the same token to authenticate inbound hook calls). After
	// this point, s.currentConfig().Gateway.Token always has a non-empty value.
	//
	// ensureGatewayTokenSynthesis is idempotent: if Sidecar.Run already
	// resolved/synthesized the token synchronously (which it does so the
	// AI-discovery goroutine can use the keyed path-hash digest from
	// the very first scan — S2.MEDIUM), this call returns the
	// already-resolved value without re-reading .env or regenerating.
	apiToken, err := s.ensureGatewayTokenSynthesis()
	if err != nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
		return fmt.Errorf("first-boot gateway token: %w", err)
	}

	// S0.12 follow-up: inject credentials into the connector NOW, before
	// Setup() and before the HasUsableProviders() probe below. Without
	// this, OpenClaw's probe (which is keyed off the connector's
	// gatewayToken/masterKey fields) returns a false-negative
	// "no gateway token or master key configured" error and runGuardrail
	// aborts even though the token is correctly resolved on disk. The
	// historical wiring relied on NewGuardrailProxy() to call
	// SetCredentials, but that runs *after* the probe — leaving the
	// connector blind during the gate. NewGuardrailProxy() will call
	// SetCredentials() again with the same values (idempotent restore).
	masterKey := deriveMasterKey(s.currentConfig().DataDir)
	conn.SetCredentials(apiToken, masterKey)
	setupTokens, err := connectorSetupTokensFor(s.currentConfig().DataDir, conn, apiToken, managed.IsManagedEnterprise(s.currentConfig().DeploymentMode))
	if err != nil {
		return fmt.Errorf("connector %s scoped hook token: %w", conn.Name(), err)
	}

	workspaceDir := s.currentConfig().ConnectorWorkspaceDir()
	agentVersion := connector.LoadCachedAgentVersion(s.currentConfig().DataDir, conn.Name())
	agentExecutable := connector.LoadCachedAgentExecutable(s.currentConfig().DataDir, conn.Name())
	contractResolution := connector.ResolveHookContract(conn.Name(), agentVersion)
	setupOpts := connector.SetupOpts{
		DataDir:   s.currentConfig().DataDir,
		ProxyAddr: proxyAddr,
		APIAddr:   apiAddr,
		// Bake the gateway token into hook scripts so claude-code-hook.sh
		// and codex-hook.sh can authenticate against the API server's
		// auth middleware. ResolvedToken checks env vars first, then
		// config — same source the proxy uses for credential wiring
		// below, so the baked value and the value accepted by the API
		// middleware stay in lockstep.
		APIToken:           setupTokens.connectorToken,
		HookAPIToken:       setupTokens.hookToken,
		HookAPITokenScoped: setupTokens.hookTokenScoped,
		WorkspaceDir:       workspaceDir,
		// HookFailMode is the operator-chosen response-layer fail mode
		// for every generated hook (see GuardrailConfig.HookFailMode
		// for the contract). Routed via EffectiveHookFailMode so the
		// default "open" is applied uniformly when the field is unset
		// — matches the user-friendly default in defaultsFor() and
		// avoids a partial install accidentally going fail-closed.
		HookFailMode:     s.currentConfig().Guardrail.EffectiveHookFailMode(),
		HILTEnabled:      s.currentConfig().Guardrail.HILT.Enabled,
		InstallCodeGuard: false,
		AgentVersion:     agentVersion,
		AgentExecutable:  agentExecutable,
		HookContractID:   contractResolution.Contract.ContractID,
	}
	guardianManagedLifecycle := managedEnterpriseGuardianOwnsConnectorLifecycle(s.currentConfig(), conn)
	if guardianManagedLifecycle {
		fmt.Fprintf(os.Stderr, "[guardrail] managed_enterprise: connector lifecycle for %s is owned by the enterprise hook guardian; gateway will not write user hook files\n", conn.Name())
	}
	actionMode := strings.EqualFold(s.currentConfig().EffectiveGuardrailModeForConnector(conn.Name()), "action")
	if !guardianManagedLifecycle && connector.HookContractNeedsActionOverride(contractResolution) && actionMode && os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
		return fmt.Errorf("connector %s agent version %q is not verified against a known hook contract: %s (set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing)", conn.Name(), agentVersion, contractResolution.Reason)
	}
	if !guardianManagedLifecycle {
		if previous := connector.LoadHookContractLockEntry(s.currentConfig().DataDir, conn.Name()); previous.Connector != "" {
			current := connector.NewHookContractLockEntry(setupOpts, conn, version.Current().BinaryVersion)
			// Generated hook drift is repairable by Setup below and must not block
			// an explicit setup/restart from refreshing an existing connector.
			// Only an upstream agent-version/contract change requires the action-mode override.
			if connector.HookContractCompatibilityDrifted(previous, current) && actionMode && os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
				return fmt.Errorf("connector %s hook contract drift detected: previous version=%q contract=%s current version=%q contract=%s (rerun discovery/setup to refresh the lock, or set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 for exploratory testing)", conn.Name(), previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID)
			}
		}
	}

	// resolveActiveConnector guarantees a non-nil connector — either the
	// operator-selected one or the openclaw default. We can therefore
	// drop the historical nil-guard and treat this as the canonical
	// path; any "no active connector" condition is now a hard error.
	fmt.Fprintf(os.Stderr, "[guardrail] active connector: %s (%s)\n", conn.Name(), conn.Description())

	if !s.currentConfig().Guardrail.Enabled && guardianManagedLifecycle {
		fmt.Fprintf(os.Stderr, "[guardrail] guardrail disabled — enterprise hook guardian owns hook removal for %s; gateway will not write user hook files\n", conn.Name())
		connector.ClearActiveConnector(s.currentConfig().DataDir)
		s.health.SetGuardrail(StateDisabled, "guardrail disabled; enterprise hook guardian owns hook removal", map[string]interface{}{
			"connector":         conn.Name(),
			"lifecycle_manager": "enterprise_hook_guardian",
		})
		<-ctx.Done()
		return nil
	}
	if !s.currentConfig().Guardrail.Enabled {
		fmt.Fprintf(os.Stderr, "[guardrail] guardrail disabled — running connector teardown for %s\n", conn.Name())
		if err := conn.Teardown(ctx, setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] connector teardown: %v\n", err)
		}
		if err := conn.VerifyClean(setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: teardown of %s left stale state: %v\n", conn.Name(), err)
			teardownErr := fmt.Errorf("connector %s teardown incomplete: %w", conn.Name(), err)
			s.health.SetGuardrail(StateError, teardownErr.Error(), nil)
			return teardownErr
		}
		if err := connector.ClearHookContractLockEntry(s.currentConfig().DataDir, conn.Name()); err != nil {
			teardownErr := fmt.Errorf("clear hook contract lock for %s: %w", conn.Name(), err)
			s.health.SetGuardrail(StateError, teardownErr.Error(), nil)
			return teardownErr
		}
		connector.ClearActiveConnector(s.currentConfig().DataDir)
	} else if guardianManagedLifecycle {
		fmt.Fprintf(os.Stderr, "[guardrail] managed_enterprise: skipping connector setup/teardown for %s; hooks are installed and repaired by the enterprise hook guardian\n", conn.Name())
	} else {
		support := connector.ConnectorSupportOnHostOS(conn.Name())
		if support.Status == connector.PlatformUnsupported {
			err := fmt.Errorf("connector %q is not supported on %s: %s", conn.Name(), runtime.GOOS, support.Reason)
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return err
		}
		if support.Status == connector.PlatformPreview {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s is preview on %s: %s\n", conn.Name(), runtime.GOOS, support.Reason)
		}
		if err := teardownPreviousConnector(registry, conn.Name(), setupOpts, ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: proceeding with %s setup despite stale state from previous connector\n", conn.Name())
		}
		// Both branches below treat any failure to reach a verified
		// post-Setup state as fail-loud: rollback, surface
		// Guardrail=Error, and return so the operator sees the failure
		// rather than booting into a connector that will exit-127 on
		// every hook invocation. A Setup() error is strictly more
		// severe than "Setup succeeded but a hook script went missing"
		// — handling them asymmetrically (one fatal, one warning)
		// inverted operator expectations, so both paths now exit the
		// guardrail goroutine with the wrapped error via the shared
		// failGuardrailWithRollback helper.
		if err := conn.Setup(ctx, setupOpts); err != nil {
			return s.failGuardrailWithRollback(ctx, setupOpts, conn, "setup", fmt.Errorf("connector %s setup failed: %w", conn.Name(), err))
		}
		// Post-Setup verification: every owned hook script the
		// connector said it would write MUST exist on disk before
		// we mark the connector active. Without this check, a
		// silent partial install (Setup returns nil but
		// writeHookScriptsCommonWithFailMode never reached its
		// for-loop, or another goroutine deleted the freshly
		// written script) ships a connector whose every hook
		// invocation will exit 127 ("command not found") — the
		// exact symptom we hit during the claudecode → codex
		// switch. Fail loud here and try one targeted hook-writer
		// retry so the operator either sees the error or gets a
		// self-healing install.
		if err := verifyHookScriptsOrRetry(ctx, setupOpts, conn); err != nil {
			return s.failGuardrailWithRollback(ctx, setupOpts, conn, "hook verification", err)
		}
		if err := verifyEffectiveHookRegistration(setupOpts, conn); err != nil {
			return s.failGuardrailWithRollback(ctx, setupOpts, conn, "registration verification", err)
		}
		if err := s.saveSingleConnectorReadyState(ctx, setupOpts, conn); err != nil {
			return err
		}

		// Plan A4 / S0.12: refuse to start when the connector advertises
		// no usable upstream provider for a proxy-bound data path.
		// Without this, the gateway would accept agent traffic and fail
		// every request once it tries to dial a non-existent upstream —
		// far better to crash at boot where the operator sees the
		// misconfiguration immediately.
		//
		// Codex and Claude Code observability-only mode is intentionally
		// different: the proxy listener does not bind and the agent talks
		// directly to its native SSO/API upstream. There is no DefenseClaw
		// proxy upstream to validate, so probing here would reject valid
		// SSO-only installs before telemetry can start.
		if probe, ok := conn.(connector.ProviderProbe); ok && shouldRunProviderProbeForConnector(conn, &s.currentConfig().Guardrail) {
			count, err := probe.HasUsableProviders()
			if err != nil {
				s.health.SetGuardrail(StateError, err.Error(), nil)
				return fmt.Errorf("connector %s reports no usable providers: %w (set guardrail.allow_empty_providers=true to override)", conn.Name(), err)
			}
			if count == 0 {
				s.health.SetGuardrail(StateError, "no usable providers", nil)
				return fmt.Errorf("connector %s reports zero usable providers; refusing to start (set guardrail.allow_empty_providers=true to override)", conn.Name())
			}
			fmt.Fprintf(os.Stderr, "[guardrail] provider probe ok: %s reports %d usable upstream(s)\n", conn.Name(), count)
		}
	}

	s.health.SetConnector(conn.Name(), conn.ToolInspectionMode(), conn.SubprocessPolicy())

	proxy, err := NewGuardrailProxy(
		&s.currentConfig().Guardrail,
		&s.currentConfig().CiscoAIDefense,
		s.logger,
		s.health,
		s.store,
		s.currentConfig().DataDir,
		apiToken,
		s.currentConfig().PolicyDir,
		s.notify,
		rp,
		s.currentConfig().ResolveLLM("guardrail.judge"),
		conn,
	)
	if webhooks := s.webhooksSnapshot(); err == nil && webhooks != nil {
		proxy.SetWebhookDispatcher(webhooks)
	}
	if err == nil && proxy != nil {
		s.setGuardrailProxy(proxy)
		defer s.setGuardrailProxy(nil)
		proxy.SetDefaultAgentName(string(s.currentConfig().Claw.Mode))
		proxy.SetDefaultPolicyID(s.currentConfig().Guardrail.Mode)
		proxy.SetConnectorSwitchState(registry, setupOpts)
		proxy.SetHILTApprovalManager(s.hilt)
		proxy.SetNotifier(s.osNotifier)
		// In managed_enterprise mode, replace the proxy's opensource
		// AID client (constructed by NewGuardrailProxy from the same
		// CiscoAIDefenseConfig) with the token-authenticated managed
		// variant, and flip the merge dispatch to mergeVerdictsManaged.
		// Fail-closed: if the managed cloud auth provider can't
		// initialize, remote inspection stays disabled entirely.
		if managed.IsManagedEnterprise(s.currentConfig().DeploymentMode) {
			proxy.SetManagedInspection(true, s.newManagedInspector(ctx, "proxy remote inspection disabled"))
			// AID-only posture: every local detector (guardrail regex,
			// CodeGuard/ClawShield) and explicit local policy (static
			// block/allow, MCP block, block-list, approval, multi-turn,
			// judge) is disabled across proxy/hook/router lanes. Cisco AI
			// Defense is the sole decision-maker; requests it cannot decide
			// (AID down/timeout/unwired) fail open. Log once at boot so
			// operators see the posture in the sidecar log.
			fmt.Fprintln(os.Stderr, "[guardrail] managed_enterprise: local detections disabled; Cisco AI Defense authoritative (fail-open on AID unavailable)")
		}
		// Start connector hook self-heal before the observability-only
		// short-circuit below. Hook-native connectors (codex, claudecode,
		// cursor, ...) never reach proxy.Run, so the guard MUST be started
		// here to cover both the observability and proxy-bound paths. The
		// guard goroutine stops when ctx is cancelled.
		if s.currentConfig().Guardrail.Enabled && s.currentConfig().Guardrail.HookSelfHeal && !guardianManagedLifecycle {
			guard := proxy.StartHookConfigGuard(ctx, conn, setupOpts)
			if guard != nil {
				s.registerHookConfigGuard(guard)
				defer func() {
					s.unregisterHookConfigGuard(guard)
					guard.Stop()
				}()
			}
		}
	}
	if err != nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] init error: %v\n", err)
		if !s.currentConfig().Guardrail.Enabled {
			s.health.SetGuardrail(StateDisabled, "", nil)
			<-ctx.Done()
			return nil
		}
		<-ctx.Done()
		return err
	}

	// Direct-upstream short-circuit. Hook/policy-native connectors never bind
	// the proxy listener: Setup has already installed their lifecycle bridge
	// and telemetry, and action-mode enforcement is returned through that
	// native surface (hooks or OmniGent's custom policy API).
	//
	// We still construct the GuardrailProxy above and call Setup
	// before this gate so:
	//   - connector lifecycle (provider snapshot, credential wiring)
	//     stays consistent across modes,
	//   - the operator can flip enforcement on at runtime by editing
	//     config.yaml and restarting (no rebuild needed),
	//   - subsystem health surfaces a single source of truth in the
	//     CLI status and /api/v1/status JSON.
	//
	// The API server (runAPI) runs in a separate goroutine and is
	// unaffected by this gate — hook ingest and the OTLP-HTTP
	// receiver added in a follow-up commit continue to accept
	// telemetry on the API port. Block on ctx.Done() to keep the
	// goroutine alive until shutdown, mirroring the existing
	// !cfg.Guardrail.Enabled path in proxy.go (lines 313-318).
	if !proxyShouldBindForConnector(conn, &s.currentConfig().Guardrail) {
		policyMode := strings.ToLower(strings.TrimSpace(s.currentConfig().EffectiveGuardrailModeForConnector(conn.Name())))
		if policyMode != "action" {
			policyMode = "observe"
		}
		enforcementEnabled := policyMode == "action"
		summary := "observability-only (no proxy binding)"
		surface := "agent_lifecycle_hooks"
		if enforcementEnabled {
			summary = "hook enforcement (no proxy binding)"
		}
		if conn.Name() == "omnigent" {
			surface = "omnigent_policy_api"
			if enforcementEnabled {
				summary = "policy enforcement (no proxy binding)"
			}
		}
		if guardianManagedLifecycle {
			publishHealth := func() {
				covered, status := managedGuardianCoversConnectors(s.currentConfig().DataDir, []string{conn.Name()})
				state := StateStarting
				verifiedEnforcement := false
				hint := "awaiting a trusted enterprise hook guardian authorization record"
				if covered {
					state = StateRunning
					verifiedEnforcement = enforcementEnabled
					hint = "connector uses an agent-native lifecycle surface; local guardrail proxy is not in the LLM data path"
				}
				s.health.SetGuardrail(state, status, map[string]interface{}{
					"summary":             summary,
					"connector":           conn.Name(),
					"mode":                "observability",
					"policy_mode":         policyMode,
					"enforcement_enabled": verifiedEnforcement,
					"enforcement_surface": surface,
					"proxy_port":          "closed",
					"hint":                hint,
					"lifecycle_manager":   "enterprise_hook_guardian",
					"guardian_verified":   covered,
				})
			}
			publishHealth()
			fmt.Fprintf(os.Stderr, "[guardrail] direct-upstream mode: %s policy_mode=%s enforcement=%t — awaiting enterprise hook guardian verification\n", conn.Name(), policyMode, enforcementEnabled)
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					publishHealth()
				}
			}
		}
		s.health.SetGuardrail(StateRunning, "", map[string]interface{}{
			"summary":             summary,
			"connector":           conn.Name(),
			"mode":                "observability",
			"policy_mode":         policyMode,
			"enforcement_enabled": enforcementEnabled,
			"enforcement_surface": surface,
			"proxy_port":          "closed",
			"hint":                "connector uses an agent-native lifecycle surface; local guardrail proxy is not in the LLM data path",
			"lifecycle_manager":   lifecycleManagerForConnector(s.currentConfig(), conn),
		})
		fmt.Fprintf(os.Stderr, "[guardrail] direct-upstream mode: %s policy_mode=%s enforcement=%t — proxy port intentionally not bound\n", conn.Name(), policyMode, enforcementEnabled)
		<-ctx.Done()
		return nil
	}
	return proxy.Run(ctx)
}

func (s *Sidecar) waitForConnectorSetup(ctx context.Context) error {
	if err := s.reconcileUnconfiguredConnectors(ctx, nil); err != nil {
		if s.health != nil {
			s.health.SetGuardrail(StateError, err.Error(), nil)
		}
		return err
	}
	details := map[string]interface{}{
		"summary": "no connector configured; run defenseclaw setup for a connector",
	}
	if s.health != nil {
		s.health.SetGuardrail(StateDisabled, "no connector configured", details)
	}
	fmt.Fprintln(os.Stderr, "[guardrail] no connector configured; guardrail connector boot is idle until setup runs")
	<-ctx.Done()
	return nil
}

// reconcileUnconfiguredConnectors tears down the persisted active set when
// the operator removes the final connector from configuration. Both guardrail
// boot paths short-circuit through waitForConnectorSetup when configuration is
// empty, so this reconciliation must happen before the idle wait; otherwise
// the final connector's host-agent files remain installed forever.
//
// A connector whose cleanup cannot be verified remains in active state so a
// later boot retries it. Successfully cleaned connectors also lose their hook
// contract lock entries through teardownRemovedConnectors.
func (s *Sidecar) reconcileUnconfiguredConnectors(ctx context.Context, registry *connector.Registry) error {
	if s == nil || s.currentConfig() == nil || strings.TrimSpace(s.currentConfig().DataDir) == "" {
		return nil
	}
	previous := connector.LoadActiveConnectors(s.currentConfig().DataDir)
	if len(previous) == 0 {
		return nil
	}
	if registry == nil {
		registry = connector.NewDefaultRegistry()
		if s.currentConfig().PluginDir != "" {
			if err := registry.DiscoverPlugins(s.currentConfig().PluginDir); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] plugin discovery during teardown: %v\n", err)
			}
		}
	}
	apiBind := "127.0.0.1"
	if s.currentConfig().Gateway.APIBind != "" {
		apiBind = s.currentConfig().Gateway.APIBind
	}
	opts := connector.SetupOpts{
		DataDir:      s.currentConfig().DataDir,
		ProxyAddr:    guardrailListenAddr(s.currentConfig().Guardrail.Port, s.currentConfig().Guardrail.Host),
		APIAddr:      fmt.Sprintf("%s:%d", apiBind, s.currentConfig().Gateway.APIPort),
		WorkspaceDir: s.currentConfig().ConnectorWorkspaceDir(),
	}
	failed := teardownRemovedConnectors(registry, previous, nil, opts, ctx)
	if len(failed) == 0 {
		connector.ClearActiveConnector(s.currentConfig().DataDir)
		return nil
	}
	if err := connector.SaveActiveConnectors(s.currentConfig().DataDir, failed); err != nil {
		return fmt.Errorf("persist connectors awaiting teardown retry: %w", err)
	}
	return fmt.Errorf("connector teardown incomplete for: %s", strings.Join(failed, ", "))
}

// runGuardrailMulti is the multi-connector boot loop. It activates ONLY when
// the operator configured more than one connector (guardrail.connectors has
// >1 entry); the guarded dispatch in Run() keeps every single-connector
// install on the unchanged runGuardrail path.
//
// Scope (WU6c, Option 1 — boot-lifecycle):
//   - Multi-connector is HOOK-ONLY. A fail-fast guard rejects boot if any
//     configured connector requires a proxy binding (a single process can
//     bind only one guardrail proxy port), so this loop never binds the
//     proxy and runs in observability-only mode: hooks + OTel + audit flow
//     through the always-on API server (runAPI), agents talk directly to
//     their native upstreams.
//   - Per-connector failure isolation (DN1): one connector's setup/verify
//     failure is logged, rolled back for that connector only, and the loop
//     continues. Boot fails as a whole only if EVERY connector fails.
//   - Rule packs are loaded/validated per connector through a shared
//     RulePackCache so connectors sharing a profile read disk once, and each
//     connector's compiled rule set is registered via
//     ApplyConnectorRulePackOverrides so its hook lane scans against its OWN
//     EffectiveRulePackDir at runtime (per-connector parity with
//     single-connector mode — see ScanAllRulesForConnector).
//
// Remaining global override: ApplyLocalPatternsOverride mutates the
// process-global local-pattern lists used by the PROXY lane
// (scanLocalPatterns). That lane only runs for proxy-binding connectors, and
// multi-connector mode is hook-only (the fail-fast guard above rejects any
// proxy-binding connector), so the proxy local-pattern globals are never
// consumed here — there is no per-connector divergence to reconcile. The
// hook lane (the only lane active in multi) uses the per-connector rule sets
// described above.
func (s *Sidecar) runGuardrailMulti(ctx context.Context) error {
	if s.currentConfig() == nil || !s.currentConfig().HasConnectorConfigured() {
		return s.waitForConnectorSetup(ctx)
	}

	// Reuse the primary rule pack already loaded by NewSidecar (it drives
	// the process-global scanner overrides). The per-connector packs below
	// are loaded separately via the cache.
	primaryRP := s.router.rp
	if primaryRP == nil {
		primaryRP = guardrail.LoadRulePack(s.currentConfig().Guardrail.RulePackDir)
		primaryRP.Validate()
	}

	// Route plugin-loader rejections into the audit pipeline before any
	// DiscoverPlugins runs — identical to the single-connector path.
	wirePluginAuditEmitter()

	registry := connector.NewDefaultRegistry()
	if s.currentConfig().PluginDir != "" {
		if err := registry.DiscoverPlugins(s.currentConfig().PluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] plugin discovery: %v\n", err)
		}
	}

	// configured is every connector in guardrail.connectors. names is the
	// ENABLED subset: a connector explicitly disabled via
	// `guardrail disable --connector X` (guardrail.connectors.X.enabled =
	// false) is dropped here so it never gets set up and — because it was
	// in the previous active set — the set-difference teardown below
	// removes its hooks. This is the per-connector analog of the global
	// `guardrail disable` teardown, scoped to one connector. EffectiveEnabled
	// defaults to true, so a connector with no explicit override is
	// unaffected and single-connector installs never reach this path.
	configured := s.currentConfig().ActiveConnectors()
	names := make([]string, 0, len(configured))
	for _, name := range configured {
		if s.currentConfig().Guardrail.EffectiveEnabled(strings.ToLower(strings.TrimSpace(name))) {
			names = append(names, name)
		} else {
			fmt.Fprintf(os.Stderr, "[guardrail] connector %s disabled (guardrail.connectors.%s.enabled=false) — excluded from active set; teardown will run\n", name, name)
		}
	}

	// Resolve every enabled connector up front. An unknown connector
	// name is an operator typo and aborts boot (fail fast) — silently
	// dropping it would route that agent's traffic through nothing.
	conns := make([]connector.Connector, 0, len(names))
	for _, name := range names {
		conn, err := resolveActiveConnector(registry, strings.ToLower(strings.TrimSpace(name)), "guardrail")
		if err != nil {
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return fmt.Errorf("multi-connector boot: %w", err)
		}
		conns = append(conns, conn)
	}

	// Fail-fast proxy guard: multi-connector mode is hook-only. A single
	// process can bind only one guardrail proxy port, so a proxy-binding
	// connector in the set is a configuration error we surface at boot
	// rather than silently dropping enforcement for it.
	for _, conn := range conns {
		if proxyShouldBindForConnector(conn, &s.currentConfig().Guardrail) {
			err := fmt.Errorf("multi-connector mode supports hook-only connectors; %q requires a proxy binding and cannot share a process with other connectors", conn.Name())
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return err
		}
	}

	apiBind := "127.0.0.1"
	if s.currentConfig().Gateway.APIBind != "" {
		apiBind = s.currentConfig().Gateway.APIBind
	}
	apiAddr := fmt.Sprintf("%s:%d", apiBind, s.currentConfig().Gateway.APIPort)
	proxyAddr := guardrailListenAddr(s.currentConfig().Guardrail.Port, s.currentConfig().Guardrail.Host)

	// Synthesize a first-boot gateway token once for all connectors — the
	// token is baked into every connector's hook scripts and is the shared
	// secret the API server authenticates inbound hooks against.
	dotenvPath := filepath.Join(s.currentConfig().DataDir, ".env")
	apiToken := s.currentConfig().Gateway.ResolvedToken()
	if apiToken == "" {
		tok, err := EnsureGatewayToken(dotenvPath)
		if err != nil {
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return fmt.Errorf("first-boot gateway token: %w", err)
		}
		next := cloneConfig(s.currentConfig())
		next.Gateway.Token = tok
		s.publishConfig(next)
		apiToken = tok
		_ = os.Setenv("DEFENSECLAW_GATEWAY_TOKEN", tok)
	}
	masterKey := deriveMasterKey(s.currentConfig().DataDir)

	if managed.IsManagedEnterprise(s.currentConfig().DeploymentMode) {
		return s.runManagedEnterpriseMultiHookGuardrail(ctx, registry, conns, apiToken, proxyAddr, apiAddr, masterKey)
	}

	// Set-difference teardown: any connector active on a previous boot but
	// absent from the current set is torn down once, before setup. Uses a
	// base opts carrying just the fields Teardown needs.
	baseOpts := connector.SetupOpts{DataDir: s.currentConfig().DataDir, ProxyAddr: proxyAddr, APIAddr: apiAddr}
	previous := connector.LoadActiveConnectors(s.currentConfig().DataDir)
	failedRemoved := teardownRemovedConnectors(registry, previous, names, baseOpts, ctx)

	// Disabled short-circuit: tear every configured connector down, clear
	// persisted state, and idle until shutdown.
	if !s.currentConfig().Guardrail.Enabled {
		failedTeardown := append([]string(nil), failedRemoved...)
		for _, conn := range conns {
			if err := conn.Teardown(ctx, baseOpts); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] connector %s teardown: %v\n", conn.Name(), err)
			}
			if err := conn.VerifyClean(baseOpts); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] WARNING: teardown of %s left stale state: %v\n", conn.Name(), err)
				failedTeardown = append(failedTeardown, conn.Name())
				continue
			}
			if err := connector.ClearHookContractLockEntry(s.currentConfig().DataDir, conn.Name()); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] WARNING: clear hook contract lock for %s: %v\n", conn.Name(), err)
				failedTeardown = append(failedTeardown, conn.Name())
			}
		}
		if len(failedTeardown) == 0 {
			connector.ClearActiveConnector(s.currentConfig().DataDir)
		} else if err := connector.SaveActiveConnectors(s.currentConfig().DataDir, failedTeardown); err != nil {
			persistErr := fmt.Errorf(
				"save connectors awaiting teardown retry (%s): %w",
				strings.Join(failedTeardown, ", "),
				err,
			)
			s.health.SetGuardrail(StateError, persistErr.Error(), nil)
			return persistErr
		}
		if len(failedTeardown) > 0 {
			teardownErr := fmt.Errorf("connector teardown incomplete for: %s", strings.Join(failedTeardown, ", "))
			s.health.SetGuardrail(StateError, teardownErr.Error(), nil)
			return teardownErr
		}
		s.health.SetGuardrail(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[guardrail] guardrail disabled — tore down %d configured connector(s)\n", len(conns))
		<-ctx.Done()
		return nil
	}

	// All-disabled guard: the global guardrail is still enabled, but every
	// configured connector was individually disabled
	// (`guardrail disable --connector X` for each). The set-difference
	// teardown above already removed their hooks; persist the now-empty
	// active set so the next boot starts clean, report the state honestly,
	// and idle. Without this we would fall through to the "all connectors
	// failed setup" error below, which would misreport a deliberate
	// per-connector disable as a boot failure.
	if len(conns) == 0 {
		if err := connector.SaveActiveConnectors(s.currentConfig().DataDir, failedRemoved); err != nil {
			persistErr := fmt.Errorf(
				"save connectors awaiting teardown retry (%s): %w",
				strings.Join(failedRemoved, ", "),
				err,
			)
			s.health.SetGuardrail(StateError, persistErr.Error(), nil)
			return persistErr
		}
		if len(failedRemoved) > 0 {
			teardownErr := fmt.Errorf("connector teardown incomplete for: %s", strings.Join(failedRemoved, ", "))
			s.health.SetGuardrail(StateError, teardownErr.Error(), nil)
			return teardownErr
		}
		s.health.SetGuardrail(StateDisabled, "all configured connectors are individually disabled", nil)
		fmt.Fprintf(os.Stderr, "[guardrail] all %d configured connector(s) disabled per-connector — none active; idle until shutdown\n", len(configured))
		<-ctx.Done()
		return nil
	}

	// Per-connector setup with failure isolation (DN1). Each connector's
	// rule pack is loaded/validated through the shared cache so connectors
	// sharing a profile read disk once.
	cache := guardrail.NewRulePackCache()
	succeeded, setupErr := s.setupConnectorsIsolated(ctx, conns, apiToken, proxyAddr, apiAddr, masterKey, cache)
	if setupErr != nil {
		s.health.SetGuardrail(StateError, setupErr.Error(), nil)
		return setupErr
	}

	// Persist the set that actually came up so the next boot's
	// set-difference teardown is accurate.
	persisted := append(append([]string(nil), succeeded...), failedRemoved...)
	if err := connector.SaveActiveConnectors(s.currentConfig().DataDir, persisted); err != nil {
		persistErr := fmt.Errorf("save active connector set: %w", err)
		if len(failedRemoved) > 0 {
			persistErr = fmt.Errorf(
				"save active connector set with teardown retry state (%s): %w",
				strings.Join(failedRemoved, ", "),
				err,
			)
		}
		s.health.SetGuardrail(StateError, persistErr.Error(), nil)
		return persistErr
	}

	// Every connector failing is a real boot failure — surface it loudly
	// rather than idling on a gateway that protects nothing.
	if len(succeeded) == 0 {
		err := fmt.Errorf("multi-connector boot: all %d configured connectors failed setup", len(conns))
		s.health.SetGuardrail(StateError, err.Error(), nil)
		<-ctx.Done()
		return err
	}

	hookGuards, err := s.startMultiHookConfigGuards(ctx, registry, succeeded, apiToken, proxyAddr, apiAddr)
	if err != nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
		return err
	}
	defer stopHookConfigGuards(hookGuards)

	// Health: register every connector that came up so each appears in the
	// roster with its own live counters, then mark the first (sorted) as the
	// primary surfaced in the back-compat singular Connector field.
	for _, name := range succeeded {
		if c, ok := registry.Get(name); ok {
			s.health.RegisterConnector(c.Name(), c.ToolInspectionMode(), c.SubprocessPolicy())
		}
	}
	if primary, ok := registry.Get(succeeded[0]); ok {
		s.health.SetConnector(primary.Name(), primary.ToolInspectionMode(), primary.SubprocessPolicy())
	}
	connectorModes := make(map[string]string, len(succeeded))
	anyEnforcement := false
	for _, name := range succeeded {
		mode := strings.ToLower(strings.TrimSpace(s.currentConfig().EffectiveGuardrailModeForConnector(name)))
		if mode != "action" {
			mode = "observe"
		}
		connectorModes[name] = mode
		anyEnforcement = anyEnforcement || mode == "action"
	}
	s.health.SetGuardrail(StateRunning, "", map[string]interface{}{
		"summary":             fmt.Sprintf("multi-connector direct-upstream mode (%d active)", len(succeeded)),
		"connectors":          succeeded,
		"connector_modes":     connectorModes,
		"enforcement_enabled": anyEnforcement,
		"proxy_port":          "closed",
		"hint":                "hook/policy connectors enforce through agent-native lifecycle surfaces; the local guardrail proxy is not in the LLM data path",
	})
	fmt.Fprintf(os.Stderr, "[guardrail] multi-connector direct-upstream mode: %d active connector(s): %s; enforcement=%t — proxy port intentionally not bound\n", len(succeeded), strings.Join(succeeded, ", "), anyEnforcement)

	<-ctx.Done()
	return nil
}

func (s *Sidecar) runManagedEnterpriseMultiHookGuardrail(ctx context.Context, registry *connector.Registry, conns []connector.Connector, apiToken, proxyAddr, apiAddr, masterKey string) error {
	if !s.currentConfig().Guardrail.Enabled {
		connector.ClearActiveConnector(s.currentConfig().DataDir)
		s.health.SetGuardrail(StateDisabled, "guardrail disabled; enterprise hook guardian owns hook removal", map[string]interface{}{
			"connectors":        connectorNames(conns),
			"lifecycle_manager": "enterprise_hook_guardian",
		})
		fmt.Fprintf(os.Stderr, "[guardrail] managed_enterprise: guardrail disabled; enterprise hook guardian owns hook removal for %d connector(s)\n", len(conns))
		<-ctx.Done()
		return nil
	}
	if len(conns) == 0 {
		if err := connector.SaveActiveConnectors(s.currentConfig().DataDir, nil); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] save active connector set: %v\n", err)
		}
		s.health.SetGuardrail(StateDisabled, "all configured connectors are individually disabled", map[string]interface{}{
			"lifecycle_manager": "enterprise_hook_guardian",
		})
		fmt.Fprintln(os.Stderr, "[guardrail] managed_enterprise: all configured connector(s) disabled; enterprise hook guardian owns hook removal")
		<-ctx.Done()
		return nil
	}

	type managedConnectorRegistration struct {
		conn connector.Connector
		opts connector.SetupOpts
	}
	registrations := make([]managedConnectorRegistration, 0, len(conns))
	for _, conn := range conns {
		opts, setupErr := s.connectorSetupOptsChecked(conn, apiToken, proxyAddr, apiAddr)
		if setupErr != nil {
			err := fmt.Errorf("connector %s scoped hook token: %w", conn.Name(), setupErr)
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return err
		}
		registrations = append(registrations, managedConnectorRegistration{conn: conn, opts: opts})
	}

	cache := guardrail.NewRulePackCache()
	succeeded := make([]string, 0, len(registrations))
	for _, registration := range registrations {
		registration.conn.SetCredentials(registration.opts.APIToken, masterKey)
		rp := cache.Load(s.currentConfig().EffectiveRulePackDirForConnector(registration.conn.Name()))
		if rp != nil {
			rp.Validate()
		}
		ApplyConnectorRulePackOverrides(registration.conn.Name(), rp)
		succeeded = append(succeeded, registration.conn.Name())
		fmt.Fprintf(os.Stderr, "[guardrail] managed_enterprise: registered %s for hook evaluation; lifecycle is owned by enterprise hook guardian\n", registration.conn.Name())
	}

	for _, name := range succeeded {
		if c, ok := registry.Get(name); ok {
			s.health.RegisterConnector(c.Name(), c.ToolInspectionMode(), c.SubprocessPolicy())
		}
	}
	if primary, ok := registry.Get(succeeded[0]); ok {
		s.health.SetConnector(primary.Name(), primary.ToolInspectionMode(), primary.SubprocessPolicy())
	}
	hookEnforcement := false
	for _, name := range succeeded {
		if strings.EqualFold(s.currentConfig().EffectiveGuardrailModeForConnector(name), "action") {
			hookEnforcement = true
			break
		}
	}
	summary := fmt.Sprintf("managed enterprise hook telemetry (%d guardian-managed)", len(succeeded))
	if hookEnforcement {
		summary = fmt.Sprintf("managed enterprise hook enforcement (%d guardian-managed)", len(succeeded))
	}
	publishHealth := func() {
		covered, status := managedGuardianCoversConnectors(s.currentConfig().DataDir, succeeded)
		state := StateStarting
		enforcementEnabled := false
		hint := "awaiting a trusted enterprise hook guardian authorization record"
		if covered {
			state = StateRunning
			enforcementEnabled = hookEnforcement
			hint = "hook-only connectors talk directly to their native upstreams; enterprise hook guardian owns installation and repair"
		}
		s.health.SetGuardrail(state, status, map[string]interface{}{
			"summary":             summary,
			"connectors":          succeeded,
			"enforcement_enabled": enforcementEnabled,
			"proxy_port":          "closed",
			"hint":                hint,
			"lifecycle_manager":   "enterprise_hook_guardian",
			"guardian_verified":   covered,
		})
	}
	publishHealth()
	fmt.Fprintf(os.Stderr, "[guardrail] managed_enterprise multi-connector hook mode: %d connector(s): %s — proxy port closed; enterprise hook guardian owns hook files\n", len(succeeded), strings.Join(succeeded, ", "))

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			publishHealth()
		}
	}
}

type managedGuardianAuthorization struct {
	ProtectedTargets []struct {
		Connector string `json:"connector"`
		OK        bool   `json:"ok"`
	} `json:"protected_targets"`
}

func managedGuardianCoversConnectors(dataDir string, connectorNames []string) (bool, string) {
	path := managed.HookGuardianAuthorizationPath(dataDir)
	if err := validateManagedGuardianAuthorization(path, "hook guardian authorization"); err != nil {
		return false, err.Error()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Sprintf("read hook guardian authorization: %v", err)
	}
	var authorization managedGuardianAuthorization
	if err := json.Unmarshal(data, &authorization); err != nil {
		return false, fmt.Sprintf("parse hook guardian authorization: %v", err)
	}
	covered := make(map[string]struct{}, len(authorization.ProtectedTargets))
	for _, target := range authorization.ProtectedTargets {
		if target.OK {
			covered[strings.ToLower(strings.TrimSpace(target.Connector))] = struct{}{}
		}
	}
	for _, name := range connectorNames {
		if _, ok := covered[strings.ToLower(strings.TrimSpace(name))]; !ok {
			return false, fmt.Sprintf("hook guardian has not authorized connector %s", name)
		}
	}
	return true, ""
}

func connectorNames(conns []connector.Connector) []string {
	names := make([]string, 0, len(conns))
	for _, conn := range conns {
		if conn != nil {
			names = append(names, conn.Name())
		}
	}
	return names
}

var newSidecarHookConfigGuard = func(sidecar *Sidecar, debounce time.Duration) *HookConfigGuard {
	metricRuntime, _ := sidecar.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	return NewHookConfigGuard(sidecar.logger, metricRuntime, debounce)
}

// startMultiHookConfigGuards starts one hook self-heal guard per connector
// that successfully came up in multi-connector mode. The single-connector path
// owns its guard through GuardrailProxy; multi-connector mode has no proxy, so
// the sidecar owns these guards directly.
func (s *Sidecar) startMultiHookConfigGuards(ctx context.Context, registry *connector.Registry, connectorNames []string, apiToken, proxyAddr, apiAddr string) ([]*HookConfigGuard, error) {
	if s == nil || s.currentConfig() == nil || registry == nil || !s.currentConfig().Guardrail.Enabled || !s.currentConfig().Guardrail.HookSelfHeal {
		return nil, nil
	}
	debounce := time.Duration(s.currentConfig().Guardrail.HookSelfHealDebounceMs) * time.Millisecond
	guards := make([]*HookConfigGuard, 0, len(connectorNames))
	for _, name := range connectorNames {
		conn, ok := registry.Get(name)
		if !ok {
			fmt.Fprintf(os.Stderr, "[guardrail] hook self-heal: connector %s not found in registry, skipping guard\n", name)
			continue
		}
		opts, err := s.connectorSetupOptsChecked(conn, apiToken, proxyAddr, apiAddr)
		if err != nil {
			stopHookConfigGuards(guards)
			return nil, fmt.Errorf("hook self-heal connector %s scoped hook token: %w", conn.Name(), err)
		}
		guard := newSidecarHookConfigGuard(s, debounce)
		guard.SetHealNotifier(s.notifyHookHealed)
		if !guard.Start(ctx, conn, opts) {
			fmt.Fprintf(os.Stderr, "[guardrail] hook registration guard for %s did not start; continuing with verified setup registration\n", conn.Name())
			continue
		}
		s.registerHookConfigGuard(guard)
		guards = append(guards, guard)
	}
	return guards, nil
}

func stopHookConfigGuards(guards []*HookConfigGuard) {
	for _, guard := range guards {
		guard.Stop()
	}
}

// notifyHookHealed fans a successful multi-connector hook re-install out to
// webhooks. The durable audit row and OTel metric are emitted by the guard.
func (s *Sidecar) notifyHookHealed(connectorName string, paths []string) {
	webhooks := s.webhooksSnapshot()
	if webhooks == nil {
		return
	}
	webhooks.Dispatch(audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    string(audit.ActionConnectorHookRepaired),
		Target:    connectorName,
		// Connector is the first-class attribution field every sink and
		// webhook payload carries; without it the heal notification's
		// connector dimension is empty and SIEM consumers must scrape
		// Target. Mirrors the audit-row fix in hook_config_guard.heal.
		Connector: connectorName,
		Actor:     "defenseclaw-hook-guard",
		Details:   fmt.Sprintf("re-installed connector hook config after manual removal: %s", strings.Join(paths, ", ")),
		Severity:  "HIGH",
	})
}

// setupConnectorsIsolated runs setupOneConnector for each connector in turn
// and returns the names that came up cleanly. It is the heart of the DN1
// failure-isolation guarantee: scoped tokens are preflighted for every
// connector before setup mutates state; after that, a connector whose setup
// fails is logged and skipped while remaining connectors continue. The order
// of the returned slice matches the input order (sorted by the caller).
func (s *Sidecar) setupConnectorsIsolated(ctx context.Context, conns []connector.Connector, apiToken, proxyAddr, apiAddr, masterKey string, cache *guardrail.RulePackCache) ([]string, error) {
	type connectorRegistration struct {
		conn connector.Connector
		opts connector.SetupOpts
	}
	registrations := make([]connectorRegistration, 0, len(conns))
	for _, conn := range conns {
		opts, err := s.connectorSetupOptsChecked(conn, apiToken, proxyAddr, apiAddr)
		if err != nil {
			return nil, fmt.Errorf("connector %s scoped hook token: %w", conn.Name(), err)
		}
		registrations = append(registrations, connectorRegistration{conn: conn, opts: opts})
	}

	succeeded := make([]string, 0, len(registrations))
	for _, registration := range registrations {
		if err := s.setupOneConnector(ctx, registration.conn, registration.opts, masterKey, cache); err != nil {
			// Isolate: roll back this connector's partial state, log, leave
			// the other connectors untouched, continue.
			recordAndRollbackFailedConnectorSetup(registration.conn, registration.opts, ctx)
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s setup failed, skipping (other connectors unaffected): %v\n", registration.conn.Name(), err)
			continue
		}
		succeeded = append(succeeded, registration.conn.Name())
		fmt.Fprintf(os.Stderr, "[guardrail] connector ready: %s (%s)\n", registration.conn.Name(), registration.conn.Description())
	}
	return succeeded, nil
}

func (s *Sidecar) connectorSetupOptsChecked(conn connector.Connector, apiToken, proxyAddr, apiAddr string) (connector.SetupOpts, error) {
	agentVersion := connector.LoadCachedAgentVersion(s.currentConfig().DataDir, conn.Name())
	agentExecutable := connector.LoadCachedAgentExecutable(s.currentConfig().DataDir, conn.Name())
	contractResolution := connector.ResolveHookContract(conn.Name(), agentVersion)
	setupTokens, err := connectorSetupTokensFor(s.currentConfig().DataDir, conn, apiToken, managed.IsManagedEnterprise(s.currentConfig().DeploymentMode))
	if err != nil {
		return connector.SetupOpts{}, err
	}
	return connector.SetupOpts{
		DataDir:            s.currentConfig().DataDir,
		ProxyAddr:          proxyAddr,
		APIAddr:            apiAddr,
		APIToken:           setupTokens.connectorToken,
		HookAPIToken:       setupTokens.hookToken,
		HookAPITokenScoped: setupTokens.hookTokenScoped,
		WorkspaceDir:       s.currentConfig().ConnectorWorkspaceDir(),
		HookFailMode:       s.currentConfig().EffectiveHookFailModeForConnector(conn.Name()),
		HILTEnabled:        s.currentConfig().EffectiveHILTForConnector(conn.Name()).Enabled,
		InstallCodeGuard:   false,
		AgentVersion:       agentVersion,
		AgentExecutable:    agentExecutable,
		HookContractID:     contractResolution.Contract.ContractID,
	}, nil
}

type connectorSetupTokens struct {
	connectorToken  string
	hookToken       string
	hookTokenScoped bool
}

func connectorSetupTokensFor(dataDir string, conn connector.Connector, gatewayToken string, managedMode bool) (connectorSetupTokens, error) {
	fallback := connectorSetupTokens{connectorToken: gatewayToken, hookToken: gatewayToken}
	if conn == nil {
		return fallback, nil
	}
	_, hasHookEndpoint := conn.(connector.HookEndpoint)
	needsHookToken := hasHookEndpoint || connector.IsProxyConnector(conn.Name()) || connector.OwnsManagedHookRuntime(conn)
	if !needsHookToken {
		return fallback, nil
	}
	scoped, err := connector.EnsureHookAPIToken(dataDir, conn.Name())
	if err != nil {
		if managedMode {
			return connectorSetupTokens{}, err
		}
		// Unmanaged installs historically allowed symlinked/group-writable data
		// directories. Preserve setup by falling back to the already-configured
		// master token and a legacy .token sidecar instead of aborting protection.
		return fallback, nil
	}
	out := connectorSetupTokens{connectorToken: scoped, hookToken: scoped, hookTokenScoped: true}
	if connector.IsProxyConnector(conn.Name()) {
		out.connectorToken = gatewayToken
	}
	return out, nil
}

// setupOneConnector performs the full setup-and-verify sequence for a single
// connector in the multi-connector boot loop. It returns an error (rather
// than aborting boot) so the caller can isolate the failure (DN1) and keep
// the other connectors running. On a post-Setup verification failure it rolls
// back just this connector's Setup before returning so a half-installed
// connector never lingers.
func (s *Sidecar) setupOneConnector(ctx context.Context, conn connector.Connector, opts connector.SetupOpts, masterKey string, cache *guardrail.RulePackCache) error {
	support := connector.ConnectorSupportOnHostOS(conn.Name())
	if support.Status == connector.PlatformUnsupported {
		return fmt.Errorf("connector %q is not supported on %s: %s", conn.Name(), runtime.GOOS, support.Reason)
	}
	if support.Status == connector.PlatformPreview {
		fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s is preview on %s: %s\n", conn.Name(), runtime.GOOS, support.Reason)
	}
	// Inject credentials before Setup so probes keyed off them succeed.
	conn.SetCredentials(opts.APIToken, masterKey)

	// Load + validate this connector's effective rule pack through the
	// shared cache. Connectors sharing a profile read disk once.
	rp := cache.Load(s.currentConfig().EffectiveRulePackDirForConnector(conn.Name()))
	if rp != nil {
		rp.Validate()
	}

	// Register this connector's rule set so its hook lane scans against its
	// own pack at runtime (per-connector parity with single-connector mode).
	// A nil pack still pins the connector to the compiled-in defaults rather
	// than inheriting whichever pack the primary installed into the global.
	ApplyConnectorRulePackOverrides(conn.Name(), rp)

	// Enforce the same hook-contract gate the single-connector path applies in
	// runGuardrail (see HookContractNeedsActionOverride call above). Without
	// this, a multi-connector boot in action mode would silently install
	// connectors whose installed agent version is unknown/unversioned or whose
	// pinned contract drifted — installing an enforcing hook against an
	// unverified surface that may mishandle verdicts. Returning an error here
	// makes the caller (setupConnectorsIsolated) skip just this connector and
	// surface a warning, keeping the other connectors running (DN1), instead of
	// shipping an unverified enforcing hook.
	contractResolution := connector.ResolveHookContract(conn.Name(), opts.AgentVersion)
	actionMode := strings.EqualFold(s.currentConfig().EffectiveGuardrailModeForConnector(conn.Name()), "action")
	if connector.HookContractNeedsActionOverride(contractResolution) &&
		actionMode &&
		os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
		return fmt.Errorf("connector %s agent version %q is not verified against a known hook contract: %s (set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing)", conn.Name(), opts.AgentVersion, contractResolution.Reason)
	}
	if previous := connector.LoadHookContractLockEntry(s.currentConfig().DataDir, conn.Name()); previous.Connector != "" {
		current := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
		// Setup refreshes generated hook artifacts for every configured
		// connector on boot. A stale generated digest is therefore a repair
		// trigger, not an upstream compatibility failure. Keep failing closed
		// only when the agent version or selected contract changed.
		if connector.HookContractCompatibilityDrifted(previous, current) &&
			actionMode &&
			os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
			return fmt.Errorf("connector %s hook contract drift detected: previous version=%q contract=%s current version=%q contract=%s (rerun discovery/setup to refresh the lock, or set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 for exploratory testing)", conn.Name(), previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID)
		}
	}

	if err := conn.Setup(ctx, opts); err != nil {
		return fmt.Errorf("connector %s setup failed: %w", conn.Name(), err)
	}
	if err := verifyHookScriptsOrRetry(ctx, opts, conn); err != nil {
		// Roll back just this connector so a half-installed connector
		// does not linger; failures during rollback are non-fatal.
		if tdErr := conn.Teardown(ctx, opts); tdErr != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] rollback teardown of %s after verification failure: %v\n", conn.Name(), tdErr)
		}
		return fmt.Errorf("connector %s hook verification failed: %w", conn.Name(), err)
	}
	if err := verifyEffectiveHookRegistration(opts, conn); err != nil {
		// Keep the same per-connector rollback contract as missing scripts: a
		// connector is not ready until its agent-visible registration is
		// effective, even when Setup itself returned nil.
		if tdErr := conn.Teardown(ctx, opts); tdErr != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] rollback teardown of %s after registration verification failure: %v\n", conn.Name(), tdErr)
		}
		return fmt.Errorf("connector %s registration verification failed: %w", conn.Name(), err)
	}
	if err := publishFreshHookRegistrationEvidence(opts, conn); err != nil {
		return fmt.Errorf("connector %s hook contract lock save failed: %w", conn.Name(), err)
	}
	return nil
}

// proxyShouldBindForConnector returns true when the active connector
// requires the proxy listener to be bound — i.e. the agent's data
// path goes through DefenseClaw. Codex, Claude Code, and other
// hook-native connectors return false: their LLM traffic stays
// direct-to-vendor while telemetry uses hooks/OTel.
// OpenClaw and ZeptoClaw always return true.
//
// Adding a new connector? Default-on (return true) is the
// conservative choice for guardrail-style adapters; only return
// false when the connector ships local hook/native telemetry that keeps
// DefenseClaw visible without a proxy listener.
func proxyShouldBindForConnector(conn connector.Connector, gc *config.GuardrailConfig) bool {
	if conn == nil {
		return true
	}
	if provider, ok := conn.(connector.ConnectorCapabilityProvider); ok {
		switch provider.Capabilities(connector.SetupOpts{}).LLMTrafficMode {
		case connector.LLMTrafficModeProxy:
			return true
		case connector.LLMTrafficModeHooksOnly:
			return false
		}
	}
	// Built-ins that predate ConnectorCapabilityProvider still use the shared
	// proxy classification. Unknown/plugin connectors retain the conservative
	// historical default unless they explicitly advertise a traffic mode.
	if connector.IsProxyConnector(conn.Name()) {
		return true
	}
	return !connector.IsKnownBuiltinConnector(conn.Name())
}

func managedEnterpriseGuardianOwnsConnectorLifecycle(cfg *config.Config, conn connector.Connector) bool {
	if cfg == nil || conn == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return false
	}
	return !proxyShouldBindForConnector(conn, &cfg.Guardrail)
}

func lifecycleManagerForConnector(cfg *config.Config, conn connector.Connector) string {
	if managedEnterpriseGuardianOwnsConnectorLifecycle(cfg, conn) {
		return "enterprise_hook_guardian"
	}
	return "gateway"
}

func shouldRunProviderProbeForConnector(conn connector.Connector, gc *config.GuardrailConfig) bool {
	if gc == nil {
		return true
	}
	if gc.AllowEmptyProviders {
		return false
	}
	return proxyShouldBindForConnector(conn, gc)
}

func configuredConnectorName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if name := strings.TrimSpace(cfg.Guardrail.Connector); name != "" {
		return strings.ToLower(name)
	}
	return strings.ToLower(strings.TrimSpace(string(cfg.Claw.Mode)))
}

func proxyShouldBindForConfiguredConnector(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	name := configuredConnectorName(cfg)
	if connector.IsProxyConnector(name) {
		return true
	}
	return !connector.IsKnownBuiltinConnector(name)
}

// gatewayShouldConnectForConfiguredConnector decides whether the sidecar
// should run its WebSocket gateway dial loop against gateway.host:port.
// This is the OpenClaw fleet client (skill admission / exec approval /
// fleet event forwarding) — NOT the local guardrail proxy listener,
// which proxyShouldBindForConfiguredConnector gates separately.
//
// Heuristic (intentionally connector- + host-derived, no new config
// field):
//
//	openclaw / zeptoclaw       → always dial. The WS upstream is the
//	                             whole point of these connectors;
//	                             skipping it would break every
//	                             existing OpenClaw install.
//	codex / claudecode + loopback host
//	                           → SKIP. These connectors emit telemetry
//	                             through hooks/native telemetry +
//	                             local API/audit only. The loopback
//	                             default (127.0.0.1:18789) means the
//	                             operator never wired in an OpenClaw
//	                             daemon — nothing is listening there
//	                             and ConnectWithRetry would spin
//	                             forever, pinning health on
//	                             RECONNECTING and spamming gateway.log.
//	codex / claudecode + non-loopback host
//	                           → dial. The operator pointed
//	                             gateway.host at a real upstream
//	                             (LAN IP, FQDN, etc.); they want
//	                             fleet integration alongside hooks.
//	hermes / cursor / windsurf / geminicli / copilot / openhands
//	                           → SKIP. These connectors are local
//	                             hook/native-telemetry surfaces in
//	                             this PR and do not use the OpenClaw
//	                             fleet WebSocket unless the operator
//	                             explicitly sets fleet_mode=enabled.
//	empty / unknown            → SKIP. Surfacing DISABLED is safer
//	                             than reconnect-loop noise against
//	                             an unconfigured upstream.
//
// Closes the "Gateway: RECONNECTING forever on a codex-only dev box"
// issue without breaking codex+OpenClaw operators who explicitly
// pointed gateway.host at their fleet. The codex+local-OpenClaw
// edge case (rare: OpenClaw daemon on 127.0.0.1 alongside codex)
// has an explicit `gateway.fleet_mode: enabled` override below.
func gatewayShouldConnectForConfiguredConnector(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	// Explicit operator override wins over the heuristic. We
	// intentionally fall THROUGH for any unrecognized value (incl.
	// typos) instead of returning a default, so a config typo can't
	// silently flip fleet integration on or off in production.
	switch strings.ToLower(strings.TrimSpace(cfg.Gateway.FleetMode)) {
	case "enabled", "on", "true":
		return true
	case "disabled", "off", "false":
		return false
	}
	switch configuredConnectorName(cfg) {
	case "openclaw", "zeptoclaw":
		return true
	case "codex", "claudecode":
		return !isLoopbackGatewayHost(cfg.Gateway.Host)
	default:
		// Empty / unknown connector: prefer DISABLED over reconnect
		// spam. An operator who genuinely wants fleet dial will set
		// connector=openclaw or wire a non-loopback host.
		return false
	}
}

// RequiresFleetGateway reports whether the configured topology depends on the
// OpenClaw fleet WebSocket subsystem. External readiness consumers use the
// same predicate as the sidecar, including the explicit fleet-mode override.
func RequiresFleetGateway(cfg *config.Config) bool {
	return gatewayShouldConnectForConfiguredConnector(cfg)
}

// isLoopbackGatewayHost reports whether host points at the local
// machine. Treats empty / "localhost" / any 127.0.0.0/8 IPv4 / ::1
// IPv6 as loopback. 0.0.0.0 (bind-all) is intentionally NOT loopback
// — operators using it usually mean "any iface", which implies a
// real listener somewhere.
//
// We do NOT do DNS resolution: the heuristic only reads what's in
// the config string. Resolving would slow down sidecar startup,
// add a network failure mode to a pure decision function, and
// could be racy if /etc/hosts changes between Run() and the dial.
// FQDNs are therefore treated as non-loopback — the right answer
// for the only case where they matter (operator pointing at a
// real fleet hostname).
func isLoopbackGatewayHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		// Empty falls back to viper default 127.0.0.1.
		return true
	}
	if h == "localhost" {
		return true
	}
	// Strip surrounding brackets from IPv6 literals (e.g. "[::1]").
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// verifyHookScriptsOnDisk checks that every hook script the connector
// claims to own (HookScriptOwner.HookScriptNames) is present in
// <dataDir>/hooks. Returns the list of missing basenames so callers
// can decide whether to retry Setup, fall back, or fail loud. Connectors
// that do not implement HookScriptOwner contribute no entries — there
// is nothing connector-specific to verify and the generic inspect-*.sh
// scripts are checked separately by the connector's own Setup path.
func verifyHookScriptsOnDisk(opts connector.SetupOpts, conn connector.Connector) []string {
	if conn == nil {
		return nil
	}
	if runtimeProvider, ok := conn.(connector.HookRuntimeArtifactProvider); ok {
		var missing []string
		for _, path := range runtimeProvider.HookRuntimeArtifacts(opts) {
			if strings.TrimSpace(path) == "" {
				missing = append(missing, "<unresolved runtime artifact>")
				continue
			}
			if _, err := os.Stat(path); err != nil {
				missing = append(missing, path)
			}
		}
		return missing
	}
	owner, ok := conn.(connector.HookScriptOwner)
	if !ok {
		return nil
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	var missing []string
	for _, name := range owner.HookScriptNames(opts) {
		if _, err := os.Stat(filepath.Join(hookDir, name)); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

// verifyHookScriptsOrRetry checks that every connector-owned hook
// script is on disk and, if any are missing, runs a targeted retry of
// JUST the hook writer (not the full Setup). The documented failure
// mode is "hook writer raced / silently missed a write"; re-running
// Setup in full would needlessly re-patch the agent config, re-capture
// managed backups, re-install subprocess enforcement, etc. The narrow
// retry is also safe to invoke unconditionally on a freshly-completed
// install because writeHookScriptsCommonWithFailMode is idempotent
// (MkdirAll + WriteFile, no destructive side-effects).
//
// The ctx argument is reserved for connectors whose hook writer ever
// gains a cancellable code path; the current implementation does not
// require it.
func verifyHookScriptsOrRetry(ctx context.Context, opts connector.SetupOpts, conn connector.Connector) error {
	_ = ctx
	missing := verifyHookScriptsOnDisk(opts, conn)
	if len(missing) == 0 {
		return nil
	}
	if _, ok := conn.(connector.HookRuntimeArtifactProvider); ok {
		return fmt.Errorf("connector %s setup completed but runtime artifacts are missing: %v", conn.Name(), missing)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s setup completed but hook scripts missing on disk: %v — retrying hook writer\n", conn.Name(), missing)
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		return fmt.Errorf("connector %s hook-writer retry after missing-hook detection failed: %w", conn.Name(), err)
	}
	if missing = verifyHookScriptsOnDisk(opts, conn); len(missing) > 0 {
		return fmt.Errorf("connector %s still missing hook scripts after hook-writer retry: %v", conn.Name(), missing)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] connector %s hook-writer retry restored missing hook scripts\n", conn.Name())
	return nil
}

// verifyEffectiveHookRegistration closes the gap between generated artifacts
// and the agent-visible registration. Connector Setup is responsible for
// atomic publication; this final authoritative read prevents ready/active
// state from being published if a concurrent teardown or replacement wins
// after Setup's internal write verification.
func verifyEffectiveHookRegistration(opts connector.SetupOpts, conn connector.Connector) error {
	if conn == nil {
		return errors.New("connector is nil")
	}
	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		return fmt.Errorf("connector %s effective hook registration check: %w", conn.Name(), err)
	}
	if !present {
		return fmt.Errorf("connector %s setup completed without an effective hook registration", conn.Name())
	}
	return nil
}

// teardownPreviousConnector checks if a different connector was previously
// active (persisted in active_connector.json) and runs its Teardown so
// hooks, env overrides, and config patches from the old connector are
// cleaned up before the new one is set up. After teardown, VerifyClean
// confirms no stale artifacts remain. Returns an error if verification
// fails — the caller can decide whether to proceed with the new setup.
func teardownPreviousConnector(registry *connector.Registry, newName string, opts connector.SetupOpts, ctx context.Context) error {
	prev := connector.LoadActiveConnector(opts.DataDir)
	if prev == "" || prev == newName {
		return nil
	}
	old, ok := registry.Get(prev)
	if !ok {
		fmt.Fprintf(os.Stderr, "[guardrail] previous connector %q not in registry — skipping teardown\n", prev)
		return nil
	}
	fmt.Fprintf(os.Stderr, "[guardrail] connector changed %s → %s — tearing down %s\n", prev, newName, prev)
	if err := old.Teardown(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] teardown of previous connector %s: %v\n", prev, err)
	}

	if err := old.VerifyClean(opts); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] WARNING: previous connector %s left stale state: %v\n", prev, err)
		return err
	}
	if err := connector.ClearHookContractLockEntry(opts.DataDir, prev); err != nil {
		return fmt.Errorf("clear hook contract lock for previous connector %s: %w", prev, err)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] previous connector %s teardown verified clean\n", prev)
	return nil
}

// teardownRemovedConnectors tears down connectors that were active on a
// previous boot but are absent from the current active set — the
// set-difference generalization of teardownPreviousConnector for the
// multi-connector boot path (removed = previous − current). It is intended to
// run once, before the per-connector setup loop.
//
// Failures are logged and collected (continue-on-error): stale state left by a
// connector being REMOVED must never block bringing up the connectors that
// are still active (DN1), while the returned names remain persisted for a
// later cleanup retry. Membership is compared case-insensitively so a case
// mismatch can never tear down a connector that is in fact still active.
func teardownRemovedConnectors(registry *connector.Registry, previous, current []string, opts connector.SetupOpts, ctx context.Context) []string {
	if registry == nil || len(previous) == 0 {
		return nil
	}
	var failed []string
	keep := make(map[string]struct{}, len(current))
	for _, n := range current {
		if trimmed := strings.TrimSpace(n); trimmed != "" {
			keep[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	for _, prev := range previous {
		prevName := strings.TrimSpace(prev)
		if prevName == "" {
			continue
		}
		if _, still := keep[strings.ToLower(prevName)]; still {
			continue
		}
		old, ok := registry.Get(prevName)
		if !ok {
			fmt.Fprintf(os.Stderr, "[guardrail] removed connector %q not in registry — skipping teardown\n", prevName)
			failed = append(failed, prevName)
			continue
		}
		fmt.Fprintf(os.Stderr, "[guardrail] connector %s no longer active — tearing down\n", prevName)
		if err := old.Teardown(ctx, opts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] teardown of removed connector %s: %v\n", prevName, err)
		}
		if err := old.VerifyClean(opts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: removed connector %s left stale state: %v\n", prevName, err)
			failed = append(failed, prevName)
			continue
		}
		if err := connector.ClearHookContractLockEntry(opts.DataDir, prevName); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: clear hook contract lock for removed connector %s: %v\n", prevName, err)
			failed = append(failed, prevName)
			continue
		}
		fmt.Fprintf(os.Stderr, "[guardrail] removed connector %s teardown verified clean\n", prevName)
	}
	return failed
}

// failGuardrailWithRollback is the shared fail-loud path for connector
// boot errors. It logs the failure with a stable surface label so
// operators can grep for the originating phase, rolls the partial
// setup back via recordAndRollbackFailedConnectorSetup, surfaces
// Guardrail=Error in the health snapshot, and returns the wrapped
// error so the caller can propagate it to the sidecar errCh.
//
// Centralising the sequence here keeps the two failure paths in
// runGuardrail (Setup error / hook verification error) in lockstep —
// any change to logging, rollback ordering, or health-state shape
// happens once and is covered by a single integration test.
func (s *Sidecar) failGuardrailWithRollback(ctx context.Context, opts connector.SetupOpts, conn connector.Connector, surface string, err error) error {
	if conn == nil || err == nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[guardrail] connector %s %s failed: %v\n", conn.Name(), surface, err)
	recordAndRollbackFailedConnectorSetup(conn, opts, ctx)
	if s != nil && s.health != nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
	}
	return err
}

func (s *Sidecar) saveSingleConnectorReadyState(ctx context.Context, opts connector.SetupOpts, conn connector.Connector) error {
	if err := connector.SaveActiveConnector(opts.DataDir, conn.Name()); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] save active connector state: %v\n", err)
	}
	if err := publishFreshHookRegistrationEvidence(opts, conn); err != nil {
		lockErr := fmt.Errorf("connector %s hook contract lock save failed: %w", conn.Name(), err)
		return s.failGuardrailWithRollback(ctx, opts, conn, "hook contract lock", lockErr)
	}
	return nil
}

func publishFreshHookRegistrationEvidence(opts connector.SetupOpts, conn connector.Connector) error {
	lockEntry := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
	if err := connector.SaveFreshHookContractLockEntry(opts.DataDir, lockEntry); err != nil {
		return err
	}
	current, err := connector.HookRuntimeRegistrationCurrent(
		opts,
		conn,
		version.Current().BinaryVersion,
	)
	if err != nil {
		return fmt.Errorf("verify fresh runtime registration evidence: %w", err)
	}
	if !current {
		return errors.New("fresh runtime registration evidence does not match the active connector contract")
	}
	return nil
}

func recordAndRollbackFailedConnectorSetup(conn connector.Connector, opts connector.SetupOpts, ctx context.Context) {
	if conn == nil {
		return
	}
	if err := connector.SaveActiveConnector(opts.DataDir, conn.Name()); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] save partial connector state for %s: %v\n", conn.Name(), err)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] rolling back partial %s setup\n", conn.Name())
	if err := conn.Teardown(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] rollback teardown of %s: %v\n", conn.Name(), err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] WARNING: partial %s setup left stale state and will be retried on next connector switch: %v\n", conn.Name(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "[guardrail] partial %s setup rolled back cleanly\n", conn.Name())
}

// runAIDiscovery starts continuous shadow-AI visibility when enabled.
func (s *Sidecar) runAIDiscovery(ctx context.Context) error {
	aiDiscovery, runDiscovery, claimed := s.claimAIDiscoveryRun()
	if aiDiscovery == nil {
		s.health.SetAIDiscovery(StateDisabled, "", nil)
		<-ctx.Done()
		return ctx.Err()
	}
	if !claimed || runDiscovery == nil {
		return fmt.Errorf("ai discovery service is already running or retired")
	}
	s.health.SetAIDiscovery(StateStarting, "", map[string]interface{}{
		"mode":                      s.currentConfig().AIDiscovery.Mode,
		"scan_interval_min":         s.currentConfig().AIDiscovery.ScanIntervalMin,
		"process_interval_s":        s.currentConfig().AIDiscovery.ProcessIntervalSec,
		"include_shell_history":     s.currentConfig().AIDiscovery.IncludeShellHistory,
		"include_package_manifests": s.currentConfig().AIDiscovery.IncludePackageManifests,
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- runDiscovery(ctx)
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-errCh:
			if ctx.Err() != nil {
				if err != nil && !isContextTermination(err) {
					s.health.SetAIDiscovery(StateError, err.Error(), nil)
					return err
				}
				s.health.SetAIDiscovery(StateStopped, "", nil)
				return ctx.Err()
			}
			if err != nil {
				s.health.SetAIDiscovery(StateError, err.Error(), nil)
				return err
			}
			s.health.SetAIDiscovery(StateStopped, "", nil)
			return nil
		case <-ticker.C:
			report := aiDiscovery.Snapshot()
			s.health.SetAIDiscovery(StateRunning, "", map[string]interface{}{
				"mode":            report.Summary.PrivacyMode,
				"last_scan":       report.Summary.ScannedAt.Format(time.RFC3339),
				"active_signals":  report.Summary.ActiveSignals,
				"new_signals":     report.Summary.NewSignals,
				"changed_signals": report.Summary.ChangedSignals,
				"gone_signals":    report.Summary.GoneSignals,
				"files_scanned":   report.Summary.FilesScanned,
				"result":          report.Summary.Result,
			})
		case <-ctx.Done():
			// Run owns the inventory database. Wait for its cancellation path to
			// finish the active scan and close the store before runRestartable can
			// start the replacement generation.
			err := <-errCh
			if err != nil && !isContextTermination(err) {
				s.health.SetAIDiscovery(StateError, err.Error(), nil)
				return err
			}
			s.health.SetAIDiscovery(StateStopped, "", nil)
			return ctx.Err()
		}
	}
}

// runAPI starts the REST API server.
func (s *Sidecar) runAPI(ctx context.Context) error {
	bind := "127.0.0.1"
	if s.currentConfig().Gateway.APIBind != "" {
		bind = s.currentConfig().Gateway.APIBind
	} else if s.currentConfig().OpenShell.IsStandalone() && s.currentConfig().Guardrail.Host != "" && s.currentConfig().Guardrail.Host != "localhost" {
		bind = s.currentConfig().Guardrail.Host
	}
	addr := fmt.Sprintf("%s:%d", bind, s.currentConfig().Gateway.APIPort)
	api := NewAPIServer(addr, s.health, s.client, s.store, s.logger, cloneConfig(s.currentConfig()))
	api.SetShutdownRequester(s.requestProcessShutdown)
	if s.configMgr != nil {
		api.SetConfigRuntime(s.configMgr.Reload, s.currentConfig)
	}
	s.setAPIServer(api)
	defer s.setAPIServer(nil)
	api.SetHILTApprovalManager(s.hilt)
	// Wire the Cisco AI Defense inspector onto the API server so the
	// hook lane (inspectToolPolicy / inspectMessageContent) can forward
	// tool calls + tool results to AID.
	//
	// Selection:
	//   - deployment_mode = managed_enterprise → construct the
	//     token-authenticated CiscoDefenseClawInspectClient. If the
	//     managed cloud auth provider can't initialize (unsupported
	//     OS, no provider registered, agent unavailable after the
	//     retry ladder), leave the inspector unset — remote inspection
	//     is disabled, with no silent fallback to API-key auth.
	//   - otherwise → the opensource NewCiscoInspectClient, unchanged.
	//     Returns nil when no key resolves; the hook lane silently
	//     skips AID and falls back to the regex + CodeGuard verdict.
	//
	// Callers must nil-check the concrete pointer BEFORE assigning to
	// Inspector (interface): a typed-nil wrapper is a non-nil
	// interface and defeats every downstream `!= nil` guard.
	if inspector := s.pickInspector(ctx); inspector != nil {
		api.SetCiscoInspector(inspector)
	}
	// Wire the LLM judge onto the API server so hook connectors listed
	// in guardrail.judge.hook_connectors get live-content adjudication
	// on the hook lane (inspectMessageContent). Same instance as the
	// proxy lane's router judge — one Bifrost client cache, one verdict
	// cache. nil when guardrail.judge.enabled is false; the hook lane
	// then skips the judge exactly as before.
	if judge := s.sharedJudge(); judge != nil {
		api.SetHookJudge(judge)
	}
	api.SetAIDiscoveryService(s.aiDiscoverySnapshot())
	api.SetNotifier(s.osNotifier)
	if s.opa != nil {
		api.SetPolicyReloader(s.opa.Reload)
	}
	reg := connector.NewDefaultRegistry()
	if s.currentConfig().PluginDir != "" {
		_ = reg.DiscoverPlugins(s.currentConfig().PluginDir)
	}
	api.SetConnectorRegistry(reg)
	// Load scoped tokens that connector setup or the enterprise hook guardian
	// previously minted. Failures are non-fatal: tokenAuth still accepts the
	// master gateway bearer for legacy/manual installs, while scoped-token
	// paths remain fail-closed until their token can be read.
	if scoped, err := connector.LoadAllOTLPPathTokens(s.currentConfig().DataDir); err == nil {
		api.SetOTLPPathTokens(scoped)
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] load OTLP path-tokens: %v\n", err)
	}
	if scoped, err := connector.LoadHookAPITokens(s.currentConfig().DataDir, reg.Names()); err == nil {
		api.SetHookAPITokens(scoped)
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] load hook API tokens: %v\n", err)
	}
	return api.Run(ctx)
}

// subscribeToSessions lists active sessions and subscribes to each one
// so we receive session.tool events for tool call/result tracing.
func (s *Sidecar) subscribeToSessions(ctx context.Context) {
	subCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	raw, err := s.client.SessionsList(subCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] sessions.list failed (will still receive agent events): %v\n", err)
		return
	}

	// The gateway returns sessions as either an array or an object keyed by
	// session ID. Try both formats.
	type sessionEntry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var sessions []sessionEntry

	if err := json.Unmarshal(raw, &sessions); err != nil {
		// Try object format: {"sessionId": {id, name, ...}, ...}
		var sessMap map[string]json.RawMessage
		if err2 := json.Unmarshal(raw, &sessMap); err2 != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] parse sessions list: %v\n", err)
			return
		}
		for k, v := range sessMap {
			var entry sessionEntry
			if json.Unmarshal(v, &entry) == nil {
				if entry.ID == "" {
					entry.ID = k
				}
				sessions = append(sessions, entry)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[sidecar] found %d active sessions, subscribing for tool events...\n", len(sessions))

	for _, sess := range sessions {
		subCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		if err := s.client.SessionsSubscribe(subCtx2, sess.ID); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] subscribe to session %s failed: %v\n", sess.ID, err)
		} else {
			fmt.Fprintf(os.Stderr, "[sidecar] subscribed to session %s (%s)\n", sess.ID, sess.Name)
		}
		cancel2()
	}
}

func (s *Sidecar) logHello(h *HelloOK) {
	fmt.Fprintf(os.Stderr, "[sidecar] connected to gateway (protocol v%d)\n", h.Protocol)
	if h.Features != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] methods: %s\n", strings.Join(h.Features.Methods, ", "))
		fmt.Fprintf(os.Stderr, "[sidecar] events:  %s\n", strings.Join(h.Features.Events, ", "))
	}
}

// reportSandboxHealth sets the sandbox subsystem health when standalone mode is active.
// It starts a background goroutine that probes the sandbox endpoint and
// transitions the state to running once reachable, or error on timeout.
func (s *Sidecar) reportSandboxHealth(ctx context.Context) {
	if !s.currentConfig().OpenShell.IsStandalone() {
		return
	}

	details := map[string]interface{}{
		"sandbox_ip":   s.currentConfig().Gateway.Host,
		"gateway_port": s.currentConfig().Gateway.Port,
	}
	s.health.SetSandbox(StateStarting, "", details)

	go s.probeSandbox(ctx, details)
}

// probeSandbox tries to TCP-dial the sandbox endpoint with back-off.
// On success it transitions sandbox health to running; on context
// cancellation or too many failures it transitions to error/stopped.
func (s *Sidecar) probeSandbox(ctx context.Context, details map[string]interface{}) {
	addr := net.JoinHostPort(s.currentConfig().Gateway.Host, fmt.Sprintf("%d", s.currentConfig().Gateway.Port))
	const maxAttempts = 20
	backoff := 500 * time.Millisecond

	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			s.health.SetSandbox(StateStopped, "context cancelled", details)
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			conn.Close()
			fmt.Fprintf(os.Stderr, "[sidecar] sandbox probe succeeded (%s reachable)\n", addr)
			s.health.SetSandbox(StateRunning, "", details)
			return
		}

		fmt.Fprintf(os.Stderr, "[sidecar] sandbox probe attempt %d/%d failed: %v\n", i+1, maxAttempts, err)

		select {
		case <-ctx.Done():
			s.health.SetSandbox(StateStopped, "context cancelled", details)
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff = backoff * 3 / 2
		}
	}

	s.health.SetSandbox(StateError, fmt.Sprintf("sandbox unreachable after %d probes (%s)", maxAttempts, addr), details)
}

// Client returns the underlying gateway client for direct RPC calls.
func (s *Sidecar) Client() *Client {
	return s.client
}

// Health returns the shared health tracker.
func (s *Sidecar) Health() *SidecarHealth {
	return s.health
}

// ensureGatewayTokenSynthesis resolves and (if absent) generates the
// gateway token used by the API server's tokenAuth middleware and by
// every hook script written into the workspace. It is idempotent:
//
//	first call:  reads ResolvedToken(); if empty calls EnsureGatewayToken
//	             which atomically writes DEFENSECLAW_GATEWAY_TOKEN into
//	             $DEFENSECLAW_HOME/.env at mode 0600, then mirrors into
//	             os.Setenv so subsequent ResolveAPIKey() calls see it.
//	later calls: ResolvedToken() now returns the synthesized value,
//	             so we short-circuit without touching .env or env vars.
//
// Sidecar.Run calls this BEFORE spawning any goroutine so the
// AI-discovery service can install its keyed path-hash digest from the
// very first scan (S2.MEDIUM). runGuardrail then calls it
// again on its own goroutine and gets the same already-resolved value
// — preserving the existing call sequence (Setup → API → guardrail
// proxy) without race or double-write.
//
// Returns an error only when EnsureGatewayToken itself fails (disk
// full, .env permissions wrong, etc); callers are expected to treat
// that as fatal because the API server cannot authenticate without a
// known token.
func (s *Sidecar) ensureGatewayTokenSynthesis() (string, error) {
	cfg := s.currentConfig()
	if tok := cfg.Gateway.ResolvedToken(); tok != "" {
		return tok, nil
	}
	dotenvPath := filepath.Join(cfg.DataDir, ".env")
	tok, err := EnsureGatewayToken(dotenvPath)
	if err != nil {
		return "", err
	}
	next := cloneConfig(cfg)
	next.Gateway.Token = tok
	s.publishConfig(next)
	// Mirror into the process env so sub-callers (judge LLM init,
	// hook generators, OTLP path-token loaders) all observe the
	// same value through their normal os.Getenv lookup path.
	_ = os.Setenv("DEFENSECLAW_GATEWAY_TOKEN", tok)
	return tok, nil
}

// deriveAIInventoryHashKey returns the per-installation HMAC key that
// inventory.SetPathHashKey uses to keyed-hash discovered paths in
// AI-discovery events. Derivation contract:
//
//	key = HMAC-SHA256(apiToken, "ai-discovery/path-hash/v1")
//
// Using the gateway token as the HMAC *secret* (rather than reusing it
// as the key directly) means a leak of the path-hash key alone does not
// disclose the gateway token. Namespacing with the version label means
// the derivation can be evolved (v2, v3, ...) without rotating the
// gateway token. Returning nil for an empty token keeps the legacy
// unsalted SHA-256 fallback in inventory.hashPath, which is what tests
// and detached scan utilities (no sidecar / no gateway token) expect.
func deriveAIInventoryHashKey(apiToken string) []byte {
	if apiToken == "" {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(apiToken))
	_, _ = mac.Write([]byte("ai-discovery/path-hash/v1"))
	return mac.Sum(nil)
}
