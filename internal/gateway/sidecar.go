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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
	"github.com/google/uuid"
)

// Sidecar is the long-running process that connects to the agent gateway,
// watches for skill installs, and exposes a local REST API.
type Sidecar struct {
	cfg         *config.Config
	client      *Client
	router      *EventRouter
	store       *audit.Store
	logger      *audit.Logger
	health      *SidecarHealth
	shell       *sandbox.OpenShell
	otel        *telemetry.Provider
	notify      *NotificationQueue
	opa         *policy.Engine
	hilt        *HILTApprovalManager
	webhooks    *WebhookDispatcher
	aiDiscovery *inventory.ContinuousDiscoveryService
	osNotifier  *notifier.Dispatcher

	alertCtx    context.Context
	alertCancel context.CancelFunc
	alertWg     sync.WaitGroup

	// events is the structured gatewaylog.Writer (gateway.jsonl +
	// stderr pretty-print). Installed during NewSidecar so every
	// verdict/judge/lifecycle emission lands here without plumbing
	// the writer through every call site.
	events *gatewaylog.Writer

	// judge is the LLM judge instance shared between the proxy lane
	// (EventRouter.SetJudge) and the hook lane (APIServer.SetHookJudge
	// in runAPI) so both lanes use one Bifrost client cache and one
	// verdict cache. nil when guardrail.judge.enabled is false.
	judge *LLMJudge

	// judgeStore is the async judge-body persistence queue.
	// Non-nil only when guardrail.retain_judge_bodies is on.
	// Sidecar.Run drains it on shutdown so queued bodies survive
	// SIGTERM.
	judgeStore *JudgeStore

	// judgeBodyStore is the Phase 4 split-out SQLite database
	// dedicated to judge_responses. Held here so Sidecar.Run can
	// close it after the queue drains; the audit.Store keeps
	// audit_events / activity_events on its own file.
	judgeBodyStore *audit.JudgeBodyStore
}

// NewSidecar creates a sidecar instance ready to connect.
func NewSidecar(cfg *config.Config, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, otel *telemetry.Provider) (*Sidecar, error) {
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
	// Mirror the same UUID to gatewaylog so the Writer choke point
	// can stamp sidecar_instance_id on events that were constructed
	// outside a request context (boot/shutdown/lifecycle). Kept in
	// lockstep with audit.SetProcessAgentInstanceID — the two setters
	// live in separate packages only to avoid an import cycle.
	gatewaylog.SetSidecarInstanceID(agentInstanceID)
	gatewaylog.SetAgentWatchContext(gatewaylog.AgentWatchContext{
		TenantID:        cfg.TenantID,
		WorkspaceID:     cfg.WorkspaceID,
		Environment:     cfg.Environment,
		DeploymentMode:  cfg.DeploymentMode,
		DiscoverySource: cfg.DiscoverySource,
	})

	// Seed run_id so every audit row / gateway.jsonl event / OTel
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
	if otel != nil {
		otel.SetAgentInstanceID(agentInstanceID)
	}

	// Persist the retention flag before any goroutines start so the
	// very first judge invocation sees the operator-configured value
	// (otherwise the default atomic would race with early traffic).
	//
	// Phase 3 flips the default to on. DEFENSECLAW_PERSIST_JUDGE is an
	// operator-facing kill-switch for environments with strict storage
	// or privacy constraints: setting it to 0/false/no forces retention
	// off regardless of config.yaml. Any other value (or leaving it
	// unset) respects the config/default.
	retainJudge := cfg.Guardrail.RetainJudgeBodies
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSECLAW_PERSIST_JUDGE"))) {
	case "0", "false", "no", "off":
		retainJudge = false
	}
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
	osNotifier := notifier.New(cfg.Notifications)

	router := NewEventRouter(client, store, logger, cfg.Gateway.AutoApprove, otel)
	router.notify = notify
	router.SetGuardrailConfig(&cfg.Guardrail)
	hilt := NewHILTApprovalManager(client, logger, otel)
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
	rp := guardrail.LoadRulePack(cfg.Guardrail.RulePackDir)
	rp.Validate()
	fmt.Fprintf(os.Stderr, "[sidecar] guardrail rule pack loaded: %s\n", rp)
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
	var hookJudge *LLMJudge
	if cfg.Guardrail.Judge.Enabled {
		dotenvPath := filepath.Join(cfg.DataDir, ".env")
		judgeLLM := cfg.ResolveLLM("guardrail.judge")
		providers, _, _ := providerRegistrySnapshot()
		judge := NewLLMJudge(&cfg.Guardrail.Judge, judgeLLM, dotenvPath, rp, providers)
		if judge != nil {
			router.SetJudge(judge)
			hookJudge = judge
			features := "tool-result-pii"
			if cfg.Guardrail.Judge.ToolInjection {
				features += ", tool-injection"
			}
			fmt.Fprintf(os.Stderr, "[sidecar] LLM judge enabled (%s) (model=%s)\n",
				features, judgeLLM.Model)
			if hooks := cfg.Guardrail.Judge.HookConnectors; len(hooks) > 0 {
				fmt.Fprintf(os.Stderr, "[sidecar] LLM judge hook lane enabled for: %s\n",
					strings.Join(hooks, ", "))
			}
		}
	}

	client.OnEvent = router.Route

	alertCtx, alertCancel := context.WithCancel(context.Background())

	// DEFENSECLAW_JSONL_DISABLE lets operators opt the structured
	// JSONL tier out at process start without editing config.yaml —
	// useful for noisy dev loops, ephemeral CI debug shells, and
	// privacy-sensitive environments where the pretty stderr stream
	// is enough. An empty JSONLPath disables the file tier cleanly;
	// pretty logging to stderr and OTel fan-out continue unchanged.
	// See docs/OBSERVABILITY.md#kill-switch for runbook guidance.
	jsonlPath := filepath.Join(cfg.DataDir, "gateway.jsonl")
	if jsonlKillSwitchEnabled(os.Getenv("DEFENSECLAW_JSONL_DISABLE")) {
		fmt.Fprintln(os.Stderr,
			"[sidecar] DEFENSECLAW_JSONL_DISABLE set — gateway.jsonl tier disabled (pretty + OTel still active)")
		jsonlPath = ""
	}
	// v7 strict schema validation: the validator runs inside
	// gatewaylog.Writer.Emit and drops any event that fails the
	// envelope schema, surfacing a single EventError per drop so
	// operators are never blind to contract regressions. Operators
	// can disable the gate with DEFENSECLAW_SCHEMA_VALIDATION=off
	// (breakglass for when a stale binary emits a new field the
	// shipped schema doesn't know about). A failure to load the
	// embedded schemas is *not* fatal: we fall back to a no-op
	// validator and log the error so the sidecar still serves
	// traffic — the Prometheus counter stays at zero, which is a
	// visible signal that validation is off.
	var schemaValidator *gatewaylog.Validator
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSECLAW_SCHEMA_VALIDATION"))) {
	case "off", "false", "0", "disabled":
		fmt.Fprintln(os.Stderr,
			"[sidecar] DEFENSECLAW_SCHEMA_VALIDATION=off — runtime schema gate disabled")
	default:
		sv, vErr := gatewaylog.NewDefaultValidator()
		if vErr != nil {
			fmt.Fprintf(os.Stderr,
				"[sidecar] schema validator init failed (%v) — runtime schema gate disabled\n", vErr)
		} else {
			schemaValidator = sv
		}
	}

	events, err := gatewaylog.New(gatewaylog.Config{
		JSONLPath: jsonlPath,
		Pretty:    os.Stderr,
		Compress:  true,
		Validator: schemaValidator,
	})
	if err != nil {
		// Release the alertCtx we just acquired so we don't leak a
		// goroutine-waiting context when boot fails before Run() picks
		// up alertCancel.
		alertCancel()
		return nil, fmt.Errorf("sidecar: init gateway event writer: %w", err)
	}
	// Mirror every structured event onto the OTel pipeline so
	// operators with an OTLP collector already deployed pick up
	// verdicts / judge latency / errors for free — no extra
	// config required when telemetry.enabled is true.
	if otel != nil && otel.Enabled() {
		events.WithFanoutContext(otel.EmitGatewayEventWithContext)
		// Route schema-violation drops into the Prometheus counter
		// so operators can alert on the metric directly without
		// scraping gateway.jsonl for EventError rows.
		events.OnSchemaViolation(func(et gatewaylog.EventType, code, _ string) {
			otel.RecordSchemaViolation(context.Background(), string(et), code)
		})
	}
	if logger != nil {
		events.WithFanoutContext(logger.ForwardGatewayEventToSinks)
	}
	SetEventWriter(events)
	// Layer 3 egress observability: wire the OTel provider so
	// RecordEgress fires alongside every EventEgress emission.
	// Resets to no-op on shutdown via the matching SetEventWriter(nil) path.
	SetEgressTelemetry(otel)

	var webhooks *WebhookDispatcher
	// Construct when there are global webhooks OR any per-connector
	// observability override (D5b); NewWebhookDispatcher returns nil when
	// neither yields an endpoint, and the nil-checks below tolerate that.
	if len(cfg.Webhooks) > 0 || len(cfg.Observability.Connectors) > 0 {
		webhooks = NewWebhookDispatcher(cfg.Webhooks, cfg.Observability)
		if webhooks != nil {
			webhooks.BindObservability(otel)
			fmt.Fprintf(os.Stderr, "[sidecar] webhook dispatcher initialized (%d global endpoints, %d per-connector overrides)\n",
				len(webhooks.endpoints), len(webhooks.connectorOverride))
		}
	}
	if shell != nil {
		shell.BindObservability(otel, events)
	}

	// Phase 1: bridge audit.Logger events into gateway.jsonl so every
	// scan result, watcher transition, and enforcement action lands
	// in the single structured stream the TUI/SIEM consume. We install
	// the bridge unconditionally — it is a cheap fanout and the
	// writer itself is the single choke point for JSONL retention.
	if logger != nil {
		logger.SetStructuredEmitter(newAuditBridge(events))
		logger.SetGatewayLogWriter(events)
	}

	// Phase 3: persist judge bodies to the local SQLite audit store
	// AND emit a structured audit event so every configured sink
	// (Splunk HEC, OTLP logs, webhook JSONL) sees a redacted summary.
	//
	// Retention defaults to on (see viper.SetDefault); operators who
	// opt out via config or DEFENSECLAW_PERSIST_JUDGE=0 get neither the
	// SQLite row nor the audit fan-out. The raw body is only touched
	// inside this process — emitJudge redacts RawResponse before it
	// flows into gateway.jsonl / sinks, and the InsertJudgeResponse
	// body stays on disk under the same ACLs as the rest of the data
	// directory.
	var (
		judgeStore     *JudgeStore
		judgeBodyStore *audit.JudgeBodyStore
	)
	if retainJudge && store != nil {
		// Resolve the queue depth. Precedence: env override > config
		// value > built-in default. The env override mirrors the
		// DEFENSECLAW_PERSIST_JUDGE pattern so operators have a
		// no-rebuild knob during incident response.
		queueDepth := cfg.Guardrail.JudgePersistQueueDepth
		if v := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_PERSIST_QUEUE_SIZE")); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				queueDepth = parsed
			}
		}
		// Phase 4 split: judge bodies live in a dedicated SQLite
		// file (~/.defenseclaw/judge_bodies.db by default). Falling
		// back to audit.db on open failure keeps the sidecar
		// running — better to share the write lock than to drop
		// judge rows entirely. The fallback is announced via the
		// structured audit logger (`gateway.judge_bodies.fallback`)
		// so operators see it in the same Splunk/OTLP stream that
		// surfaces the `defenseclaw.sqlite.busy_retries` regression
		// the fallback re-enables.
		bodyDBPath := strings.TrimSpace(cfg.JudgeBodiesDB)
		if bodyDBPath == "" {
			bodyDBPath = filepath.Join(cfg.DataDir, config.DefaultJudgeBodiesDBName)
		}
		var inserter JudgeBodyInserter
		if bs, openErr := audit.NewJudgeBodyStore(bodyDBPath); openErr == nil {
			judgeBodyStore = bs
			inserter = &judgeBodyStoreInserter{s: bs}
			if logger != nil {
				_ = logger.LogEvent(audit.Event{
					Action:   string(audit.ActionGatewayJudgeBodiesReady),
					Actor:    "defenseclaw-gateway",
					Severity: "INFO",
					Details:  "path=" + bodyDBPath,
				})
			}
		} else {
			if logger != nil {
				_ = logger.LogEvent(audit.Event{
					Action:   string(audit.ActionGatewayJudgeBodiesFallback),
					Actor:    "defenseclaw-gateway",
					Severity: "ERROR",
					Details: fmt.Sprintf(
						"path=%s error=%v fallback=audit.db",
						bodyDBPath, openErr,
					),
				})
			} else {
				// Boot-time fallback: logger isn't wired yet. Stderr
				// is the best we have until the sidecar is fully up.
				fmt.Fprintf(os.Stderr, "[sidecar] judge bodies db open failed, falling back to audit.db: %v\n", openErr)
			}
			inserter = &auditStoreInserter{s: store}
		}
		// Async judge persistence: rows queue on a buffered channel
		// and flush in batched transactions on a dedicated worker.
		// See internal/gateway/judge_store.go for the design notes;
		// the legacy SetJudgePersistor synchronous closure that
		// used to live here is gone — its dropped writes under
		// burst load were the motivating bug for this fix.
		judgeStore = NewJudgeStore(inserter, logger, queueDepth)
		SetJudgeResponseStore(judgeStore)
	}

	// Boot path — no request context exists yet. Writer.Emit stamps
	// sidecar_instance_id; run_id is inherited from the env var via
	// stampEventCorrelation.
	emitLifecycle(context.Background(), "gateway", "init", map[string]string{
		"host":         cfg.Gateway.Host,
		"api_port":     fmt.Sprintf("%d", cfg.Gateway.APIPort),
		"auto_approve": fmt.Sprintf("%v", cfg.Gateway.AutoApprove),
	})

	aiDiscovery, err := inventory.NewContinuousDiscoveryService(cfg, otel, events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] ai discovery init failed: %v\n", err)
		emitError(context.Background(), "ai_discovery", "init-failed", "continuous AI discovery disabled", err)
	}

	return &Sidecar{
		cfg:            cfg,
		client:         client,
		router:         router,
		store:          store,
		logger:         logger,
		health:         NewSidecarHealth(),
		shell:          shell,
		otel:           otel,
		notify:         notify,
		webhooks:       webhooks,
		hilt:           hilt,
		aiDiscovery:    aiDiscovery,
		osNotifier:     osNotifier,
		alertCtx:       alertCtx,
		alertCancel:    alertCancel,
		events:         events,
		judge:          hookJudge,
		judgeStore:     judgeStore,
		judgeBodyStore: judgeBodyStore,
	}, nil
}

// Run starts all subsystems as independent goroutines. Each subsystem runs
// in its own goroutine so that a gateway disconnect does not stop the watcher
// or API server. Run blocks until ctx is cancelled, then shuts everything down.
func (s *Sidecar) Run(ctx context.Context) error {
	runID := gatewaylog.ProcessRunID()
	fmt.Fprintf(os.Stderr, "[sidecar] starting subsystems (auto_approve=%v watcher=%v api_port=%d guardrail=%v run_id=%s)\n",
		s.cfg.Gateway.AutoApprove, s.cfg.Gateway.Watcher.Enabled, s.cfg.Gateway.APIPort, s.cfg.Guardrail.Enabled, runID)
	emitLifecycle(ctx, "sidecar", "start", map[string]string{
		"run_id":       runID,
		"auto_approve": fmt.Sprintf("%v", s.cfg.Gateway.AutoApprove),
		"watcher":      fmt.Sprintf("%v", s.cfg.Gateway.Watcher.Enabled),
		"api_port":     fmt.Sprintf("%d", s.cfg.Gateway.APIPort),
		"guardrail":    fmt.Sprintf("%v", s.cfg.Guardrail.Enabled),
	})
	_ = s.logger.LogAction(string(audit.ActionSidecarStart), "", "starting all subsystems")

	if s.cfg.Guardrail.Enabled && s.cfg.Guardrail.Model == "" &&
		proxyShouldBindForConfiguredConnector(s.cfg) {
		fmt.Fprintf(os.Stderr, "[sidecar] WARNING: guardrail.enabled is true but guardrail.model is empty — relying on fetch-interceptor routing.\n")
		fmt.Fprintf(os.Stderr, "[sidecar]          Set guardrail.model in ~/.defenseclaw/config.yaml only if you need a fixed advertised model name.\n")
	}

	if strings.EqualFold(s.cfg.Guardrail.Host, "localhost") {
		fmt.Fprintf(os.Stderr, "[sidecar] WARNING: guardrail.host is set to \"localhost\" which may resolve to IPv6 (::1) on macOS.\n")
		fmt.Fprintf(os.Stderr, "[sidecar]          The proxy binds 127.0.0.1 only. Set guardrail.host to \"127.0.0.1\" to avoid silent connection failures.\n")
	}

	// Initialize OPA engine before goroutines so both the watcher and the
	// API reload handler share the same instance.
	if s.cfg.PolicyDir != "" {
		if engine, err := policy.New(s.cfg.PolicyDir); err == nil {
			if compileErr := engine.Compile(); compileErr == nil {
				s.opa = engine
				fmt.Fprintf(os.Stderr, "[sidecar] OPA policy engine loaded from %s\n", s.cfg.PolicyDir)
				emitLifecycle(ctx, "opa", "ready", map[string]string{"policy_dir": s.cfg.PolicyDir})
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] OPA compile error (falling back to built-in): %v\n", compileErr)
				emitError(ctx, "opa", "compile-failed", "falling back to built-in policies", compileErr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[sidecar] OPA init skipped (falling back to built-in): %v\n", err)
			emitError(ctx, "opa", "init-failed", "falling back to built-in policies", err)
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
	if apiToken, tokErr := s.ensureGatewayTokenSynthesis(); tokErr != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] FATAL: failed to synthesize gateway token: %v\n", tokErr)
		emitError(ctx, "sidecar", "token-synthesis-failed", "fatal", tokErr)
		return fmt.Errorf("sidecar: gateway token synthesis: %w", tokErr)
	} else {
		inventory.SetPathHashKey(deriveAIInventoryHashKey(apiToken))
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 5)

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
		if err := s.runGatewayLoop(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] gateway loop exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 2: Skill/MCP watcher (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runWatcher(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 3: REST API server (always runs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runAPI(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] api server exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 4: guardrail proxy (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Guarded dispatch: the multi-connector boot loop runs ONLY when
		// the operator configured more than one connector
		// (guardrail.connectors has >1 entry). The single-connector path
		// — every existing install — keeps calling runGuardrail unchanged,
		// so its behavior is preserved byte-for-byte.
		runGuardrailFn := s.runGuardrail
		if len(s.cfg.ActiveConnectors()) > 1 {
			runGuardrailFn = s.runGuardrailMulti
		}
		if err := runGuardrailFn(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] guardrail exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 5: continuous AI discovery (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runAIDiscovery(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] ai discovery exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Report telemetry (OTel) health — not a goroutine, just state
	s.reportTelemetryHealth()
	if s.otel != nil {
		s.otel.EmitStartupSpan(ctx)
	}

	// Report aggregate audit-sink health — not a goroutine, just state
	s.reportSinksHealth()

	// Report sandbox health — only present when standalone mode is active
	s.reportSandboxHealth(ctx)

	// Wait for context cancellation (signal handler in CLI layer)
	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "[sidecar] context cancelled, waiting for subsystems to stop ...\n")
	wg.Wait()

	s.alertCancel()
	s.alertWg.Wait()

	// Shutdown — ctx is already Done, but still carries correlation values.
	emitLifecycle(ctx, "gateway", "stop", nil)
	_ = s.logger.LogAction(string(audit.ActionSidecarStop), "", "all subsystems stopped")
	if s.webhooks != nil {
		s.webhooks.Close()
	}
	// Drain the async judge-persistence queue BEFORE the audit DB
	// handle is closed: any rows still buffered after a SIGTERM
	// must land in SQLite or they are lost forever. Shutdown
	// bounds the wait to judgePersistShutdownTimeout (5s) so a
	// pathological DB doesn't wedge the process; drops still
	// surface as defenseclaw.judge.persist.drops with
	// reason="shutdown" if we run out of time.
	judgeStoreClosed := true
	if s.judgeStore != nil {
		// Detach from the global so any post-drain emit path sees a
		// nil store instead of racing the worker.
		SetJudgeResponseStore(nil)
		if err := s.judgeStore.Shutdown(ctx); err != nil {
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
	s.logger.Close()
	_ = s.client.Close()
	if s.events != nil {
		// Detach the audit bridge BEFORE closing the writer so any
		// final audit.Logger emission during shutdown either goes
		// through cleanly or is dropped — never writes into a closed
		// lumberjack handle.
		if s.logger != nil {
			s.logger.SetStructuredEmitter(nil)
		}
		_ = s.events.Close()
		SetEventWriter(nil)
		SetEgressTelemetry(nil)
		SetJudgePersistor(nil)
	}

	// Return the first non-nil error if any subsystem failed before shutdown
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
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
	if !gatewayShouldConnectForConfiguredConnector(s.cfg) {
		connName := configuredConnectorName(s.cfg)
		details := map[string]interface{}{
			"summary": "no OpenClaw fleet configured (standalone mode)",
			"host":    s.cfg.Gateway.Host,
			"port":    s.cfg.Gateway.Port,
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
		details["scope"] = fmt.Sprintf("process-global — fleet uplink is shared across all %d connectors, not per-connector (see Agents)", len(s.cfg.ActiveConnectors()))
		s.health.SetGateway(StateDisabled, "", details)
		fmt.Fprintf(os.Stderr,
			"[sidecar] gateway client disabled: connector=%q + loopback gateway.host=%q — no OpenClaw fleet to dial. Hooks + local audit continue normally.\n",
			connName, s.cfg.Gateway.Host)
		emitLifecycle(ctx, "gateway", "disabled", map[string]string{
			"connector": connName,
			"host":      s.cfg.Gateway.Host,
			"port":      fmt.Sprintf("%d", s.cfg.Gateway.Port),
			"reason":    "no-fleet-configured",
		})
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
		fmt.Fprintf(os.Stderr, "[sidecar] connecting to %s:%d ...\n", s.cfg.Gateway.Host, s.cfg.Gateway.Port)

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

		if !firstConnect && s.otel != nil {
			s.otel.RecordWatcherRestart(ctx)
		}
		firstConnect = false

		hello := s.client.Hello()
		s.logHello(hello)
		// Mirror the "gateway is ready to serve" event on both
		// structured (gateway.jsonl / OTel fanout) and audit paths
		// (SQLite / Splunk HEC / HTTP JSONL sinks). The structured
		// emit is synchronous and independent of the audit DB, so
		// operators still see the transition on the observability
		// bus even if the SQLite write later fails. Pairing the two
		// emissions is the v7 contract — a ready gateway must be
		// visible on every surface, not just the audit row.
		emitLifecycle(ctx, "gateway", "ready", map[string]string{
			"protocol": fmt.Sprintf("%d", hello.Protocol),
		})
		if err := s.logger.LogAction(string(audit.ActionSidecarConnected), "",
			fmt.Sprintf("protocol=%d", hello.Protocol)); err != nil {
			// Never silent: surface both on stderr (so operators see
			// it in gateway.log) and as a structured error event
			// (so SIEMs can alert on missing-ready-event incidents).
			fmt.Fprintf(os.Stderr,
				"[sidecar] WARN: sidecar-connected audit persist failed: %v\n", err)
			emitError(ctx, "gateway", "audit-persist-failed",
				"sidecar-connected audit event did not persist", err)
		}
		s.health.SetGateway(StateRunning, "", map[string]interface{}{
			"protocol": hello.Protocol,
		})

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
	wcfg := s.cfg.Gateway.Watcher

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
	conn, err := resolveActiveConnector(reg, configuredConnectorName(s.cfg), "watcher")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: connector resolution: %v\n", err)
	}

	skillDirs, pluginDirs, _ := resolveWatcherDirs(s.cfg, conn, wcfg)

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
		s.health.SetWatcher(StateError, "no directories configured", nil)
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

	w := watcher.New(s.cfg, skillDirs, pluginDirs, s.store, s.logger, s.shell, s.opa, s.otel, func(r watcher.AdmissionResult) {
		s.handleAdmissionResult(r)
	})
	if s.otel != nil {
		w.SetOTelProvider(s.otel)
	}
	if s.webhooks != nil {
		w.SetWebhookDispatcher(s.webhooks)
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
	if !s.cfg.Gateway.Watcher.Skill.TakeAction {
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

	if s.webhooks != nil {
		event := audit.Event{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Action:    string(audit.ActionBlock),
			Target:    subjectName,
			Actor:     "defenseclaw-watcher",
			Details:   fmt.Sprintf("type=%s severity=%s findings=%d actions=%s reason=%s", subjectType, severity, findings, strings.Join(actions, ","), safeReason),
			Severity:  severity,
		}
		s.webhooks.Dispatch(event)
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
	if !s.cfg.Gateway.Watcher.Plugin.TakeAction {
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
	if !s.cfg.Gateway.Watcher.MCP.TakeAction {
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
	return gatewayShouldConnectForConfiguredConnector(s.cfg)
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
	if s.cfg == nil || !s.cfg.HasConnectorConfigured() {
		return s.waitForConnectorSetup(ctx)
	}

	// Reuse the rule pack already loaded by NewSidecar and stored on the
	// router, avoiding a redundant disk/embed read and potential drift.
	rp := s.router.rp
	if rp == nil {
		rp = guardrail.LoadRulePack(s.cfg.Guardrail.RulePackDir)
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
	if s.cfg.PluginDir != "" {
		if err := registry.DiscoverPlugins(s.cfg.PluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] plugin discovery: %v\n", err)
		}
	}
	conn, err := resolveActiveConnector(registry, configuredConnectorName(s.cfg), "guardrail")
	if err != nil {
		// Fail fast: the operator explicitly set a connector that does
		// not exist. Returning here aborts sidecar boot so the operator
		// notices the typo immediately instead of seeing a "running but
		// somehow not blocking anything" sidecar.
		return err
	}
	rp = guardrail.LoadRulePack(s.cfg.Guardrail.EffectiveRulePackDir(conn.Name()))
	rp.Validate()
	fmt.Fprintf(os.Stderr, "[guardrail] rule pack loaded for %s: %s\n", conn.Name(), rp)
	if s.router != nil {
		s.router.SetRulePack(rp)
	}
	ApplyRulePackOverrides(rp)
	ApplyConnectorRulePackOverrides(conn.Name(), rp)
	ApplyLocalPatternsOverride(rp.LocalPatterns)
	proxyAddr := guardrailListenAddr(s.cfg.Guardrail.Port, s.cfg.Guardrail.Host)
	apiBind := "127.0.0.1"
	if s.cfg.Gateway.APIBind != "" {
		apiBind = s.cfg.Gateway.APIBind
	}
	apiAddr := fmt.Sprintf("%s:%d", apiBind, s.cfg.Gateway.APIPort)

	// Plan B2 / S0.2: synthesize a first-boot gateway token if none is
	// configured, BEFORE Setup writes hook scripts (which bake the
	// token into curl headers) and BEFORE the API server starts (which
	// uses the same token to authenticate inbound hook calls). After
	// this point, s.cfg.Gateway.Token always has a non-empty value.
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
	masterKey := deriveMasterKey(s.cfg.DataDir)
	conn.SetCredentials(apiToken, masterKey)

	workspaceDir := s.cfg.ConnectorWorkspaceDir()
	agentVersion := connector.LoadCachedAgentVersion(s.cfg.DataDir, conn.Name())
	contractResolution := connector.ResolveHookContract(conn.Name(), agentVersion)
	setupOpts := connector.SetupOpts{
		DataDir:   s.cfg.DataDir,
		ProxyAddr: proxyAddr,
		APIAddr:   apiAddr,
		// Bake the gateway token into hook scripts so claude-code-hook.sh
		// and codex-hook.sh can authenticate against the API server's
		// auth middleware. ResolvedToken checks env vars first, then
		// config — same source the proxy uses for credential wiring
		// below, so the baked value and the value accepted by the API
		// middleware stay in lockstep.
		APIToken:     apiToken,
		WorkspaceDir: workspaceDir,
		// HookFailMode is the operator-chosen response-layer fail mode
		// for every generated hook (see GuardrailConfig.HookFailMode
		// for the contract). Routed via EffectiveHookFailMode so the
		// default "open" is applied uniformly when the field is unset
		// — matches the user-friendly default in defaultsFor() and
		// avoids a partial install accidentally going fail-closed.
		HookFailMode:     s.cfg.Guardrail.EffectiveHookFailMode(),
		HILTEnabled:      s.cfg.Guardrail.HILT.Enabled,
		InstallCodeGuard: false,
		AgentVersion:     agentVersion,
		HookContractID:   contractResolution.Contract.ContractID,
	}
	if connector.HookContractNeedsActionOverride(contractResolution) && strings.EqualFold(s.cfg.Guardrail.Mode, "action") && os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
		return fmt.Errorf("connector %s agent version %q is not verified against a known hook contract: %s (set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing)", conn.Name(), agentVersion, contractResolution.Reason)
	}
	if previous := connector.LoadHookContractLockEntry(s.cfg.DataDir, conn.Name()); previous.Connector != "" {
		current := connector.NewHookContractLockEntry(setupOpts, conn, version.Current().BinaryVersion)
		if connector.HookContractLockDrifted(previous, current) && strings.EqualFold(s.cfg.Guardrail.Mode, "action") && os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
			return fmt.Errorf("connector %s hook contract drift detected: previous version=%q contract=%s current version=%q contract=%s (rerun discovery/setup to refresh the lock, or set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 for exploratory testing)", conn.Name(), previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID)
		}
	}

	// resolveActiveConnector guarantees a non-nil connector — either the
	// operator-selected one or the openclaw default. We can therefore
	// drop the historical nil-guard and treat this as the canonical
	// path; any "no active connector" condition is now a hard error.
	fmt.Fprintf(os.Stderr, "[guardrail] active connector: %s (%s)\n", conn.Name(), conn.Description())

	if !s.cfg.Guardrail.Enabled {
		fmt.Fprintf(os.Stderr, "[guardrail] guardrail disabled — running connector teardown for %s\n", conn.Name())
		if err := conn.Teardown(ctx, setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] connector teardown: %v\n", err)
		}
		if err := conn.VerifyClean(setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: teardown of %s left stale state: %v\n", conn.Name(), err)
		}
		connector.ClearActiveConnector(s.cfg.DataDir)
	} else {
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
		if err := connector.SaveActiveConnector(s.cfg.DataDir, conn.Name()); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] save active connector state: %v\n", err)
		}
		lockEntry := connector.NewHookContractLockEntry(setupOpts, conn, version.Current().BinaryVersion)
		if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lockEntry); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] save hook contract lock: %v\n", err)
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
		if probe, ok := conn.(connector.ProviderProbe); ok && shouldRunProviderProbeForConnector(conn, &s.cfg.Guardrail) {
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
		&s.cfg.Guardrail,
		&s.cfg.CiscoAIDefense,
		s.logger,
		s.health,
		s.otel,
		s.store,
		s.cfg.DataDir,
		s.cfg.PolicyDir,
		s.notify,
		rp,
		s.cfg.ResolveLLM("guardrail.judge"),
		conn,
	)
	if err == nil && s.webhooks != nil {
		proxy.SetWebhookDispatcher(s.webhooks)
	}
	if err == nil && proxy != nil {
		proxy.SetDefaultAgentName(string(s.cfg.Claw.Mode))
		proxy.SetDefaultPolicyID(s.cfg.Guardrail.Mode)
		proxy.SetConnectorSwitchState(registry, setupOpts)
		proxy.SetHILTApprovalManager(s.hilt)
		proxy.SetNotifier(s.osNotifier)
		// Start connector hook self-heal before the observability-only
		// short-circuit below. Hook-native connectors (codex, claudecode,
		// cursor, ...) never reach proxy.Run, so the guard MUST be started
		// here to cover both the observability and proxy-bound paths. The
		// guard goroutine stops when ctx is cancelled.
		if s.cfg.Guardrail.Enabled && s.cfg.Guardrail.HookSelfHeal {
			proxy.StartHookConfigGuard(ctx, conn, setupOpts)
		}
	}
	if err != nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] init error: %v\n", err)
		if !s.cfg.Guardrail.Enabled {
			s.health.SetGuardrail(StateDisabled, "", nil)
			<-ctx.Done()
			return nil
		}
		<-ctx.Done()
		return err
	}

	// Observability-only short-circuit. When the active connector is
	// codex or claudecode AND its enforcement flag is false (the
	// production default), we never bind the proxy listener: the
	// connector's Setup() has already installed hooks + OTel + notify
	// for end-to-end telemetry, and the agent talks DIRECTLY to its
	// native upstream (api.openai.com / chatgpt.com or
	// api.anthropic.com).
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
	if !proxyShouldBindForConnector(conn, &s.cfg.Guardrail) {
		s.health.SetGuardrail(StateRunning, "", map[string]interface{}{
			"summary":             "observability-only (no proxy binding)",
			"connector":           conn.Name(),
			"enforcement_enabled": false,
			"proxy_port":          "closed",
			"hint":                "connector uses hooks/native telemetry; local guardrail proxy is not in the LLM data path",
		})
		fmt.Fprintf(os.Stderr, "[guardrail] observability mode: %s talks directly to its native upstream — proxy port intentionally not bound\n", conn.Name())
		<-ctx.Done()
		return nil
	}
	return proxy.Run(ctx)
}

func (s *Sidecar) waitForConnectorSetup(ctx context.Context) error {
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
	if s.cfg == nil || !s.cfg.HasConnectorConfigured() {
		return s.waitForConnectorSetup(ctx)
	}

	// Reuse the primary rule pack already loaded by NewSidecar (it drives
	// the process-global scanner overrides). The per-connector packs below
	// are loaded separately via the cache.
	primaryRP := s.router.rp
	if primaryRP == nil {
		primaryRP = guardrail.LoadRulePack(s.cfg.Guardrail.RulePackDir)
		primaryRP.Validate()
	}

	// Route plugin-loader rejections into the audit pipeline before any
	// DiscoverPlugins runs — identical to the single-connector path.
	wirePluginAuditEmitter()

	registry := connector.NewDefaultRegistry()
	if s.cfg.PluginDir != "" {
		if err := registry.DiscoverPlugins(s.cfg.PluginDir); err != nil {
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
	configured := s.cfg.ActiveConnectors()
	names := make([]string, 0, len(configured))
	for _, name := range configured {
		if s.cfg.Guardrail.EffectiveEnabled(strings.ToLower(strings.TrimSpace(name))) {
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
		if proxyShouldBindForConnector(conn, &s.cfg.Guardrail) {
			err := fmt.Errorf("multi-connector mode supports hook-only connectors; %q requires a proxy binding and cannot share a process with other connectors", conn.Name())
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return err
		}
	}

	apiBind := "127.0.0.1"
	if s.cfg.Gateway.APIBind != "" {
		apiBind = s.cfg.Gateway.APIBind
	}
	apiAddr := fmt.Sprintf("%s:%d", apiBind, s.cfg.Gateway.APIPort)
	proxyAddr := guardrailListenAddr(s.cfg.Guardrail.Port, s.cfg.Guardrail.Host)

	// Synthesize a first-boot gateway token once for all connectors — the
	// token is baked into every connector's hook scripts and is the shared
	// secret the API server authenticates inbound hooks against.
	dotenvPath := filepath.Join(s.cfg.DataDir, ".env")
	apiToken := s.cfg.Gateway.ResolvedToken()
	if apiToken == "" {
		tok, err := EnsureGatewayToken(dotenvPath)
		if err != nil {
			s.health.SetGuardrail(StateError, err.Error(), nil)
			return fmt.Errorf("first-boot gateway token: %w", err)
		}
		s.cfg.Gateway.Token = tok
		apiToken = tok
		_ = os.Setenv("DEFENSECLAW_GATEWAY_TOKEN", tok)
	}
	masterKey := deriveMasterKey(s.cfg.DataDir)

	// Set-difference teardown: any connector active on a previous boot but
	// absent from the current set is torn down once, before setup. Uses a
	// base opts carrying just the fields Teardown needs.
	baseOpts := connector.SetupOpts{DataDir: s.cfg.DataDir, ProxyAddr: proxyAddr, APIAddr: apiAddr}
	previous := connector.LoadActiveConnectors(s.cfg.DataDir)
	teardownRemovedConnectors(registry, previous, names, baseOpts, ctx)

	// Disabled short-circuit: tear every configured connector down, clear
	// persisted state, and idle until shutdown.
	if !s.cfg.Guardrail.Enabled {
		for _, conn := range conns {
			opts := s.connectorSetupOpts(conn, apiToken, proxyAddr, apiAddr)
			if err := conn.Teardown(ctx, opts); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] connector %s teardown: %v\n", conn.Name(), err)
			}
			if err := conn.VerifyClean(opts); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] WARNING: teardown of %s left stale state: %v\n", conn.Name(), err)
			}
		}
		connector.ClearActiveConnector(s.cfg.DataDir)
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
		if err := connector.SaveActiveConnectors(s.cfg.DataDir, nil); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] save active connector set: %v\n", err)
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
	succeeded := s.setupConnectorsIsolated(ctx, conns, apiToken, proxyAddr, apiAddr, masterKey, cache)

	// Persist the set that actually came up so the next boot's
	// set-difference teardown is accurate.
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, succeeded); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] save active connector set: %v\n", err)
	}

	// Every connector failing is a real boot failure — surface it loudly
	// rather than idling on a gateway that protects nothing.
	if len(succeeded) == 0 {
		err := fmt.Errorf("multi-connector boot: all %d configured connectors failed setup", len(conns))
		s.health.SetGuardrail(StateError, err.Error(), nil)
		<-ctx.Done()
		return err
	}

	hookGuards := s.startMultiHookConfigGuards(ctx, registry, succeeded, apiToken, proxyAddr, apiAddr)
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
	s.health.SetGuardrail(StateRunning, "", map[string]interface{}{
		"summary":             fmt.Sprintf("multi-connector observability (%d active)", len(succeeded)),
		"connectors":          succeeded,
		"enforcement_enabled": false,
		"proxy_port":          "closed",
		"hint":                "hook-only connectors talk directly to their native upstreams; the local guardrail proxy is not in the LLM data path",
	})
	fmt.Fprintf(os.Stderr, "[guardrail] multi-connector observability mode: %d active connector(s): %s — proxy port intentionally not bound\n", len(succeeded), strings.Join(succeeded, ", "))

	<-ctx.Done()
	return nil
}

// startMultiHookConfigGuards starts one hook self-heal guard per connector
// that successfully came up in multi-connector mode. The single-connector path
// owns its guard through GuardrailProxy; multi-connector mode has no proxy, so
// the sidecar owns these guards directly.
func (s *Sidecar) startMultiHookConfigGuards(ctx context.Context, registry *connector.Registry, connectorNames []string, apiToken, proxyAddr, apiAddr string) []*HookConfigGuard {
	if s == nil || s.cfg == nil || registry == nil || !s.cfg.Guardrail.Enabled || !s.cfg.Guardrail.HookSelfHeal {
		return nil
	}
	debounce := time.Duration(s.cfg.Guardrail.HookSelfHealDebounceMs) * time.Millisecond
	guards := make([]*HookConfigGuard, 0, len(connectorNames))
	for _, name := range connectorNames {
		conn, ok := registry.Get(name)
		if !ok {
			fmt.Fprintf(os.Stderr, "[guardrail] hook self-heal: connector %s not found in registry, skipping guard\n", name)
			continue
		}
		opts := s.connectorSetupOpts(conn, apiToken, proxyAddr, apiAddr)
		guard := NewHookConfigGuard(s.logger, s.otel, debounce)
		guard.SetHealNotifier(s.notifyHookHealed)
		guard.Start(ctx, conn, opts)
		guards = append(guards, guard)
	}
	return guards
}

func stopHookConfigGuards(guards []*HookConfigGuard) {
	for _, guard := range guards {
		guard.Stop()
	}
}

// notifyHookHealed fans a successful multi-connector hook re-install out to
// webhooks. The durable audit row and OTel metric are emitted by the guard.
func (s *Sidecar) notifyHookHealed(connectorName string, paths []string) {
	if s == nil || s.webhooks == nil {
		return
	}
	s.webhooks.Dispatch(audit.Event{
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
// failure-isolation guarantee: a connector whose setup fails is logged and
// skipped, and the remaining connectors are set up regardless, so one
// connector's failure can never cascade and take the others down. The order
// of the returned slice matches the input order (sorted by the caller).
func (s *Sidecar) setupConnectorsIsolated(ctx context.Context, conns []connector.Connector, apiToken, proxyAddr, apiAddr, masterKey string, cache *guardrail.RulePackCache) []string {
	succeeded := make([]string, 0, len(conns))
	for _, conn := range conns {
		opts := s.connectorSetupOpts(conn, apiToken, proxyAddr, apiAddr)
		if err := s.setupOneConnector(ctx, conn, opts, masterKey, cache); err != nil {
			// Isolate: roll back this connector's partial state, log, leave
			// the other connectors untouched, continue.
			recordAndRollbackFailedConnectorSetup(conn, opts, ctx)
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s setup failed, skipping (other connectors unaffected): %v\n", conn.Name(), err)
			continue
		}
		succeeded = append(succeeded, conn.Name())
		fmt.Fprintf(os.Stderr, "[guardrail] connector ready: %s (%s)\n", conn.Name(), conn.Description())
	}
	return succeeded
}

// connectorSetupOpts builds the per-connector SetupOpts for the
// multi-connector boot loop. It mirrors the single-connector setupOpts
// construction in runGuardrail but resolves the fail mode per connector via
// EffectiveHookFailModeFor so a per-connector hook_fail_mode override is
// honored.
func (s *Sidecar) connectorSetupOpts(conn connector.Connector, apiToken, proxyAddr, apiAddr string) connector.SetupOpts {
	agentVersion := connector.LoadCachedAgentVersion(s.cfg.DataDir, conn.Name())
	contractResolution := connector.ResolveHookContract(conn.Name(), agentVersion)
	return connector.SetupOpts{
		DataDir:          s.cfg.DataDir,
		ProxyAddr:        proxyAddr,
		APIAddr:          apiAddr,
		APIToken:         apiToken,
		WorkspaceDir:     s.cfg.ConnectorWorkspaceDir(),
		HookFailMode:     s.cfg.Guardrail.EffectiveHookFailModeFor(conn.Name()),
		HILTEnabled:      s.cfg.Guardrail.EffectiveHILT(conn.Name()).Enabled,
		InstallCodeGuard: false,
		AgentVersion:     agentVersion,
		HookContractID:   contractResolution.Contract.ContractID,
	}
}

// setupOneConnector performs the full setup-and-verify sequence for a single
// connector in the multi-connector boot loop. It returns an error (rather
// than aborting boot) so the caller can isolate the failure (DN1) and keep
// the other connectors running. On a post-Setup verification failure it rolls
// back just this connector's Setup before returning so a half-installed
// connector never lingers.
func (s *Sidecar) setupOneConnector(ctx context.Context, conn connector.Connector, opts connector.SetupOpts, masterKey string, cache *guardrail.RulePackCache) error {
	// Inject credentials before Setup so probes keyed off them succeed.
	conn.SetCredentials(opts.APIToken, masterKey)

	// Load + validate this connector's effective rule pack through the
	// shared cache. Connectors sharing a profile read disk once.
	rp := cache.Load(s.cfg.Guardrail.EffectiveRulePackDir(conn.Name()))
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
	if connector.HookContractNeedsActionOverride(contractResolution) &&
		strings.EqualFold(s.cfg.Guardrail.Mode, "action") &&
		os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
		return fmt.Errorf("connector %s agent version %q is not verified against a known hook contract: %s (set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing)", conn.Name(), opts.AgentVersion, contractResolution.Reason)
	}
	if previous := connector.LoadHookContractLockEntry(s.cfg.DataDir, conn.Name()); previous.Connector != "" {
		current := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
		if connector.HookContractLockDrifted(previous, current) &&
			strings.EqualFold(s.cfg.Guardrail.Mode, "action") &&
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
	lockEntry := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lockEntry); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] save hook contract lock for %s: %v\n", conn.Name(), err)
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
	switch conn.Name() {
	case "codex", "claudecode":
		return false
	case "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode":
		// opencode is a hook-only connector (it governs tool execution via
		// an auto-loaded JS bridge plugin, not a proxy listener), so it can
		// share a process in multi-connector mode like the other hook
		// connectors. Omitting it here made the gateway reject any
		// multi-connector set containing opencode as "requires a proxy
		// binding".
		return false
	default:
		return true
	}
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
	switch configuredConnectorName(cfg) {
	case "codex", "claudecode":
		return false
	case "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity":
		return false
	default:
		return true
	}
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
	case "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity":
		return false
	default:
		// Empty / unknown connector: prefer DISABLED over reconnect
		// spam. An operator who genuinely wants fleet dial will set
		// connector=openclaw or wire a non-loopback host.
		return false
	}
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
func verifyHookScriptsOnDisk(dataDir string, conn connector.Connector) []string {
	if conn == nil {
		return nil
	}
	owner, ok := conn.(connector.HookScriptOwner)
	if !ok {
		return nil
	}
	hookDir := filepath.Join(dataDir, "hooks")
	var missing []string
	for _, name := range owner.HookScriptNames(connector.SetupOpts{DataDir: dataDir}) {
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
	missing := verifyHookScriptsOnDisk(opts.DataDir, conn)
	if len(missing) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s setup completed but hook scripts missing on disk: %v — retrying hook writer\n", conn.Name(), missing)
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		return fmt.Errorf("connector %s hook-writer retry after missing-hook detection failed: %w", conn.Name(), err)
	}
	if missing = verifyHookScriptsOnDisk(opts.DataDir, conn); len(missing) > 0 {
		return fmt.Errorf("connector %s still missing hook scripts after hook-writer retry: %v", conn.Name(), missing)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] connector %s hook-writer retry restored missing hook scripts\n", conn.Name())
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
	fmt.Fprintf(os.Stderr, "[guardrail] previous connector %s teardown verified clean\n", prev)
	return nil
}

// teardownRemovedConnectors tears down connectors that were active on a
// previous boot but are absent from the current active set — the
// set-difference generalization of teardownPreviousConnector for the
// multi-connector boot path (removed = previous − current). It is intended to
// run once, before the per-connector setup loop.
//
// Failures are logged and skipped (continue-on-error): stale state left by a
// connector being REMOVED must never block bringing up the connectors that
// are still active (DN1). Membership is compared case-insensitively so a case
// mismatch can never tear down a connector that is in fact still active. A
// removed name absent from the registry is skipped with a log, mirroring
// teardownPreviousConnector.
func teardownRemovedConnectors(registry *connector.Registry, previous, current []string, opts connector.SetupOpts, ctx context.Context) {
	if registry == nil || len(previous) == 0 {
		return
	}
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
			continue
		}
		fmt.Fprintf(os.Stderr, "[guardrail] connector %s no longer active — tearing down\n", prevName)
		if err := old.Teardown(ctx, opts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] teardown of removed connector %s: %v\n", prevName, err)
		}
		if err := old.VerifyClean(opts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: removed connector %s left stale state: %v\n", prevName, err)
		}
	}
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
	if s.aiDiscovery == nil {
		s.health.SetAIDiscovery(StateDisabled, "", nil)
		return nil
	}
	s.health.SetAIDiscovery(StateStarting, "", map[string]interface{}{
		"mode":                      s.cfg.AIDiscovery.Mode,
		"scan_interval_min":         s.cfg.AIDiscovery.ScanIntervalMin,
		"process_interval_s":        s.cfg.AIDiscovery.ProcessIntervalSec,
		"include_shell_history":     s.cfg.AIDiscovery.IncludeShellHistory,
		"include_package_manifests": s.cfg.AIDiscovery.IncludePackageManifests,
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.aiDiscovery.Run(ctx)
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-errCh:
			if ctx.Err() != nil {
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
			report := s.aiDiscovery.Snapshot()
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
			s.health.SetAIDiscovery(StateStopped, "", nil)
			return ctx.Err()
		}
	}
}

// runAPI starts the REST API server.
func (s *Sidecar) runAPI(ctx context.Context) error {
	bind := "127.0.0.1"
	if s.cfg.Gateway.APIBind != "" {
		bind = s.cfg.Gateway.APIBind
	} else if s.cfg.OpenShell.IsStandalone() && s.cfg.Guardrail.Host != "" && s.cfg.Guardrail.Host != "localhost" {
		bind = s.cfg.Guardrail.Host
	}
	addr := fmt.Sprintf("%s:%d", bind, s.cfg.Gateway.APIPort)
	api := NewAPIServer(addr, s.health, s.client, s.store, s.logger, s.cfg)
	api.SetOTelProvider(s.otel)
	api.SetHILTApprovalManager(s.hilt)
	// Wire the Cisco AI Defense inspector onto the API server so the
	// hook lane (inspectToolPolicy / inspectMessageContent) can forward
	// tool calls + tool results to AID for operators who configured
	// cisco_ai_defense.api_key_env. NewCiscoInspectClient returns nil
	// when no key resolves; the hook lane silently skips AID in that
	// case and falls back to the regex + CodeGuard verdict.
	if cisco := NewCiscoInspectClient(&s.cfg.CiscoAIDefense, filepath.Join(s.cfg.DataDir, ".env")); cisco != nil {
		cisco.SetTelemetry(s.otel)
		api.SetCiscoInspector(cisco)
	}
	// Wire the LLM judge onto the API server so hook connectors listed
	// in guardrail.judge.hook_connectors get live-content adjudication
	// on the hook lane (inspectMessageContent). Same instance as the
	// proxy lane's router judge — one Bifrost client cache, one verdict
	// cache. nil when guardrail.judge.enabled is false; the hook lane
	// then skips the judge exactly as before.
	if s.judge != nil {
		api.SetHookJudge(s.judge)
	}
	api.SetAIDiscoveryService(s.aiDiscovery)
	api.SetNotifier(s.osNotifier)
	if s.opa != nil {
		api.SetPolicyReloader(s.opa.Reload)
	}
	// Load any per-source OTLP path-tokens that connector setup
	// previously minted (e.g. ${data_dir}/hooks/.otlp-geminicli.token).
	// Failure to load is logged but non-fatal: tokenAuth falls back
	// to the master-bearer comparison so a missing per-source token
	// only loses the scoped-token path, never breaks /otlp/.
	if scoped, err := connector.LoadAllOTLPPathTokens(s.cfg.DataDir); err == nil {
		api.SetOTLPPathTokens(scoped)
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] load OTLP path-tokens: %v\n", err)
	}
	reg := connector.NewDefaultRegistry()
	if s.cfg.PluginDir != "" {
		_ = reg.DiscoverPlugins(s.cfg.PluginDir)
	}
	api.SetConnectorRegistry(reg)
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

// reportTelemetryHealth sets the OTel telemetry subsystem health based on
// whether the provider was initialized and which signals are active.
type destinationRoutingHealth struct {
	provider    *telemetry.Provider
	destination string
}

func (h destinationRoutingHealth) MarshalJSON() ([]byte, error) {
	stats := h.provider.DestinationRoutingStats(h.destination)
	total := stats.Accepted + stats.Dropped
	percentage := float64(0)
	if total > 0 {
		percentage = 100 * float64(stats.Accepted) / float64(total)
	}
	return json.Marshal(map[string]interface{}{
		"eligible":               stats.Accepted,
		"filtered":               stats.Dropped,
		"total":                  total,
		"eligibility_percentage": percentage,
		// Compatibility aliases for clients predating delivery telemetry.
		"accepted":            stats.Accepted,
		"dropped":             stats.Dropped,
		"accepted_percentage": percentage,
	})
}

type destinationDeliveryHealth struct {
	provider    *telemetry.Provider
	destination string
}

func destinationSignalNames(destination config.OTelDestinationConfig) []string {
	signals := make([]string, 0, 3)
	if destination.Traces.Enabled {
		signals = append(signals, "traces")
	}
	if destination.Metrics.Enabled {
		signals = append(signals, "metrics")
	}
	if destination.Logs.Enabled {
		signals = append(signals, "logs")
	}
	return signals
}

func (h destinationDeliveryHealth) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.provider.DestinationDeliveryStats(h.destination))
}

func (s *Sidecar) reportTelemetryHealth() {
	if s.otel == nil || !s.otel.Enabled() {
		s.health.SetTelemetry(StateDisabled, "", nil)
		return
	}

	details := map[string]interface{}{}
	if len(s.cfg.OTel.Destinations) > 0 {
		destinations := make([]map[string]interface{}, 0, len(s.cfg.OTel.Destinations))
		for _, destination := range s.cfg.OTel.Destinations {
			signals := destinationSignalNames(destination)
			entry := map[string]interface{}{
				"name":     destination.Name,
				"preset":   destination.Preset,
				"enabled":  destination.Enabled,
				"scope":    "process",
				"endpoint": netguard.EndpointForDisplay(destination.Endpoint),
				"signals":  strings.Join(signals, ", "),
			}
			if destination.Traces.Enabled {
				entry["delivery"] = destinationDeliveryHealth{
					provider: s.otel, destination: destination.Name,
				}
			}
			if destination.SpanFilter.Enabled() {
				entry["routing"] = destinationRoutingHealth{
					provider: s.otel, destination: destination.Name,
				}
			}
			destinations = append(destinations, entry)
		}
		details["destination_count"] = len(destinations)
		details["destinations"] = destinations
		s.health.SetTelemetry(StateRunning, "", details)
		return
	}
	// Config validation requires at least one named destination whenever OTel
	// is enabled, so reaching this branch indicates an invalid in-memory config.
	s.health.SetTelemetry(StateError, "otel enabled without named destinations", details)
}

// reportSandboxHealth sets the sandbox subsystem health when standalone mode is active.
// It starts a background goroutine that probes the sandbox endpoint and
// transitions the state to running once reachable, or error on timeout.
func (s *Sidecar) reportSandboxHealth(ctx context.Context) {
	if !s.cfg.OpenShell.IsStandalone() {
		return
	}

	details := map[string]interface{}{
		"sandbox_ip":   s.cfg.Gateway.Host,
		"gateway_port": s.cfg.Gateway.Port,
	}
	s.health.SetSandbox(StateStarting, "", details)

	go s.probeSandbox(ctx, details)
}

// probeSandbox tries to TCP-dial the sandbox endpoint with back-off.
// On success it transitions sandbox health to running; on context
// cancellation or too many failures it transitions to error/stopped.
func (s *Sidecar) probeSandbox(ctx context.Context, details map[string]interface{}) {
	addr := net.JoinHostPort(s.cfg.Gateway.Host, fmt.Sprintf("%d", s.cfg.Gateway.Port))
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

// reportSinksHealth aggregates the configured audit-sink declarations
// into the sidecar health snapshot. Per-sink Forward/Flush errors are
// surfaced separately on the sinks.Manager itself; this function only
// reports static configuration health (count, kinds, names) so the TUI
// can render a "Sinks: 2 enabled (splunk_hec, otlp_logs)" row.
//
// The legacy splunk-bridge auto-generated credentials surface (Splunk
// Web URL, local user/password) is intentionally dropped — the v4
// audit_sinks model is provider-agnostic and operators bring their own
// collector/SIEM credentials.
func (s *Sidecar) reportSinksHealth() {
	connectorNames := s.cfg.Observability.ConnectorNames()
	total := len(s.cfg.AuditSinks)
	for _, name := range connectorNames {
		pc := s.cfg.Observability.Connectors[name]
		if pc.AuditSinks == nil {
			continue
		}
		if len(*pc.AuditSinks) == 0 {
			total++ // explicit empty override suppresses global routing
			continue
		}
		total += len(*pc.AuditSinks)
	}
	if total == 0 {
		// Nothing configured — surface the explicit reason + a hint
		// pointing operators at the right CLI command. Without this
		// the CLI status row showed a bare "Sinks: DISABLED" with no
		// context, leaving operators unsure whether their setup
		// command had taken effect.
		s.health.SetSinks(StateDisabled, "", map[string]interface{}{
			"summary": "no audit sinks configured",
			"hint":    "run 'defenseclaw setup local-observability' or 'defenseclaw setup observability add <preset>' to enable audit forwarding",
		})
		return
	}

	enabled := 0
	enabledKinds := make([]string, 0, total)
	rows := make([]map[string]interface{}, 0, total)
	details := make(map[string]interface{}, total+4)

	appendSink := func(sink config.AuditSink, scope string) {
		row := map[string]interface{}{
			"name":    sink.Name,
			"kind":    string(sink.Kind),
			"enabled": sink.Enabled,
			"scope":   scope,
		}
		var endpoint string
		switch sink.Kind {
		case config.SinkKindSplunkHEC:
			if sink.SplunkHEC != nil {
				endpoint = sink.SplunkHEC.Endpoint
				row["index"] = sink.SplunkHEC.Index
			}
		case config.SinkKindOTLPLogs:
			if sink.OTLPLogs != nil {
				endpoint = sink.OTLPLogs.Endpoint
				row["protocol"] = sink.OTLPLogs.Protocol
			}
		case config.SinkKindHTTPJSONL:
			if sink.HTTPJSONL != nil {
				endpoint = sink.HTTPJSONL.URL
			}
		}
		displayEndpoint := ""
		if endpoint != "" {
			displayEndpoint = netguard.EndpointForDisplay(endpoint)
			if sink.Kind == config.SinkKindHTTPJSONL {
				row["url"] = displayEndpoint
			} else {
				row["endpoint"] = displayEndpoint
			}
		}
		rows = append(rows, row)

		state := "disabled"
		if sink.Enabled {
			enabled++
			enabledKinds = append(enabledKinds, string(sink.Kind))
			state = "enabled"
		}

		// Per-sink scalar key so the CLI status renderer can show
		// one human-readable line per sink. Two-digit zero-padded
		// index keeps the alphabetical key sort matching the config
		// order (sink_01 before sink_10), so the rendered list
		// follows config.yaml ordering rather than map iteration.
		key := fmt.Sprintf("sink_%02d", len(rows))
		prefix := ""
		if scope != "global" {
			prefix = scope + ": "
		}
		if displayEndpoint != "" {
			details[key] = fmt.Sprintf(
				"%s%s (%s) -> %s [%s]", prefix, sink.Name, sink.Kind, displayEndpoint, state,
			)
		} else {
			// Sink missing its kind block (validation should reject
			// this at config-load, but be defensive — health is
			// strictly read-only and must never panic).
			details[key] = fmt.Sprintf(
				"%s%s (%s) [%s, missing %s block]",
				prefix, sink.Name, sink.Kind, state, sink.Kind,
			)
		}
	}

	for _, sink := range s.cfg.AuditSinks {
		appendSink(sink, "global")
	}
	for _, connectorName := range connectorNames {
		pc := s.cfg.Observability.Connectors[connectorName]
		if pc.AuditSinks == nil {
			continue // inherits global; no duplicate rows
		}
		if len(*pc.AuditSinks) == 0 {
			rows = append(rows, map[string]interface{}{
				"name":       "(none)",
				"kind":       "suppressed",
				"enabled":    false,
				"scope":      "connector:" + connectorName,
				"suppressed": true,
			})
			key := fmt.Sprintf("sink_%02d", len(rows))
			details[key] = fmt.Sprintf(
				"connector:%s: no sinks [global inheritance suppressed]", connectorName,
			)
			continue
		}
		for _, sink := range *pc.AuditSinks {
			appendSink(sink, "connector:"+connectorName)
		}
	}

	// Backward-compatible structured fields preserved for /health
	// JSON consumers (TUI, dashboards, the regression test in
	// gateway_test.go::TestHealthEndpointNoSecrets). The CLI
	// printer's scalar-only filter hides these on the terminal —
	// the per-sink string keys above carry the human-readable view.
	details["count"] = enabled
	details["kinds"] = enabledKinds
	details["sinks"] = rows

	if enabled == 0 {
		// At least one sink is configured but all are disabled —
		// distinct from "no audit sinks configured" so operators
		// know they have stale entries to flip on or remove rather
		// than nothing at all.
		details["summary"] = fmt.Sprintf(
			"0 of %d sink(s) enabled — flip one on with 'defenseclaw setup observability enable <name>'",
			total,
		)
		s.health.SetSinks(StateDisabled, "", details)
		return
	}

	details["summary"] = fmt.Sprintf("%d of %d enabled", enabled, total)
	s.health.SetSinks(StateRunning, "", details)
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
	if tok := s.cfg.Gateway.ResolvedToken(); tok != "" {
		return tok, nil
	}
	dotenvPath := filepath.Join(s.cfg.DataDir, ".env")
	tok, err := EnsureGatewayToken(dotenvPath)
	if err != nil {
		return "", err
	}
	s.cfg.Gateway.Token = tok
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
