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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
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

	alertCtx    context.Context
	alertCancel context.CancelFunc
	alertWg     sync.WaitGroup

	// events is the structured gatewaylog.Writer (gateway.jsonl +
	// stderr pretty-print). Installed during NewSidecar so every
	// verdict/judge/lifecycle emission lands here without plumbing
	// the writer through every call site.
	events *gatewaylog.Writer
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

	router := NewEventRouter(client, store, logger, cfg.Gateway.AutoApprove, otel)
	router.notify = notify
	router.SetGuardrailConfig(&cfg.Guardrail)
	hilt := NewHILTApprovalManager(client, logger, otel)
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

	// Wire LLM judge when enabled. The judge handles tool-call injection
	// detection AND tool-result PII inspection (via inspectToolResult),
	// so it must be initialized whenever judge is enabled — not only when
	// tool_injection is on.
	if cfg.Guardrail.Judge.Enabled {
		dotenvPath := filepath.Join(cfg.DataDir, ".env")
		judgeLLM := cfg.ResolveLLM("guardrail.judge")
		judge := NewLLMJudge(&cfg.Guardrail.Judge, judgeLLM, dotenvPath, rp)
		if judge != nil {
			router.SetJudge(judge)
			features := "tool-result-pii"
			if cfg.Guardrail.Judge.ToolInjection {
				features += ", tool-injection"
			}
			fmt.Fprintf(os.Stderr, "[sidecar] LLM judge enabled (%s) (model=%s)\n",
				features, judgeLLM.Model)
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
		events.WithFanout(otel.EmitGatewayEvent)
		// Route schema-violation drops into the Prometheus counter
		// so operators can alert on the metric directly without
		// scraping gateway.jsonl for EventError rows.
		events.OnSchemaViolation(func(et gatewaylog.EventType, code, _ string) {
			otel.RecordSchemaViolation(context.Background(), string(et), code)
		})
	}
	SetEventWriter(events)
	// Layer 3 egress observability: wire the OTel provider so
	// RecordEgress fires alongside every EventEgress emission.
	// Resets to no-op on shutdown via the matching SetEventWriter(nil) path.
	SetEgressTelemetry(otel)

	var webhooks *WebhookDispatcher
	if len(cfg.Webhooks) > 0 {
		webhooks = NewWebhookDispatcher(cfg.Webhooks)
		if webhooks != nil {
			webhooks.BindObservability(otel)
			fmt.Fprintf(os.Stderr, "[sidecar] webhook dispatcher initialized (%d endpoints)\n", len(webhooks.endpoints))
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
	if retainJudge && store != nil {
		SetJudgePersistor(func(ctx context.Context, p gatewaylog.JudgePayload, dir gatewaylog.Direction, opts JudgeEmitOpts) {
			if err := store.InsertJudgeResponse(audit.JudgeResponse{
				Kind:       p.Kind,
				Direction:  string(dir),
				Model:      p.Model,
				Action:     p.Action,
				Severity:   string(p.Severity),
				LatencyMs:  p.LatencyMs,
				ParseError: p.ParseError,
				Raw:        p.RawResponse,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "[sidecar] persist judge response: %v\n", err)
			}

			// Fan out a redacted summary through the audit pipeline.
			// Using logger.LogEvent keeps the sink filters, run_id
			// stamping, and OTel emission consistent with every
			// other audit event — no bespoke Splunk/OTLP wiring here.
			// RawResponse is intentionally NOT included in Details;
			// the sinks see only the structured metadata (kind,
			// model, latency, verdict, parse error). The full body
			// lives only in SQLite for local forensics.
			//
			// v7: merge the request-scoped correlation envelope
			// (from ctx) with the per-emission overlay (tool +
			// policy + destination_app derived from the active
			// request). Without this, every llm-judge-response row
			// landed in SQLite with agent/session/run/trace NULL
			// because the closure had no access to request
			// context — see review finding on empty envelope
			// coverage for judge rows.
			if logger != nil {
				env := audit.MergeEnvelope(audit.EnvelopeFromContext(ctx), audit.CorrelationEnvelope{
					ToolName:       opts.ToolName,
					ToolID:         opts.ToolID,
					PolicyID:       opts.PolicyID,
					DestinationApp: opts.DestinationApp,
				})
				evt := audit.Event{
					Action:   "llm-judge-response",
					Target:   p.Model,
					Actor:    "defenseclaw-gateway",
					Severity: string(p.Severity),
					Details: fmt.Sprintf(
						"kind=%s direction=%s action=%s latency_ms=%d input_bytes=%d parse_error=%q",
						p.Kind, dir, p.Action, p.LatencyMs, p.InputBytes, p.ParseError,
					),
				}
				audit.ApplyEnvelope(&evt, env)
				_ = logger.LogEvent(evt)
			}
		})
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
		cfg:         cfg,
		client:      client,
		router:      router,
		store:       store,
		logger:      logger,
		health:      NewSidecarHealth(),
		shell:       shell,
		otel:        otel,
		notify:      notify,
		webhooks:    webhooks,
		hilt:        hilt,
		aiDiscovery: aiDiscovery,
		alertCtx:    alertCtx,
		alertCancel: alertCancel,
		events:      events,
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
	_ = s.logger.LogAction("sidecar-start", "", "starting all subsystems")

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
		if err := s.runGuardrail(ctx); err != nil && ctx.Err() == nil {
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
	_ = s.logger.LogAction("sidecar-stop", "", "all subsystems stopped")
	if s.webhooks != nil {
		s.webhooks.Close()
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
		s.health.SetGateway(StateDisabled, "", map[string]interface{}{
			"summary":   "no OpenClaw fleet configured (standalone mode)",
			"connector": connName,
			"host":      s.cfg.Gateway.Host,
			"port":      s.cfg.Gateway.Port,
			"hint":      "telemetry continues via hooks + local audit; point gateway.host at a real OpenClaw upstream and restart to enable fleet integration",
		})
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
		if err := s.logger.LogAction("sidecar-connected", "",
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
			_ = s.logger.LogAction("sidecar-disconnected", "", "connection lost, reconnecting")
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
			compTargets = scanner.ComponentTargets("")
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
			_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
				fmt.Sprintf("type=%s verdict=%s (no handler)", r.Event.Type, r.Verdict))
		}
	}
}

func (s *Sidecar) handleSkillAdmission(r watcher.AdmissionResult) {
	if !s.cfg.Gateway.Watcher.Skill.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
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
			_ = s.logger.LogAction("sidecar-watcher-disable", r.Event.Name,
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
			Action:    "block",
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
		_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
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
			_ = s.logger.LogAction("sidecar-watcher-disable-plugin", r.Event.Name,
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
		_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
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
			_ = s.logger.LogAction("sidecar-watcher-block-mcp", r.Event.Name,
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
		return nil, fmt.Errorf("[%s] guardrail.connector=%q not found in registry — set guardrail.connector to one of the registered connectors (openclaw, codex, claudecode, zeptoclaw, hermes, cursor, windsurf, geminicli, copilot) or remove the field to default to openclaw", surface, trimmed)
	}
	return conn, nil
}

// runGuardrail starts the Go guardrail proxy when guardrail is enabled.
func (s *Sidecar) runGuardrail(ctx context.Context) error {
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
		// Also push into the process env so subsequent ResolveAPIKey
		// calls (e.g. judge LLM init) see the synthesized value.
		_ = os.Setenv("DEFENSECLAW_GATEWAY_TOKEN", tok)
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

	workspaceDir, _ := os.Getwd()
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
		// Per-connector enforcement gates: when false (the default),
		// the connector's Setup() installs hooks + native OTel
		// exporters but skips the proxy-redirect path. See
		// GuardrailConfig.CodexEnforcementEnabled /
		// ClaudeCodeEnforcementEnabled in internal/config/config.go
		// for the rationale. Plumbed through SetupOpts so the codex
		// and claudecode connectors can branch on a single source of
		// truth without re-reading config from disk.
		CodexEnforcement:      s.cfg.Guardrail.CodexEnforcementEnabled,
		ClaudeCodeEnforcement: s.cfg.Guardrail.ClaudeCodeEnforcementEnabled,
		// HookFailMode is the operator-chosen response-layer fail mode
		// for every generated hook (see GuardrailConfig.HookFailMode
		// for the contract). Routed via EffectiveHookFailMode so the
		// default "open" is applied uniformly when the field is unset
		// — matches the user-friendly default in defaultsFor() and
		// avoids a partial install accidentally going fail-closed.
		HookFailMode:     s.cfg.Guardrail.EffectiveHookFailMode(),
		HILTEnabled:      s.cfg.Guardrail.HILT.Enabled,
		InstallCodeGuard: false,
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
		if err := conn.Setup(ctx, setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] connector setup %s failed: %v — connector may not be fully initialized\n", conn.Name(), err)
			recordAndRollbackFailedConnectorSetup(conn, setupOpts, ctx)
		} else {
			if err := connector.SaveActiveConnector(s.cfg.DataDir, conn.Name()); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] save active connector state: %v\n", err)
			}
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
			"hint":                fmt.Sprintf("flip on with guardrail.%s_enforcement_enabled: true in config.yaml", conn.Name()),
		})
		fmt.Fprintf(os.Stderr, "[guardrail] observability mode: %s talks directly to its native upstream — proxy port intentionally not bound\n", conn.Name())
		<-ctx.Done()
		return nil
	}
	return proxy.Run(ctx)
}

// proxyShouldBindForConnector returns true when the active connector
// requires the proxy listener to be bound — i.e. the agent's data
// path goes through DefenseClaw. For the observability-default
// connectors this returns false in observability mode, so the proxy
// port stays unbound and the agent talks directly to its native upstream.
// OpenClaw and ZeptoClaw always return true: those connectors were
// designed around the fetch-interceptor / api_base redirect from day one
// and have no observability-only path.
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
	case "codex":
		return gc.CodexEnforcementEnabled
	case "claudecode":
		return gc.ClaudeCodeEnforcementEnabled
	case "hermes", "cursor", "windsurf", "geminicli", "copilot":
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
	case "codex":
		return cfg.Guardrail.CodexEnforcementEnabled
	case "claudecode":
		return cfg.Guardrail.ClaudeCodeEnforcementEnabled
	case "hermes", "cursor", "windsurf", "geminicli", "copilot":
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
//	                           → SKIP. Codex/Claude Code in either
//	                             observe or action mode emit telemetry
//	                             through hooks/native telemetry +
//	                             local API/audit; action mode can
//	                             additionally bind the proxy when
//	                             enforcement is enabled. The loopback
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
//	hermes / cursor / windsurf / geminicli / copilot
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
	case "hermes", "cursor", "windsurf", "geminicli", "copilot":
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
	api.SetAIDiscoveryService(s.aiDiscovery)
	if s.opa != nil {
		api.SetPolicyReloader(s.opa.Reload)
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
func (s *Sidecar) reportTelemetryHealth() {
	if s.otel == nil || !s.otel.Enabled() {
		s.health.SetTelemetry(StateDisabled, "", nil)
		return
	}

	details := map[string]interface{}{}
	if s.cfg.OTel.Endpoint != "" {
		details["endpoint"] = s.cfg.OTel.Endpoint
	}

	var signals []string
	if s.cfg.OTel.Traces.Enabled {
		signals = append(signals, "traces")
	}
	if s.cfg.OTel.Metrics.Enabled {
		signals = append(signals, "metrics")
	}
	if s.cfg.OTel.Logs.Enabled {
		signals = append(signals, "logs")
	}
	if len(signals) > 0 {
		details["signals"] = strings.Join(signals, ", ")
	}

	if ep := s.cfg.OTel.Traces.Endpoint; ep != "" {
		details["traces_endpoint"] = ep
	}

	s.health.SetTelemetry(StateRunning, "", details)
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
	total := len(s.cfg.AuditSinks)
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

	for i, sink := range s.cfg.AuditSinks {
		row := map[string]interface{}{
			"name":    sink.Name,
			"kind":    string(sink.Kind),
			"enabled": sink.Enabled,
		}
		var endpoint string
		switch sink.Kind {
		case config.SinkKindSplunkHEC:
			if sink.SplunkHEC != nil {
				endpoint = sink.SplunkHEC.Endpoint
				row["endpoint"] = endpoint
				row["index"] = sink.SplunkHEC.Index
			}
		case config.SinkKindOTLPLogs:
			if sink.OTLPLogs != nil {
				endpoint = sink.OTLPLogs.Endpoint
				row["endpoint"] = endpoint
				row["protocol"] = sink.OTLPLogs.Protocol
			}
		case config.SinkKindHTTPJSONL:
			if sink.HTTPJSONL != nil {
				endpoint = sink.HTTPJSONL.URL
				row["url"] = endpoint
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
		key := fmt.Sprintf("sink_%02d", i+1)
		if endpoint != "" {
			details[key] = fmt.Sprintf(
				"%s (%s) -> %s [%s]", sink.Name, sink.Kind, endpoint, state,
			)
		} else {
			// Sink missing its kind block (validation should reject
			// this at config-load, but be defensive — health is
			// strictly read-only and must never panic).
			details[key] = fmt.Sprintf(
				"%s (%s) [%s, missing %s block]",
				sink.Name, sink.Kind, state, sink.Kind,
			)
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
