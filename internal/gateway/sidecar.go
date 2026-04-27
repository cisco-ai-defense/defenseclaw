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
	cfg      *config.Config
	client   *Client
	router   *EventRouter
	store    *audit.Store
	logger   *audit.Logger
	health   *SidecarHealth
	shell    *sandbox.OpenShell
	otel     *telemetry.Provider
	notify   *NotificationQueue
	opa      *policy.Engine
	webhooks *WebhookDispatcher

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

	notify := NewNotificationQueue()

	router := NewEventRouter(client, store, logger, cfg.Gateway.AutoApprove, otel)
	router.notify = notify
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

	if s.cfg.Guardrail.Enabled && s.cfg.Guardrail.Model == "" {
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
	errCh := make(chan error, 4)

	// Goroutine 1: Gateway connection loop (always runs)
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
// running indefinitely until ctx is cancelled.
func (s *Sidecar) runGatewayLoop(ctx context.Context) error {
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
	var compTargets map[string][]string
	connectorName := s.cfg.Guardrail.Connector
	if connectorName == "" {
		connectorName = "openclaw"
	}
	reg := connector.NewDefaultRegistry()
	if conn, ok := reg.Get(connectorName); ok {
		if scanner, ok := conn.(connector.ComponentScanner); ok && scanner.SupportsComponentScanning() {
			compTargets = scanner.ComponentTargets("")
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: using %s connector ComponentTargets\n", connectorName)
		}
	}

	// Resolve skill dirs: explicit config overrides connector autodiscovery
	var skillDirs []string
	if wcfg.Skill.Enabled {
		if len(wcfg.Skill.Dirs) > 0 {
			skillDirs = wcfg.Skill.Dirs
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: using configured skill dirs: %v\n", skillDirs)
		} else if paths := compTargets["skill"]; len(paths) > 0 {
			skillDirs = paths
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: connector-discovered skill dirs: %v\n", skillDirs)
		} else {
			skillDirs = s.cfg.SkillDirs()
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: autodiscovered skill dirs: %v\n", skillDirs)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill watching disabled\n")
	}

	// Plugin dirs: explicit config overrides connector autodiscovery
	var pluginDirs []string
	if wcfg.Plugin.Enabled {
		if len(wcfg.Plugin.Dirs) > 0 {
			pluginDirs = wcfg.Plugin.Dirs
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: using configured plugin dirs: %v\n", pluginDirs)
		} else if paths := compTargets["plugin"]; len(paths) > 0 {
			pluginDirs = paths
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: connector-discovered plugin dirs: %v\n", pluginDirs)
		} else {
			pluginDirs = s.cfg.PluginDirs()
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: autodiscovered plugin dirs: %v\n", pluginDirs)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: plugin watching disabled\n")
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

	err := w.Run(ctx)
	s.health.SetWatcher(StateStopped, "", nil)
	return err
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

	if shouldDisableAtGateway(r) && s.client != nil {
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

	if shouldDisableAtGateway(r) && s.client != nil {
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

	if shouldDisableAtGateway(r) && s.client != nil {
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

func (s *Sidecar) activeSessionKeys() []string {
	if s.router == nil {
		return nil
	}
	return s.router.ActiveSessionKeys()
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
	// written by `defenseclaw setup` into guardrail.connector (defaults
	// to "openclaw" for backward compat).
	registry := connector.NewDefaultRegistry()
	if s.cfg.PluginDir != "" {
		if err := registry.DiscoverPlugins(s.cfg.PluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] plugin discovery: %v\n", err)
		}
	}
	connectorName := s.cfg.Guardrail.Connector
	if connectorName == "" {
		connectorName = "openclaw"
	}
	conn, ok := registry.Get(connectorName)
	if !ok {
		fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %q not found in registry, falling back to openclaw\n", connectorName)
		conn, _ = registry.Get("openclaw")
	}
	proxyAddr := guardrailListenAddr(s.cfg.Guardrail.Port, s.cfg.Guardrail.Host)
	apiBind := "127.0.0.1"
	if s.cfg.Gateway.APIBind != "" {
		apiBind = s.cfg.Gateway.APIBind
	}
	apiAddr := fmt.Sprintf("%s:%d", apiBind, s.cfg.Gateway.APIPort)

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
		APIToken: s.cfg.Gateway.ResolvedToken(),
	}

	if conn != nil {
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
			} else {
				if err := connector.SaveActiveConnector(s.cfg.DataDir, conn.Name()); err != nil {
					fmt.Fprintf(os.Stderr, "[guardrail] save active connector state: %v\n", err)
				}
			}
		}

		s.health.SetConnector(conn.Name(), conn.ToolInspectionMode(), conn.SubprocessPolicy())
	}

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
	return proxy.Run(ctx)
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
	if s.opa != nil {
		api.SetPolicyReloader(s.opa.Reload)
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
	enabled := 0
	kinds := make([]string, 0, len(s.cfg.AuditSinks))
	rows := make([]map[string]interface{}, 0, len(s.cfg.AuditSinks))
	for _, sink := range s.cfg.AuditSinks {
		if !sink.Enabled {
			continue
		}
		enabled++
		kinds = append(kinds, string(sink.Kind))
		row := map[string]interface{}{
			"name":    sink.Name,
			"kind":    string(sink.Kind),
			"enabled": true,
		}
		switch sink.Kind {
		case config.SinkKindSplunkHEC:
			if sink.SplunkHEC != nil {
				row["endpoint"] = sink.SplunkHEC.Endpoint
				row["index"] = sink.SplunkHEC.Index
			}
		case config.SinkKindOTLPLogs:
			if sink.OTLPLogs != nil {
				row["endpoint"] = sink.OTLPLogs.Endpoint
				row["protocol"] = sink.OTLPLogs.Protocol
			}
		case config.SinkKindHTTPJSONL:
			if sink.HTTPJSONL != nil {
				row["url"] = sink.HTTPJSONL.URL
			}
		}
		rows = append(rows, row)
	}

	if enabled == 0 {
		s.health.SetSinks(StateDisabled, "", nil)
		return
	}

	details := map[string]interface{}{
		"count": enabled,
		"kinds": kinds,
		"sinks": rows,
	}
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
