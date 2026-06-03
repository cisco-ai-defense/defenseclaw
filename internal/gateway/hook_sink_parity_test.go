// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestHookSinkParity_ConnectorIdentityAcrossSQLiteJSONLAndSpan is the
// runtime DN2 parity gate (plan PR11): a single hook finalisation must
// stamp the SAME per-connector identity — connector / step_idx /
// enforced / rule_pack_dir — onto ALL THREE sinks:
//
//   - SQLite audit_events row (dedicated columns, migration 16),
//   - the gateway.jsonl structured bridge (typed Lifecycle.Details keys,
//     C2), and
//   - the active OTel span attributes (C1).
//
// step_idx has a per-turn side effect, so finalizeAgentHook stamps the
// envelope exactly once and feeds the result to every sink; this test
// would fail loudly if a future change re-derived identity per-sink (the
// classic source of three half-populated, mutually-disagreeing streams).
func TestHookSinkParity_ConnectorIdentityAcrossSQLiteJSONLAndSpan(t *testing.T) {
	const (
		wantConnector = "codex"
		wantRulePack  = "/packs/codex"
		wantStepIdx   = 1
	)

	// --- Sink 1+2: SQLite store + structured JSONL bridge ---------------
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}

	writer, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var jsonlEvents []gatewaylog.Event
	writer.WithFanout(func(e gatewaylog.Event) {
		jsonlEvents = append(jsonlEvents, e)
	})

	logger := audit.NewLogger(store)
	logger.SetStructuredEmitter(newAuditBridge(writer))
	t.Cleanup(func() { logger.Close() })

	// --- OTel metric provider so the finalize "otel" section runs -------
	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	t.Cleanup(func() { _ = otelProvider.Shutdown(context.Background()) })

	// --- Sink 3: recording span on the request context -----------------
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = wantConnector
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		wantConnector: {RulePackDir: wantRulePack},
	}
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	api.SetOTelProvider(otelProvider)

	ctx, span := tp.Tracer("test").Start(context.Background(), "hook")

	req := agentHookRequest{
		ConnectorName: wantConnector,
		HookEventName: "PreToolUse",
		SessionID:     "sess-parity-1",
		TurnID:        "turn-parity-1",
		ToolName:      "shell",
	}
	// action=block under mode=action ⇒ Enforced must be true.
	resp := agentHookResponse{Action: "block", RawAction: "block", Severity: "HIGH", Mode: "action"}

	api.finalizeAgentHook(ctx, wantConnector, req, resp, nil, []byte(`{"command":"rm -rf /"}`), 5*time.Millisecond, false, nil)
	span.End()

	// --- Sink 1 assertions: SQLite audit row ---------------------------
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var row *audit.Event
	for i := range events {
		if events[i].Action == string(audit.ActionConnectorHook) {
			row = &events[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("no connector-hook audit row persisted; got %d events", len(events))
	}
	if row.Connector != wantConnector {
		t.Errorf("SQLite connector = %q, want %q", row.Connector, wantConnector)
	}
	if row.StepIdx != wantStepIdx {
		t.Errorf("SQLite step_idx = %d, want %d", row.StepIdx, wantStepIdx)
	}
	if !row.Enforced {
		t.Errorf("SQLite enforced = false, want true (action=block, mode=action)")
	}
	if row.RulePackDir != wantRulePack {
		t.Errorf("SQLite rule_pack_dir = %q, want %q", row.RulePackDir, wantRulePack)
	}

	// --- Sink 2 assertions: gateway.jsonl structured bridge -------------
	var bridged *gatewaylog.Event
	for i := range jsonlEvents {
		ev := &jsonlEvents[i]
		if ev.Lifecycle == nil {
			continue
		}
		if ev.Lifecycle.Details["action"] == string(audit.ActionConnectorHook) {
			bridged = ev
			break
		}
	}
	if bridged == nil {
		t.Fatalf("connector-hook not bridged into gateway.jsonl; got %d events", len(jsonlEvents))
	}
	details := bridged.Lifecycle.Details
	if details["connector"] != wantConnector {
		t.Errorf("JSONL connector = %q, want %q", details["connector"], wantConnector)
	}
	if details["step_idx"] != strconv.Itoa(wantStepIdx) {
		t.Errorf("JSONL step_idx = %q, want %q", details["step_idx"], strconv.Itoa(wantStepIdx))
	}
	if details["enforced"] != "true" {
		t.Errorf("JSONL enforced = %q, want \"true\"", details["enforced"])
	}
	if details["rule_pack_dir"] != wantRulePack {
		t.Errorf("JSONL rule_pack_dir = %q, want %q", details["rule_pack_dir"], wantRulePack)
	}

	// --- Sink 3 assertions: OTel span attributes -----------------------
	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatalf("no spans recorded")
	}
	attrs := spans[0].Attributes
	if v, ok := attrByKey(attrs, "defenseclaw.connector.step_idx"); !ok {
		t.Errorf("span missing defenseclaw.connector.step_idx")
	} else if got := v.AsInt64(); got != int64(wantStepIdx) {
		t.Errorf("span step_idx = %d, want %d", got, wantStepIdx)
	}
	if v, ok := attrByKey(attrs, "defenseclaw.connector.enforced"); !ok {
		t.Errorf("span missing defenseclaw.connector.enforced")
	} else if !v.AsBool() {
		t.Errorf("span enforced = false, want true")
	}
	if v, ok := attrByKey(attrs, "defenseclaw.connector.rule_pack_dir"); !ok {
		t.Errorf("span missing defenseclaw.connector.rule_pack_dir")
	} else if got := v.AsString(); got != wantRulePack {
		t.Errorf("span rule_pack_dir = %q, want %q", got, wantRulePack)
	}
}
