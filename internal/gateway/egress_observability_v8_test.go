// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type recordingGatewayEgressRuntime struct {
	gatewayEgressV8Runtime
	mu      sync.Mutex
	metrics []observability.EventName
	emitErr error
}

func (runtime *recordingGatewayEgressRuntime) Emit(
	ctx context.Context,
	metadata router.Metadata,
	builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	result, err := runtime.gatewayEgressV8Runtime.Emit(ctx, metadata, builder)
	runtime.mu.Lock()
	runtime.emitErr = err
	runtime.mu.Unlock()
	return result, err
}

func (runtime *recordingGatewayEgressRuntime) RecordGeneratedMetric(
	ctx context.Context,
	family observability.EventName,
	builder observabilityruntime.GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	result, err := runtime.gatewayEgressV8Runtime.RecordGeneratedMetric(ctx, family, builder)
	runtime.mu.Lock()
	runtime.metrics = append(runtime.metrics, family)
	runtime.mu.Unlock()
	return result, err
}

func (runtime *recordingGatewayEgressRuntime) metricFamilies() []observability.EventName {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]observability.EventName(nil), runtime.metrics...)
}

func TestGatewayEgressV8EmitsGeneratedLogAndMetricWithoutLegacyPath(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t err=%v", bound, err)
	}
	owner, ok := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	if !ok || owner == nil {
		t.Fatalf("owned runtime=%T", fixture.sidecar.observabilityV8)
	}
	runtime := &recordingGatewayEgressRuntime{gatewayEgressV8Runtime: owner}
	proxy := &GuardrailProxy{}
	proxy.observabilityV8Mu.Lock()
	proxy.observabilityV8Egress = runtime
	proxy.observabilityV8EgressAuthoritative = true
	proxy.observabilityV8Mu.Unlock()

	ctx := audit.ContextWithEnvelope(
		ContextWithRequestID(t.Context(), "request-egress-1"),
		audit.CorrelationEnvelope{
			SessionID: "session-egress-1", Connector: "codex", ToolID: "tool-call-egress-1",
		},
	)
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{AgentID: "agent-egress-1", UserID: "user-egress-1"})
	proxy.emitEgress(ctx, gatewaylog.EgressPayload{
		TargetHost: "api.example.com", TargetPath: "/v1/chat?api-key=secret",
		BodyShape: "messages", LooksLikeLLM: true, Branch: "shape",
		Decision: "block", Reason: "unknown-host-no-shape", Source: "go",
	})

	rows, err := fixture.store.ListEvents(10)
	if err != nil || len(rows) < 2 {
		t.Fatalf("event rows=%d err=%v emitErr=%v, want generated egress plus bootstrap", len(rows), err, runtime.emitErr)
	}
	row := rows[0]
	if row.Action != string(gatewaylog.EventEgress) || !row.Enforced ||
		row.RequestID != "request-egress-1" {
		t.Fatalf("generated egress row=%+v", row)
	}
	if got := runtime.metricFamilies(); len(got) != 1 ||
		got[0] != observability.EventName(observability.TelemetryInstrumentDefenseClawEgressEvents) {
		t.Fatalf("metric families=%v", got)
	}
	payload := row.Structured
	for key, want := range map[string]any{
		"gen_ai.conversation.id":             "session-egress-1",
		"gen_ai.agent.id":                    "agent-egress-1",
		"defenseclaw.agent.lifecycle.id":     stableLLMEventID("lifecycle", "codex", "session-egress-1", "agent-egress-1"),
		"defenseclaw.agent.execution.id":     stableLLMEventID("execution", "codex", "session-egress-1", "agent-egress-1", gatewaylog.ProcessRunID()),
		"user.id":                            "user-egress-1",
		"gen_ai.tool.call.id":                "tool-call-egress-1",
		"defenseclaw.network.target_ref":     "api.example.com",
		"defenseclaw.network.target_path":    "/v1/chat",
		"defenseclaw.network.body_shape":     "messages",
		"defenseclaw.network.branch":         "shape",
		"defenseclaw.network.decision":       "block",
		"defenseclaw.network.source":         "go",
		"defenseclaw.network.looks_like_llm": true,
		"defenseclaw.network.blocked":        true,
	} {
		if payload[key] != want {
			t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, payload[key], want, payload)
		}
	}
}

func TestGatewayEgressV8StickyDetachDoesNotInvokeFallthroughHooks(t *testing.T) {
	proxy := &GuardrailProxy{}
	proxy.observabilityV8EgressAuthoritative = true
	calledCounter := false
	calledAlert := false
	oldCounter := incEgressCounter
	oldAlert := emitEgressAlert
	incEgressCounter = func(context.Context, string, string, string) { calledCounter = true }
	emitEgressAlert = func(context.Context, gatewaylog.EgressPayload) { calledAlert = true }
	t.Cleanup(func() {
		incEgressCounter = oldCounter
		emitEgressAlert = oldAlert
	})
	proxy.emitEgress(t.Context(), gatewaylog.EgressPayload{
		TargetHost: "blocked.example", Branch: "shape", Decision: "block", Source: "go",
	})
	if calledCounter || calledAlert {
		t.Fatalf("detached v8 occurrence invoked fallthrough hooks: counter=%t alert=%t", calledCounter, calledAlert)
	}
}
