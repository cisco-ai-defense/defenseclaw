// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestEmitNetworkEgressLogCarriesAgentAndTraceCorrelation(t *testing.T) {
	provider, exporter := newProviderWithLogCapture(t)
	traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	provider.EmitNetworkEgressLog(ctx, NetworkEgressLogAttrs{
		SessionID: "child-session", Connector: "codex", AgentID: "child",
		RootAgentID: "root", ParentAgentID: "root", RootSessionID: "root-session",
		LifecycleID: "lifecycle-1", ExecutionID: "execution-1", ToolID: "tool-1",
		Hostname: "example.com", HTTPMethod: "GET", Protocol: "https",
		PolicyOutcome: "allowed", DecisionCode: "NETWORK_DEFAULT_ALLOW",
	})
	records := exporter.snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%d want 1", len(records))
	}
	record := records[0]
	for key, want := range map[string]string{
		"defenseclaw.gateway.event_type": "network_egress",
		"gen_ai.agent.id":                "child",
		"defenseclaw.agent.root.id":      "root",
		"defenseclaw.agent.parent.id":    "root",
		"defenseclaw.session.root.id":    "root-session",
		"gen_ai.tool.call.id":            "tool-1",
		"server.address":                 "example.com",
		"trace_id":                       traceID.String(),
	} {
		if got := attrValue(record, key); got != want {
			t.Errorf("%s=%q want %q", key, got, want)
		}
	}
	body := record.Body().AsString()
	if !strings.Contains(body, `"trace_id":"`+traceID.String()+`"`) {
		t.Fatalf("body missing derived-field trace ID: %s", body)
	}
	if strings.Contains(body, "https://") {
		t.Fatalf("body leaked full URL: %s", body)
	}
}
