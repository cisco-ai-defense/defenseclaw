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

package insightclaw

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func setupTestAdapter(t *testing.T) (*Adapter, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := mp.Meter("test")

	adapter, err := NewAdapter(meter, Config{Enabled: true})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	return adapter, reader
}

func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

func findMetric(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func TestNilAdapterIsNoop(t *testing.T) {
	var a *Adapter
	// These should not panic.
	a.EmitMessageReceived(context.Background(), "test")
	a.EmitMessageSent(context.Background(), "test")
	a.EmitToolCall(context.Background(), "bash", "session-1")
	a.EmitToolError(context.Background(), "bash")
	a.EmitTokenUsage(context.Background(), "claudecode", "claude-4", 100, 50, 150)
	a.EmitLLMDuration(context.Background(), "claude-4", 123.4)
	a.EmitAgentTurnDuration(context.Background(), "claude-4", "agent-1", 500.0)
	a.EmitWebhookReceived(context.Background(), "slack", "message")
	a.EmitSessionState(context.Background(), "active", "")
}

func TestDisabledConfigReturnsNil(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := mp.Meter("test")

	adapter, err := NewAdapter(meter, Config{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter != nil {
		t.Fatal("expected nil adapter when disabled")
	}
}

func TestEmitMessageReceived(t *testing.T) {
	adapter, reader := setupTestAdapter(t)
	ctx := context.Background()

	adapter.EmitMessageReceived(ctx, "claudecode")
	adapter.EmitMessageReceived(ctx, "claudecode")
	adapter.EmitMessageReceived(ctx, "codex")

	rm := collectMetrics(t, reader)
	m := findMetric(rm, "openclaw.messages.received")
	if m == nil {
		t.Fatal("metric openclaw.messages.received not found")
	}

	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", m.Data)
	}

	// Should have 2 data points (claudecode=2, codex=1).
	if len(sum.DataPoints) != 2 {
		t.Fatalf("expected 2 data points, got %d", len(sum.DataPoints))
	}

	total := int64(0)
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	if total != 3 {
		t.Fatalf("expected total=3, got %d", total)
	}
}

func TestEmitTokenUsage(t *testing.T) {
	adapter, reader := setupTestAdapter(t)
	ctx := context.Background()

	adapter.EmitTokenUsage(ctx, "claudecode", "claude-4", 100, 50, 150)

	rm := collectMetrics(t, reader)

	for _, name := range []string{
		"openclaw.llm.tokens.prompt",
		"openclaw.llm.tokens.completion",
		"openclaw.llm.tokens.total",
		"openclaw.llm.requests",
	} {
		m := findMetric(rm, name)
		if m == nil {
			t.Errorf("metric %s not found", name)
		}
	}

	// Verify prompt tokens value.
	m := findMetric(rm, "openclaw.llm.tokens.prompt")
	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 {
		t.Fatalf("expected 1 data point, got %d", len(sum.DataPoints))
	}
	if sum.DataPoints[0].Value != 100 {
		t.Fatalf("expected prompt tokens=100, got %d", sum.DataPoints[0].Value)
	}

	// Verify model attribute.
	found := false
	for _, attr := range sum.DataPoints[0].Attributes.ToSlice() {
		if attr.Key == attribute.Key("gen_ai.request.model") && attr.Value.AsString() == "claude-4" {
			found = true
		}
	}
	if !found {
		t.Error("gen_ai.request.model attribute not found on token metric")
	}
}

func TestEmitToolCall(t *testing.T) {
	adapter, reader := setupTestAdapter(t)
	ctx := context.Background()

	adapter.EmitToolCall(ctx, "bash", "session-abc")

	rm := collectMetrics(t, reader)
	m := findMetric(rm, "openclaw.tool.calls")
	if m == nil {
		t.Fatal("metric openclaw.tool.calls not found")
	}

	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("expected 1 tool call, got %v", sum.DataPoints)
	}

	// Verify session.key attribute is present.
	found := false
	for _, attr := range sum.DataPoints[0].Attributes.ToSlice() {
		if attr.Key == attribute.Key("session.key") && attr.Value.AsString() == "session-abc" {
			found = true
		}
	}
	if !found {
		t.Error("session.key attribute not found on tool.calls metric")
	}
}

func TestCustomPrefix(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := mp.Meter("test")

	adapter, err := NewAdapter(meter, Config{Enabled: true, Prefix: "myprefix"})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	adapter.EmitMessageReceived(context.Background(), "test")

	rm := collectMetrics(t, reader)
	m := findMetric(rm, "myprefix.messages.received")
	if m == nil {
		t.Fatal("metric myprefix.messages.received not found (custom prefix)")
	}
}
