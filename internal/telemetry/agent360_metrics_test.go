// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"strings"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestAgent360MetricsCarryStableTreeCorrelation(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Shutdown(context.Background())

	observation := AgentLifecycleObservation{
		Connector: "codex", AgentID: "child-agent", AgentName: "reviewer", AgentType: "subagent",
		RootAgentID: "root-agent", ParentAgentID: "root-agent", RootSessionID: "root-session",
		LifecycleID: "lifecycle-0123456789abcdef", ExecutionID: "execution-0123456789abcdef",
		Event: "turn_end", State: "completed", Depth: 1,
		ReportedCostUSD: 0.042, ReportedCostPresent: true,
	}
	provider.RecordAgentLifecycle(context.Background(), observation)
	provider.RecordAgentTokenUsage(context.Background(), observation, 120, 30)

	rm := collect(t, provider, reader)
	lastSeen := findGauge(rm, "defenseclaw.agent.last_seen")
	if lastSeen == nil {
		t.Fatal("agent last_seen gauge missing")
	}
	lastSeenData, ok := lastSeen.Data.(metricdata.Gauge[float64])
	if !ok || len(lastSeenData.DataPoints) != 1 {
		t.Fatalf("unexpected last_seen data: %T %+v", lastSeen.Data, lastSeen.Data)
	}
	attrs := lastSeenData.DataPoints[0].Attributes
	for key, want := range map[string]string{
		"connector": "codex", "gen_ai.agent.id": "child-agent",
		"defenseclaw.agent.root.id":      "root-agent",
		"defenseclaw.agent.parent.id":    "root-agent",
		"defenseclaw.agent.lifecycle.id": "lifecycle-0123456789abcdef",
		"defenseclaw.agent.execution.id": "execution-0123456789abcdef",
	} {
		if !hasAttribute(attrs, key, want) {
			t.Errorf("last_seen missing %s=%s", key, want)
		}
	}

	transitions := sumOf(t, rm, "defenseclaw.agent.lifecycle.transitions")
	if got := counterValueByAttr(transitions, "gen_ai.agent.id", "child-agent"); got != 1 {
		t.Fatalf("lifecycle transitions = %d, want 1", got)
	}
	tokens := sumOf(t, rm, "defenseclaw.agent.token.usage")
	if got := counterValueByAttr(tokens, "kind", "input"); got != 120 {
		t.Errorf("input tokens = %d, want 120", got)
	}
	if got := counterValueByAttr(tokens, "kind", "output"); got != 30 {
		t.Errorf("output tokens = %d, want 30", got)
	}

	cost := findGauge(rm, "defenseclaw.agent.reported_cost")
	if cost == nil {
		t.Fatal("reported cost gauge missing")
	}
	costData, ok := cost.Data.(metricdata.Gauge[float64])
	if !ok || len(costData.DataPoints) != 1 || costData.DataPoints[0].Value != 0.042 {
		t.Fatalf("unexpected reported cost: %T %+v", cost.Data, cost.Data)
	}
}

func TestNormalizeMetricIdentityLabelHashesOpaqueValuesWithoutCollapsing(t *testing.T) {
	t.Parallel()
	if got := normalizeMetricIdentityLabel("agent-123"); got != "agent-123" {
		t.Fatalf("readable ID changed: %q", got)
	}
	first := normalizeMetricIdentityLabel("opaque/" + strings.Repeat("a", 100))
	second := normalizeMetricIdentityLabel("opaque/" + strings.Repeat("b", 100))
	if !strings.HasPrefix(first, "id-") || first == second {
		t.Fatalf("opaque identities collapsed: first=%q second=%q", first, second)
	}
}
