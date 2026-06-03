// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// These tests pin the per-connector metric dimension added so dashboards can
// split alerts, inspect evaluations, and scan findings by connector. The
// label must always be present (normalizing empty/uncolonized inputs to
// "unknown") so connector-scoped dashboard selectors still match every series.

func TestConnectorFromInspectTool(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"codex:PreToolUse", "codex"},
		{"claudecode:PostToolUse", "claudecode"},
		{" openclaw :hilt", "openclaw"}, // trims surrounding space
		{"Bash", "unknown"},             // bare passthrough tool, no connector prefix
		{"", "unknown"},
		{":PreToolUse", "unknown"}, // empty prefix
	}
	for _, c := range cases {
		if got := connectorFromInspectTool(c.tool); got != c.want {
			t.Errorf("connectorFromInspectTool(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func collect(t *testing.T, p *Provider, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

func sumOf(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Sum[int64] {
	t.Helper()
	m := findCounter(rm, name)
	if m == nil {
		t.Fatalf("metric %s not found", name)
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("metric %s: expected Sum[int64], got %T", name, m.Data)
	}
	return sum
}

func TestRecordInspectEvaluation_EmitsConnector(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordInspectEvaluation(ctx, "codex:PreToolUse", "block", "HIGH")
	p.RecordInspectEvaluation(ctx, "claudecode:PreToolUse", "allow", "LOW")
	p.RecordInspectEvaluation(ctx, "Bash", "allow", "LOW") // no connector prefix

	sum := sumOf(t, collect(t, p, reader), "defenseclaw.inspect.evaluations")
	if v := counterValueByAttr(sum, "connector", "codex"); v != 1 {
		t.Errorf("connector=codex count = %d, want 1", v)
	}
	if v := counterValueByAttr(sum, "connector", "claudecode"); v != 1 {
		t.Errorf("connector=claudecode count = %d, want 1", v)
	}
	if v := counterValueByAttr(sum, "connector", "unknown"); v != 1 {
		t.Errorf("connector=unknown count = %d, want 1", v)
	}
}

func TestRecordAlert_EmitsConnector(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordAlert(ctx, "guardrail-block", "HIGH", "local-guardrail", "codex")
	p.RecordAlert(ctx, "network-egress-blocked", "HIGH", "network-policy", "") // global -> unknown

	sum := sumOf(t, collect(t, p, reader), "defenseclaw.alert.count")
	if v := counterValueByAttr(sum, "connector", "codex"); v != 1 {
		t.Errorf("connector=codex count = %d, want 1", v)
	}
	if v := counterValueByAttr(sum, "connector", "unknown"); v != 1 {
		t.Errorf("connector=unknown count = %d, want 1", v)
	}
}

func TestRecordScanFindingByRule_EmitsConnector(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordScanFindingByRule(ctx, "skill", "skill.secret.aws", "HIGH", "codex")
	p.RecordScanFindingByRule(ctx, "mcp", "mcp.tool.shadow", "MEDIUM", "") // -> unknown

	sum := sumOf(t, collect(t, p, reader), "defenseclaw.scan.findings.by_rule")
	if v := counterValueByAttr(sum, "connector", "codex"); v != 1 {
		t.Errorf("connector=codex count = %d, want 1", v)
	}
	if v := counterValueByAttr(sum, "connector", "unknown"); v != 1 {
		t.Errorf("connector=unknown count = %d, want 1", v)
	}
}

func TestRecordScan_FindingsTotalEmitsConnector(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordScan(ctx, "skill", "skill", "blocked", 10, map[string]int{"HIGH": 2}, "codex")
	p.RecordScan(ctx, "mcp", "mcp", "clean", 5, map[string]int{"LOW": 1}, "") // -> unknown

	sum := sumOf(t, collect(t, p, reader), "defenseclaw.scan.findings")
	if v := counterValueByAttr(sum, "connector", "codex"); v != 2 {
		t.Errorf("connector=codex finding total = %d, want 2", v)
	}
	if v := counterValueByAttr(sum, "connector", "unknown"); v != 1 {
		t.Errorf("connector=unknown finding total = %d, want 1", v)
	}
}
