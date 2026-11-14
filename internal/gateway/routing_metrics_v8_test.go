// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func capturedMetrics(capture *proxyCanonicalCapture, name string) []telemetry.V8ProjectedMetric {
	var out []telemetry.V8ProjectedMetric
	for _, m := range capture.metricSnapshot() {
		if m.Descriptor().Name == name {
			out = append(out, m)
		}
	}
	return out
}

func TestRoutingDecisionMetricLabelsAreClosedAndLeakNothing(t *testing.T) {
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	ctx := context.Background()
	outcome := SemanticRouteOutcome{
		Result: SemanticRouteDenied, FailureCode: SemanticRouteFailureFiltered,
		Deny: &engine.DenyReason{Code: "budget_exceeded:eng-monthly", Message: "Your model budget eng-monthly is used up. It resets at 2026-12-01 by alice@example.com"},
		Route: &engine.Decision{
			Source: "rules", Category: "coding", FilteredBy: "sensitive",
		},
		RequestModel: "secret-model-name",
	}
	recordSemanticRoutingDecisionMetricsV8(ctx, runtime, "claudecode", "route_only", outcome)
	// A free-form category, source, filter and refusal code fall to other.
	recordSemanticRoutingDecisionMetricsV8(ctx, runtime, "codex", "somewhere", SemanticRouteOutcome{
		Result: SemanticRouteDenied, FailureCode: SemanticRouteFailureFiltered,
		Deny:  &engine.DenyReason{Code: "weird code with spaces:" + strings.Repeat("x", 90)},
		Route: &engine.Decision{Source: "mystery", Category: "has spaces and a prompt fragment", FilteredBy: "free text"},
	})
	got := capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawSemanticRoutingDecision)
	if len(got) != 2 {
		t.Fatalf("decision metrics = %d", len(got))
	}
	a := got[0].Attributes()
	want := map[string]string{
		"defenseclaw.metric.result": "denied", "defenseclaw.metric.error.code": "filtered", "defenseclaw.metric.decision": "default",
		"defenseclaw.connector.source": "claudecode", "defenseclaw.route.source": "rules", "defenseclaw.route.category": "coding",
		"defenseclaw.route.filtered_by": "sensitive", "defenseclaw.route.listener": "route_only",
		"defenseclaw.route.deny_reason": "budget_exceeded", "defenseclaw.budget.id": "eng-monthly",
	}
	for k, v := range want {
		if fmt.Sprint(a[k]) != v {
			t.Errorf("%s = %v, want %s (all %v)", k, a[k], v, a)
		}
	}
	for _, v := range a {
		for _, forbidden := range []string{"alice", "resets", "secret-model-name", "used up"} {
			if strings.Contains(fmt.Sprint(v), forbidden) {
				t.Fatalf("decision metric leaked %q: %v", forbidden, a)
			}
		}
	}
	b := got[1].Attributes()
	for k, v := range map[string]string{
		"defenseclaw.route.source": "other", "defenseclaw.route.category": "other", "defenseclaw.route.filtered_by": "other",
		"defenseclaw.route.deny_reason": "other",
	} {
		if fmt.Sprint(b[k]) != v {
			t.Errorf("%s = %v, want %s", k, b[k], v)
		}
	}
	if _, present := b["defenseclaw.route.listener"]; present {
		t.Errorf("an unknown listener must be absent, got %v", b["defenseclaw.route.listener"])
	}
	if _, present := b["defenseclaw.budget.id"]; present {
		t.Errorf("a non-budget refusal carries no budget id, got %v", b["defenseclaw.budget.id"])
	}
}

func TestRoutingDecisionDenyClasses(t *testing.T) {
	for code, want := range map[string][2]string{
		"":                                    {"routing_admin_denied", ""},
		"budget_cost_unknown:b1":              {"budget_cost_unknown", "b1"},
		"budget_unavailable:b2":               {"budget_unavailable", "b2"},
		"budget_downgrade_unavailable:b3":     {"budget_downgrade_unavailable", "b3"},
		"routing_sensitive_local_unavailable": {"routing_sensitive_local_unavailable", ""},
		"routing_admin_denied":                {"routing_admin_denied", ""},
		"budget_exceeded:has a space":         {"budget_exceeded", "other"},
		"made-up":                             {"other", ""},
	} {
		class, id := routeDenyClass(&engine.DenyReason{Code: code})
		if class != want[0] || id != want[1] {
			t.Errorf("%q -> %q %q, want %q %q", code, class, id, want[0], want[1])
		}
	}
	if class, id := routeDenyClass(nil); class != "" || id != "" {
		t.Errorf("nil refusal -> %q %q", class, id)
	}
}

func TestRouteOnlyRecordsItsRoutingDecision(t *testing.T) {
	f := newRouteOnlyFixture(t)
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	f.srv.metrics = func() hookLifecycleMetricV8Runtime { return runtime }
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("a quick question about sorting"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawSemanticRoutingDecision)
	if len(got) != 1 {
		t.Fatalf("route-only decision metrics = %d, want 1", len(got))
	}
	a := got[0].Attributes()
	if fmt.Sprint(a["defenseclaw.route.listener"]) != "route_only" || fmt.Sprint(a["defenseclaw.metric.result"]) != "applied" ||
		fmt.Sprint(a["defenseclaw.connector.source"]) != "claudecode" || fmt.Sprint(a["defenseclaw.route.source"]) != "rules" {
		t.Fatalf("route-only decision attributes: %v", a)
	}
	// A server with no metrics wired still serves.
	f.srv.metrics = nil
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("a quick question about sorting"), nil); rec.Code != http.StatusOK {
		t.Fatalf("no metrics: status %d", rec.Code)
	}
}

func budgetSidecar(cfg *config.Config) *Sidecar {
	s := &Sidecar{cfg: cfg}
	return s
}

func TestBudgetGaugesReportEachBudgetAndNeverZeroForUnknownSpend(t *testing.T) {
	cfg := routingAPIConfig()
	cfg.Routing.Admin.BudgetStore = &config.RoutingBudgetStoreConfig{URL: "https://store.example.test"}
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	now := time.Now().UTC()
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	s := budgetSidecar(cfg)

	// Before the remote spend is read: limits are known, spend is absent.
	loaded := func(id string) bool { return routingAdminRuntime.Ledger().Seeded(id) }
	if loaded("daily") {
		t.Skip("shared ledger already seeded by another test")
	}
	items := s.budgetMetricBatch(t.Context(), now)
	if _, err := runtime.RecordGeneratedMetricBatch(t.Context(), items); err != nil {
		t.Fatal(err)
	}
	if n := len(capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetLimit)); n != 2 {
		t.Fatalf("limit gauges = %d, want 2", n)
	}
	if n := len(capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetSpend)); n != 0 {
		t.Fatalf("spend must be absent while loading, got %d series", n)
	}

	routingAdminRuntime.Ledger().ApplyRemote([]string{"daily", "eng"}, nil, now)
	routingAdminRuntime.Charge([]string{"user:daily:*:1001"}, 4, now)
	routingAdminRuntime.Charge([]string{"user:daily:*:1002"}, 11, now)
	runtime2, capture2 := newProxyGeneratedMetricRuntime(t)
	if _, err := runtime2.RecordGeneratedMetricBatch(t.Context(), s.budgetMetricBatch(t.Context(), now)); err != nil {
		t.Fatal(err)
	}
	spend := capturedMetrics(capture2, observability.TelemetryInstrumentDefenseClawBudgetSpend)
	peak := capturedMetrics(capture2, observability.TelemetryInstrumentDefenseClawBudgetPeakSubjectSpend)
	exceeded := capturedMetrics(capture2, observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded)
	if len(spend) != 2 || len(peak) != 2 || len(exceeded) != 2 {
		t.Fatalf("series spend/peak/exceeded = %d/%d/%d, want 2 each", len(spend), len(peak), len(exceeded))
	}
	for _, m := range spend {
		attrs := m.Attributes()
		if fmt.Sprint(attrs["defenseclaw.budget.id"]) != "daily" {
			continue
		}
		if v, ok := m.Value().Double(); !ok || v != 15 {
			t.Fatalf("daily spend = %v, want 15 (4+11)", m.Value())
		}
	}
	for _, m := range exceeded {
		if fmt.Sprint(m.Attributes()["defenseclaw.budget.id"]) == "daily" {
			if v, ok := m.Value().Int64(); !ok || v != 1 {
				t.Fatalf("daily subjects over the 10 USD limit = %v, want 1", m.Value())
			}
		}
	}
	// No subject, user id or group name is a label anywhere.
	for _, m := range append(append(spend, peak...), exceeded...) {
		for k, v := range m.Attributes() {
			if strings.Contains(fmt.Sprint(v), "1001") || strings.Contains(fmt.Sprint(v), "DCLAB") || strings.Contains(k, "subject") {
				t.Fatalf("budget gauge leaked a subject: %v", m.Attributes())
			}
		}
	}
	// Store gauges: configured store, no sync error.
	if n := len(capturedMetrics(capture2, observability.TelemetryInstrumentDefenseClawBudgetStoreHealthy)); n != 1 {
		t.Fatalf("store healthy gauges = %d", n)
	}
	if n := len(capturedMetrics(capture2, observability.TelemetryInstrumentDefenseClawBudgetStoreSyncAge)); n != 1 {
		t.Fatalf("store sync age gauges = %d (a sync just worked)", n)
	}
	// The fleet store answers a pooled budget with over the limit only: no spend, one exceeded.
	routingAdminRuntime.Charge([]string{"group:eng:*:" + "pool"}, budgetstore.ExceededUSD, now)
	runtime3, capture3 := newProxyGeneratedMetricRuntime(t)
	if _, err := runtime3.RecordGeneratedMetricBatch(t.Context(), s.budgetMetricBatch(t.Context(), now)); err != nil {
		t.Fatal(err)
	}
	for _, m := range capturedMetrics(capture3, observability.TelemetryInstrumentDefenseClawBudgetSpend) {
		if fmt.Sprint(m.Attributes()["defenseclaw.budget.id"]) == "eng" {
			t.Fatalf("a pooled over-the-limit marker must not be exported as a spend: %v", m.Value())
		}
	}
}

func TestBudgetGaugesCostNothingWithoutBudgets(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{}
	if items := budgetSidecar(cfg).budgetMetricBatch(t.Context(), time.Now()); items != nil {
		t.Fatalf("no budgets must emit nothing, got %d items", len(items))
	}
	if items := budgetSidecar(&config.Config{}).budgetMetricBatch(t.Context(), time.Now()); items != nil {
		t.Fatalf("no routing.admin must emit nothing, got %d items", len(items))
	}
}

func baselinePricing() config.PricingConfig {
	return config.PricingConfig{
		Version: "t1",
		Models: []config.PriceEntryConfig{
			{Provider: "anthropic", Model: "claude-haiku-4-5*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usageF64(1), OutputPerMTok: usageF64(5)}},
			{Provider: "anthropic", Model: "claude-sonnet-4-5*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usageF64(3), OutputPerMTok: usageF64(15)}},
		},
	}
}

func TestModelUsageSinkEmitsBaselineAndComparedOnlyWhenBothKnown(t *testing.T) {
	engine, capture := newUsageTestEngine(t, []string{"logs", "metrics"}, baselinePricing())
	call := engine.Begin(context.Background(), modelusage.CallFacts{
		RequestID: "req-base-1", Connector: "codex", Listener: "route_only", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
		RequestedProvider: "anthropic", RequestedModel: "claude-sonnet-4-5",
		SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
		Route: modelusage.RouteFacts{Decision: modelusage.DecisionApplied, Source: "rules", FilteredBy: "sensitive"},
	})
	call.Usage(modelusage.ParsedUsage{Input: 1000, Output: 500, Has: modelusage.HasInput | modelusage.HasOutput})
	rec := call.End(nil)
	// haiku: (1000*1 + 500*5)/1e6 = 0.0035; sonnet: (1000*3 + 500*15)/1e6 = 0.0105.
	if rec.Cost.USD == nil || rec.Cost.BaselineUSD == nil || *rec.Cost.USD != 0.0035 || *rec.Cost.BaselineUSD != 0.0105 {
		t.Fatalf("cost/baseline: %+v", rec.Cost)
	}
	body, _ := usageLogBody(t, capture, true)
	if v, _ := body["defenseclaw.cost.baseline_usd"].(float64); v != 0.0105 {
		t.Fatalf("log baseline = %v: %v", body["defenseclaw.cost.baseline_usd"], body)
	}
	if body["defenseclaw.route.listener"] != "route_only" || body["defenseclaw.route.filtered_by"] != "sensitive" {
		t.Fatalf("log listener/filtered_by: %v", body)
	}
	var names map[string]struct{}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		_, metrics := capture.snapshot()
		names = hookModelV8CapturedMetricNames(metrics)
		if _, ok := names[observability.TelemetryInstrumentDefenseClawModelCostCompared]; ok {
			break
		}
	}
	for _, n := range []string{
		observability.TelemetryInstrumentDefenseClawModelCost, observability.TelemetryInstrumentDefenseClawModelCostBaseline,
		observability.TelemetryInstrumentDefenseClawModelCostCompared,
	} {
		if _, ok := names[n]; !ok {
			t.Fatalf("%s not recorded: %v", n, names)
		}
	}
}

func TestModelUsageSinkNoBaselineWhenRequestedModelHasNoPrice(t *testing.T) {
	engine, capture := newUsageTestEngine(t, []string{"logs", "metrics"}, baselinePricing())
	call := engine.Begin(context.Background(), modelusage.CallFacts{
		RequestID: "req-base-2", Connector: "codex", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
		RequestedProvider: "anthropic", RequestedModel: "claude-unpriced-9",
		SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
	})
	call.Usage(modelusage.ParsedUsage{Input: 1000, Output: 500, Has: modelusage.HasInput | modelusage.HasOutput})
	rec := call.End(nil)
	if rec.Cost.USD == nil || rec.Cost.BaselineUSD != nil {
		t.Fatalf("an unpriced requested model must leave the baseline absent: %+v", rec.Cost)
	}
	body, _ := usageLogBody(t, capture, true)
	if _, present := body["defenseclaw.cost.baseline_usd"]; present {
		t.Fatal("an absent baseline must stay absent, never 0")
	}
	time.Sleep(200 * time.Millisecond)
	_, metrics := capture.snapshot()
	names := hookModelV8CapturedMetricNames(metrics)
	for _, n := range []string{observability.TelemetryInstrumentDefenseClawModelCostBaseline, observability.TelemetryInstrumentDefenseClawModelCostCompared} {
		if _, ok := names[n]; ok {
			t.Fatalf("%s recorded without a baseline", n)
		}
	}
}

func TestModelUsageLogCarriesTheFallbackCauseOnlyOnAFallback(t *testing.T) {
	engine, capture := newUsageTestEngine(t, []string{"logs"}, baselinePricing())
	call := engine.Begin(context.Background(), modelusage.CallFacts{
		RequestID: "req-fb-1", Connector: "codex", Listener: "guardrail", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
		RequestedProvider: "anthropic", RequestedModel: "claude-sonnet-4-5",
		SelectedProvider: "anthropic", SelectedModel: "claude-sonnet-4-5",
		Route: modelusage.RouteFacts{Decision: modelusage.DecisionFallback, FallbackReason: "upstream_status", Source: "rules"},
	})
	call.Usage(modelusage.ParsedUsage{Input: 10, Output: 5, Has: modelusage.HasInput | modelusage.HasOutput})
	call.End(nil)
	body, _ := usageLogBody(t, capture, false)
	if body["defenseclaw.route.decision"] != "fallback" || body["defenseclaw.route.fallback_reason"] != "upstream_status" {
		t.Fatalf("fallback record: %v", body)
	}
	if got := routeFallbackReasonLabel("upstream_status", "applied"); got != "" {
		t.Fatalf("an applied call has no fallback cause, got %q", got)
	}
	for in, want := range map[string]string{"": "", "none": "", "timeout": "timeout", "free text with a prompt": "other"} {
		if got := routeFallbackReasonLabel(in, "fallback"); got != want {
			t.Errorf("routeFallbackReasonLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
