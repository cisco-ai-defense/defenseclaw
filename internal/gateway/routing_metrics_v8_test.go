// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
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

func budgetTestConfig(store bool) *config.Config {
	cfg := routingAPIConfig()
	if store {
		cfg.Routing.Admin.BudgetStore = &config.RoutingBudgetStoreConfig{URL: "https://store.example.test"}
	}
	return cfg
}

func recordBudgetBatch(t *testing.T, cfg *config.Config, ledger *routingadmin.Ledger, now time.Time) *proxyCanonicalCapture {
	t.Helper()
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	items := budgetMetricBatchFor(t.Context(), now, cfg, ledger)
	if _, err := runtime.RecordGeneratedMetricBatch(t.Context(), items); err != nil {
		t.Fatal(err)
	}
	return capture
}

func budgetValue(t *testing.T, capture *proxyCanonicalCapture, name, id string) (float64, bool) {
	t.Helper()
	for _, m := range capturedMetrics(capture, name) {
		if fmt.Sprint(m.Attributes()["defenseclaw.budget.id"]) != id {
			continue
		}
		if v, ok := m.Value().Double(); ok {
			return v, true
		}
		if v, ok := m.Value().Int64(); ok {
			return float64(v), true
		}
	}
	return 0, false
}

func TestBudgetGaugesReportEachBudgetAndNeverZeroForUnknownSpend(t *testing.T) {
	cfg := budgetTestConfig(false)
	ledger := routingadmin.NewLedger()
	now := time.Now().UTC()

	// Before the remote spend is read: the limits are known, the spend is absent.
	capture := recordBudgetBatch(t, cfg, ledger, now)
	if n := len(capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetLimit)); n != 2 {
		t.Fatalf("limit gauges = %d, want 2", n)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawBudgetSpend, observability.TelemetryInstrumentDefenseClawBudgetPeakSubjectSpend,
		observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded,
	} {
		if n := len(capturedMetrics(capture, name)); n != 0 {
			t.Fatalf("%s must be absent while spend loads, got %d series", name, n)
		}
	}

	ledger.ApplyRemote([]string{"daily", "eng"}, nil, now)
	ledger.Charge([]string{"user:daily:*:1001"}, 4, now)
	ledger.Charge([]string{"user:daily:*:1002"}, 11, now)
	ledger.Charge([]string{"group:eng:" + `DCLAB\eng` + ":pool"}, 7, now)
	capture = recordBudgetBatch(t, cfg, ledger, now)
	for _, want := range []struct {
		name, id string
		value    float64
	}{
		{observability.TelemetryInstrumentDefenseClawBudgetSpend, "daily", 15},
		{observability.TelemetryInstrumentDefenseClawBudgetPeakSubjectSpend, "daily", 11},
		{observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded, "daily", 1}, // the 10 USD limit: only the 11 USD user
		{observability.TelemetryInstrumentDefenseClawBudgetSpend, "eng", 7},
		{observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded, "eng", 0}, // 7 of 100 USD: a real 0, spend is known
	} {
		if got, ok := budgetValue(t, capture, want.name, want.id); !ok || got != want.value {
			t.Errorf("%s{%s} = %v (present %v), want %v", want.name, want.id, got, ok, want.value)
		}
	}
	// No subject, user id or group name is a label anywhere.
	for _, m := range capture.metricSnapshot() {
		for k, v := range m.Attributes() {
			if strings.Contains(fmt.Sprint(v), "1001") || strings.Contains(fmt.Sprint(v), "DCLAB") || strings.Contains(k, "subject") {
				t.Fatalf("budget gauge leaked a subject: %v", m.Attributes())
			}
		}
	}
	// No store configured: no store gauges.
	for _, name := range []string{observability.TelemetryInstrumentDefenseClawBudgetStoreHealthy, observability.TelemetryInstrumentDefenseClawBudgetStoreSyncAge} {
		if n := len(capturedMetrics(capture, name)); n != 0 {
			t.Fatalf("%s without a fleet store: %d series", name, n)
		}
	}
}

func TestBudgetGaugesPooledMarkerIsNotAnExportedSpend(t *testing.T) {
	cfg := budgetTestConfig(false)
	ledger := routingadmin.NewLedger()
	now := time.Now().UTC()
	ledger.ApplyRemote([]string{"daily", "eng"}, nil, now)
	// The fleet store answers a pooled budget with over the limit only.
	ledger.Charge([]string{"group:eng:" + `DCLAB\eng` + ":pool"}, budgetstore.ExceededUSD, now)
	capture := recordBudgetBatch(t, cfg, ledger, now)
	if _, ok := budgetValue(t, capture, observability.TelemetryInstrumentDefenseClawBudgetSpend, "eng"); ok {
		t.Fatal("a pooled over-the-limit marker must not be exported as a spend")
	}
	if got, ok := budgetValue(t, capture, observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded, "eng"); !ok || got != 1 {
		t.Fatalf("a marked pooled budget is over its limit: got %v present %v", got, ok)
	}
}

func TestBudgetGaugesUnderAFleetStore(t *testing.T) {
	cfg := budgetTestConfig(true)
	ledger := routingadmin.NewLedger()
	now := time.Now().UTC()
	ledger.ApplyRemote([]string{"daily", "eng"}, nil, now)
	ledger.Charge([]string{"user:daily:*:1001"}, 4, now)
	ledger.Charge([]string{"group:eng:" + `DCLAB\eng` + ":pool"}, 7, now) // this device's share only
	capture := recordBudgetBatch(t, cfg, ledger, now)
	if _, ok := budgetValue(t, capture, observability.TelemetryInstrumentDefenseClawBudgetSpend, "eng"); ok {
		t.Fatal("under a fleet store a pooled budget's spend is this device's share only and must stay absent")
	}
	if got, ok := budgetValue(t, capture, observability.TelemetryInstrumentDefenseClawBudgetSpend, "daily"); !ok || got != 4 {
		t.Fatalf("a per-user budget keeps its spend under a store: %v %v", got, ok)
	}
	// This device's 7 of 100 USD share is not "over the limit": only the store's marker says that.
	if got, ok := budgetValue(t, capture, observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded, "eng"); !ok || got != 0 {
		t.Fatalf("a pooled budget under its limit must not read as exceeded under a store: %v %v", got, ok)
	}
	// The store never answered: healthy, but no sync age yet (never a made-up 0).
	if n := len(capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetStoreHealthy)); n != 1 {
		t.Fatalf("store healthy gauges = %d", n)
	}
	if n := len(capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetStoreSyncAge)); n != 0 {
		t.Fatalf("sync age before the fleet ever answered = %d series, want absent", n)
	}
	// The fleet answers: the age starts at 0 and grows.
	ledger.MarkFleetRead(now)
	capture = recordBudgetBatch(t, cfg, ledger, now.Add(90*time.Second))
	age := capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetStoreSyncAge)
	if len(age) != 1 {
		t.Fatalf("sync age series = %d", len(age))
	}
	if v, ok := age[0].Value().Double(); !ok || v != 90 {
		t.Fatalf("sync age = %v, want 90 s", age[0].Value())
	}
	// The store goes down: ApplyRemote from the device's own store must not refresh the age,
	// and the failure turns healthy to 0.
	ledger.ApplyRemote([]string{"daily", "eng"}, nil, now.Add(120*time.Second))
	ledger.SyncFailed(errors.New("store unreachable"))
	capture = recordBudgetBatch(t, cfg, ledger, now.Add(300*time.Second))
	age = capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetStoreSyncAge)
	if len(age) != 1 {
		t.Fatalf("sync age series = %d", len(age))
	}
	if v, _ := age[0].Value().Double(); v != 300 {
		t.Fatalf("sync age during an outage = %v, want 300 s (the last fleet answer, not the last fallback)", v)
	}
	healthy := capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawBudgetStoreHealthy)
	if len(healthy) != 1 {
		t.Fatalf("store healthy gauges = %d", len(healthy))
	}
	if v, _ := healthy[0].Value().Int64(); v != 0 {
		t.Fatalf("healthy during an outage = %v, want 0", v)
	}
}

func TestBudgetGaugesCostNothingWithoutBudgets(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{}
	if items := budgetMetricBatchFor(t.Context(), time.Now(), cfg, routingadmin.NewLedger()); items != nil {
		t.Fatalf("no budgets must emit nothing, got %d items", len(items))
	}
	if items := budgetMetricBatchFor(t.Context(), time.Now(), &config.Config{}, nil); items != nil {
		t.Fatalf("no routing.admin must emit nothing, got %d items", len(items))
	}
}

func TestRouteCategoryLabelIsBoundedWhateverTheClassifierSays(t *testing.T) {
	set := &boundedLabelSet{seen: map[string]struct{}{}, max: 4}
	var got []string
	for _, v := range []string{"coding", "chat", "coding", "a", "b", "c", "has spaces", ""} {
		got = append(got, set.bound(v))
	}
	want := []string{"coding", "chat", "coding", "a", "b", "other", "other", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bound #%d = %q, want %q (all %v)", i, got[i], want[i], got)
		}
	}
}

func baselinePricing() config.PricingConfig {
	return config.PricingConfig{
		Version: "t1",
		Models: []config.PriceEntryConfig{
			{Provider: "anthropic", Model: "claude-haiku-4-5*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usageF64(1), OutputPerMTok: usageF64(5)}},
			{Provider: "anthropic", Model: "claude-sonnet-4-5*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usageF64(3), OutputPerMTok: usageF64(15)}},
			{Provider: "ollama", Model: "qwen*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usageF64(0), OutputPerMTok: usageF64(0)}},
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

func TestModelUsageSinkAFreeRequestedModelStillCountsTheCompareSide(t *testing.T) {
	engine, capture := newUsageTestEngine(t, []string{"logs", "metrics"}, baselinePricing())
	call := engine.Begin(context.Background(), modelusage.CallFacts{
		RequestID: "req-base-3", Connector: "codex", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
		RequestedProvider: "ollama", RequestedModel: "qwen2.5:1.5b",
		SelectedProvider: "anthropic", SelectedModel: "claude-sonnet-4-5",
		Route: modelusage.RouteFacts{Decision: modelusage.DecisionApplied},
	})
	call.Usage(modelusage.ParsedUsage{Input: 1000, Output: 500, Has: modelusage.HasInput | modelusage.HasOutput})
	rec := call.End(nil)
	if rec.Cost.USD == nil || rec.Cost.BaselineUSD == nil || *rec.Cost.BaselineUSD != 0 || *rec.Cost.USD <= 0 {
		t.Fatalf("free requested model: %+v", rec.Cost)
	}
	body, _ := usageLogBody(t, capture, true)
	if v, present := body["defenseclaw.cost.baseline_usd"].(float64); !present || v != 0 {
		t.Fatalf("a free requested model has a known baseline of 0: %v", body)
	}
	var names map[string]struct{}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		_, metrics := capture.snapshot()
		names = hookModelV8CapturedMetricNames(metrics)
		if _, ok := names[observability.TelemetryInstrumentDefenseClawModelCostCompared]; ok {
			break
		}
	}
	if _, ok := names[observability.TelemetryInstrumentDefenseClawModelCostCompared]; !ok {
		t.Fatalf("the spend on a call a free model would have served must reach compared: %v", names)
	}
	if _, ok := names[observability.TelemetryInstrumentDefenseClawModelCostBaseline]; ok {
		t.Fatal("a baseline of 0 adds nothing to the baseline counter")
	}
}

func TestRoutedMetricOutcomeReportsWhatTheCallDid(t *testing.T) {
	applied := SemanticRouteOutcome{Result: SemanticRouteApplied, FailureCode: SemanticRouteFailureNone,
		Decision: &ModelRouterDecision{Model: "m"}, Route: &engine.Decision{FilteredBy: "sensitive"}}
	if got := routedMetricOutcome(applied, true); got.Result != SemanticRouteApplied || got.Decision == nil {
		t.Fatalf("a call that went to the routed model stays applied: %+v", got)
	}
	got := routedMetricOutcome(applied, false)
	if got.Result != SemanticRouteFallback || got.FailureCode != SemanticRouteFailureFiltered || got.Decision != nil {
		t.Fatalf("an applied decision that did not route is a fallback: %+v", got)
	}
	if got.Route == nil || got.Route.FilteredBy != "sensitive" {
		t.Fatalf("the sensitive filter must survive on the fallback so the leak panel counts it: %+v", got.Route)
	}
	withCause := applied
	withCause.FailureCode = SemanticRouteFailureCredential
	if got := routedMetricOutcome(withCause, false); got.FailureCode != SemanticRouteFailureCredential {
		t.Fatalf("a known cause is kept: %+v", got)
	}
	for _, o := range []SemanticRouteOutcome{
		{Result: SemanticRouteFallback, FailureCode: SemanticRouteFailureTimeout},
		{Result: SemanticRouteDenied, FailureCode: SemanticRouteFailureFiltered},
	} {
		if got := routedMetricOutcome(o, false); got.Result != o.Result || got.FailureCode != o.FailureCode {
			t.Fatalf("outcome %+v changed to %+v", o, got)
		}
	}
}

func TestRouteOnlyDecisionMetricFollowsTheFinalRouteChoice(t *testing.T) {
	f := newRouteOnlyFixture(t)
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	f.srv.metrics = func() hookLifecycleMetricV8Runtime { return runtime }
	req := httptest.NewRequest(http.MethodPost, "/r/claudecode/v1/messages", nil)
	applied := SemanticRouteOutcome{Result: SemanticRouteApplied, FailureCode: SemanticRouteFailureNone,
		Decision: &ModelRouterDecision{Model: "m"}, Route: &engine.Decision{Source: "rules", FilteredBy: "sensitive"}}
	f.srv.recordDecision(req, "claudecode", applied, false) // credential could not cross: the original model got the call
	f.srv.recordDecision(req, "claudecode", applied, true)
	f.srv.recordDecision(req, "claudecode", SemanticRouteOutcome{}, false) // the router never looked at it
	got := capturedMetrics(capture, observability.TelemetryInstrumentDefenseClawSemanticRoutingDecision)
	if len(got) != 2 {
		t.Fatalf("decision metrics = %d, want 2 (an unrouted request records none)", len(got))
	}
	results := []string{fmt.Sprint(got[0].Attributes()["defenseclaw.metric.result"]), fmt.Sprint(got[1].Attributes()["defenseclaw.metric.result"])}
	if (results[0] != "fallback" || results[1] != "applied") && (results[0] != "applied" || results[1] != "fallback") {
		t.Fatalf("results = %v", results)
	}
}
