// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"google.golang.org/protobuf/proto"
)

const usageBody = `{"id":"msg_1","type":"message","model":"claude-haiku-4-5-20251001","usage":{"input_tokens":12,"cache_creation_input_tokens":100,"cache_read_input_tokens":2000,"output_tokens":34}}`

func usageF64(v float64) *float64 { return &v }

func usageTestPricing() config.PricingConfig {
	return config.PricingConfig{
		Version: "t1",
		Models: []config.PriceEntryConfig{{
			Provider: "anthropic", Model: "claude-haiku-4-5*",
			PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usageF64(1), OutputPerMTok: usageF64(5), CacheReadPerMTok: usageF64(0.1), CacheWritePerMTok: usageF64(1.25)},
		}},
	}
}

func newUsageTestEngine(t *testing.T, signals []string, pricing config.PricingConfig) (*modelusage.Engine, *hookModelV8OTLPCapture) {
	t.Helper()
	api, capture := bindHookModelV8Runtime(t, signals)
	sink := newModelUsageV8Sink(
		func() sidecarRuntimeEmitter { return api.observabilityV8RuntimeEmitter() },
		func() hookLifecycleMetricV8Runtime {
			r, _ := api.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
			return r
		},
	)
	engine := modelusage.NewEngine(sink)
	engine.Apply(config.TokenomicsConfig{Enabled: true}, pricing)
	t.Cleanup(func() { engine.Apply(config.TokenomicsConfig{}, config.PricingConfig{}) })
	return engine, capture
}

// usageLogBody returns the decoded body of the exported model.usage record, and the wire bytes.
func usageLogBody(t *testing.T, capture *hookModelV8OTLPCapture, wantMetrics bool) (map[string]any, []byte) {
	t.Helper()
	var body map[string]any
	var wire []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		body, wire = nil, wire[:0]
		for _, request := range capture.logSnapshot() {
			encoded, _ := proto.Marshal(request)
			wire = append(wire, encoded...)
			for _, resource := range request.GetResourceLogs() {
				for _, scope := range resource.GetScopeLogs() {
					for _, record := range scope.GetLogRecords() {
						if logStringAttribute(record.GetAttributes(), "defenseclaw.event.name") != observability.TelemetryEventModelUsage {
							continue
						}
						var envelope struct {
							Body map[string]any `json:"body"`
						}
						if json.Unmarshal([]byte(record.GetBody().GetStringValue()), &envelope) == nil {
							body = envelope.Body
						}
					}
				}
			}
		}
		_, metrics := capture.snapshot()
		names := hookModelV8CapturedMetricNames(metrics)
		_, haveCost := names[observability.TelemetryInstrumentDefenseClawModelCost]
		_, haveTokens := names[observability.TelemetryInstrumentDefenseClawModelTokens]
		if body != nil && (!wantMetrics || (haveCost && haveTokens)) {
			return body, wire
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no model.usage record exported (body=%v)", body)
	return nil, nil
}

func TestModelUsageSinkEmitsGeneratedLogAndMetrics(t *testing.T) {
	engine, capture := newUsageTestEngine(t, []string{"logs", "metrics"}, usageTestPricing())
	call := engine.Begin(context.Background(), modelusage.CallFacts{
		RequestID: "req-usage-1", Connector: "claudecode", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
		RequestedProvider: "anthropic", RequestedModel: "claude-sonnet-4-5",
		SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
		Route:       modelusage.RouteFacts{Decision: modelusage.DecisionApplied, Source: "rules", Category: "coding", RuleID: "cheap-coding"},
		ProfileName: "eng", ProfileDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Subject: "1201", SubjectKind: "posix_uid", Groups: []string{"secret-group-name"}, IdentityVerified: true,
	})
	call.UpstreamHeader(200, nil)
	call.Body([]byte(usageBody))
	rec := call.End(nil)
	if rec.Cost.USD == nil {
		t.Fatalf("priced call has no cost: %+v", rec.Cost)
	}
	body, wire := usageLogBody(t, capture, true)
	num := func(k string) float64 { v, _ := body[k].(float64); return v }
	str := func(k string) string { v, _ := body[k].(string); return v }
	if num("gen_ai.usage.input_tokens") != 2112 || num("gen_ai.usage.output_tokens") != 34 ||
		num("defenseclaw.usage.cache_read_tokens") != 2000 || num("defenseclaw.usage.cache_creation_tokens") != 100 {
		t.Fatalf("token fields wrong: %v", body)
	}
	if _, present := body["defenseclaw.usage.reasoning_tokens"]; present {
		t.Fatal("an absent reasoning count must stay absent")
	}
	if str("gen_ai.request.model") != "claude-sonnet-4-5" || str("defenseclaw.model.selected") != "claude-haiku-4-5-20251001" ||
		str("defenseclaw.route.decision") != "applied" || str("defenseclaw.route.rule_id") != "cheap-coding" ||
		str("defenseclaw.api.family") != "messages" || str("defenseclaw.call.role") != "agent" ||
		str("defenseclaw.cost.basis") != "computed" || str("defenseclaw.pricing.version") != "t1" ||
		str("defenseclaw.usage.source") != "provider" || str("defenseclaw.guardrail.profile.name") != "eng" {
		t.Fatalf("provenance fields wrong: %v", body)
	}
	if got := num("defenseclaw.cost.usd"); got <= 0 || got != *rec.Cost.USD {
		t.Fatalf("cost.usd = %v, want %v", got, *rec.Cost.USD)
	}
	if bytes.Contains(wire, []byte("secret-group-name")) {
		t.Fatal("a directory group name reached an exported record")
	}
	if _, present := body["defenseclaw.guardrail.profile.matched_group"]; present {
		t.Fatal("matched_group must never be set on a usage record")
	}
}

func TestModelUsageSinkAbsentCostIsAbsentNotZero(t *testing.T) {
	engine, capture := newUsageTestEngine(t, []string{"logs", "metrics"}, config.PricingConfig{}) // no price table
	call := engine.Begin(context.Background(), modelusage.CallFacts{
		RequestID: "req-usage-2", Connector: "codex", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
		SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5",
	})
	call.Body([]byte(usageBody))
	call.End(nil)
	body, _ := usageLogBody(t, capture, false)
	if _, present := body["defenseclaw.cost.usd"]; present {
		t.Fatal("unknown cost must be absent, never 0")
	}
	if body["defenseclaw.cost.basis"] != "none" {
		t.Fatalf("basis = %v", body["defenseclaw.cost.basis"])
	}
	var names map[string]struct{}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		_, metrics := capture.snapshot()
		names = hookModelV8CapturedMetricNames(metrics)
		if _, ok := names[observability.TelemetryInstrumentDefenseClawModelTokens]; ok {
			break
		}
	}
	if _, ok := names[observability.TelemetryInstrumentDefenseClawModelCost]; ok {
		t.Fatal("a call with no cost must not touch defenseclaw.model.cost")
	}
	if _, ok := names[observability.TelemetryInstrumentDefenseClawModelTokens]; !ok {
		t.Fatal("tokens are known, so defenseclaw.model.tokens must be recorded")
	}
}

func TestModelUsageMetricsDirectError(t *testing.T) {
	api, _ := bindHookModelV8Runtime(t, []string{"metrics"})
	rt, _ := api.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	if rt == nil {
		t.Fatal("no lifecycle metric runtime")
	}
	rec := modelusage.Record{
		Facts:   modelusage.CallFacts{RequestID: "r", Connector: "codex", SelectedProvider: "anthropic"},
		Usage:   modelusage.Usage{Input: 10, Output: 5, Has: modelusage.HasInput | modelusage.HasOutput},
		EndedAt: time.Now(), Labels: []modelusage.Label{{Key: "connector", Value: "codex"}, {Key: "provider", Value: "anthropic"}, {Key: "model", Value: "anthropic/claude-haiku-4-5*"}, {Key: "route_decision", Value: "applied"}, {Key: "call_role", Value: "agent"}, {Key: "profile", Value: "eng"}},
		Cost: modelusage.Cost{USD: usageF64(0.01), Basis: modelusage.BasisComputed},
	}
	if err := emitModelUsageMetricsV8(context.Background(), rt, rec); err != nil {
		t.Fatalf("metric batch error: %v", err)
	}
}

func TestModelUsageLogDirectError(t *testing.T) {
	api, _ := bindHookModelV8Runtime(t, []string{"logs"})
	rec := modelusage.Record{
		Facts: modelusage.CallFacts{
			RequestID: "r", Connector: "claudecode", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
			SelectedProvider: "anthropic", SelectedModel: "m", RequestedModel: "m2",
			Route:       modelusage.RouteFacts{Decision: "applied", Source: "rules", Category: "coding", RuleID: "cheap-coding"},
			ProfileName: "eng", ProfileDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Subject: "1201", SubjectKind: "posix_uid", IdentityVerified: true,
		},
		Usage:   modelusage.Usage{Input: 10, Output: 5, Has: modelusage.HasInput | modelusage.HasOutput},
		Outcome: "completed", EndedAt: time.Now(),
	}
	if err := emitModelUsageLogV8(context.Background(), api.observabilityV8RuntimeEmitter(), rec); err != nil {
		t.Fatalf("log emit error: %v", err)
	}
}

func TestModelUsageBuildErrorDetail(t *testing.T) {
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "x", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope := observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: "claudecode", Action: "model_usage", Phase: "model",
		Provenance: observability.FamilyProvenanceInput{Producer: modelUsageV8Producer, BinaryVersion: "test", ConfigGeneration: 1,
			ConfigDigest: "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	rec := modelusage.Record{
		Facts: modelusage.CallFacts{
			RequestID: "r", Connector: "claudecode", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
			SelectedProvider: "anthropic", SelectedModel: "m", RequestedModel: "m2",
			Route:       modelusage.RouteFacts{Decision: "applied", Source: "rules", Category: "coding", RuleID: "cheap-coding"},
			ProfileName: "eng", ProfileDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Subject: "1201", SubjectKind: "posix_uid", IdentityVerified: true,
		},
		Usage:   modelusage.Usage{Input: 10, Output: 5, Has: modelusage.HasInput | modelusage.HasOutput},
		Cost:    modelusage.Cost{Basis: modelusage.BasisComputed, PriceEntry: "anthropic/claude-haiku-4-5*", TableVersion: "t1", TableDigest: "00ff"},
		Outcome: "completed", EndedAt: time.Now(),
	}
	if _, err := builder.BuildLogModelUsage(buildModelUsageLogInput(envelope, rec)); err != nil {
		t.Fatalf("build: %v", err)
	}
}

func TestModelUsageIsAppliedToTheModelSpan(t *testing.T) {
	cost := 0.0042
	rec := modelusage.Record{
		Facts: modelusage.CallFacts{
			RequestID: "r1", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
			SelectedModel: "claude-haiku-4-5", Route: modelusage.RouteFacts{Decision: modelusage.DecisionApplied, RuleID: "cheap"},
		},
		Usage: modelusage.Usage{Input: 100, Output: 20, CacheRead: 60, Has: modelusage.HasInput | modelusage.HasOutput | modelusage.HasCacheRead, Source: modelusage.SourceProvider},
		Cost:  modelusage.Cost{USD: &cost, Basis: modelusage.BasisComputed, TableVersion: "t1"},
		Total: 250 * time.Millisecond,
	}
	var in observability.SpanModelChatInput
	applyModelUsageToSpanV8(&in, rec)
	if v, ok := in.GenAIUsageInputTokens.Get(); !ok || v != 100 {
		t.Fatalf("input tokens %v %v", v, ok)
	}
	if v, ok := in.DefenseClawUsageCacheReadTokens.Get(); !ok || v != 60 {
		t.Fatalf("cache read %v %v", v, ok)
	}
	if _, ok := in.DefenseClawUsageReasoningTokens.Get(); ok {
		t.Fatal("an absent reasoning count must stay absent on the span")
	}
	if v, ok := in.DefenseClawCostUsd.Get(); !ok || v != cost {
		t.Fatalf("cost %v %v", v, ok)
	}
	if v, ok := in.DefenseClawCostBasis.Get(); !ok || v != "computed" {
		t.Fatalf("basis %v %v", v, ok)
	}
	var none observability.SpanModelChatInput
	applyModelUsageToSpanV8(&none, modelusage.Record{})
	if _, ok := none.DefenseClawCostUsd.Get(); ok {
		t.Fatal("an empty record must not touch the span")
	}
}
