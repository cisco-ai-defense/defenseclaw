// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

const (
	nativeUsageClaudeMatch = "otlp.claudecode.api_request.v1.log.model.response"
	nativeUsageSession     = "5b2c9e0a-61f4-4d0e-9a57-7f3c2f0e9b11"
	nativeUsagePrompt      = "0f6e1c2a-8d4b-4c1e-b0aa-3e9d5f7a1c22"
	nativeUsageRequestID   = "req_011CVxN9aJ5p3kQw2yZ8tR4m"
)

type nativeUsageSink struct {
	mu   sync.Mutex
	recs []modelusage.Record
	ch   chan struct{}
}

func (s *nativeUsageSink) Emit(_ context.Context, rec modelusage.Record) {
	s.mu.Lock()
	s.recs = append(s.recs, rec)
	s.mu.Unlock()
	s.ch <- struct{}{}
}

func (s *nativeUsageSink) one(t *testing.T) modelusage.Record {
	t.Helper()
	select {
	case <-s.ch:
	case <-time.After(3 * time.Second):
		t.Fatal("no usage record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recs[len(s.recs)-1]
}

func (s *nativeUsageSink) none(t *testing.T) {
	t.Helper()
	select {
	case <-s.ch:
		t.Fatalf("unexpected usage record %+v", s.recs)
	case <-time.After(150 * time.Millisecond):
	}
}

// installNativeUsageEngine makes a test engine the process usage engine.
func installNativeUsageEngine(t *testing.T, tok config.TokenomicsConfig) *nativeUsageSink {
	t.Helper()
	sink := &nativeUsageSink{ch: make(chan struct{}, 64)}
	engine := modelusage.NewEngine(sink)
	engine.Apply(tok, nativeUsagePricing())
	previous := processModelUsage.Swap(engine)
	t.Cleanup(func() {
		engine.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
		processModelUsage.Store(previous)
	})
	return sink
}

func nativeUsagePricing() config.PricingConfig {
	price := func(v float64) *float64 { return &v }
	return config.PricingConfig{Version: "native-test", Models: []config.PriceEntryConfig{
		{Provider: "anthropic", Model: "claude-sonnet-4-5*", PriceRatesConfig: config.PriceRatesConfig{
			InputPerMTok: price(3), OutputPerMTok: price(15), CacheReadPerMTok: price(0.3), CacheWritePerMTok: price(3.75),
		}},
		{Provider: "openai", Model: "gpt-5*", PriceRatesConfig: config.PriceRatesConfig{
			InputPerMTok: price(1.25), OutputPerMTok: price(10), CacheReadPerMTok: price(0.125),
		}},
	}}
}

func setNativeUsageSuppressed(t *testing.T, fn func(string) bool) {
	t.Helper()
	previous := nativeUsageSuppressed
	nativeUsageSuppressed = fn
	t.Cleanup(func() { nativeUsageSuppressed = previous })
}

func nativeDoubleAttribute(key string, value float64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: value}}}
}

// claudeAPIRequestAttributes is a claude_code.api_request log as Claude Code
// 2.1.322 exports it (attribute names and value types read from its event
// logger): event.name without the claude_code. prefix, integer token counts,
// a double cost_usd for this request alone.
func claudeAPIRequestAttributes() []*commonpb.KeyValue {
	return []*commonpb.KeyValue{
		otlpClassifierStringAttribute("user.id", "3f1d2c7b9a8e"),
		otlpClassifierStringAttribute("session.id", nativeUsageSession),
		otlpClassifierStringAttribute("terminal.type", "tmux"),
		otlpClassifierStringAttribute("event.name", "api_request"),
		otlpClassifierStringAttribute("event.timestamp", "2026-11-12T10:00:00.000Z"),
		otlpClassifierIntAttribute("event.sequence", 7),
		otlpClassifierStringAttribute("prompt.id", nativeUsagePrompt),
		otlpClassifierStringAttribute("model", "claude-sonnet-4-5-20250929"),
		otlpClassifierIntAttribute("input_tokens", 12),
		otlpClassifierIntAttribute("output_tokens", 431),
		otlpClassifierIntAttribute("cache_read_tokens", 18240),
		otlpClassifierIntAttribute("cache_creation_tokens", 2051),
		otlpClassifierIntAttribute("cache_creation_5m_tokens", 2051),
		otlpClassifierIntAttribute("cache_creation_1h_tokens", 0),
		nativeDoubleAttribute("cost_usd", 0.01990695),
		otlpClassifierIntAttribute("cost_usd_micros", 19907),
		otlpClassifierIntAttribute("duration_ms", 8123),
		otlpClassifierIntAttribute("ttft_ms", 1460),
		otlpClassifierStringAttribute("request_id", nativeUsageRequestID),
		otlpClassifierStringAttribute("client_request_id", "9a1f7c3e-2b4d-4e8f-a6c1-5d7e9f0b2a33"),
		otlpClassifierStringAttribute("speed", "normal"),
		otlpClassifierStringAttribute("query_source", "repl_main_thread"),
	}
}

func claudeAPIRequestLog(now time.Time, attributes []*commonpb.KeyValue) *collectorlogspb.ExportLogsServiceRequest {
	return &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "claude-code"),
			otlpClassifierStringAttribute("service.version", "2.1.322"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code.events", Version: "2.1.322"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "claude_code.api_request"}},
				Attributes:   attributes,
			}},
		}},
	}}}
}

func codexCompletedLog(now time.Time, attributes ...*commonpb.KeyValue) *collectorlogspb.ExportLogsServiceRequest {
	base := []*commonpb.KeyValue{
		otlpClassifierStringAttribute("event.name", "codex.sse_event"),
		otlpClassifierStringAttribute("event.kind", "response.completed"),
		otlpClassifierStringAttribute("conversation.id", "019f4f18-3c1c-7f00-80b2-8248d5894a01"),
		otlpClassifierStringAttribute("model", "gpt-5.4"),
	}
	return &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "response.completed"}},
				Attributes:   append(base, attributes...),
			}},
		}},
	}}}
}

func withNativeAttribute(attributes []*commonpb.KeyValue, key string, replacement *commonpb.KeyValue) []*commonpb.KeyValue {
	out := make([]*commonpb.KeyValue, 0, len(attributes))
	for _, attribute := range attributes {
		if attribute.GetKey() == key {
			if replacement != nil {
				out = append(out, replacement)
			}
			continue
		}
		out = append(out, attribute)
	}
	return out
}

func firstNativeLogLeaf(t *testing.T, request proto.Message) otlpDecodedLeaf {
	t.Helper()
	var leaf otlpDecodedLeaf
	found := false
	if _, err := walkDecodedOTLPLeaves(request, otelSignalLogs, func(item otlpDecodedLeaf) error {
		if !found {
			leaf, found = item, true
		}
		return nil
	}); err != nil || !found {
		t.Fatalf("decode leaf: found=%t err=%v", found, err)
	}
	return leaf
}

func TestNativeUsageClaudeAPIRequestDiscriminator(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	now := time.Now().UTC()
	for _, test := range []struct {
		name       string
		attributes []*commonpb.KeyValue
		source     string
		want       otlpInboundIdentityState
	}{
		{"real event name", claudeAPIRequestAttributes(), "claudecode", otlpInboundIdentityMatched},
		{"body-style event name is not what Claude Code sends", withNativeAttribute(claudeAPIRequestAttributes(), "event.name",
			otlpClassifierStringAttribute("event.name", "claude_code.api_request")), "claudecode", otlpInboundIdentityUnsupported},
		{"other connector", claudeAPIRequestAttributes(), "codex", otlpInboundIdentityUnsupported},
		{"api_error is not a call with usage", withNativeAttribute(claudeAPIRequestAttributes(), "event.name",
			otlpClassifierStringAttribute("event.name", "api_error")), "claudecode", otlpInboundIdentityUnsupported},
		{"no model", withNativeAttribute(claudeAPIRequestAttributes(), "model", nil), "claudecode", otlpInboundIdentityUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf := firstNativeLogLeaf(t, claudeAPIRequestLog(now, test.attributes))
			result, err := classifier.classify(leaf, test.source)
			if err != nil || result.identityState != test.want {
				t.Fatalf("state=%d err=%v want=%d", result.identityState, err, test.want)
			}
			if test.want == otlpInboundIdentityMatched && result.match.ID() != nativeUsageClaudeMatch {
				t.Fatalf("match=%q", result.match.ID())
			}
		})
	}
}

func TestNativeUsageClaudeAPIRequestRecordsPerCallUsageJoinedToHooks(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	sink := installNativeUsageEngine(t, config.TokenomicsConfig{Enabled: true})
	const agentID = "agent-5d41402abc4b2a76"
	meta := llmEventMeta{
		Source: "claudecode", SessionID: nativeUsageSession, TurnID: nativeUsagePrompt,
		AgentID: agentID, AgentName: "main", AgentType: "claudecode", RootAgentID: agentID,
		RootSessionID: nativeUsageSession, LineageProvenance: "reported", Phase: "model",
	}
	key := hookSessionStateKey(meta)
	api := &APIServer{hookSessionStates: map[string]hookSessionState{key: {meta: meta}}, hookSessionStateOrder: []string{key}}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), claudeAPIRequestLog(now, claudeAPIRequestAttributes()), otelSignalLogs, "claudecode", now,
	)
	if err != nil || !accounting.valid() {
		t.Fatalf("accounting=%+v err=%v", accounting, err)
	}
	if got := codexNativeStoredEventCount(t, fixture.path, "model.response"); got != 1 {
		t.Fatalf("model.response records=%d want 1", got)
	}
	rec := sink.one(t)
	f, u, c := rec.Facts, rec.Usage, rec.Cost
	if f.Connector != "claudecode" || f.CallRole != modelusage.RoleAgent || f.APIFamily != modelusage.FamilyMessages ||
		f.SelectedProvider != "anthropic" || f.SelectedModel != "claude-sonnet-4-5-20250929" || f.Listener != "native_otel" {
		t.Fatalf("facts %+v", f)
	}
	if f.SessionID != nativeUsageSession || f.TurnID != nativeUsagePrompt || f.AgentID != agentID ||
		f.ModelResponseID != nativeUsageRequestID {
		t.Fatalf("hook correlation %+v", f)
	}
	all := modelusage.HasInput | modelusage.HasOutput | modelusage.HasCacheRead | modelusage.HasCacheCreation
	if u.Has != all || u.Input != 12+18240+2051 || u.CacheRead != 18240 || u.CacheCreation != 2051 ||
		u.Output != 431 || u.Source != modelusage.SourceNativeOTel || u.Partial != "" {
		t.Fatalf("usage %+v", u)
	}
	if c.Basis != modelusage.BasisReported || c.USD == nil || *c.USD != 0.01990695 || c.ComputedUSD == nil {
		t.Fatalf("cost %+v", c)
	}
	want := (12*3 + 18240*0.3 + 2051*3.75 + 431*15) / 1e6
	if diff := *c.ComputedUSD - want; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("computed %v want %v", *c.ComputedUSD, want)
	}
	if rec.Total != 8123*time.Millisecond || rec.TTFB != 1460*time.Millisecond {
		t.Fatalf("timing total=%v ttfb=%v", rec.Total, rec.TTFB)
	}
}

func TestNativeUsageCodexResponseCompletedMapsReasoning(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	sink := installNativeUsageEngine(t, config.TokenomicsConfig{Enabled: true})
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	request := codexCompletedLog(now,
		otlpClassifierStringAttribute("input_token_count", "12770"),
		otlpClassifierStringAttribute("cached_token_count", "2432"),
		otlpClassifierStringAttribute("output_token_count", "19"),
		otlpClassifierStringAttribute("reasoning_token_count", "11"),
	)
	accounting, err := api.importDecodedOTLPRequestV8(context.Background(), request, otelSignalLogs, "codex", now)
	if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 {
		t.Fatalf("accounting=%+v err=%v", accounting, err)
	}
	rec := sink.one(t)
	u := rec.Usage
	want := modelusage.HasInput | modelusage.HasCacheRead | modelusage.HasOutput | modelusage.HasReasoning
	if u.Has != want || u.Input != 12770 || u.CacheRead != 2432 || u.Output != 19 || u.Reasoning != 11 {
		t.Fatalf("usage %+v", u)
	}
	if rec.Facts.APIFamily != modelusage.FamilyResponses || rec.Facts.SelectedProvider != "openai" ||
		rec.Facts.SessionID != "019f4f18-3c1c-7f00-80b2-8248d5894a01" {
		t.Fatalf("facts %+v", rec.Facts)
	}
	if rec.Cost.ReportedUSD != nil || rec.Cost.Basis != modelusage.BasisComputed {
		t.Fatalf("Codex reports no cost; the table prices it: %+v", rec.Cost)
	}
}

func TestNativeUsageAbsentCountsStayAbsent(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	sink := installNativeUsageEngine(t, config.TokenomicsConfig{Enabled: true})
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	attributes := claudeAPIRequestAttributes()
	for _, key := range []string{"cache_read_tokens", "cache_creation_tokens", "cost_usd", "input_tokens"} {
		attributes = withNativeAttribute(attributes, key, nil)
	}
	attributes = withNativeAttribute(attributes, "output_tokens", otlpClassifierIntAttribute("output_tokens", 0))
	if _, err := api.importDecodedOTLPRequestV8(context.Background(), claudeAPIRequestLog(now, attributes), otelSignalLogs, "claudecode", now); err != nil {
		t.Fatal(err)
	}
	rec := sink.one(t)
	if rec.Usage.Has != modelusage.HasOutput || rec.Usage.Output != 0 || rec.Cost.ReportedUSD != nil ||
		rec.Cost.USD != nil || rec.Cost.Basis != modelusage.BasisNone {
		t.Fatalf("absent counts and cost must stay absent, the zero output present: %+v %+v", rec.Usage, rec.Cost)
	}
	codex := codexCompletedLog(now,
		otlpClassifierStringAttribute("input_token_count", "5"),
		otlpClassifierStringAttribute("output_token_count", "0"),
	)
	if _, err := api.importDecodedOTLPRequestV8(context.Background(), codex, otelSignalLogs, "codex", now); err != nil {
		t.Fatal(err)
	}
	rec = sink.one(t)
	if rec.Usage.Has != modelusage.HasInput|modelusage.HasOutput || rec.Usage.Output != 0 {
		t.Fatalf("no cached or reasoning count was sent: %+v", rec.Usage)
	}
}

func TestNativeUsageGatingAndProxySuppression(t *testing.T) {
	off := false
	for _, test := range []struct {
		name     string
		tok      config.TokenomicsConfig
		suppress func(string) bool
		record   bool
	}{
		{name: "tokenomics off", tok: config.TokenomicsConfig{}},
		{name: "claudecode import off", tok: config.TokenomicsConfig{Enabled: true,
			NativeOTelImport: config.TokenomicsNativeImportConfig{ClaudeCode: &off}}},
		{name: "agent role not recorded", tok: config.TokenomicsConfig{Enabled: true, Roles: []string{"judge"}}},
		{name: "proxy carries claudecode", tok: config.TokenomicsConfig{Enabled: true},
			suppress: func(connector string) bool { return connector == "claudecode" }},
		{name: "proxy carries codex only", tok: config.TokenomicsConfig{Enabled: true},
			suppress: func(connector string) bool { return connector == "codex" }, record: true},
		{name: "codex import off", tok: config.TokenomicsConfig{Enabled: true,
			NativeOTelImport: config.TokenomicsNativeImportConfig{Codex: &off}}, record: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCodexNativeOTLPFixture(t)
			sink := installNativeUsageEngine(t, test.tok)
			if test.suppress != nil {
				setNativeUsageSuppressed(t, test.suppress)
			}
			api := &APIServer{}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			now := time.Now().UTC()
			accounting, err := api.importDecodedOTLPRequestV8(
				context.Background(), claudeAPIRequestLog(now, claudeAPIRequestAttributes()), otelSignalLogs, "claudecode", now,
			)
			if err != nil || !accounting.valid() {
				t.Fatalf("accounting=%+v err=%v", accounting, err)
			}
			// The native import itself is the cross-check and always runs.
			if got := codexNativeStoredEventCount(t, fixture.path, "model.response"); got != 1 {
				t.Fatalf("model.response records=%d want 1", got)
			}
			if test.record {
				sink.one(t)
			} else {
				sink.none(t)
			}
		})
	}
	if nativeUsageSuppressed("claudecode") || nativeUsageSuppressed("codex") {
		t.Fatal("the default must never suppress")
	}
}

func TestNativeUsageNeverTakesCumulativeCostAsPerCall(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	sink := installNativeUsageEngine(t, config.TokenomicsConfig{Enabled: true})
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	// A request event that names running totals but no per-call cost_usd.
	attributes := withNativeAttribute(claudeAPIRequestAttributes(), "cost_usd", nil)
	attributes = append(attributes, nativeDoubleAttribute("total_cost_usd", 4.75), nativeDoubleAttribute("session_cost_usd", 4.75))
	if _, err := api.importDecodedOTLPRequestV8(context.Background(), claudeAPIRequestLog(now, attributes), otelSignalLogs, "claudecode", now); err != nil {
		t.Fatal(err)
	}
	rec := sink.one(t)
	if rec.Cost.ReportedUSD != nil || rec.Cost.Basis != modelusage.BasisComputed {
		t.Fatalf("a running total became the call cost: %+v", rec.Cost)
	}
	// claude_code.cost.usage (a USD counter, cumulative or delta) derives no usage record.
	value := 4.75
	counter := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{otlpClassifierStringAttribute("service.name", "claude-code")}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{
			Scope: &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code"},
			Metrics: []*metricspb.Metric{{
				Name: "claude_code.cost.usage", Unit: "USD",
				Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
					AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, IsMonotonic: true,
					DataPoints: []*metricspb.NumberDataPoint{{
						StartTimeUnixNano: uint64(now.Add(-time.Minute).UnixNano()), TimeUnixNano: uint64(now.UnixNano()),
						Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
						Attributes: []*commonpb.KeyValue{
							otlpClassifierStringAttribute("session.id", nativeUsageSession),
							otlpClassifierStringAttribute("model", "claude-sonnet-4-5-20250929"),
						},
					}},
				}},
			}},
		}},
	}}}
	if _, err := api.importDecodedOTLPRequestV8(context.Background(), counter, otelSignalMetrics, "claudecode", now); err != nil {
		t.Fatal(err)
	}
	sink.none(t)
}

func TestNativeUsageMalformedCountIsDroppedNotZero(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	sink := installNativeUsageEngine(t, config.TokenomicsConfig{Enabled: true})
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	attributes := withNativeAttribute(claudeAPIRequestAttributes(), "cache_read_tokens",
		otlpClassifierStringAttribute("cache_read_tokens", "lots"))
	attributes = withNativeAttribute(attributes, "speed", otlpClassifierStringAttribute("speed", "fast"))
	if _, err := api.importDecodedOTLPRequestV8(context.Background(), claudeAPIRequestLog(now, attributes), otelSignalLogs, "claudecode", now); err != nil {
		t.Fatal(err)
	}
	rec := sink.one(t)
	if rec.Usage.Has&(modelusage.HasInput|modelusage.HasCacheRead) != 0 || rec.Usage.Has&modelusage.HasOutput == 0 ||
		rec.Usage.Anomaly != "invalid_count" || rec.Usage.Partial != "speed:fast" {
		t.Fatalf("a malformed cache count must drop the input total, not read as 0: %+v", rec.Usage)
	}
	if rec.Cost.Basis != modelusage.BasisReported {
		t.Fatalf("the reported call cost stays: %+v", rec.Cost)
	}
}

func TestNativeClaudeProvider(t *testing.T) {
	for model, want := range map[string]string{
		"claude-sonnet-4-5-20250929":                                               "anthropic",
		"us.anthropic.claude-sonnet-4-5-20250929-v1:0":                             "bedrock",
		"anthropic.claude-haiku-4-5-20251001-v1:0":                                 "bedrock",
		"arn:aws:bedrock:us-east-1:000000000000:application-inference-profile/abc": "bedrock",
		"": "anthropic",
	} {
		if got := nativeClaudeProvider(model); got != want {
			t.Fatalf("%q: %q want %q", model, got, want)
		}
	}
}
