// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// Native usage is reconciled per call with the route-only listener
// (rel-1-0-10 GAP-1227, GAP-0223): a call the listener recorded is counted
// once, whatever order the listener record and the agent's OTLP export
// arrive in, and a call the listener did not record is counted from the
// export, whatever the config says when it arrives. The tests drive only the
// OTLP import and the usage recorder calls the listener makes.

const (
	perCallRequestA = "req_011CVxN9aJ5p3kQw2yZ8tR4m"
	perCallRequestB = "req_011CVxPq7Lm2dRt8WkZ4yB6c"
)

type perCallUsage struct {
	t       *testing.T
	sink    *nativeUsageSink
	spend   *countingSpendSink
	api     *APIServer
	sidecar *Sidecar
}

// routeOnlyClaudeConfig is config.yaml with Claude Code routed route-only
// (routing on or off) and tokenomics on.
func routeOnlyClaudeConfig(routing bool, connectors ...string) *config.Config {
	cfg := &config.Config{}
	cfg.Observability.Tokenomics.Enabled = true
	cfg.Routing.Enabled = routing
	cfg.Routing.RouteOnly.Connectors = connectors
	cfg.Routing.RouteOnly.Upstreams = map[string]config.RoutingUpstreamConfig{
		"claudecode": {BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages},
	}
	return cfg
}

// newPerCallUsage installs a test usage engine. A non-nil cfg is applied
// first as the gateway applies config.yaml on start (and later reloads go
// through p.reload).
func newPerCallUsage(t *testing.T, cfg *config.Config) *perCallUsage {
	t.Helper()
	p := &perCallUsage{t: t}
	if cfg != nil {
		previous := processModelUsage.Load()
		p.sidecar = &Sidecar{}
		p.sidecar.applyModelUsage(cfg)
		t.Cleanup(func() {
			p.sidecar.stopModelUsage()
			processModelUsage.Store(previous)
		})
	}
	fixture := newCodexNativeOTLPFixture(t)
	p.sink = installNativeUsageEngine(t, config.TokenomicsConfig{Enabled: true})
	p.spend = &countingSpendSink{}
	processModelUsage.Load().SetSpendSink(p.spend)
	p.api = &APIServer{}
	p.api.bindOTLPObservabilityRuntime(fixture.runtime)
	return p
}

func (p *perCallUsage) reload(cfg *config.Config) {
	p.sidecar.applyModelUsage(cfg)
}

// begin starts the record the route-only listener makes for one call.
func (p *perCallUsage) begin(connector string, family modelusage.APIFamily, provider, model string) modelusage.Call {
	return processModelUsage.Load().Begin(context.Background(), modelusage.CallFacts{
		Connector: connector, Listener: "route_only", APIFamily: family, CallRole: modelusage.RoleAgent,
		SelectedProvider: provider, SelectedModel: model, ChargeKeys: []string{"user:1001"},
	})
}

func (p *perCallUsage) beginClaude() modelusage.Call {
	return p.begin("claudecode", modelusage.FamilyMessages, "anthropic", "claude-sonnet-4-5-20250929")
}

// finish ends a listener call as the listener feeds it a non-streamed answer.
func finishListenerCall(call modelusage.Call, requestID, body string) {
	h := http.Header{"Content-Type": {"application/json"}}
	if requestID != "" {
		h.Set("Request-Id", requestID)
	}
	call.UpstreamHeader(http.StatusOK, h)
	call.Body([]byte(body))
	call.End(nil)
}

// claudeAnswer is the Anthropic answer of the call claudeCall reports
// (input_tokens excludes the cache counts on both sides).
func claudeAnswer(output int) string {
	return fmt.Sprintf(`{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":12,"output_tokens":%d,"cache_read_input_tokens":18240,"cache_creation_input_tokens":2051}}`, output)
}

// claudeCall is the claude_code.api_request Claude Code exports for one call.
func claudeCall(requestID string, output int64) []*commonpb.KeyValue {
	attributes := withNativeAttribute(claudeAPIRequestAttributes(), "request_id", otlpClassifierStringAttribute("request_id", requestID))
	attributes = withNativeAttribute(attributes, "client_request_id", otlpClassifierStringAttribute("client_request_id", "client-"+requestID))
	return withNativeAttribute(attributes, "output_tokens", otlpClassifierIntAttribute("output_tokens", output))
}

func (p *perCallUsage) exportClaude(attributes []*commonpb.KeyValue) {
	p.t.Helper()
	now := time.Now().UTC()
	if _, err := p.api.importDecodedOTLPRequestV8(
		context.Background(), claudeAPIRequestLog(now, attributes), otelSignalLogs, "claudecode", now,
	); err != nil {
		p.t.Fatal(err)
	}
}

// records waits for want usage records, checks that no other one follows
// and returns them.
func (p *perCallUsage) records(want int) []modelusage.Record {
	p.t.Helper()
	for i := 0; i < want; i++ {
		p.sink.one(p.t)
	}
	p.sink.none(p.t)
	p.sink.mu.Lock()
	defer p.sink.mu.Unlock()
	return append([]modelusage.Record(nil), p.sink.recs...)
}

func (p *perCallUsage) charges() int {
	p.spend.mu.Lock()
	defer p.spend.mu.Unlock()
	return p.spend.calls
}

func listenerOf(recs []modelusage.Record) map[string]int {
	out := map[string]int{}
	for _, rec := range recs {
		out[rec.Facts.Listener]++
	}
	return out
}

// TestNativeUsagePerCallRecordedCallIsCountedOnce: a call the route-only
// listener recorded and the agent also exported is one record, the
// listener's, and one budget charge, in either arrival order, with or
// without a provider request id on the listener side.
func TestNativeUsagePerCallRecordedCallIsCountedOnce(t *testing.T) {
	for _, test := range []struct {
		name          string
		nativeFirst   bool
		listenerReqID string
	}{
		{name: "listener first, request id", listenerReqID: perCallRequestA},
		{name: "listener first, token counts only"},
		{name: "native first while the listener call is in flight, request id", nativeFirst: true, listenerReqID: perCallRequestA},
		{name: "native first while the listener call is in flight, token counts only", nativeFirst: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newPerCallUsage(t, nil)
			call := p.beginClaude()
			if test.nativeFirst {
				p.exportClaude(claudeCall(perCallRequestA, 431))
				finishListenerCall(call, test.listenerReqID, claudeAnswer(431))
			} else {
				finishListenerCall(call, test.listenerReqID, claudeAnswer(431))
				p.exportClaude(claudeCall(perCallRequestA, 431))
			}
			recs := p.records(1)
			if recs[0].Facts.Listener != "route_only" || recs[0].Usage.Output != 431 {
				t.Fatalf("the listener record is the one counted: %+v", recs[0])
			}
			if got := p.charges(); got != 1 {
				t.Fatalf("budget charges = %d, want 1", got)
			}
		})
	}
	t.Run("codex, token counts only", func(t *testing.T) {
		p := newPerCallUsage(t, nil)
		call := p.begin("codex", modelusage.FamilyResponses, "openai", "gpt-5.4")
		finishListenerCall(call, "", `{"model":"gpt-5.4","usage":{"input_tokens":12770,"input_tokens_details":{"cached_tokens":2432},"output_tokens":19,"output_tokens_details":{"reasoning_tokens":11}}}`)
		now := time.Now().UTC()
		if _, err := p.api.importDecodedOTLPRequestV8(context.Background(), codexCompletedLog(now,
			otlpClassifierStringAttribute("input_token_count", "12770"),
			otlpClassifierStringAttribute("cached_token_count", "2432"),
			otlpClassifierStringAttribute("output_token_count", "19"),
			otlpClassifierStringAttribute("reasoning_token_count", "11"),
		), otelSignalLogs, "codex", now); err != nil {
			t.Fatal(err)
		}
		if recs := p.records(1); recs[0].Facts.Listener != "route_only" {
			t.Fatalf("the listener record is the one counted: %+v", recs[0])
		}
	})
}

// TestNativeUsagePerCallUnrecordedCallIsCounted: Claude Code is routed
// route-only, but this call never reached the listener (a session started
// before routing enable, a managed user not rendered yet, gateway signing
// that could not start): its native usage is the only record of it.
func TestNativeUsagePerCallUnrecordedCallIsCounted(t *testing.T) {
	t.Run("no listener call", func(t *testing.T) {
		p := newPerCallUsage(t, routeOnlyClaudeConfig(true, "claudecode"))
		p.exportClaude(claudeCall(perCallRequestA, 431))
		recs := p.records(1)
		if recs[0].Facts.Listener != "native_otel" || recs[0].Usage.Output != 431 {
			t.Fatalf("the native record must be counted: %+v", recs[0])
		}
	})
	t.Run("another routed call in flight", func(t *testing.T) {
		p := newPerCallUsage(t, routeOnlyClaudeConfig(true, "claudecode"))
		call := p.beginClaude()
		p.exportClaude(claudeCall(perCallRequestB, 77))
		finishListenerCall(call, perCallRequestA, claudeAnswer(431))
		recs := p.records(2)
		if got := listenerOf(recs); got["route_only"] != 1 || got["native_otel"] != 1 {
			t.Fatalf("one listener and one native record, got %v", got)
		}
		for _, rec := range recs {
			if rec.Facts.Listener == "native_otel" && rec.Usage.Output != 77 {
				t.Fatalf("the unrecorded call keeps its own numbers: %+v", rec.Usage)
			}
		}
	})
}

// TestNativeUsagePerCallEmptyListenerUsageDoesNotSuppress: the listener
// forwarded a call but read no usage from it (an answer over its body
// budget, an answer without a usage block): the agent's numbers are counted.
func TestNativeUsagePerCallEmptyListenerUsageDoesNotSuppress(t *testing.T) {
	p := newPerCallUsage(t, routeOnlyClaudeConfig(true, "claudecode"))
	call := p.beginClaude()
	finishListenerCall(call, perCallRequestA, `{"type":"message","model":"claude-sonnet-4-5-20250929"}`)
	p.exportClaude(claudeCall(perCallRequestA, 431))
	recs := p.records(2)
	var output int64
	for _, rec := range recs {
		output += rec.Usage.Output
	}
	if got := listenerOf(recs); got["native_otel"] != 1 || output != 431 {
		t.Fatalf("the native numbers must be counted once: listeners %v output %d", got, output)
	}
}

// TestNativeUsagePerCallSurvivesReload: a reload or a routing enable or
// disable between a call and its export changes neither answer.
func TestNativeUsagePerCallSurvivesReload(t *testing.T) {
	t.Run("recorded, routing disabled before the export", func(t *testing.T) {
		p := newPerCallUsage(t, routeOnlyClaudeConfig(true, "claudecode"))
		finishListenerCall(p.beginClaude(), perCallRequestA, claudeAnswer(431))
		p.reload(routeOnlyClaudeConfig(false, "claudecode"))
		p.exportClaude(claudeCall(perCallRequestA, 431))
		if recs := p.records(1); recs[0].Facts.Listener != "route_only" {
			t.Fatalf("one record, the listener's: %+v", recs[0])
		}
	})
	t.Run("recorded, connector removed before the export", func(t *testing.T) {
		p := newPerCallUsage(t, routeOnlyClaudeConfig(true, "claudecode"))
		finishListenerCall(p.beginClaude(), perCallRequestA, claudeAnswer(431))
		p.reload(routeOnlyClaudeConfig(true))
		p.exportClaude(claudeCall(perCallRequestA, 431))
		if recs := p.records(1); recs[0].Facts.Listener != "route_only" {
			t.Fatalf("one record, the listener's: %+v", recs[0])
		}
	})
	t.Run("direct, routing enabled before the export", func(t *testing.T) {
		p := newPerCallUsage(t, routeOnlyClaudeConfig(false, "claudecode"))
		p.reload(routeOnlyClaudeConfig(true, "claudecode"))
		p.exportClaude(claudeCall(perCallRequestA, 431))
		if recs := p.records(1); recs[0].Facts.Listener != "native_otel" {
			t.Fatalf("the direct call is counted from its export: %+v", recs[0])
		}
	})
}
