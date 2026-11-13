// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
)

type usageCaptureSink struct{ ch chan modelusage.Record }

func (s usageCaptureSink) Emit(_ context.Context, rec modelusage.Record) { s.ch <- rec }

func installUsageEngine(t *testing.T) chan modelusage.Record {
	t.Helper()
	ch := make(chan modelusage.Record, 16)
	e := modelusage.NewEngine(usageCaptureSink{ch: ch})
	e.Apply(config.TokenomicsConfig{Enabled: true}, config.PricingConfig{})
	prev := processModelUsage.Load()
	processModelUsage.Store(e)
	t.Cleanup(func() {
		e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
		processModelUsage.Store(prev)
	})
	return ch
}

func nextUsage(t *testing.T, ch chan modelusage.Record) modelusage.Record {
	t.Helper()
	select {
	case rec := <-ch:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no usage record")
	}
	return modelusage.Record{}
}

func TestRouteOnlyRecordsRoutedUsage(t *testing.T) {
	ch := installUsageEngine(t)
	f := newRouteOnlyFixture(t)
	f.alt.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"message","model":"claude-haiku-4-5","usage":{"input_tokens":12,"output_tokens":3}}`))
	})
	body := messagesBody("quick question")
	body["stream"] = false
	rec := f.post(t, "/r/claudecode/v1/messages", body, nil)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	got := nextUsage(t, ch)
	fc := got.Facts
	if fc.Listener != "route_only" || fc.Connector != "claudecode" || fc.APIFamily != modelusage.FamilyMessages {
		t.Fatalf("facts = %+v", fc)
	}
	if fc.RequestedModel != "claude-sonnet-4-5" || fc.SelectedModel != "claude-haiku-4-5" || fc.Route.Decision != modelusage.DecisionApplied || fc.Route.SelectedAlias != "haiku" {
		t.Fatalf("route facts = %+v", fc)
	}
	if !fc.IdentityVerified || fc.Subject == "" {
		t.Fatal("route-only caller identity missing")
	}
	if got.Usage.Input != 12 || got.Usage.Output != 3 {
		t.Fatalf("usage = %+v", got.Usage)
	}
}

func TestRouteOnlyRecordsUnroutedStreamAsPassthrough(t *testing.T) {
	ch := installUsageEngine(t)
	f := newRouteOnlyFixture(t)
	f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil)
	got := nextUsage(t, ch)
	if got.Facts.Route.Decision == modelusage.DecisionApplied || !got.Facts.Streaming || got.Facts.SelectedModel != "claude-sonnet-4-5" {
		t.Fatalf("facts = %+v", got.Facts)
	}
}

func TestUsageOffRecordsNothing(t *testing.T) {
	prev := processModelUsage.Load()
	processModelUsage.Store(nil)
	t.Cleanup(func() { processModelUsage.Store(prev) })
	if usageRecorder() != modelusage.Noop {
		t.Fatal("no engine must mean the no-op recorder")
	}
}

func TestPassthroughRecordsUsage(t *testing.T) {
	ch := installUsageEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","model":"gpt-4.1","usage":{"input_tokens":5,"output_tokens":2}}`))
	}))
	defer up.Close()
	proxy := newForwardingProxy(t, up.URL)
	rec := postPassthrough(t, proxy, up.URL, "/v1/responses", nil, mustJSON(t, map[string]any{"model": "gpt-4.1", "input": "hi"}))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	got := nextUsage(t, ch)
	if got.Facts.Listener != "guardrail" || got.Facts.APIFamily != modelusage.FamilyResponses || got.Facts.Route.Decision != modelusage.DecisionNone {
		t.Fatalf("facts = %+v", got.Facts)
	}
	if got.Usage.Input != 5 || got.Usage.Output != 2 {
		t.Fatalf("usage = %+v", got.Usage)
	}
}

func TestWithStreamIncludeUsage(t *testing.T) {
	prev := processModelUsage.Load()
	processModelUsage.Store(nil)
	if out, added := withStreamIncludeUsage([]byte(`{"stream":true}`)); added || string(out) != `{"stream":true}` {
		t.Fatal("tokenomics off must not change the body")
	}
	processModelUsage.Store(prev)
	installUsageEngine(t)
	for in, want := range map[string]bool{
		`{"model":"m","stream":true}`:                                          true,
		`{"model":"m","stream":true,"stream_options":{"include_usage":false}}`: true,
		`{"model":"m","stream":true,"stream_options":{"include_usage":true}}`:  false,
		`{"model":"m","stream":false}`:                                         false,
		`not json`:                                                             false,
	} {
		out, added := withStreamIncludeUsage([]byte(in))
		if added != want {
			t.Fatalf("%s: added = %v", in, added)
		}
		if added {
			var got struct {
				StreamOptions struct {
					IncludeUsage bool `json:"include_usage"`
				} `json:"stream_options"`
				Model string `json:"model"`
			}
			if err := json.Unmarshal(out, &got); err != nil || !got.StreamOptions.IncludeUsage || got.Model != "m" {
				t.Fatalf("%s -> %s", in, out)
			}
		}
	}
	if !isUsageOnlyChunk(`{"choices":[],"usage":{"prompt_tokens":1}}`) || isUsageOnlyChunk(`{"choices":[{"delta":{}}],"usage":{"prompt_tokens":1}}`) || isUsageOnlyChunk(`{"choices":[]}`) {
		t.Fatal("usage-only chunk detection")
	}
}
