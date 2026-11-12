// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type routeOnlyFixture struct {
	srv               *routeOnlyServer
	cfg               *config.Config
	token             string
	origHits, altHits int32
	origBody, altBody []byte
	origHdr, altHdr   http.Header
	altStatus         int
	orig, alt         *httptest.Server
}

func newRouteOnlyFixture(t *testing.T) *routeOnlyFixture {
	t.Helper()
	f := &routeOnlyFixture{altStatus: http.StatusOK}
	f.orig = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.origHits, 1)
		f.origBody, _ = io.ReadAll(r.Body)
		f.origHdr = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "event: message_stop\ndata: {}\n\n")
	}))
	t.Cleanup(f.orig.Close)
	f.alt = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.altHits, 1)
		f.altBody, _ = io.ReadAll(r.Body)
		f.altHdr = r.Header.Clone()
		w.WriteHeader(f.altStatus)
		_, _ = io.WriteString(w, `{"type":"message"}`)
	}))
	t.Cleanup(f.alt.Close)
	t.Setenv("ROUTE_ONLY_TEST_KEY_5511", "k-alt")
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models:    []config.RoutingModelBackend{{Name: "haiku", Provider: "anthropic", Model: "claude-haiku-4-5", BaseURL: f.alt.URL, APIKeyEnv: "ROUTE_ONLY_TEST_KEY_5511"}},
		Signals:   config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "quick", Keywords: []string{"quick question"}}}},
		Decisions: []config.RoutingDecisionRule{{Name: "quick", Conditions: []config.RoutingCondition{{Type: "keyword", Name: "quick"}}, ModelRefs: []string{"haiku"}}},
		RouteOnly: config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}, Upstreams: map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: f.orig.URL, API: "messages"}}},
	}
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	f.srv = newRouteOnlyServer(newEngineRouter(cfg, nil, ""), func() *config.Config { return f.cfg }, cfg.DataDir)
	tok, err := f.srv.tokens.Token("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	f.token = tok
	prev := acpLoopbackPeerUID
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return os.Getuid(), nil }
	t.Cleanup(func() { acpLoopbackPeerUID = prev })
	return f
}

func (f *routeOnlyFixture) post(t *testing.T, path string, body any, mut func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:50123"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Api-Key", "sk-ant-agent")
	r.Header.Set("Anthropic-Version", "2023-06-01")
	r.Header.Set("X-Custom-Agent", "kept-same-provider")
	r.Header.Set(routeTokenHeader, f.token)
	if mut != nil {
		mut(r)
	}
	rec := httptest.NewRecorder()
	routeOnlyDispatch(func() *routeOnlyServer { return f.srv }, http.NotFoundHandler()).ServeHTTP(rec, r)
	return rec
}

func messagesBody(text string) map[string]any {
	return map[string]any{"model": "claude-sonnet-4-5", "stream": true, "messages": []any{
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "<system-reminder>quick question hidden</system-reminder>" + text}}},
	}}
}

func TestRouteOnlyRefusals(t *testing.T) {
	f := newRouteOnlyFixture(t)
	for name, tc := range map[string]struct {
		mut  func(*http.Request)
		path string
		want int
	}{
		"no route credential": {func(r *http.Request) { r.Header.Del(routeTokenHeader) }, "/r/claudecode/v1/messages", 401},
		"wrong credential":    {func(r *http.Request) { r.Header.Set(routeTokenHeader, "dcr1-00") }, "/r/claudecode/v1/messages", 401},
		"browser origin":      {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, "/r/claudecode/v1/messages", 403},
		"rebinding host":      {func(r *http.Request) { r.Host = "evil.example:18970" }, "/r/claudecode/v1/messages", 403},
		"remote caller":       {func(r *http.Request) { r.RemoteAddr = "10.0.0.5:4444" }, "/r/claudecode/v1/messages", 403},
		"websocket":           {func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }, "/r/claudecode/v1/responses", 426},
		"not enabled":         {nil, "/r/codex/v1/responses", 404},
		"traversal":           {nil, "/r/claudecode/../../api/v1/inspect", 400},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := f.post(t, tc.path, messagesBody("hi"), tc.mut); rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	prev := acpLoopbackPeerUID
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return os.Getuid() + 1, nil }
	defer func() { acpLoopbackPeerUID = prev }()
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hi"), nil); rec.Code != 401 && os.Getenv("GOOS") != "windows" {
		t.Fatalf("another account = %d, want 401", rec.Code)
	}
	if atomic.LoadInt32(&f.origHits)+atomic.LoadInt32(&f.altHits) != 0 {
		t.Fatal("a refused request reached an upstream")
	}
}

func TestRouteOnlyUnroutedIsByteExactAndStreams(t *testing.T) {
	f := newRouteOnlyFixture(t)
	raw, _ := json.Marshal(messagesBody("hello there"))
	rec := f.post(t, "/r/claudecode/v1/messages?beta=true", messagesBody("hello there"), nil)
	if rec.Code != 200 || atomic.LoadInt32(&f.origHits) != 1 || !bytes.Equal(f.origBody, raw) {
		t.Fatalf("unrouted: %d hits=%d body equal=%v", rec.Code, f.origHits, bytes.Equal(f.origBody, raw))
	}
	if !strings.Contains(rec.Body.String(), "message_stop") || f.origHdr.Get("X-Api-Key") != "sk-ant-agent" || f.origHdr.Get(routeTokenHeader) != "" || f.origHdr.Get("X-Custom-Agent") == "" {
		t.Fatalf("stream or headers wrong: %q hdr=%v", rec.Body.String(), f.origHdr)
	}
}

func TestRouteOnlyRoutesAcrossCredentialBoundary(t *testing.T) {
	f := newRouteOnlyFixture(t)
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("quick question: what is 2+2"), nil)
	if rec.Code != 200 || atomic.LoadInt32(&f.altHits) != 1 || rec.Header().Get("X-Semantic-Router") != "routed" {
		t.Fatalf("routed: %d alt=%d orig=%d", rec.Code, f.altHits, f.origHits)
	}
	var got map[string]any
	_ = json.Unmarshal(f.altBody, &got)
	if got["model"] != "claude-haiku-4-5" || f.altHdr.Get("X-Api-Key") != "k-alt" || f.altHdr.Get("X-Custom-Agent") != "" || f.altHdr.Get("Anthropic-Version") == "" {
		t.Fatalf("routed body model=%v key=%q custom=%q", got["model"], f.altHdr.Get("X-Api-Key"), f.altHdr.Get("X-Custom-Agent"))
	}
}

func TestRouteOnlyReminderTextIsNotClassified(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.post(t, "/r/claudecode/v1/messages", messagesBody("plain request"), nil)
	if atomic.LoadInt32(&f.altHits) != 0 {
		t.Fatal("text inside <system-reminder> steered the route")
	}
}

func TestRouteOnlyRetriesTheOriginalBeforeTheFirstByte(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.altStatus = http.StatusServiceUnavailable
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("quick question"), nil)
	if rec.Code != 200 || atomic.LoadInt32(&f.altHits) != 1 || atomic.LoadInt32(&f.origHits) != 1 || rec.Header().Get("X-Semantic-Router") != "fallback" {
		t.Fatalf("retry: %d alt=%d orig=%d %q", rec.Code, f.altHits, f.origHits, rec.Header().Get("X-Semantic-Router"))
	}
	if f.origHdr.Get("X-Api-Key") != "sk-ant-agent" {
		t.Fatal("the original retry must use the agent credential")
	}
	f.altStatus = http.StatusInternalServerError
	rec = f.post(t, "/r/claudecode/v1/messages", messagesBody("quick question"), nil)
	if rec.Code != 500 || atomic.LoadInt32(&f.origHits) != 1 {
		t.Fatalf("500 must not be retried: %d orig=%d", rec.Code, f.origHits)
	}
}

func TestRouteOnlyOffAndManaged(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.cfg.Routing.Enabled = false
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hi"), nil); rec.Code != 404 {
		t.Fatalf("routing off = %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	routeOnlyDispatch(func() *routeOnlyServer { return nil }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })).ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/health", nil))
	if rec.Code != 299 {
		t.Fatal("non-/r/ requests must reach the API chain")
	}
}
