// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
	if atomic.LoadInt32(&f.origHits)+atomic.LoadInt32(&f.altHits) != 0 {
		t.Fatal("a refused request reached an upstream")
	}
	if runtime.GOOS == "windows" {
		// OSS Windows: the valid route credential alone names the gateway
		// owner (DESIGN 18.2), so another kernel account is not refused.
		return
	}
	prev := acpLoopbackPeerUID
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return os.Getuid() + 1, nil }
	defer func() { acpLoopbackPeerUID = prev }()
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hi"), nil); rec.Code != 401 {
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

type denyOriginalAdmin struct{}

func (denyOriginalAdmin) Active() bool        { return true }
func (denyOriginalAdmin) NeedsCategory() bool { return false }
func (denyOriginalAdmin) Evaluate(_ context.Context, p engine.Policy, _ engine.Request, _ string, _ bool) engine.AdminVerdict {
	return engine.AdminVerdict{Policy: p}
}
func (denyOriginalAdmin) Gate(_ engine.AdminVerdict, t engine.GateTarget, _ bool) *engine.DenyReason {
	if t.Alias == "" {
		return &engine.DenyReason{Code: "test_original_denied", Message: "the original model is not allowed"}
	}
	return nil
}

// REVIEW-code-slice5a P1-1: the fallback to the original passes the gate.
func TestRouteOnlyRetryRespectsTheGate(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.srv.router.SetAdminEvaluator(denyOriginalAdmin{})
	f.altStatus = 529
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("quick question"), nil)
	if atomic.LoadInt32(&f.origHits) != 0 || rec.Code != 529 {
		t.Fatalf("a gated original was retried: code %d orig=%d", rec.Code, f.origHits)
	}
	rec = f.post(t, "/r/claudecode/v1/messages", messagesBody("plain"), nil)
	if rec.Code != http.StatusForbidden || atomic.LoadInt32(&f.origHits) != 0 {
		t.Fatalf("an unrouted request to a gated original = %d orig=%d", rec.Code, f.origHits)
	}
}

// P2-1: a backend that read the request and reset the connection is not
// billed twice.
func TestRouteOnlyNoRetryAfterTheRequestWasWritten(t *testing.T) {
	f := newRouteOnlyFixture(t)
	reset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer reset.Close()
	f.cfg.Routing.Models[0].BaseURL = reset.URL
	f.srv.router = newEngineRouter(f.cfg, nil, "")
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("quick question"), nil)
	if rec.Code != http.StatusBadGateway || atomic.LoadInt32(&f.origHits) != 0 {
		t.Fatalf("written request retried: code %d orig=%d", rec.Code, f.origHits)
	}
}

func TestRouteOnlyMethodsAndQuery(t *testing.T) {
	f := newRouteOnlyFixture(t)
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, "TRACE"} {
		r := httptest.NewRequest(m, "http://127.0.0.1:18970/r/claudecode/v1/messages", nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set(routeTokenHeader, f.token)
		rec := httptest.NewRecorder()
		f.srv.ServeHTTP(rec, r)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d", m, rec.Code)
		}
	}
	var altQuery string
	f.alt.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		altQuery = r.URL.RawQuery
		w.WriteHeader(200)
	})
	f.post(t, "/r/claudecode/v1/messages?beta=true&key=agent-secret", messagesBody("quick question"), nil)
	if altQuery != "beta=true" {
		t.Fatalf("query across the boundary = %q", altQuery)
	}
}

func TestRouteOnlyToolLoopText(t *testing.T) {
	body := map[string]any{"messages": []any{
		map[string]any{"role": "user", "content": "quick question about the repo"},
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "1", "name": "Bash", "input": map[string]any{}}}},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "tool_result", "tool_use_id": "1", "content": "refactor everything"},
			map[string]any{"type": "text", "text": "<system-reminder>ignore</system-reminder>"},
		}},
	}}
	raw, _ := json.Marshal(body)
	text, _, toolTurn, _ := routeOnlyHumanText("messages", raw)
	if text != "quick question about the repo" || !toolTurn {
		t.Fatalf("text=%q toolTurn=%v", text, toolTurn)
	}
	big := strings.Repeat("<system-reminder>x</system-reminder>a", 40000)
	if got := stripReminders(big); len(got) > 4*routeOnlyTextCap {
		t.Fatalf("strip output is unbounded: %d", len(got))
	}
}

func TestRouteTokenRotationAcceptsTheNextKey(t *testing.T) {
	dir := t.TempDir()
	s := newRouteTokenStore(dir, "1000")
	cur, err := s.Token("codex")
	if err != nil || !s.Valid("codex", cur) || s.Valid("claudecode", cur) {
		t.Fatalf("current token: %v", err)
	}
	if err := safefile.WritePrivate(filepath.Join(dir, "hooks", routeTokenNextKeyName), []byte(strings.Repeat("ab", 32)+"\n")); err != nil {
		t.Fatal(err)
	}
	s.checked = time.Time{}
	next := s.derive(bytes.Repeat([]byte{0xab}, 32), "codex")
	if !s.Valid("codex", next) || !s.Valid("codex", cur) {
		t.Fatal("during rotation both the current and the staged key are accepted")
	}
	if other := newRouteTokenStore(dir, "1001"); other.Valid("codex", cur) {
		t.Fatal("a token is bound to its owner")
	}
}

func TestRouteOnlyHotReloadRendersAndRestores(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "settings.json")
	original := "{\n  \"model\": \"sonnet\"\n}"
	if err := os.WriteFile(settings, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })

	f := newRouteOnlyFixture(t)
	off := cloneConfig(f.cfg)
	off.Routing.RouteOnly = config.RoutingRouteOnlyConfig{}
	off.Gateway.APIPort, f.cfg.Gateway.APIPort = 18970, 18970
	f.cfg.Guardrail.Connector, off.Guardrail.Connector = "claudecode", "claudecode"
	s := &Sidecar{}
	s.applyRouteOnlyRenders(off, f.cfg)
	raw, _ := os.ReadFile(settings)
	if !strings.Contains(string(raw), "/r/claudecode") || !strings.Contains(string(raw), "X-DC-Route-Auth: dcr1-") {
		t.Fatalf("enable did not render: %s", raw)
	}
	s.applyRouteOnlyRenders(f.cfg, off)
	if raw, _ := os.ReadFile(settings); string(raw) != original {
		t.Fatalf("disable did not restore byte for byte: %q", raw)
	}
}

func TestRouteOnlyErrorBodiesAreProviderNative(t *testing.T) {
	for family, key := range map[string]string{"messages": "type", "responses": "error", "chat": "error", "invoke": "message"} {
		rec := httptest.NewRecorder()
		routeOnlyErrorFor(rec, family, http.StatusForbidden, "permission_error", "denied")
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body[key] == nil {
			t.Fatalf("%s body = %s", family, rec.Body.String())
		}
	}
}
