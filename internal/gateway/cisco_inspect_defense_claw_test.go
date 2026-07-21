// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// fakeCloudProvider is a scriptable cloudreg.Provider used to drive the
// managed inspection client without loading a real dylib. Token()
// returns the head of the tokens slice; Invalidate() drops the head
// and bumps invalidateCount so tests can assert refresh flows.
type fakeCloudProvider struct {
	mu              chan struct{}
	tokens          []string
	invalidateCount int32
}

func newFakeCloudProvider(tokens ...string) *fakeCloudProvider {
	p := &fakeCloudProvider{
		mu:     make(chan struct{}, 1),
		tokens: append([]string(nil), tokens...),
	}
	p.mu <- struct{}{}
	return p
}

func (p *fakeCloudProvider) lock()   { <-p.mu }
func (p *fakeCloudProvider) unlock() { p.mu <- struct{}{} }

func (p *fakeCloudProvider) Token(_ context.Context) (string, error) {
	p.lock()
	defer p.unlock()
	if len(p.tokens) == 0 {
		return "", errors.New("fake: token exhausted")
	}
	return p.tokens[0], nil
}

func (p *fakeCloudProvider) Refresh(_ context.Context) error { return nil }

func (p *fakeCloudProvider) Invalidate() {
	atomic.AddInt32(&p.invalidateCount, 1)
	p.lock()
	defer p.unlock()
	if len(p.tokens) > 0 {
		p.tokens = p.tokens[1:]
	}
}

// TestDefenseClawInspect_WireShape asserts the outbound HTTP request
// matches the DefenseClawInspect proto contract from
// ai-common/protos/ai_defense/inspection/v1/inspection.proto: POST
// /api/v1/inspect/defense_claw with Authorization: Bearer <cmid_token>,
// messages[].content as {"text": ...}, and no device_id / dc_metadata.
func TestDefenseClawInspect_WireShape(t *testing.T) {
	var (
		gotMethod   string
		gotPath     string
		gotAuth     string
		gotAPIKey   string
		gotBody     []byte
		requestSeen bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("X-Cisco-AI-Defense-API-Key")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		requestSeen = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[{"rule_name":"Prompt Injection","classification":"SECURITY_VIOLATION"}],"is_redaction_enabled":false}`)
	}))
	t.Cleanup(srv.Close)

	prov := newFakeCloudProvider("cmid-token-1")
	c := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		TimeoutMs: 3000,
	}, prov)
	if c == nil {
		t.Fatal("expected non-nil client")
	}

	verdict := c.Inspect(t.Context(), []ChatMessage{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: "hello"},
	})
	if !requestSeen {
		t.Fatal("expected server to receive a request")
	}
	if verdict == nil {
		t.Fatal("expected non-nil verdict on 200 response")
	}

	// Path + method
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/inspect/defense_claw" {
		t.Errorf("path = %q, want /api/v1/inspect/defense_claw", gotPath)
	}
	// Bearer auth; no API-key header should have leaked in.
	if gotAuth != "Bearer cmid-token-1" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer cmid-token-1")
	}
	if gotAPIKey != "" {
		t.Errorf("X-Cisco-AI-Defense-API-Key must be absent, got %q", gotAPIKey)
	}

	// Body shape: content is {"text": ...} object, not a bare string.
	var body map[string]interface{}
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v; body=%s", err, gotBody)
	}
	messages, ok := body["messages"].([]interface{})
	if !ok || len(messages) != 2 {
		t.Fatalf("messages = %v, want 2-element array", body["messages"])
	}
	for i, mRaw := range messages {
		m, ok := mRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("messages[%d] not object: %v", i, mRaw)
		}
		content, ok := m["content"].(map[string]interface{})
		if !ok {
			t.Errorf("messages[%d].content must be an object (defense_claw shape), got %T (%v)", i, m["content"], m["content"])
			continue
		}
		if _, ok := content["text"].(string); !ok {
			t.Errorf("messages[%d].content.text missing or non-string: %v", i, content)
		}
	}
	if _, present := body["device_id"]; present {
		t.Errorf("device_id must NOT appear (cloud derives from token); body=%s", gotBody)
	}
	if _, present := body["dc_metadata"]; present {
		t.Errorf("dc_metadata must NOT appear (cloud derives from token); body=%s", gotBody)
	}
	// The defense_claw endpoint's tenant is the authoritative source of
	// the rule catalog for managed callers. Sending config.enabled_rules
	// triggered a 400 on every request in the preview deployment, which
	// forced doInspectHTTP into a
	// two-round-trip retry per inspection. The client MUST omit the
	// config block on this path — if a future edit reintroduces it,
	// this assertion catches the regression before it burns cycles in
	// production.
	if _, present := body["config"]; present {
		t.Errorf("config must NOT appear on the defense_claw path (tenant owns the rule catalog); body=%s", gotBody)
	}

	// Verdict: cloud action="Block" → local {Action:block, Severity:HIGH}.
	if verdict.Action != "block" {
		t.Errorf("Action = %q, want block", verdict.Action)
	}
	if verdict.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", verdict.Severity)
	}
	if !strings.Contains(verdict.Reason, "Prompt Injection") {
		t.Errorf("Reason = %q, expected to include 'Prompt Injection'", verdict.Reason)
	}
}

// TestDefenseClawInspect_UnauthorizedRefreshAndRetry: on 401, the
// client must invalidate the provider's token cache and retry with a
// fresh token exactly once.
func TestDefenseClawInspect_UnauthorizedRefreshAndRetry(t *testing.T) {
	var calls int32
	var seenAuths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		seenAuths = append(seenAuths, r.Header.Get("Authorization"))
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"detail":"token expired"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	prov := newFakeCloudProvider("stale-token", "fresh-token")
	c := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		TimeoutMs: 3000,
	}, prov)
	verdict := c.Inspect(t.Context(), []ChatMessage{{Role: "user", Content: "hi"}})
	if verdict == nil {
		t.Fatal("expected non-nil verdict after 401 → refresh → 200 retry")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("upstream call count = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&prov.invalidateCount); got != 1 {
		t.Errorf("invalidateCount = %d, want 1", got)
	}
	if len(seenAuths) != 2 {
		t.Fatalf("captured auths = %v, want 2 entries", seenAuths)
	}
	if seenAuths[0] != "Bearer stale-token" {
		t.Errorf("first auth = %q, want Bearer stale-token", seenAuths[0])
	}
	if seenAuths[1] != "Bearer fresh-token" {
		t.Errorf("second auth = %q, want Bearer fresh-token", seenAuths[1])
	}
	if verdict.Action != "allow" {
		t.Errorf("Action = %q, want allow after successful retry", verdict.Action)
	}
}

// TestDefenseClawInspect_UnauthorizedTwiceReturnsNil: if the retry also
// 401s, the client must give up and return a nil verdict.
func TestDefenseClawInspect_UnauthorizedTwiceReturnsNil(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"detail":"forbidden"}`)
	}))
	t.Cleanup(srv.Close)

	prov := newFakeCloudProvider("t1", "t2", "t3")
	c := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		TimeoutMs: 3000,
	}, prov)
	verdict := c.Inspect(t.Context(), []ChatMessage{{Role: "user", Content: "hi"}})
	if verdict != nil {
		t.Fatalf("expected nil verdict after repeated 401, got %#v", verdict)
	}
	// Client attempts once, gets 401, invalidates, retries once more,
	// still 401 → gives up. Two upstream calls.
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("upstream call count = %d, want 2", got)
	}
}

func TestDefenseClawInspect_RequestContextCancelsUpstream(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	requestCancelled := make(chan struct{}, 1)
	c := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: "https://inspect.example.test", TimeoutMs: 5000,
	}, newFakeCloudProvider("cmid-token"))
	c.client = &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestStarted <- struct{}{}
		<-request.Context().Done()
		requestCancelled <- struct{}{}
		return nil, request.Context().Err()
	})}

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan *ScanVerdict, 1)
	go func() {
		result <- c.Inspect(ctx, []ChatMessage{{Role: "user", Content: "cancel"}})
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("managed Cisco request did not reach the transport")
	}
	cancel()
	select {
	case <-requestCancelled:
	case <-time.After(time.Second):
		t.Fatal("managed Cisco upstream did not observe caller cancellation")
	}
	select {
	case verdict := <-result:
		if verdict != nil {
			t.Fatalf("cancelled managed request verdict=%+v, want nil", verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("managed Cisco inspection did not return after cancellation")
	}
}

func TestSidecarManagedInspectorBindsActiveV8Runtime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	sidecar := &Sidecar{
		cfg: &config.Config{
			DeploymentMode: "managed_enterprise",
			CiscoAIDefense: config.CiscoAIDefenseConfig{Endpoint: srv.URL, TimeoutMs: 3000},
		},
		observabilityV8Lifecycle: runtime,
		cmidProviderInst:         newFakeCloudProvider("cmid-token"),
	}
	inspector := sidecar.newManagedInspector(t.Context(), "test inspector unavailable")
	if inspector == nil {
		t.Fatal("expected managed inspector")
	}
	client, ok := inspector.(*CiscoDefenseClawInspectClient)
	if !ok {
		t.Fatalf("managed inspector type=%T", inspector)
	}
	if client.observabilityV8Runtime() == nil {
		t.Fatal("managed inspector was not bound to the active v8 runtime")
	}

	ctx, _ := ciscoCorrelatedContext(t)
	verdict := inspector.Inspect(ctx, []ChatMessage{{Role: "user", Content: "hello"}})
	if verdict == nil || verdict.Action != "allow" {
		t.Fatalf("managed verdict=%+v", verdict)
	}
	metrics := ciscoMetricMap(capture.metricSnapshot())
	latencies := metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency]
	if len(latencies) != 1 ||
		latencies[0].Attributes()["defenseclaw.outcome"] != string(observability.OutcomeCompleted) {
		t.Fatalf("managed generated metrics=%v", metrics)
	}
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("managed client fabricated %d standalone spans", len(spans))
	}
}

// TestDefenseClawInspect_NilProviderReturnsNil: constructing with a nil
// provider yields a nil client, and calling Inspect on a nil client is
// a safe no-op.
func TestDefenseClawInspect_NilProviderReturnsNil(t *testing.T) {
	c := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: "https://example.invalid",
	}, nil)
	if c != nil {
		t.Fatalf("expected nil client when provider is nil, got %#v", c)
	}
}

// TestDefenseClawInspect_EmptyEndpointReturnsNil: managed installs
// missing the installer-rendered endpoint fail closed at construction.
func TestDefenseClawInspect_EmptyEndpointReturnsNil(t *testing.T) {
	prov := newFakeCloudProvider("t1")
	c := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{}, prov)
	if c != nil {
		t.Fatalf("expected nil client when endpoint is empty, got %#v", c)
	}
}
