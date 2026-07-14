// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"
	cpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	rpb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

const (
	testTraceHex = "5b8efff798038103d269b633813fc60c"
	testSpanHex  = "eee19b7ec3c1b174"
)

// fakeCloudProvider is an in-memory cloudreg.Provider. Token returns the token
// for the current generation; Invalidate advances the generation, modeling a
// re-mint.
type fakeCloudProvider struct {
	mu              sync.Mutex
	seq             []string
	gen             int
	invalidateCount int
	tokenErr        error
}

func (f *fakeCloudProvider) Token(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenErr != nil {
		return "", f.tokenErr
	}
	if f.gen >= len(f.seq) {
		return f.seq[len(f.seq)-1], nil
	}
	return f.seq[f.gen], nil
}

func (f *fakeCloudProvider) Refresh(context.Context) error { return nil }

func (f *fakeCloudProvider) Invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidateCount++
	f.gen++
}

func (f *fakeCloudProvider) invalidations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.invalidateCount
}

// capturedRequest records what the mock ingest endpoint received.
type capturedRequest struct {
	path string
	auth string
	ct   string
	body []byte
}

type captureServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []capturedRequest
	// statusFor lets a test choose the response per bearer token.
	statusFor func(token string) int
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{
		statusFor: func(string) int { return http.StatusOK },
	}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		auth := r.Header.Get("Authorization")
		cs.mu.Lock()
		cs.requests = append(cs.requests, capturedRequest{
			path: r.URL.Path,
			auth: auth,
			ct:   r.Header.Get("Content-Type"),
			body: body,
		})
		cs.mu.Unlock()
		token := ""
		if len(auth) > len("Bearer ") {
			token = auth[len("Bearer "):]
		}
		w.WriteHeader(cs.statusFor(token))
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *captureServer) captured() []capturedRequest {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]capturedRequest, len(cs.requests))
	copy(out, cs.requests)
	return out
}

func managedOTelConfig(endpoint string) *config.Config {
	return &config.Config{
		DeploymentMode: "managed_enterprise",
		CiscoAIDefense: config.CiscoAIDefenseConfig{Endpoint: endpoint},
		OTel: config.OTelConfig{
			Enabled: true,
			Resource: config.OTelResourceConfig{
				Attributes: map[string]string{"defenseclaw.connector.source": "codex"},
			},
		},
	}
}

func verdictEvent() gatewaylog.Event {
	return gatewaylog.Event{
		EventType: gatewaylog.EventVerdict,
		Severity:  gatewaylog.SeverityHigh,
		Verdict: &gatewaylog.VerdictPayload{
			Stage:     gatewaylog.StageRegex,
			Action:    "block",
			Reason:    "regex match",
			LatencyMs: 5,
		},
	}
}

func ctxWithSpan(t *testing.T) context.Context {
	t.Helper()
	tid, err := trace.TraceIDFromHex(testTraceHex)
	if err != nil {
		t.Fatalf("trace id: %v", err)
	}
	sid, err := trace.SpanIDFromHex(testSpanHex)
	if err != nil {
		t.Fatalf("span id: %v", err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	return trace.ContextWithSpanContext(context.Background(), sc)
}

// --- JSON navigation helpers over the decoded payload -----------------------

func mapAt(t *testing.T, v any, key string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object for %q, got %T", key, v)
	}
	child, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("expected object at %q, got %T", key, m[key])
	}
	return child
}

func sliceAt(t *testing.T, v any, key string) []any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object for %q, got %T", key, v)
	}
	s, ok := m[key].([]any)
	if !ok {
		t.Fatalf("expected array at %q, got %T", key, m[key])
	}
	return s
}

func attrStringValue(t *testing.T, attrs []any, key string) (string, bool) {
	t.Helper()
	for _, a := range attrs {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if am["key"] == key {
			val, ok := am["value"].(map[string]any)
			if !ok {
				return "", false
			}
			s, ok := val["stringValue"].(string)
			return s, ok
		}
	}
	return "", false
}

// --- Tests ------------------------------------------------------------------

func TestCiscoAIDefenseIngestURL(t *testing.T) {
	cases := map[string]string{
		"https://us.api.inspect.aidefense.security.cisco.com":  "https://us.api.inspect.aidefense.security.cisco.com/api/v1/defenseclaw/events/ingest",
		"https://us.api.inspect.aidefense.security.cisco.com/": "https://us.api.inspect.aidefense.security.cisco.com/api/v1/defenseclaw/events/ingest",
		"http://localhost:8080":                                "http://localhost:8080/api/v1/defenseclaw/events/ingest",
	}
	for in, want := range cases {
		if got := ciscoAIDefenseIngestURL(in); got != want {
			t.Errorf("ciscoAIDefenseIngestURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMarshalLogsPayloadEnvelopeHexAndStringNanos(t *testing.T) {
	tid, _ := hex.DecodeString(testTraceHex)
	sid, _ := hex.DecodeString(testSpanHex)
	strVal := func(s string) *cpb.AnyValue {
		return &cpb.AnyValue{Value: &cpb.AnyValue_StringValue{StringValue: s}}
	}
	rls := []*logspb.ResourceLogs{{
		Resource: &rpb.Resource{Attributes: []*cpb.KeyValue{
			{Key: "service.name", Value: strVal("defenseclaw")},
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &cpb.InstrumentationScope{Name: "defenseclaw"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: 1544712660000000000,
				TraceId:      tid,
				SpanId:       sid,
				Body:         strVal("hello"),
				Attributes: []*cpb.KeyValue{
					{Key: "event.name", Value: strVal("defenseclaw.gateway.verdict")},
				},
			}},
		}},
	}}

	body, err := marshalLogsPayload(rls)
	if err != nil {
		t.Fatalf("marshalLogsPayload: %v", err)
	}

	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("unmarshal body: %v\n%s", err, body)
	}
	payload := mapAt(t, root, "payload")
	resourceLogs := sliceAt(t, payload, "resourceLogs")
	if len(resourceLogs) != 1 {
		t.Fatalf("resourceLogs len = %d, want 1", len(resourceLogs))
	}
	rl0 := resourceLogs[0]
	resource := mapAt(t, rl0, "resource")
	if _, ok := attrStringValue(t, sliceAt(t, resource, "attributes"), "service.name"); !ok {
		t.Errorf("resource missing service.name attribute")
	}
	scopeLogs := sliceAt(t, rl0, "scopeLogs")
	logRecords := sliceAt(t, scopeLogs[0], "logRecords")
	rec := logRecords[0].(map[string]any)

	if v, ok := rec["timeUnixNano"].(string); !ok || v != "1544712660000000000" {
		t.Errorf("timeUnixNano = %v (type %T), want string \"1544712660000000000\"", rec["timeUnixNano"], rec["timeUnixNano"])
	}
	if rec["traceId"] != testTraceHex {
		t.Errorf("traceId = %v, want hex %q", rec["traceId"], testTraceHex)
	}
	if rec["spanId"] != testSpanHex {
		t.Errorf("spanId = %v, want hex %q", rec["spanId"], testSpanHex)
	}
	if v, ok := attrStringValue(t, sliceAt(t, rec, "attributes"), "event.name"); !ok || v != "defenseclaw.gateway.verdict" {
		t.Errorf("event.name attr = %q (ok=%v), want defenseclaw.gateway.verdict", v, ok)
	}
}

func TestCiscoAIDLogSinkEndToEnd(t *testing.T) {
	srv := newCaptureServer(t)
	fake := &fakeCloudProvider{seq: []string{"tok-1"}}

	p, err := NewProviderInactive(context.Background(), managedOTelConfig(srv.URL), "test",
		WithCloudAuthProvider(fake))
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}
	if p.CloudAuthProvider() != fake {
		t.Fatalf("CloudAuthProvider not the injected instance")
	}
	if p.TracesEnabled() {
		t.Errorf("traces should be disabled: this is a logs-only sink")
	}

	p.EmitGatewayEventWithContext(ctxWithSpan(t), verdictEvent())
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown/flush: %v", err)
	}

	reqs := srv.captured()
	if len(reqs) != 1 {
		t.Fatalf("captured %d requests, want 1", len(reqs))
	}
	got := reqs[0]
	if got.path != CiscoAIDefenseTelemetryPath {
		t.Errorf("path = %q, want %q", got.path, CiscoAIDefenseTelemetryPath)
	}
	if got.auth != "Bearer tok-1" {
		t.Errorf("auth = %q, want Bearer tok-1", got.auth)
	}
	if got.ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", got.ct)
	}

	var root any
	if err := json.Unmarshal(got.body, &root); err != nil {
		t.Fatalf("unmarshal body: %v\n%s", err, got.body)
	}
	payload := mapAt(t, root, "payload")
	resourceLogs := sliceAt(t, payload, "resourceLogs")
	if len(resourceLogs) == 0 {
		t.Fatalf("no resourceLogs in payload")
	}
	rl0 := resourceLogs[0]
	resAttrs := sliceAt(t, mapAt(t, rl0, "resource"), "attributes")
	if v, ok := attrStringValue(t, resAttrs, "service.name"); !ok || v != "defenseclaw" {
		t.Errorf("resource service.name = %q (ok=%v), want defenseclaw", v, ok)
	}
	if v, ok := attrStringValue(t, resAttrs, "defenseclaw.connector.source"); !ok || v != "codex" {
		t.Errorf("resource connector.source = %q (ok=%v), want codex", v, ok)
	}
	scopeLogs := sliceAt(t, rl0, "scopeLogs")
	if name := mapAt(t, scopeLogs[0], "scope")["name"]; name != "defenseclaw" {
		t.Errorf("scope name = %v, want defenseclaw", name)
	}
	rec := sliceAt(t, scopeLogs[0], "logRecords")[0].(map[string]any)
	if _, ok := rec["timeUnixNano"].(string); !ok {
		t.Errorf("timeUnixNano not a string: %T", rec["timeUnixNano"])
	}
	if rec["traceId"] != testTraceHex {
		t.Errorf("traceId = %v, want %q", rec["traceId"], testTraceHex)
	}
	if rec["spanId"] != testSpanHex {
		t.Errorf("spanId = %v, want %q", rec["spanId"], testSpanHex)
	}
	recAttrs := sliceAt(t, rec, "attributes")
	if v, ok := attrStringValue(t, recAttrs, "event.name"); !ok || v != "defenseclaw.gateway.verdict" {
		t.Errorf("event.name = %q (ok=%v), want defenseclaw.gateway.verdict", v, ok)
	}
	if v, ok := attrStringValue(t, recAttrs, "defenseclaw.verdict.action"); !ok || v != "block" {
		t.Errorf("verdict.action = %q (ok=%v), want block", v, ok)
	}
}

func TestCiscoAIDLogSinkReMintOn401(t *testing.T) {
	srv := newCaptureServer(t)
	srv.statusFor = func(token string) int {
		if token == "tok-1" {
			return http.StatusUnauthorized
		}
		return http.StatusOK
	}
	fake := &fakeCloudProvider{seq: []string{"tok-1", "tok-2"}}

	p, err := NewProviderInactive(context.Background(), managedOTelConfig(srv.URL), "test",
		WithCloudAuthProvider(fake))
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}

	p.EmitGatewayEventWithContext(ctxWithSpan(t), verdictEvent())
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown/flush: %v", err)
	}

	if got := fake.invalidations(); got != 1 {
		t.Errorf("invalidate count = %d, want exactly 1", got)
	}
	reqs := srv.captured()
	if len(reqs) != 2 {
		t.Fatalf("captured %d requests, want 2 (401 then retry)", len(reqs))
	}
	if reqs[0].auth != "Bearer tok-1" {
		t.Errorf("first auth = %q, want Bearer tok-1", reqs[0].auth)
	}
	if reqs[1].auth != "Bearer tok-2" {
		t.Errorf("retry auth = %q, want Bearer tok-2", reqs[1].auth)
	}
}

func TestCiscoAIDLogSinkGateOffWhenNotManaged(t *testing.T) {
	srv := newCaptureServer(t)
	fake := &fakeCloudProvider{seq: []string{"tok-1"}}
	cfg := managedOTelConfig(srv.URL)
	cfg.DeploymentMode = "" // not managed_enterprise

	p, err := NewProviderInactive(context.Background(), cfg, "test", WithCloudAuthProvider(fake))
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}
	if p.CloudAuthProvider() != nil {
		t.Errorf("cisco sink must not be provisioned outside managed_enterprise")
	}
}

func TestCiscoAIDLogSinkActiveWhenOTelDisabled(t *testing.T) {
	// Relaxed gate: managed_enterprise + cisco_ai_defense.endpoint alone must
	// activate the sink, with no otel.enabled and no user destination.
	srv := newCaptureServer(t)
	fake := &fakeCloudProvider{seq: []string{"tok-1"}}
	cfg := managedOTelConfig(srv.URL)
	cfg.OTel.Enabled = false
	cfg.OTel.Destinations = nil

	p, err := NewProviderInactive(context.Background(), cfg, "test", WithCloudAuthProvider(fake))
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}
	if p.CloudAuthProvider() != fake {
		t.Fatalf("cisco sink must be provisioned from managed_enterprise + endpoint alone (otel.enabled=false)")
	}
	if !p.Enabled() {
		t.Errorf("provider must be enabled so emitted events reach the managed sink")
	}

	p.EmitGatewayEventWithContext(ctxWithSpan(t), verdictEvent())
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown/flush: %v", err)
	}
	reqs := srv.captured()
	if len(reqs) != 1 {
		t.Fatalf("captured %d requests, want 1", len(reqs))
	}
	if reqs[0].path != CiscoAIDefenseTelemetryPath {
		t.Errorf("path = %q, want %q", reqs[0].path, CiscoAIDefenseTelemetryPath)
	}
	if reqs[0].auth != "Bearer tok-1" {
		t.Errorf("auth = %q, want Bearer tok-1", reqs[0].auth)
	}
}

func TestCiscoAIDLogSinkSkippedWhenEndpointMissing(t *testing.T) {
	fake := &fakeCloudProvider{seq: []string{"tok-1"}}
	cfg := managedOTelConfig("") // managed_enterprise but no endpoint

	p, err := NewProviderInactive(context.Background(), cfg, "test", WithCloudAuthProvider(fake))
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}
	if p.CloudAuthProvider() != nil {
		t.Errorf("cisco sink must be skipped when endpoint is empty")
	}
}

func TestCiscoAIDLogSinkFailClosedKeepsUserDestinations(t *testing.T) {
	ciscoSrv := newCaptureServer(t)
	userSrv := newCaptureServer(t)
	// Provider whose token mint fails => cisco sink must fail-closed.
	fake := &fakeCloudProvider{tokenErr: context.DeadlineExceeded}

	cfg := managedOTelConfig(ciscoSrv.URL)
	cfg.OTel.Destinations = []config.OTelDestinationConfig{{
		Name:     "user",
		Enabled:  true,
		Protocol: "http",
		Endpoint: userSrv.URL,
		Logs:     config.OTelLogsConfig{Enabled: true},
	}}

	p, err := NewProviderInactive(context.Background(), cfg, "test", WithCloudAuthProvider(fake))
	if err != nil {
		t.Fatalf("NewProviderInactive should not fail when cisco sink is unavailable: %v", err)
	}
	if p.CloudAuthProvider() != nil {
		t.Errorf("cisco sink should be skipped on token error")
	}
	if !p.LogsEnabled() {
		t.Errorf("user log destination should still be built when cisco sink fails")
	}
	if len(ciscoSrv.captured()) != 0 {
		t.Errorf("no traffic should reach the cisco endpoint when its sink is skipped")
	}
}
