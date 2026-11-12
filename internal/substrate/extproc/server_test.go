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

package extproc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// dial serves h's engine over an in-memory listener.
func dial(t *testing.T, h *harness) extprocv3.ExternalProcessorClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := NewGRPCServer(h.eng, nil)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return extprocv3.NewExternalProcessorClient(conn)
}

func identityAttrs(atespace, name string) map[string]*structpb.Struct {
	st, _ := structpb.NewStruct(map[string]any{
		identityAttributeKey: "spiffe://substrate-actor.local/worker-for-actor/" + atespace + "/" + name,
	})
	return map[string]*structpb.Struct{identityAttributeFilter: st}
}

func headersMsg(attrs map[string]*structpb.Struct, eos bool, kv ...string) *extprocv3.ProcessingRequest {
	hm := &corev3.HeaderMap{}
	for i := 0; i+1 < len(kv); i += 2 {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.ProcessingRequest{Attributes: attrs, Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: hm, EndOfStream: eos}}}
}

func bodyMsg(b []byte) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: b, EndOfStream: true}}}
}

func open(t *testing.T, c extprocv3.ExternalProcessorClient) (extprocv3.ExternalProcessor_ProcessClient, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, err := c.Process(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return s, cancel
}

func exchange(t *testing.T, s extprocv3.ExternalProcessor_ProcessClient, m *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	t.Helper()
	if err := s.Send(m); err != nil {
		t.Fatal(err)
	}
	r, err := s.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// waitEvents waits for n events (the server finishes a stream after its
// last response).
func waitEvents(t *testing.T, c *captureSink, n int) []Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.events)
		c.mu.Unlock()
		if got >= n {
			c.mu.Lock()
			defer c.mu.Unlock()
			return append([]Event(nil), c.events...)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %d events", n)
	return nil
}

func TestStreamDenyBlockedFeedHost(t *testing.T) {
	h := newHarness(t, nil)
	s, cancel := open(t, dial(t, h))
	defer cancel()
	r := exchange(t, s, headersMsg(identityAttrs("t1", "c1"), true,
		":method", "GET", ":authority", "pastebin.com", ":path", "/raw/x", ":scheme", "https"))
	ir := r.GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("want 403 immediate response, got %v", r)
	}
	var body egress.BlockResponse
	if err := json.Unmarshal(ir.GetBody(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "egress_blocked" || body.Category != "paste_site" || body.Host != "pastebin.com" || body.HowToUnblock == "" {
		t.Fatalf("body: %+v", body)
	}
	var ct bool
	for _, o := range ir.GetHeaders().GetSetHeaders() {
		if o.GetHeader().GetKey() == "content-type" && string(o.GetHeader().GetRawValue()) == "application/json" {
			ct = true
		}
	}
	if !ct {
		t.Fatal("refusal is not application/json")
	}
	if ev := waitEvents(t, h.events, 1)[0]; ev.Event != EventEgressBlocked || ev.Category != "paste_site" || ev.BodyInspected {
		t.Fatalf("event: %+v", ev)
	}
}

func TestStreamAllowAddsDecisionHeader(t *testing.T) {
	h := newHarness(t, nil)
	s, cancel := open(t, dial(t, h))
	defer cancel()
	r := exchange(t, s, headersMsg(identityAttrs("t1", "c1"), true,
		":method", "GET", ":authority", "example.com", ":path", "/", ":scheme", "https", DecisionHeader, "forged"))
	hr := r.GetRequestHeaders()
	if hr == nil || r.GetModeOverride() != nil {
		t.Fatalf("got %v", r)
	}
	set := hr.GetResponse().GetHeaderMutation().GetSetHeaders()
	if len(set) != 1 || set[0].GetHeader().GetKey() != DecisionHeader || string(set[0].GetHeader().GetRawValue()) != "allow" ||
		set[0].GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Fatalf("mutation: %v", set)
	}
}

func TestStreamNoIdentityRefused(t *testing.T) {
	h := newHarness(t, nil)
	s, cancel := open(t, dial(t, h))
	defer cancel()
	r := exchange(t, s, headersMsg(nil, true, ":method", "GET", ":authority", "example.com", ":path", "/"))
	if r.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("got %v", r)
	}
}

func mcpCall(tool string) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": map[string]any{"q": "x"}}})
	return b
}

func mcpHeaders(body []byte, extra ...string) *extprocv3.ProcessingRequest {
	kv := []string{":method", "POST", ":authority", "mcp.example.com", ":path", "/mcp", ":scheme", "https",
		"content-type", "application/json", "accept", "application/json, text/event-stream",
		"content-length", strconv.Itoa(len(body))}
	return headersMsg(identityAttrs("t1", "c1"), false, append(kv, extra...)...)
}

func TestStreamMCPBodyModeDeniesToolCall(t *testing.T) {
	h := newHarness(t, nil)
	h.judge.block = true
	s, cancel := open(t, dial(t, h))
	defer cancel()
	body := mcpCall("delete_everything")
	r := exchange(t, s, mcpHeaders(body))
	if !proto.Equal(r.GetModeOverride(), overrideMode()) {
		t.Fatalf("mode override %v, want %v", r.GetModeOverride(), overrideMode())
	}
	r = exchange(t, s, bodyMsg(body))
	ir := r.GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden || !bytes.Contains(ir.GetBody(), []byte("mcp_tool_blocked")) {
		t.Fatalf("got %v", r)
	}
	if len(h.judge.calls) != 1 || h.judge.calls[0].Server != "tickets" || h.judge.calls[0].Tool != "delete_everything" ||
		string(h.judge.calls[0].Args) != `{"q":"x"}` {
		t.Fatalf("judge calls: %+v", h.judge.calls)
	}
	ev := waitEvents(t, h.events, 1)[0]
	if !ev.BodyInspected || ev.BodyOverCap || ev.Category != CategoryMCPToolBlocked {
		t.Fatalf("event: %+v", ev)
	}
	if h.eng.BodyModeStatus() != "supported" {
		t.Fatalf("body mode %s", h.eng.BodyModeStatus())
	}
}

func TestStreamMCPAllowedThenResponsePhases(t *testing.T) {
	h := newHarness(t, nil)
	s, cancel := open(t, dial(t, h))
	defer cancel()
	body := mcpCall("list_tickets")
	if r := exchange(t, s, mcpHeaders(body)); r.GetModeOverride() == nil {
		t.Fatalf("no override: %v", r)
	}
	if r := exchange(t, s, bodyMsg(body)); r.GetRequestBody() == nil {
		t.Fatalf("got %v", r)
	}
	resp := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{}}}
	if r := exchange(t, s, resp); r.GetResponseHeaders() == nil {
		t.Fatalf("got %v", r)
	}
	rb := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: []byte("{}"), EndOfStream: true}}}
	if r := exchange(t, s, rb); r.GetResponseBody() == nil {
		t.Fatalf("got %v", r)
	}
	if ev := waitEvents(t, h.events, 1)[0]; ev.Decision != "allow" || !ev.BodyInspected {
		t.Fatalf("event: %+v", ev)
	}
}

func TestBodyModeNeverForSSEOrModelOrOtherHosts(t *testing.T) {
	h := newHarness(t, nil)
	body := mcpCall("x")
	cases := []struct {
		name string
		msg  *extprocv3.ProcessingRequest
	}{
		{"sse request body", headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST", ":authority", "mcp.example.com",
			":path", "/mcp", "content-type", "text/event-stream", "content-length", "10")},
		{"sse listening GET", headersMsg(identityAttrs("t1", "c1"), true, ":method", "GET", ":authority", "mcp.example.com",
			":path", "/mcp", "accept", "text/event-stream")},
		{"model call via DefenseClaw", headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST",
			":authority", "defenseclaw-actor.defenseclaw-system.svc", ":path", "/llm/bedrock/model/x/invoke-with-response-stream",
			"content-type", "application/json", "content-length", "100")},
		{"unlisted host", headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST", ":authority", "example.com",
			":path", "/", "content-type", "application/json", "content-length", strconv.Itoa(len(body)))},
		{"grpc", headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST", ":authority", "upload.example.org",
			":path", "/svc/M", "content-type", "application/grpc", "content-length", "10")},
		{"chunked, length unknown", headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST", ":authority", "mcp.example.com",
			":path", "/mcp", "content-type", "application/json")},
		{"over cap", headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST", ":authority", "mcp.example.com",
			":path", "/mcp", "content-type", "application/json", "content-length", strconv.Itoa(2<<20))},
	}
	c := dial(t, h)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, cancel := open(t, c)
			defer cancel()
			r := exchange(t, s, tc.msg)
			if r.GetModeOverride() != nil || r.GetRequestHeaders() == nil {
				t.Fatalf("got %v", r)
			}
		})
	}
	evs := waitEvents(t, h.events, 6)
	var overCap int
	for _, e := range evs {
		if e.BodyOverCap {
			overCap++
		}
	}
	if overCap != 2 {
		t.Fatalf("want 2 body_over_cap events (unknown length, over cap), got %d: %+v", overCap, evs)
	}
}

func TestBodyModeDetectionStock(t *testing.T) {
	h := newHarness(t, nil)
	c := dial(t, h)
	body := mcpCall("x")
	for i := 0; i < bodyMissLimit; i++ {
		s, cancel := open(t, c)
		if r := exchange(t, s, mcpHeaders(body)); r.GetModeOverride() == nil {
			t.Fatalf("round %d: no override", i)
		}
		// Stock v1.0.0: the filter ignores the override and ends the stream.
		_ = s.CloseSend()
		if _, err := s.Recv(); err == nil {
			t.Fatal("stream did not end")
		}
		cancel()
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.eng.BodyModeStatus() != "unsupported" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := h.eng.BodyModeStatus(); st != "unsupported" {
		t.Fatalf("status %s", st)
	}
	s, cancel := open(t, c)
	defer cancel()
	if r := exchange(t, s, mcpHeaders(body)); r.GetModeOverride() != nil {
		t.Fatal("override still requested after detection")
	}
	evs := waitEvents(t, h.events, bodyMissLimit)
	if evs[0].BodyInspected || evs[0].Decision != "allow" {
		t.Fatalf("headers-only event: %+v", evs[0])
	}
}

func TestBodyModeOff(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) { c.BodyInspection = BodyOff })
	s, cancel := open(t, dial(t, h))
	defer cancel()
	if r := exchange(t, s, mcpHeaders(mcpCall("x"))); r.GetModeOverride() != nil {
		t.Fatal("override with body_inspection off")
	}
}

func TestDecideBody(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	r := req("eng-web", "POST", "mcp.example.com", "/mcp", "content-type", "application/json")
	base := Verdict{Allow: true, Profile: "eng"}
	cases := []struct {
		name     string
		body     string
		allow    bool
		category string
	}{
		{"plain tools/call", string(mcpCall("list")), true, ""},
		{"not json-rpc", "hello", true, ""},
		{"duplicate method key", `{"jsonrpc":"2.0","method":"ping","method":"tools/call","params":{"name":"x"}}`, false, CategoryMCPToolBlocked},
		{"duplicate tool name", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"a","name":"b"}}`, false, CategoryMCPToolBlocked},
		{"no tool name", `{"jsonrpc":"2.0","method":"tools/call","params":{}}`, false, CategoryMCPToolBlocked},
		{"secret in arguments", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"k":"` + fakeAWSKey + `"}}}`, false, findSecretInBody},
		{"actor secret in arguments", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"k":"s3cret-db-value-123"}}}`, false, findActorSecret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := h.eng.DecideBody(ctx, r, base, []byte(c.body))
			if v.Allow != c.allow || (!c.allow && v.Category != c.category) || !v.BodyInspected {
				t.Fatalf("got %+v", v)
			}
		})
	}
	// Case-folded keys are not the method the server reads: not a tools/call.
	before := len(h.judge.calls)
	if v := h.eng.DecideBody(ctx, r, base, []byte(`{"jsonrpc":"2.0","METHOD":"tools/call","params":{"name":"x"}}`)); !v.Allow || len(h.judge.calls) != before {
		t.Fatalf("case-folded key judged: %+v", v)
	}
	batch := "[" + string(mcpCall("a")) + "," + string(mcpCall("b")) + "]"
	h.judge.block = true
	if v := h.eng.DecideBody(ctx, r, base, []byte(batch)); v.Allow || len(h.judge.calls) != before+1 {
		t.Fatalf("batch: %+v", v)
	}
	big := bytes.Repeat([]byte("a"), (1<<20)+1)
	if v := h.eng.DecideBody(ctx, r, base, big); !v.Allow || !v.BodyOverCap || v.BodyInspected {
		t.Fatalf("over cap: %+v", v)
	}
	h.judge.block, h.judge.err = false, errors.New("gateway down")
	if v := h.eng.DecideBody(ctx, r, base, mcpCall("x")); v.Allow || v.Category != CategoryCalloutError || !v.Retryable {
		t.Fatalf("judge error closed: %+v", v)
	}
}

// TestRedactionInLogsAndBodies proves that injected credentials, the actor
// JWT, configured secret headers, placeholders and secret values never reach
// a log line or a refusal body.
func TestRedactionInLogsAndBodies(t *testing.T) {
	var logBuf bytes.Buffer
	h := newHarness(t, func(c *Config, o *Options) {
		c.RedactHeaders = []string{"x-custom-secret"}
		o.Events = NewJSONLogSink(&logBuf)
	})
	c := dial(t, h)
	secrets := []string{injectedBearer, fakeJWT, fakeGitHubToken, fakeAWSKey, "DC_SECRET_GITHUB", "s3cret-db-value-123", "custom-value-xyz-1"}
	msgs := []*extprocv3.ProcessingRequest{
		// Allowed: injected credential on its bound host, and extra headers.
		headersMsg(identityAttrs("eng-web", "c1"), true, ":method", "GET", ":authority", "api.github.com",
			":path", "/repos/acme/x?page=DC_SECRET_GITHUB", "authorization", injectedBearer,
			"x-api-key", fakeGitHubToken, "x-custom-secret", "custom-value-xyz-1", "cookie", "sid="+fakeJWT),
		// Refused: a secret in a data header, placeholder in another.
		headersMsg(identityAttrs("eng-web", "c1"), true, ":method", "POST", ":authority", "example.com",
			":path", "/p/"+fakeAWSKey, "x-defenseclaw-actor", "Bearer "+fakeJWT, "x-token", "DC_SECRET_GITHUB",
			"x-note", "pw=s3cret-db-value-123"),
	}
	var bodies [][]byte
	for _, m := range msgs {
		s, cancel := open(t, c)
		r := exchange(t, s, m)
		if ir := r.GetImmediateResponse(); ir != nil {
			bodies = append(bodies, ir.GetBody())
		}
		cancel()
	}
	if len(bodies) != 1 {
		t.Fatalf("want one refusal, got %d", len(bodies))
	}
	deadline := time.Now().Add(3 * time.Second)
	for strings.Count(logBuf.String(), "\n") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	logs := logBuf.String()
	if strings.Count(logs, "\n") < 2 {
		t.Fatalf("logs: %s", logs)
	}
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("log carries %q", s[:6])
		}
		for _, b := range bodies {
			if strings.Contains(string(b), s) {
				t.Errorf("refusal body carries %q", s[:6])
			}
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if err := redaction.AssertNoCredentials(line); err != nil {
			t.Errorf("log line: %v", err)
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"authorization", "x-api-key", "x-custom-secret", "cookie", "x-defenseclaw-actor"} {
			if v, ok := ev.Headers[n]; ok && !strings.HasPrefix(v, "<redacted len=") {
				t.Errorf("%s logged as %q", n, v)
			}
		}
		if strings.Contains(ev.Path, "?") {
			t.Errorf("path logged with its query: %q", ev.Path)
		}
	}
}

func TestOverrideModeMatchesUpstreamAllowedEntry(t *testing.T) {
	m := overrideMode()
	if m.GetRequestBodyMode() != filterv3.ProcessingMode_BUFFERED || m.GetResponseBodyMode() != filterv3.ProcessingMode_BUFFERED ||
		m.GetResponseHeaderMode() != filterv3.ProcessingMode_SEND || m.GetRequestTrailerMode() != filterv3.ProcessingMode_SKIP ||
		m.GetResponseTrailerMode() != filterv3.ProcessingMode_SKIP {
		t.Fatalf("override %v does not match #3817's allowed_override_modes entry", m)
	}
}
