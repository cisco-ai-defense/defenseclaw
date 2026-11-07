// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func shapeFallbackMessages(content string) []ChatMessage {
	return []ChatMessage{
		{Role: "assistant", ToolCalls: json.RawMessage(`[{"id":"call-1","type":"function","function":{"name":"Editor","arguments":"{\"file\":\"notes.txt\"}"}}]`)},
		{Role: "user", Content: "Tool call: Editor\n" + content},
	}
}

func shapeFallbackWire(t *testing.T, r *http.Request) []map[string]json.RawMessage {
	t.Helper()
	var payload struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Errorf("decode inspection request: %v", err)
	}
	return payload.Messages
}

func hasShapeFallbackToolCalls(messages []map[string]json.RawMessage) bool {
	for _, message := range messages {
		if len(message["tool_calls"]) > 0 {
			return true
		}
	}
	return false
}

var shapeFallbackEndpointID atomic.Uint64

func TestCiscoInspectAPIKeyToolCallValidationFallback(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var mu sync.Mutex
			var requests [][]map[string]json.RawMessage
			cachedBothStarted := make(chan struct{})
			requestSnapshot := func() [][]map[string]json.RawMessage {
				mu.Lock()
				defer mu.Unlock()
				return append([][]map[string]json.RawMessage(nil), requests...)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/inspect/chat" {
					t.Errorf("path = %q", r.URL.Path)
				}
				messages := shapeFallbackWire(t, r)
				mu.Lock()
				requests = append(requests, messages)
				requestNumber := len(requests)
				if requestNumber == 4 {
					close(cachedBothStarted)
				}
				mu.Unlock()
				if requestNumber == 3 || requestNumber == 4 {
					select {
					case <-cachedBothStarted:
					case <-r.Context().Done():
						return
					}
				}
				if hasShapeFallbackToolCalls(messages) {
					w.WriteHeader(status)
					_, _ = io.WriteString(w, `{"detail":"tool_calls validation"}`)
					return
				}
				if len(messages) == 1 && string(messages[0]["content"]) == `"Tool call: Editor\nordinary edit"` {
					_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
					return
				}
				_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[{"rule_name":"Policy","classification":"VIOLATION"}]}`)
			}))
			t.Cleanup(srv.Close)

			client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			messages := shapeFallbackMessages(`{"file":"notes.txt"}`)
			if verdict := client.Inspect(t.Context(), messages); verdict == nil || verdict.Action != "block" {
				t.Fatalf("fallback verdict = %+v, want block", verdict)
			}
			gotRequests := requestSnapshot()
			if len(gotRequests) != 2 || !hasShapeFallbackToolCalls(gotRequests[0]) || hasShapeFallbackToolCalls(gotRequests[1]) {
				t.Fatalf("request shapes = %v", gotRequests)
			}
			wantText := []map[string]json.RawMessage{{"role": json.RawMessage(`"user"`), "content": json.RawMessage(`"Tool call: Editor\n{\"file\":\"notes.txt\"}"`)}}
			if !reflect.DeepEqual(gotRequests[1], wantText) {
				t.Fatalf("fallback messages = %v, want %v", gotRequests[1], wantText)
			}

			// A reconstructed client in the same process uses the learned
			// text form and checks the structured form within the same budget.
			client = &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			if verdict := client.Inspect(t.Context(), messages); verdict == nil || verdict.Action != "block" {
				t.Fatalf("remembered format verdict = %+v, want block", verdict)
			}
			gotRequests = requestSnapshot()
			bothShapes := len(gotRequests) == 4 &&
				(reflect.DeepEqual(gotRequests[2], wantText) && hasShapeFallbackToolCalls(gotRequests[3]) ||
					hasShapeFallbackToolCalls(gotRequests[2]) && reflect.DeepEqual(gotRequests[3], wantText))
			if !bothShapes {
				t.Fatalf("remembered format shapes = %v", gotRequests)
			}
			if verdict := client.Inspect(t.Context(), shapeFallbackMessages("ordinary edit")); verdict == nil || verdict.Action != "allow" {
				t.Fatalf("benign fallback verdict = %+v, want allow", verdict)
			}
			gotRequests = requestSnapshot()
			if len(gotRequests) != 6 || !hasShapeFallbackToolCalls(gotRequests[4]) || hasShapeFallbackToolCalls(gotRequests[5]) {
				t.Fatalf("different request formats = %v", gotRequests)
			}
		})
	}
}

func TestCiscoInspectAPIKeyMessageToolValidationFallback(t *testing.T) {
	const reviewedArgs = `{"topic":"policy-review"}`
	const ordinaryArgs = `{"topic":"team-update"}`
	var mu sync.Mutex
	var requests []struct {
		structured bool
		content    string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		messages := shapeFallbackWire(t, r)
		structured := hasShapeFallbackToolCalls(messages)
		var content string
		if structured {
			if len(messages) != 2 || string(messages[0]["role"]) != `"assistant"` ||
				string(messages[1]["role"]) != `"user"` {
				t.Errorf("structured messages = %v", messages)
			} else if err := json.Unmarshal(messages[1]["content"], &content); err != nil {
				t.Errorf("decode structured content: %v", err)
			}
		} else {
			if len(messages) != 1 || string(messages[0]["role"]) != `"user"` {
				t.Errorf("text messages = %v", messages)
			}
			if err := json.Unmarshal(messages[0]["content"], &content); err != nil {
				t.Errorf("decode content: %v", err)
			}
		}
		mu.Lock()
		requests = append(requests, struct {
			structured bool
			content    string
		}{structured, content})
		mu.Unlock()
		if structured {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		switch content {
		case reviewedArgs:
			_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[]}`)
		case ordinaryArgs:
			_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
		default:
			t.Errorf("unexpected text content = %q", content)
		}
	}))
	t.Cleanup(srv.Close)

	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	api := testAPIServerWithConfig(t, "action")
	api.SetCiscoInspector(client)
	inspect := func(args string) *ScanVerdict {
		return api.hookAIDInspectToolCall(t.Context(), aidToolCall{Name: "message", Args: json.RawMessage(args)}, args)
	}
	if verdict := inspect(reviewedArgs); verdict == nil || verdict.Action != "block" {
		t.Fatalf("reviewed verdict = %+v, want block", verdict)
	}
	if verdict := inspect(ordinaryArgs); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("ordinary verdict = %+v, want allow", verdict)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []struct {
		structured bool
		content    string
	}{{true, reviewedArgs}, {false, reviewedArgs}, {true, ordinaryArgs}, {false, ordinaryArgs}}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("request formats = %v, want %v", requests, want)
	}
}

func TestCiscoInspectAPIKeyMessageToolBenignTwin(t *testing.T) {
	const ordinaryArgs = `{"topic":"team-update"}`
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		messages := shapeFallbackWire(t, r)
		calls.Add(1)
		if len(messages) != 2 || !hasShapeFallbackToolCalls(messages) ||
			string(messages[1]["content"]) != `"{\"topic\":\"team-update\"}"` {
			t.Errorf("accepted messages = %v", messages)
		}
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)

	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	api := testAPIServerWithConfig(t, "action")
	api.SetCiscoInspector(client)
	verdict := api.hookAIDInspectToolCall(t.Context(), aidToolCall{Name: "message", Args: json.RawMessage(ordinaryArgs)}, ordinaryArgs)
	if verdict == nil || verdict.Action != "allow" || calls.Load() != 1 {
		t.Fatalf("benign verdict = %+v, calls = %d, want allow in one call", verdict, calls.Load())
	}
}

func TestCiscoInspectAPIKeyTextRetryPreservesDifferentToolCalls(t *testing.T) {
	var mu sync.Mutex
	var formats []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		messages := shapeFallbackWire(t, r)
		if !hasShapeFallbackToolCalls(messages) {
			mu.Lock()
			formats = append(formats, "text")
			mu.Unlock()
			_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
			return
		}
		var calls []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		}
		if len(messages) != 2 || json.Unmarshal(messages[0]["tool_calls"], &calls) != nil || len(calls) != 1 {
			t.Errorf("structured messages = %v", messages)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		formats = append(formats, "structured:"+calls[0].Function.Name)
		mu.Unlock()
		if calls[0].Function.Name == "message" && string(messages[1]["content"]) == `"{\"topic\":\"team-update\"}"` {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[]}`)
	}))
	t.Cleanup(srv.Close)

	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	api := testAPIServerWithConfig(t, "action")
	api.SetCiscoInspector(client)
	inspect := func(name, args string) *ScanVerdict {
		return api.hookAIDInspectToolCall(t.Context(), aidToolCall{Name: name, Args: json.RawMessage(args)}, args)
	}
	if verdict := inspect("message", `{"topic":"team-update"}`); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("message fallback verdict = %+v, want allow", verdict)
	}
	if verdict := inspect("Bash", `{"command":"review"}`); verdict == nil || verdict.Action != "block" {
		t.Fatalf("different tool verdict = %+v, want block", verdict)
	}
	if verdict := inspect("message", `{"topic":"review"}`); verdict == nil || verdict.Action != "block" {
		t.Fatalf("different request verdict = %+v, want block", verdict)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"structured:message", "text", "structured:Bash", "structured:message"}; !reflect.DeepEqual(formats, want) {
		t.Fatalf("request formats = %v, want %v", formats, want)
	}
}

func TestCiscoInspectAPIKeyRulesRetryKeepsToolCall(t *testing.T) {
	var mu sync.Mutex
	var shapes []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Messages []map[string]json.RawMessage `json:"messages"`
			Config   json.RawMessage              `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode inspection request: %v", err)
		}
		mu.Lock()
		shapes = append(shapes, hasShapeFallbackToolCalls(payload.Messages))
		mu.Unlock()
		if len(payload.Config) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"detail":"invalid rule name"}`)
			return
		}
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)
	client := &CiscoInspectClient{
		apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client(),
		enabledRules: []map[string]string{{"rule_name": "Policy"}},
	}
	if verdict := client.Inspect(t.Context(), shapeFallbackMessages("ordinary edit")); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("rules retry verdict = %+v, want allow", verdict)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(shapes, []bool{true, true}) {
		t.Fatalf("request shapes = %v, want tool calls on both attempts", shapes)
	}
}

func TestCiscoInspectAPIKeyAcceptedToolCallAndBenignTwin(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		messages := shapeFallbackWire(t, r)
		calls.Add(1)
		if len(messages) != 2 || !hasShapeFallbackToolCalls(messages) {
			t.Errorf("accepted endpoint should receive tool calls: %v", messages)
		}
		if string(messages[1]["content"]) == `"Tool call: Editor\nordinary edit"` {
			_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[{"rule_name":"Policy","classification":"VIOLATION"}]}`)
	}))
	t.Cleanup(srv.Close)

	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	if verdict := client.Inspect(t.Context(), shapeFallbackMessages("reviewed edit")); verdict == nil || verdict.Action != "block" {
		t.Fatalf("reviewed verdict = %+v, want block", verdict)
	}
	if verdict := client.Inspect(t.Context(), shapeFallbackMessages("ordinary edit")); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign verdict = %+v, want allow", verdict)
	}
	if calls.Load() != 2 {
		t.Fatalf("request count = %d, want 2", calls.Load())
	}
}

func TestCiscoInspectAPIKeyTextOnlyBenignTwin(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		messages := shapeFallbackWire(t, r)
		if len(messages) != 1 || hasShapeFallbackToolCalls(messages) ||
			string(messages[0]["content"]) != `"ordinary edit"` {
			t.Errorf("text-only messages = %v", messages)
		}
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)
	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	if verdict := client.Inspect(t.Context(), []ChatMessage{{Role: "user", Content: "ordinary edit"}}); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign text verdict = %+v, want allow", verdict)
	}
	if calls.Load() != 1 {
		t.Fatalf("benign text calls = %d, want 1", calls.Load())
	}
}

func TestCiscoInspectAPIKeyToolCallNonValidationStatusesDoNotRetry(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if !hasShapeFallbackToolCalls(shapeFallbackWire(t, r)) {
					t.Error("first request lost tool call")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"detail":"unavailable"}`)
			}))
			t.Cleanup(srv.Close)
			client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			if verdict := client.Inspect(t.Context(), shapeFallbackMessages("ordinary edit")); verdict != nil {
				t.Fatalf("status %d verdict = %+v, want nil", status, verdict)
			}
			if calls.Load() != 1 {
				t.Fatalf("status %d calls = %d, want 1", status, calls.Load())
			}
		})
	}
}

func TestCiscoInspectAPIKeyUnpairedToolCallKeepsOriginalShape(t *testing.T) {
	toolCall := shapeFallbackMessages("ordinary edit")[0]
	messageCall := ChatMessage{Role: "assistant", ToolCalls: json.RawMessage(`[{"type":"function","function":{"name":"message","arguments":"{\"topic\":\"team-update\"}"}}]`)}
	for name, messages := range map[string][]ChatMessage{
		"last message is a tool call": {
			{Role: "user", Content: "ordinary context"}, toolCall,
		},
		"user text has no tool companion": {
			toolCall, {Role: "user", Content: "ordinary context"},
		},
		"message text differs from tool arguments": {
			messageCall, {Role: "user", Content: "ordinary context"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				wire := shapeFallbackWire(t, r)
				if len(wire) != 2 || !hasShapeFallbackToolCalls(wire) {
					t.Errorf("original messages = %v", wire)
				}
				w.WriteHeader(http.StatusUnprocessableEntity)
			}))
			t.Cleanup(srv.Close)
			client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			if verdict := client.Inspect(t.Context(), messages); verdict != nil {
				t.Fatalf("unpaired verdict = %+v, want nil", verdict)
			}
			if calls.Load() != 1 {
				t.Fatalf("unpaired calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestCiscoInspectAPIKeyFailedTextRetryDoesNotRemember(t *testing.T) {
	var mu sync.Mutex
	var shapes []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toolCalls := hasShapeFallbackToolCalls(shapeFallbackWire(t, r))
		mu.Lock()
		shapes = append(shapes, toolCalls)
		mu.Unlock()
		if toolCalls {
			w.WriteHeader(http.StatusUnprocessableEntity)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	for range 2 {
		if verdict := client.Inspect(t.Context(), shapeFallbackMessages("ordinary edit")); verdict != nil {
			t.Fatalf("failed retry verdict = %+v, want nil", verdict)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(shapes, []bool{true, false, true, false}) {
		t.Fatalf("request shapes = %v", shapes)
	}
}

func TestCiscoInspectAPIKeyTextRetrySharesTimeout(t *testing.T) {
	var deadlines []time.Time
	transport := ciscoRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("inspection request has no deadline")
		}
		deadlines = append(deadlines, deadline)
		status, body := http.StatusUnprocessableEntity, `{"detail":"tool_calls validation"}`
		if len(deadlines) == 2 {
			status, body = http.StatusOK, `{"is_safe":true,"action":"Allow","rules":[]}`
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})
	client := &CiscoInspectClient{
		apiKey: "test-key", endpoint: fmt.Sprintf("https://inspection-%d.example.test", shapeFallbackEndpointID.Add(1)), timeout: time.Second,
		client: &http.Client{Timeout: time.Second, Transport: transport},
	}
	if verdict := client.Inspect(t.Context(), shapeFallbackMessages("ordinary edit")); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("retry verdict = %+v, want allow", verdict)
	}
	if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatalf("request deadlines = %v, want one shared deadline", deadlines)
	}
}

func TestCiscoInspectSecureClientValidationKeepsToolCallFormat(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !hasShapeFallbackToolCalls(shapeFallbackWire(t, r)) {
			t.Error("Secure Client request lost tool call")
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	t.Cleanup(srv.Close)
	client := NewCiscoDefenseClawInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: srv.URL, TimeoutMs: 1000,
	}, newFakeCloudProvider("test-token"))
	if client == nil {
		t.Fatal("expected Secure Client inspector")
	}
	if verdict := client.Inspect(context.Background(), shapeFallbackMessages("ordinary edit")); verdict != nil {
		t.Fatalf("Secure Client verdict = %+v, want nil", verdict)
	}
	if calls.Load() != 1 {
		t.Fatalf("Secure Client calls = %d, want 1", calls.Load())
	}
}
