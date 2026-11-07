// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func ciscoMessageCompatMessages(args string) []ChatMessage {
	encodedArgs, _ := json.Marshal(args)
	return []ChatMessage{
		{Role: "assistant", ToolCalls: json.RawMessage(`[{"id":"call-1","type":"function","function":{"name":"message","arguments":` + string(encodedArgs) + `}}]`)},
		{Role: "user", Content: args},
	}
}

func TestCiscoInspectAPIKeyMessageToolWireFallback(t *testing.T) {
	const args = `{"topic":"policy-review"}`
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role      string          `json:"role"`
				Content   string          `json:"content"`
				ToolCalls json.RawMessage `json:"tool_calls"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		switch calls.Add(1) {
		case 1:
			if len(request.Messages) != 2 || len(request.Messages[0].ToolCalls) == 0 {
				t.Errorf("first request messages = %+v", request.Messages)
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
		case 2:
			if len(request.Messages) != 1 || request.Messages[0].Role != "user" || request.Messages[0].Content != args || len(request.Messages[0].ToolCalls) != 0 {
				t.Errorf("second request messages = %+v", request.Messages)
			}
			_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[]}`)
		default:
			t.Error("unexpected extra inspection request")
		}
	}))
	t.Cleanup(srv.Close)
	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	if verdict := client.Inspect(t.Context(), ciscoMessageCompatMessages(args)); verdict == nil || verdict.Action != "block" || calls.Load() != 2 {
		t.Fatalf("verdict = %+v, calls = %d; want block after one retry", verdict, calls.Load())
	}
}

func TestCiscoInspectAPIKeyMessageToolWireBenignTwin(t *testing.T) {
	const args = `{"topic":"team-update"}`
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		calls.Add(1)
		if len(request.Messages) != 2 || request.Messages[1].Content != args {
			t.Errorf("accepted request messages = %+v", request.Messages)
		}
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)
	client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
	if verdict := client.Inspect(t.Context(), ciscoMessageCompatMessages(args)); verdict == nil || verdict.Action != "allow" || calls.Load() != 1 {
		t.Fatalf("verdict = %+v, calls = %d; want allow in one call", verdict, calls.Load())
	}
}
