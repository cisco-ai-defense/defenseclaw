// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

func ciscoPreferenceMessages(t *testing.T, id string) []ChatMessage {
	t.Helper()
	const args = `{"command":"echo reviewed"}`
	calls, err := json.Marshal([]map[string]any{{
		"id": id, "type": "function",
		"function": map[string]string{"name": "Bash", "arguments": args},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return []ChatMessage{
		{Role: "assistant", ToolCalls: calls},
		{Role: "user", Content: "Tool call: Bash\n" + args},
	}
}

func ciscoPreferenceRequestShape(t *testing.T, r *http.Request) string {
	t.Helper()
	var body struct {
		Messages []struct {
			ToolCalls json.RawMessage `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("decode request: %v", err)
		return "invalid"
	}
	if len(body.Messages) == 2 && len(body.Messages[0].ToolCalls) > 0 {
		return "structured"
	}
	if len(body.Messages) == 1 && len(body.Messages[0].ToolCalls) == 0 {
		return "text"
	}
	return "invalid"
}

func TestCiscoInspectAPIKeyTextAllowRechecksStructured(t *testing.T) {
	for _, tc := range []struct {
		name, action string
	}{
		{name: "structured_block", action: "block"},
		{name: "benign_twin", action: "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var formats []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				shape := ciscoPreferenceRequestShape(t, r)
				mu.Lock()
				index := len(formats)
				formats = append(formats, shape)
				mu.Unlock()
				if shape == "invalid" {
					t.Error("invalid request shape")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if index == 0 {
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
				if index == 1 || tc.action == "allow" {
					_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
					return
				}
				_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[]}`)
			}))
			t.Cleanup(srv.Close)

			client := &CiscoInspectClient{apiKey: "provided by test fixture", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			if first := client.Inspect(t.Context(), ciscoPreferenceMessages(t, "first")); first == nil || first.Action != "allow" {
				t.Fatalf("first verdict = %+v, want allow", first)
			}
			if second := client.Inspect(t.Context(), ciscoPreferenceMessages(t, "second")); second == nil || second.Action != tc.action {
				t.Fatalf("second verdict = %+v, want %s", second, tc.action)
			}
			mu.Lock()
			defer mu.Unlock()
			if want := []string{"structured", "text", "structured"}; !reflect.DeepEqual(formats, want) {
				t.Fatalf("request formats = %v, want %v", formats, want)
			}
		})
	}
}

func TestCiscoInspectAPIKeyCachedBlockRechecksTextAllow(t *testing.T) {
	for _, tc := range []struct {
		name, action string
	}{
		{name: "structured_block", action: "block"},
		{name: "benign_twin", action: "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var formats []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				shape := ciscoPreferenceRequestShape(t, r)
				mu.Lock()
				index := len(formats)
				formats = append(formats, shape)
				mu.Unlock()
				if shape == "invalid" {
					t.Error("invalid request shape")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if index == 0 || index == 3 && tc.action == "allow" {
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
				if index == 1 || index == 3 {
					_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[]}`)
					return
				}
				_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
			}))
			t.Cleanup(srv.Close)

			client := &CiscoInspectClient{apiKey: "provided by test fixture", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			if first := client.Inspect(t.Context(), ciscoPreferenceMessages(t, "first")); first == nil || first.Action != "block" {
				t.Fatalf("first verdict = %+v, want block", first)
			}
			if second := client.Inspect(t.Context(), ciscoPreferenceMessages(t, "second")); second == nil || second.Action != tc.action {
				t.Fatalf("second verdict = %+v, want %s", second, tc.action)
			}
			mu.Lock()
			defer mu.Unlock()
			if want := []string{"structured", "text", "text", "structured"}; !reflect.DeepEqual(formats, want) {
				t.Fatalf("request formats = %v, want %v", formats, want)
			}
		})
	}
}

func TestCiscoInspectAPIKeyTextPreferenceExpires(t *testing.T) {
	now := time.Now()
	key := sha256.Sum256([]byte(t.Name() + now.String()))
	if !ciscoRememberAPIKeyTextOnlyRequest(key, now) || !ciscoAPIKeyTextOnlyRequestKnown(key, now) {
		t.Fatal("new preference was not available")
	}
	if ciscoAPIKeyTextOnlyRequestKnown(key, now.Add(ciscoAPIKeyTextPreferenceLifetime)) {
		t.Fatal("preference remained after its lifetime")
	}
}
