// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func ciscoInspectBodyForRules(t *testing.T, rules []string) []byte {
	t.Helper()
	bodies := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	client := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: srv.URL, APIKey: "test-key", TimeoutMs: 3000, EnabledRules: rules,
	}, "")
	if client == nil {
		t.Fatal("expected Cisco AI Defense client")
	}
	if verdict := client.Inspect(t.Context(), []ChatMessage{{Role: "user", Content: "hello"}}); verdict == nil {
		t.Fatal("expected verdict on 200 response")
	}
	return <-bodies
}

func decodeCiscoInspectBody(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode inspect request %q: %v", body, err)
	}
	return payload
}

func TestCiscoInspectClient_ConfiguredRulesPreserveOrder(t *testing.T) {
	body := ciscoInspectBodyForRules(t, []string{"Prompt Injection", "Custom Policy Rule"})
	payload := decodeCiscoInspectBody(t, body)
	if len(payload) != 2 || payload["messages"] == nil {
		t.Fatalf("inspect request must contain only messages and config: %s", body)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(payload["config"], &cfg); err != nil {
		t.Fatalf("decode inspect config: %v; body=%s", err, body)
	}
	if len(cfg) != 1 {
		t.Fatalf("inspect config=%s, want enabled_rules only", payload["config"])
	}
	var got []map[string]string
	if err := json.Unmarshal(cfg["enabled_rules"], &got); err != nil {
		t.Fatalf("decode enabled_rules: %v; body=%s", err, body)
	}
	want := []map[string]string{
		{"rule_name": "Prompt Injection"},
		{"rule_name": "Custom Policy Rule"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("enabled_rules=%v, want %v", got, want)
	}
	if strings.Contains(string(body), `"Jailbreak"`) {
		t.Errorf("unconfigured catalog rule appeared in inspect request: %s", body)
	}
}

func TestCiscoInspectClient_EmptyEnabledRulesOmitConfig(t *testing.T) {
	body := ciscoInspectBodyForRules(t, []string{})
	payload := decodeCiscoInspectBody(t, body)
	if len(payload) != 1 || payload["messages"] == nil {
		t.Errorf("empty enabled_rules must send only messages: %s", body)
	}
	if _, present := payload["config"]; present {
		t.Errorf("config must be absent for an empty enabled_rules list: %s", body)
	}
}

func TestCiscoInspectClient_ConfiguredRulesRetryWithoutConfig(t *testing.T) {
	bodies := make(chan []byte, 3)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"detail":"This connection already has rules configured. Remove enabled rules from the request and try again."}`)
			return
		}
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	client := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: srv.URL, APIKey: "test-key", TimeoutMs: 3000,
		EnabledRules: []string{"Prompt Injection"},
	}, "")
	if client == nil {
		t.Fatal("expected Cisco AI Defense client")
	}
	if verdict := client.Inspect(t.Context(), []ChatMessage{{Role: "user", Content: "hello"}}); verdict == nil {
		t.Fatal("expected verdict after retry without config")
	}
	if got := len(bodies); got != 2 {
		t.Fatalf("inspect requests=%d, want 2", got)
	}
	first := decodeCiscoInspectBody(t, <-bodies)
	if _, present := first["config"]; !present {
		t.Fatal("configured rules missing from first inspect request")
	}
	second := decodeCiscoInspectBody(t, <-bodies)
	if _, present := second["config"]; present {
		t.Fatal("retry must omit config after a rules-related 400")
	}
}

// GAP-0660: with no enabled_rules there is no config block to drop, so a
// rules-related 400 is final; retrying would re-send the identical request.
func TestCiscoInspectClient_RulesRelated400WithoutConfigIsNotRetried(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"detail":"This connection already has rules configured."}`)
	}))
	t.Cleanup(srv.Close)

	client := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: srv.URL, APIKey: "test-key", TimeoutMs: 3000,
	}, "")
	if client == nil {
		t.Fatal("expected Cisco AI Defense client")
	}
	if verdict := client.Inspect(t.Context(), []ChatMessage{{Role: "user", Content: "hello"}}); verdict != nil {
		t.Fatalf("verdict=%+v, want nil for a final 400", verdict)
	}
	if requests != 1 {
		t.Fatalf("inspect requests=%d, want 1 (no config block to drop)", requests)
	}
}
