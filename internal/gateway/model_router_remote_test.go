// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

func classifierCode(err error) string {
	var ce *engine.ClassifierError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

func TestRemoteRouterClassifySendsOnlyHumanText(t *testing.T) {
	var received map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/classify/intent" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(classifyResponse{
			RecommendedModel: "fast",
			RoutingDecision:  "keyword",
			Classification:   classifyClassification{Category: "code", Confidence: 0.95},
		})
	}))
	defer srv.Close()

	res, err := NewRemoteRouterClient(srv.URL+"/", 100).Classify(context.Background(), engine.ClassifyInput{Text: "debug this", Connector: "openclaw"})
	if err != nil || len(res.Aliases) != 1 || res.Aliases[0] != "fast" || res.Category != "code" || res.Confidence != 0.95 || res.RuleID != "keyword" {
		t.Fatalf("Classify = %+v, %v", res, err)
	}
	if len(received) != 2 || received["messages"] == nil || received["options"] == nil {
		t.Fatalf("classifier received gateway context: keys=%v", received)
	}
	var messages []classifyMessage
	if err := json.Unmarshal(received["messages"], &messages); err != nil || len(messages) != 1 || messages[0].Content != "debug this" {
		t.Fatalf("classify messages = %+v, err=%v", messages, err)
	}
}

func TestRemoteRouterClassifyFailureCodes(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(200 * time.Millisecond) }))
	defer slow.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"secret-key-must-not-be-copied"}`))
	}))
	defer bad.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not-json")) }))
	defer garbage.Close()
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer empty.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("followed a redirect") }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, tc := range []struct {
		name, endpoint, code string
		timeout              int
	}{
		{"no endpoint", "", engine.FailureConfig, 10},
		{"timeout", slow.URL, engine.FailureTimeout, 20},
		{"upstream status", bad.URL, engine.FailureUpstreamStatus, 500},
		{"decode", garbage.URL, engine.FailureDecode, 500},
		{"no model", empty.URL, engine.FailureDecode, 500},
		{"redirect not followed", redirect.URL, engine.FailureUpstreamStatus, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := NewRemoteRouterClient(tc.endpoint, tc.timeout).Classify(context.Background(), engine.ClassifyInput{Text: "x"})
			if err == nil || classifierCode(err) != tc.code || len(res.Aliases) != 0 {
				t.Fatalf("Classify = %+v, %v (code %q), want %s", res, err, classifierCode(err), tc.code)
			}
		})
	}
}

func TestRemoteRouterHealthUsesItsOwnBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/classify/intent":
			_ = json.NewEncoder(w).Encode(classifyResponse{RecommendedModel: "fast"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := NewRemoteRouterClient(srv.URL, 50)
	if !client.Healthy(context.Background()) {
		t.Fatal("health response within the probe budget inherited the shorter classification timeout")
	}
	if _, err := client.Classify(context.Background(), engine.ClassifyInput{}); classifierCode(err) != engine.FailureTimeout {
		t.Fatalf("classification exceeded its latency budget: %v", err)
	}
}
