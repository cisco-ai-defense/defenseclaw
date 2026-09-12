// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPEvaluatorRequiresLiteralLoopback(t *testing.T) {
	for _, endpoint := range []string{
		"https://127.0.0.1:18970/api/v1/acp/evaluate",
		"http://localhost:18970/api/v1/acp/evaluate",
		"http://192.0.2.1/api/v1/acp/evaluate",
		"http://user@127.0.0.1:18970/api/v1/acp/evaluate",
	} {
		if _, err := NewHTTPEvaluator(endpoint, "secret"); err == nil {
			t.Fatalf("NewHTTPEvaluator(%q) accepted a non-literal-loopback endpoint", endpoint)
		}
	}
	for _, endpoint := range []string{
		"http://127.0.0.1:18970/api/v1/acp/evaluate",
		"http://[::1]:18970/api/v1/acp/evaluate",
	} {
		if _, err := NewHTTPEvaluator(endpoint, "secret"); err != nil {
			t.Fatalf("NewHTTPEvaluator(%q): %v", endpoint, err)
		}
	}
}

func TestHTTPEvaluatorReturnsHardModeMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	evaluator, err := NewHTTPEvaluator(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = evaluator.Evaluate(context.Background(), Evaluation{})
	if !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("error = %v, want ErrModeMismatch", err)
	}
}

func TestHTTPEvaluatorDoesNotFollowRedirectWithScopedToken(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("Authorization") != "" {
			t.Error("scoped token reached redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	evaluator, err := NewHTTPEvaluator(origin.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = evaluator.Evaluate(context.Background(), Evaluation{
		Mode: ModeObserve, Direction: ClientToAgent, Surface: SurfaceProtocol,
		Payload: []byte(`{"jsonrpc":"2.0","method":"initialized"}`),
	})
	if err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected {
		t.Fatal("ACP evaluator followed a redirect")
	}
}
