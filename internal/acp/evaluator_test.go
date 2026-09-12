// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"context"
	"errors"
	"io"
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
	const token = "secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		keyID := r.Header.Get(AuthKeyIDHeader)
		nonce := r.Header.Get(AuthNonceHeader)
		if !VerifyHTTPRequestMAC(token, keyID, nonce, r.Method, r.URL.Path, body, r.Header.Get(AuthRequestMACHeader)) {
			t.Error("request MAC did not verify")
		}
		w.Header().Set(AuthResponseMACHeader, HTTPResponseMAC(token, keyID, nonce, http.StatusConflict, nil))
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	evaluator, err := NewHTTPEvaluator(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = evaluator.Evaluate(context.Background(), Evaluation{})
	if !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("error = %v, want ErrModeMismatch", err)
	}
}

func TestHTTPEvaluatorRejectsLoopbackImpersonatorWithoutLeakingToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("ACP credential crossed loopback in Authorization: %q", got)
		}
		for name, values := range r.Header {
			for _, value := range values {
				if value == token {
					t.Errorf("ACP credential crossed loopback in %s", name)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow"}`))
	}))
	defer server.Close()
	evaluator, err := NewHTTPEvaluator(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = evaluator.Evaluate(context.Background(), Evaluation{
		Mode: ModeAction, Direction: ClientToAgent, Surface: SurfaceProtocol,
		Payload: []byte(`{"jsonrpc":"2.0","method":"initialized"}`),
	})
	if err == nil || err.Error() != "ACP evaluator response authentication failed" {
		t.Fatalf("impersonator error = %v", err)
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
