// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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
	valid := []string{"http://127.0.0.1:18970/api/v1/acp/evaluate"}
	// The Windows connected-process proof uses the IPv4 TCP table. An IPv6
	// endpoint must be refused there rather than bypassing that proof.
	if runtime.GOOS != "windows" {
		valid = append(valid, "http://[::1]:18970/api/v1/acp/evaluate")
	} else if _, err := NewHTTPEvaluator("http://[::1]:18970/api/v1/acp/evaluate", "secret"); err == nil {
		t.Fatal("Windows accepted an IPv6 per-user evaluator without a connected-process proof")
	}
	for _, endpoint := range valid {
		if _, err := NewHTTPEvaluator(endpoint, "secret"); err != nil {
			t.Fatalf("NewHTTPEvaluator(%q): %v", endpoint, err)
		}
	}
}

func TestPerUserEvaluatorPinsRequestsToConfiguredGateway(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	var received atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()
	evaluator, err := NewHTTPEvaluator(origin.URL, "private-acp-token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, other.URL+"/api/v1/acp/challenge", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(AuthRequestMACHeader, "private-auth-proof")
	response, err := evaluator.client.Do(request)
	if err == nil {
		_ = response.Body.Close()
	}
	if err == nil || received.Load() != 0 {
		t.Fatalf("per-user evaluator sent %d authenticated requests to another endpoint; error = %v", received.Load(), err)
	}
}

func TestManagedEvaluatorUsesServiceTransport(t *testing.T) {
	previousFactory := managedGatewayClientFactory
	var requestedAddr, requestedService string
	managedGatewayClientFactory = func(timeout time.Duration, apiAddr, serviceName string) (*http.Client, error) {
		requestedAddr, requestedService = apiAddr, serviceName
		return &http.Client{Timeout: timeout}, nil
	}
	t.Cleanup(func() { managedGatewayClientFactory = previousFactory })
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	var received atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer service.Close()
	evaluator, err := NewManagedHTTPEvaluator(origin.URL, "managed-secret")
	if err != nil {
		t.Fatal(err)
	}
	if requestedAddr != origin.Listener.Addr().String() || requestedService != managedGatewayServiceName() {
		t.Fatalf("managed transport selected %q, %q; want the configured endpoint and service", requestedAddr, requestedService)
	}
	response, err := evaluator.client.Get(service.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if received.Load() != 1 {
		t.Fatalf("managed service received %d requests, want one", received.Load())
	}
}

func TestManagedEvaluatorRefusesUnverifiedServiceBeforeChallenge(t *testing.T) {
	var received atomic.Int32
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer listener.Close()
	evaluator, err := NewManagedHTTPEvaluator(listener.URL, "managed-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluator.Evaluate(context.Background(), Evaluation{}); err == nil {
		t.Fatal("an unverified managed gateway answered the ACP challenge")
	}
	if got := received.Load(); got != 0 {
		t.Fatalf("unverified managed listener received %d ACP challenge requests, want zero", got)
	}
}

func TestHTTPEvaluatorReturnsHardModeMismatch(t *testing.T) {
	const token = "secret"
	const serverNonce = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	// On a Secure Client host the guard sends no session facts, as its
	// hooks send none (issue #1092), even from inside an SSH session.
	restoreSecureClient := secureClientHost
	secureClientHost = func() bool { return true }
	t.Cleanup(func() { secureClientHost = restoreSecureClient })
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.20 22")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if facts := r.Header.Get(useridentity.SessionFactsHeader); facts != "" {
			t.Errorf("Secure Client guard sent session facts %q", facts)
		}
		body, _ := io.ReadAll(r.Body)
		keyID := r.Header.Get(AuthKeyIDHeader)
		nonce := r.Header.Get(AuthNonceHeader)
		if !VerifyHTTPRequestMAC(token, keyID, nonce, r.Method, r.URL.Path, body, r.Header.Get(AuthRequestMACHeader)) {
			t.Error("request MAC did not verify")
		}
		if r.URL.Path == "/api/v1/acp/challenge" {
			payload, _ := json.Marshal(httpGatewayChallenge{ServerNonce: serverNonce})
			w.Header().Set(AuthResponseMACHeader, HTTPResponseMAC(token, keyID, nonce, http.StatusOK, payload))
			_, _ = w.Write(payload)
			return
		}
		plaintext, err := OpenHTTPPayload(
			token, keyID, r.Header.Get(AuthChallengeNonceHeader), r.Header.Get(AuthServerNonceHeader),
			nonce, r.Method, r.URL.Path, body,
		)
		if err != nil {
			t.Errorf("encrypted request did not open: %v", err)
		}
		if !bytes.Contains(plaintext, []byte(`"payload"`)) {
			t.Errorf("decrypted evaluation is malformed: %q", plaintext)
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
	const sensitive = "initialized-sensitive-content"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(sensitive)) {
			t.Error("ACP content reached an unauthenticated loopback process")
		}
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
		Payload: []byte(`{"jsonrpc":"2.0","method":"` + sensitive + `"}`),
	})
	if err == nil || err.Error() != "ACP gateway challenge authentication failed" || !errors.Is(err, ErrResponseAuthentication) {
		t.Fatalf("impersonator error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("unauthenticated loopback process received %d requests, want only the empty challenge", requests)
	}
}

func TestHTTPPayloadEncryptionBindsChallengeAndRoutingMetadata(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const challengeNonce = "1111111111111111111111111111111111111111111111111111111111111111"
	const serverNonce = "2222222222222222222222222222222222222222222222222222222222222222"
	const requestNonce = "3333333333333333333333333333333333333333333333333333333333333333"
	keyID := HTTPAuthKeyID(token)
	plaintext := []byte(`{"payload":"private ACP content"}`)
	ciphertext, err := SealHTTPPayload(
		token, keyID, challengeNonce, serverNonce, requestNonce,
		http.MethodPost, "/api/v1/acp/evaluate", plaintext,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) || bytes.Contains(ciphertext, []byte("private ACP content")) {
		t.Fatal("sealed ACP payload retained plaintext")
	}
	opened, err := OpenHTTPPayload(
		token, keyID, challengeNonce, serverNonce, requestNonce,
		http.MethodPost, "/api/v1/acp/evaluate", ciphertext,
	)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened payload = %q, err=%v", opened, err)
	}
	if _, err := OpenHTTPPayload(
		token, keyID, challengeNonce, serverNonce, requestNonce,
		http.MethodPost, "/api/v1/acp/other", ciphertext,
	); err == nil {
		t.Fatal("ciphertext opened under a different route")
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
