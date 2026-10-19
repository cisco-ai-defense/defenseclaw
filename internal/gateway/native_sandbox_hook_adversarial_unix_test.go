// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// These tests use owned host Unix sockets and synthetic hook posts. They do
// not launch an agent, enter a sandbox, mount a socket or contact a provider.
func adversarialNativeSession(t *testing.T, fixture *sandboxIngressFixture, sessionID string) (*nativeSandboxHookIngress, *http.Client, sandboxauth.Binding, string, context.CancelFunc) {
	t.Helper()
	listener := nativeHookSocket(t)
	binding, token := nativeHookBinding(t, fixture, "claudecode", func(spec *sandboxauth.Spec) {
		spec.SandboxID = sessionID
		spec.SandboxName = sessionID
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	endpoint, err := fixture.api.newNativeSandboxHookIngress(ctx, listener, sessionID, binding.ID, token)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", listener.Addr().String())
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := endpoint.Close(cleanup); err != nil {
			t.Error("native hook owner did not finish cleanup")
		}
		cancel()
	})
	return endpoint, client, binding, token, cancel
}

func adversarialNativePost(t *testing.T, client *http.Client, path, body string, headers map[string]string) (int, http.Header) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://sandbox.invalid"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
	for name, value := range headers {
		if value == "" {
			request.Header.Del(name)
		} else {
			request.Header.Set(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10)); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header.Clone()
}

func adversarialObservedBinding(t *testing.T, seen <-chan sandboxauth.Binding, want string) {
	t.Helper()
	select {
	case binding := <-seen:
		if binding.ID != want {
			t.Fatal("native connection selected another session's binding")
		}
	default:
		t.Fatal("existing ingress did not observe the authenticated binding")
	}
}

func TestNativeHookOwnedSessionsCannotSelectEachOtherBindingOrReplay(t *testing.T) {
	seen := make(chan sandboxauth.Binding, 16)
	fixture := newSandboxIngressFixture(t, func(config *SandboxIngressConfig) {
		config.OnRequest = func(binding sandboxauth.Binding, _ sandboxauth.Route) { seen <- binding }
	})
	a, clientA, bindingA, tokenA, _ := adversarialNativeSession(t, fixture, "native-session-a")
	_, clientB, bindingB, tokenB, _ := adversarialNativeSession(t, fixture, "native-session-b")
	if bindingA.ID == bindingB.ID || bindingA.SandboxID == bindingB.SandboxID {
		t.Fatal("two owned sessions share an identity")
	}
	path := "/api/v1/claude-code/hook"
	for _, test := range []struct {
		client *http.Client
		id     string
	}{
		{clientA, bindingA.ID}, {clientB, bindingB.ID},
	} {
		if status, _ := adversarialNativePost(t, test.client, path, `{}`, nil); status != http.StatusBadRequest {
			t.Fatalf("owned hook reached wrong route result: %d", status)
		}
		adversarialObservedBinding(t, seen, test.id)
	}
	spoof := `{"sandbox_id":"` + bindingB.SandboxID + `","binding_id":"` + bindingB.ID + `"}`
	if status, _ := adversarialNativePost(t, clientA, path, spoof, map[string]string{"X-DefenseClaw-Sandbox-ID": bindingB.SandboxID}); status != http.StatusBadRequest {
		t.Fatalf("guest identity metadata changed the route result: %d", status)
	}
	adversarialObservedBinding(t, seen, bindingA.ID)
	if status, _ := adversarialNativePost(t, clientA, path, `{}`, map[string]string{"Authorization": "Bearer " + tokenB}); status != http.StatusBadRequest {
		t.Fatalf("guest-selected bearer was accepted: %d", status)
	}
	select {
	case <-seen:
		t.Fatal("guest Authorization reached the authenticated ingress")
	default:
	}
	key := map[string]string{SandboxHookIdempotencyHeader: "shared-native-key-0001"}
	for _, test := range []struct {
		client *http.Client
		id     string
	}{
		{clientA, bindingA.ID}, {clientB, bindingB.ID},
	} {
		status, header := adversarialNativePost(t, test.client, path, `not json`, key)
		if status != http.StatusBadRequest || header.Get(sandboxIdempotentReplayHeader) != "" {
			t.Fatal("foreign session replayed the first use of a shared key")
		}
		adversarialObservedBinding(t, seen, test.id)
		status, header = adversarialNativePost(t, test.client, path, `not json`, key)
		if status != http.StatusBadRequest || header.Get(sandboxIdempotentReplayHeader) != "true" {
			t.Fatal("same-session retry bypassed the existing replay cache")
		}
		adversarialObservedBinding(t, seen, test.id)
		if status, _ := adversarialNativePost(t, test.client, path, `{"changed":true}`, key); status != http.StatusUnprocessableEntity {
			t.Fatalf("changed body reused a session's key: %d", status)
		}
		adversarialObservedBinding(t, seen, test.id)
	}
	cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := a.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Match(tokenA); !errors.Is(err, sandboxauth.ErrUnauthenticated) {
		t.Fatal("stopped session's bearer survived revocation")
	}
	if _, err := fixture.store.Match(tokenB); err != nil {
		t.Fatal("stopping one session revoked another")
	}
	if status, _ := adversarialNativePost(t, clientB, path, `{}`, nil); status != http.StatusBadRequest {
		t.Fatalf("second owned session stopped with the first: %d", status)
	}
	adversarialObservedBinding(t, seen, bindingB.ID)
}

func TestNativeHookStillUsesExistingRouteBodyCSRFAndRateChecks(t *testing.T) {
	fixture := newSandboxIngressFixture(t)
	_, clientA, _, _, _ := adversarialNativeSession(t, fixture, "native-constraints-a")
	path := "/api/v1/claude-code/hook"
	for _, test := range []struct {
		path    string
		body    string
		headers map[string]string
		want    int
	}{
		{"/v1/logs", `{}`, nil, http.StatusForbidden},
		{"/api/v1/codex/hook", `{}`, nil, http.StatusForbidden},
		{path, `{}`, map[string]string{"X-DefenseClaw-Client": ""}, http.StatusForbidden},
		{path, `{}`, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{path, `{}`, map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		{path, strings.Repeat("x", int(apiRequestBodyMaxBytes)+1), nil, http.StatusRequestEntityTooLarge},
	} {
		if status, _ := adversarialNativePost(t, clientA, test.path, test.body, test.headers); status != test.want {
			t.Fatalf("existing ingress constraint changed: got %d, want %d", status, test.want)
		}
	}
	limited := newSandboxIngressFixture(t, func(config *SandboxIngressConfig) {
		config.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{HookRPS: 0.001, HookBurst: 1, OTLPRPS: 1, OTLPBurst: 1})
	})
	_, clientA, _, _, _ = adversarialNativeSession(t, limited, "native-limits-a")
	_, clientB, _, _, _ := adversarialNativeSession(t, limited, "native-limits-b")
	if status, _ := adversarialNativePost(t, clientA, path, `{}`, nil); status != http.StatusBadRequest {
		t.Fatalf("first admitted hook refused by its budget: %d", status)
	}
	if status, _ := adversarialNativePost(t, clientA, path, `{}`, nil); status != http.StatusTooManyRequests {
		t.Fatalf("per-binding rate limit was bypassed: %d", status)
	}
	if status, _ := adversarialNativePost(t, clientB, path, `{}`, nil); status != http.StatusBadRequest {
		t.Fatalf("another binding inherited the first budget: %d", status)
	}
}

func TestNativeHookOwnerAndCurrentIngressAuthorityLossFailClosed(t *testing.T) {
	t.Run("api-generation-replaced", func(t *testing.T) {
		fixture := newSandboxIngressFixture(t)
		endpoint, client, binding, token, _ := adversarialNativeSession(t, fixture, "native-api-loss")
		if err := fixture.api.SetSandboxIngress(SandboxIngressConfig{}); err != nil {
			t.Fatal(err)
		}
		if status, _ := adversarialNativePost(t, client, "/api/v1/claude-code/hook", `{}`, nil); status != http.StatusServiceUnavailable {
			t.Fatalf("replaced API ingress still authorized the old native session: %d", status)
		}
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := endpoint.Close(cleanup); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.Match(token); !errors.Is(err, sandboxauth.ErrUnauthenticated) {
			t.Fatal("API authority loss left the binding live")
		}
		if binding.SandboxID != "native-api-loss" || binding.ExecutionOS != runtime.GOOS {
			t.Fatal("test did not exercise an admitted native binding")
		}
	})
	t.Run("owner-canceled", func(t *testing.T) {
		fixture := newSandboxIngressFixture(t)
		endpoint, _, binding, token, cancel := adversarialNativeSession(t, fixture, "native-owner-loss")
		cancel()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{}`))
		request = request.WithContext(context.WithValue(request.Context(), nativeHookConnectionKey{}, endpoint))
		response := httptest.NewRecorder()
		endpoint.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatal("canceled owner re-admitted a native request")
		}
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := endpoint.Close(cleanup); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.Match(token); !errors.Is(err, sandboxauth.ErrUnauthenticated) {
			t.Fatal("owner loss left the binding live")
		}
		if binding.SandboxID != "native-owner-loss" || binding.ExecutionOS != runtime.GOOS {
			t.Fatal("test did not exercise an admitted native binding")
		}
	})
}
