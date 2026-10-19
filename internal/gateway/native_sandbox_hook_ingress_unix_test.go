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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// This is a host transport test, not a sandbox mount/seccomp or real agent
// acceptance test. No executable, namespace or external service is used.
func nativeHookSocket(t *testing.T) *net.UnixListener {
	t.Helper()
	// A short private directory avoids Unix sockaddr limits on macOS. Cleanup
	// removes only these two known objects; it never traverses a directory.
	directory, err := os.MkdirTemp("", "dch-")
	if err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(directory)
	if err != nil {
		_ = os.Remove(directory)
		t.Fatal(err)
	}
	path := filepath.Join(directory, "hook")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		_ = held.Close()
		_ = os.Remove(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error("owned test socket cleanup failed")
		}
		_ = held.Close()
		if err := os.Remove(directory); err != nil {
			t.Error("owned test directory cleanup failed")
		}
	})
	return listener
}

func nativeHookBinding(t *testing.T, fixture *sandboxIngressFixture, name string, mutate ...func(*sandboxauth.Spec)) (sandboxauth.Binding, string) {
	t.Helper()
	spec := sandboxauth.Spec{SandboxName: "native-" + name, SandboxID: "owned-" + name, Connector: name,
		ExecutionOS: runtime.GOOS, Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		Routes: []sandboxauth.Route{sandboxauth.RouteHook}, TTL: time.Minute}
	for _, change := range mutate {
		change(&spec)
	}
	binding, token, err := fixture.store.Mint(spec)
	if err != nil {
		t.Fatal(err)
	}
	return binding, token
}

func nativeHookEndpoint(t *testing.T, fixture *sandboxIngressFixture, name string) (*nativeSandboxHookIngress, *http.Client, sandboxauth.Binding) {
	t.Helper()
	listener := nativeHookSocket(t)
	binding, token := nativeHookBinding(t, fixture, name)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	endpoint, err := fixture.api.newNativeSandboxHookIngress(ctx, listener, binding.SandboxID, binding.ID, token)
	if err != nil {
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
			t.Error("owned endpoint did not finish cleanup")
		}
	})
	return endpoint, client, binding
}

func nativeHookPost(t *testing.T, client *http.Client, path string, headers ...string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://sandbox.invalid"+path, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func TestNativeHookIngressAllConnectorsUseExistingAuthenticatedDispatch(t *testing.T) {
	for _, name := range []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "omnigent", "opencode", "openhands"} {
		t.Run(name, func(t *testing.T) {
			seen := make(chan sandboxauth.Binding, 8)
			fixture := newSandboxIngressFixture(t, func(config *SandboxIngressConfig) {
				config.OnRequest = func(binding sandboxauth.Binding, _ sandboxauth.Route) { seen <- binding }
			})
			_, client, binding := nativeHookEndpoint(t, fixture, name)
			registered, ok := sharedDefaultRegistry().Get(name)
			if !ok {
				t.Fatal("existing connector is absent")
			}
			path := registered.(connector.HookEndpoint).HookAPIPath()
			code, body := nativeHookPost(t, client, path)
			want := "hook event name is required"
			if name == "codex" {
				want = "installer-bound Codex hook event is required"
			} else if name == "copilot" {
				want = "Copilot hook event registration is required"
			} else if name == "antigravity" {
				want = "Antigravity hook event registration is required"
			}
			if code != http.StatusBadRequest || !strings.Contains(body, want) {
				t.Fatalf("request did not reach the existing connector pipeline: status=%d", code)
			}
			select {
			case observed := <-seen:
				if observed.ID != binding.ID || observed.Connector != name || observed.ExecutionOS != runtime.GOOS {
					t.Fatal("request selected a different authenticated binding")
				}
			default:
				t.Fatal("existing ingress did not observe the request")
			}
			if code, _ := nativeHookPost(t, client, path, "Authorization", "Bearer guest-selected"); code != http.StatusBadRequest {
				t.Fatal("guest Authorization was accepted")
			}
			if code, _ := nativeHookPost(t, client, "/v1/logs"); code != http.StatusForbidden {
				t.Fatal("hook-only binding acquired telemetry authority")
			}
			other := "/api/v1/claude-code/hook"
			if name == "claudecode" {
				other = "/api/v1/codex/hook"
			}
			if code, _ := nativeHookPost(t, client, other); code != http.StatusForbidden {
				t.Fatal("connection selected another connector")
			}
			if err := fixture.store.Revoke(binding.ID); err != nil {
				t.Fatal(err)
			}
			if code, _ := nativeHookPost(t, client, path); code != http.StatusUnauthorized {
				t.Fatal("revoked binding remained authorized")
			}
		})
	}
}

func TestNativeHookIngressRefusesUnscopedBindingsAndUnboundedOwner(t *testing.T) {
	for _, mutation := range []string{"legacy-os", "default-routes", "unbounded-token", "missing-session", "wrong-session", "wrong-token", "unbounded-owner"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newSandboxIngressFixture(t)
			binding, token := nativeHookBinding(t, fixture, "claudecode", func(spec *sandboxauth.Spec) {
				switch mutation {
				case "legacy-os":
					spec.ExecutionOS = ""
				case "default-routes":
					spec.Routes = nil
				case "unbounded-token":
					spec.TTL = 0
				case "missing-session":
					spec.SandboxID = ""
				}
			})
			presented := token
			if mutation == "wrong-token" {
				presented = "guest-selected"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if mutation == "unbounded-owner" {
				ctx = context.Background()
			}
			sessionID := binding.SandboxID
			if mutation == "wrong-session" {
				sessionID = "owned-another-session"
			}
			endpoint, err := fixture.api.newNativeSandboxHookIngress(ctx, nativeHookSocket(t), sessionID, binding.ID, presented)
			if endpoint != nil || !errors.Is(err, errNativeHookIngress) {
				t.Fatal("unqualified native binding or owner was accepted")
			}
			if _, err := fixture.store.Match(token); err != nil {
				t.Fatal("constructor refusal consumed caller-owned binding")
			}
		})
	}
}

func TestNativeHookIngressCannotGrantTCPAuthorityOrMutateGuestHeaders(t *testing.T) {
	fixture := newSandboxIngressFixture(t)
	endpoint, _, _ := nativeHookEndpoint(t, fixture, "claudecode")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{}`))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	request = request.WithContext(endpoint.connectionContext(request.Context(), left))
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("foreign transport acquired native binding authority")
	}
	request = request.WithContext(context.WithValue(request.Context(), nativeHookConnectionKey{}, endpoint))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
	endpoint.ServeHTTP(httptest.NewRecorder(), request)
	if request.Header.Get("Authorization") != "" {
		t.Fatal("host bearer escaped into caller request headers")
	}
}

func TestNativeHookIngressCloseRevokesBeforeRetainedRequestDrain(t *testing.T) {
	fixture := newSandboxIngressFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	fixture.api.sandboxIngressState().handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release // deliberately ignores cancellation to test retained cleanup
	})
	endpoint, client, binding := nativeHookEndpoint(t, fixture, "claudecode")
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, err := client.Post("http://sandbox.invalid/api/v1/claude-code/hook", "application/json", strings.NewReader(`{}`))
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owned request did not start")
	}
	cleanup, done := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := endpoint.Close(cleanup)
	done()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending handler was reported as cleaned up")
	}
	if _, err := fixture.store.Get(binding.ID); !errors.Is(err, sandboxauth.ErrNotFound) {
		t.Fatal("binding was not revoked before request drain")
	}
	releaseOnce.Do(func() { close(release) })
	cleanup, done = context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := endpoint.Close(cleanup); err != nil {
		t.Fatal("retained cleanup did not complete on retry")
	}
	select {
	case <-finished:
	case <-cleanup.Done():
		t.Fatal("owned HTTP client did not finish")
	}
}
