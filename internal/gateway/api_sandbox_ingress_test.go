// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const sandboxTestMasterToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type sandboxIngressFixture struct {
	api       *APIServer
	store     *sandboxauth.FileStore
	handler   http.Handler
	dataDir   string
	project   string
	claude    sandboxauth.Binding
	claudeTok string
	codex     sandboxauth.Binding
	codexTok  string
}

func newSandboxIngressFixture(t *testing.T, mutate ...func(*SandboxIngressConfig)) *sandboxIngressFixture {
	t.Helper()
	dataDir := t.TempDir()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: dataDir, Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, cfg)
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(dataDir), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	claude, claudeTok, err := store.Mint(sandboxauth.Spec{
		SandboxName:    "dc-claude-app",
		SandboxID:      "11111111-2222-3333-4444-555555555555",
		Connector:      "claudecode",
		AgentVersion:   "2.1.156",
		HookContractID: "claudecode-hooks-v1",
		PolicyProfile:  "open",
		Routes:         []sandboxauth.Route{sandboxauth.RouteHook, sandboxauth.RouteOTLP, sandboxauth.RouteInspect},
		Workdir: sandboxauth.Workdir{
			Mode:   sandboxauth.WorkdirMount,
			Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: project}},
		},
		HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	codex, codexTok, err := store.Mint(sandboxauth.Spec{
		SandboxName:    "dc-codex-app",
		Connector:      "codex",
		AgentVersion:   "0.128.0",
		HookContractID: "codex-hooks-v1",
		Workdir:        sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		HostUser:       sandboxauth.HostUser{UID: "1000", Name: "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ingress := SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: store}
	for _, m := range mutate {
		m(&ingress)
	}
	if err := api.SetSandboxIngress(ingress); err != nil {
		t.Fatal(err)
	}
	handler, err := api.SandboxIngressHandler()
	if err != nil {
		t.Fatal(err)
	}
	return &sandboxIngressFixture{
		api: api, store: store, handler: handler, dataDir: dataDir, project: project,
		claude: claude, claudeTok: claudeTok, codex: codex, codexTok: codexTok,
	}
}

func (f *sandboxIngressFixture) do(t *testing.T, method, path, token, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:43210"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestSetSandboxIngressValidatesConfig(t *testing.T) {
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil)
	store := staticMatcher{}
	for _, tc := range []struct {
		name string
		cfg  SandboxIngressConfig
	}{
		{"no bindings", SandboxIngressConfig{Addr: "127.0.0.1:18971"}},
		{"no port", SandboxIngressConfig{Addr: "127.0.0.1", Bindings: store}},
		{"wildcard", SandboxIngressConfig{Addr: "0.0.0.0:18971", Bindings: store}},
		{"lan", SandboxIngressConfig{Addr: "192.168.1.10:18971", Bindings: store}},
		{"hostname", SandboxIngressConfig{Addr: "localhost:18971", Bindings: store}},
		{"main port", SandboxIngressConfig{Addr: "127.0.0.1:18970", Bindings: store}},
		{"bad port", SandboxIngressConfig{Addr: "127.0.0.1:99999", Bindings: store}},
		{"negative otlp cap", SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: store, OTLPMaxBodyBytes: -1}},
		{"otlp cap above host", SandboxIngressConfig{
			Addr: "127.0.0.1:18971", Bindings: store, OTLPMaxBodyBytes: otlpRequestBodyMaxBytes + 1,
		}},
	} {
		if err := api.SetSandboxIngress(tc.cfg); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if err := api.SetSandboxIngress(SandboxIngressConfig{Addr: "[::1]:18971", Bindings: store}); err != nil {
		t.Fatalf("ipv6 loopback: %v", err)
	}
	if api.SandboxIngressAddr() != "[::1]:18971" || api.SandboxIngressInFlight() == nil {
		t.Fatal("ingress state not recorded")
	}
	if err := api.SetSandboxIngress(SandboxIngressConfig{}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if api.SandboxIngressAddr() != "" || api.SandboxIngressInFlight() != nil {
		t.Fatal("zero config did not disable the ingress")
	}
	if _, err := api.SandboxIngressHandler(); err == nil {
		t.Fatal("handler available while disabled")
	}
	if err := api.RunSandboxIngress(context.Background()); err == nil {
		t.Fatal("run while disabled")
	}
}

func TestSandboxIngressAddrClashesWithMainAPI(t *testing.T) {
	for _, tc := range []struct {
		ingress, main string
		clash         bool
	}{
		{"127.0.0.1:18970", "127.0.0.1:18970", true},
		{"127.0.0.1:18970", "localhost:18970", true},
		{"[::1]:18970", "LocalHost.:18970", true},
		{"127.0.0.1:18970", ":18970", true},
		{"127.0.0.1:18970", "0.0.0.0:18970", true},
		{"127.0.0.1:18970", "[::]:18970", true},
		// A hostname could resolve to loopback; only the port is known.
		{"127.0.0.1:18970", "gateway.internal:18970", true},
		{"127.0.0.1:18970", "127.0.0.2:18970", false},
		{"127.0.0.1:18970", "[::1]:18970", false},
		{"127.0.0.1:18971", "localhost:18970", false},
		{"127.0.0.1:18971", ":18970", false},
		{"127.0.0.1:18971", "", false},
		// An ephemeral ingress port never clashes.
		{"127.0.0.1:0", ":0", false},
	} {
		err := validateSandboxIngressAddr(tc.ingress, tc.main)
		if (err != nil) != tc.clash {
			t.Errorf("ingress %q with main %q: err = %v, want clash %v", tc.ingress, tc.main, err, tc.clash)
		}
	}
}

// TestRunSandboxIngressDrainsInFlightRequests pins graceful shutdown:
// cancelling the run context stops new connections but does not cancel the
// context of a request already running, which completes within the grace
// period; a request that overruns it is cut off.
func TestRunSandboxIngressDrainsInFlightRequests(t *testing.T) {
	for _, tc := range []struct {
		name    string
		overrun bool
	}{{"drain", false}, {"overrun", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Skipf("loopback listener unavailable: %v", err)
			}
			addr := ln.Addr().String()
			_ = ln.Close()
			api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil)
			if err := api.SetSandboxIngress(SandboxIngressConfig{Addr: addr, Bindings: staticMatcher{}}); err != nil {
				t.Fatal(err)
			}
			if tc.overrun {
				previous := sandboxIngressShutdownTimeout
				sandboxIngressShutdownTimeout = 200 * time.Millisecond
				t.Cleanup(func() { sandboxIngressShutdownTimeout = previous })
			}
			started := make(chan struct{})
			release := make(chan struct{})
			canceled := make(chan struct{}, 1)
			st := api.sandboxIngressState()
			st.handlerOnce.Do(func() {
				st.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Like every hook handler, consume the body first; the
					// server then watches the connection for a hang-up.
					_, _ = io.Copy(io.Discard, r.Body)
					close(started)
					select {
					case <-release:
						w.WriteHeader(http.StatusOK)
					case <-r.Context().Done():
						canceled <- struct{}{}
					}
				})
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() { runErr <- api.RunSandboxIngress(ctx) }()

			respCh := make(chan int, 1)
			go func() {
				client := &http.Client{Timeout: 10 * time.Second}
				for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
					resp, err := client.Post("http://"+addr+"/", "application/json", strings.NewReader(`{}`))
					if err == nil {
						_ = resp.Body.Close()
						respCh <- resp.StatusCode
						return
					}
					select {
					case <-started:
						respCh <- 0
						return
					default:
					}
					time.Sleep(20 * time.Millisecond)
				}
				respCh <- -1
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request never reached the handler")
			}
			cancel()
			select {
			case <-canceled:
				if !tc.overrun {
					t.Fatal("stopping the ingress cancelled an in-flight request")
				}
			case <-time.After(100 * time.Millisecond):
				if tc.overrun {
					// Still running: the grace period has not ended yet.
					break
				}
				close(release)
			}
			if tc.overrun {
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("an overrunning request was never cut off")
				}
			}
			if status := <-respCh; !tc.overrun && status != http.StatusOK {
				t.Fatalf("drained request status = %d", status)
			}
			select {
			case err := <-runErr:
				if tc.overrun != (err != nil) {
					t.Fatalf("RunSandboxIngress = %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("ingress did not shut down")
			}
		})
	}
}

type staticMatcher map[string]sandboxauth.Binding

func (m staticMatcher) Match(token string) (sandboxauth.Binding, error) {
	if b, ok := m[token]; ok {
		return b, nil
	}
	return sandboxauth.Binding{}, sandboxauth.ErrUnauthenticated
}

func TestSandboxIngressRejectsEveryOtherCredential(t *testing.T) {
	f := newSandboxIngressFixture(t)
	hookToken, err := connector.EnsureHookAPIToken(f.dataDir, "claudecode")
	if err != nil {
		t.Fatal(err)
	}
	otlpToken, err := connector.EnsureOTLPPathToken(f.dataDir, connector.OTLPScopeClaude)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"none":                      "",
		"master gateway token":      sandboxTestMasterToken,
		"connector hook token":      hookToken,
		"otlp scoped token":         otlpToken,
		"unsubstituted placeholder": "openshell:resolve:env:v13503686996004693124_DEFENSECLAW_SANDBOX_TOKEN",
		"malformed binding":         sandboxauth.TokenPrefix + "not-a-token",
	} {
		for _, path := range []string{"/api/v1/claude-code/hook", "/v1/logs", "/api/v1/inspect/tool", "/health", "/status"} {
			if rec := f.do(t, http.MethodPost, path, token, `{}`); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s on %s: status %d, want 401", name, path, rec.Code)
			}
		}
	}
	// Other credential headers never authenticate, even alongside nothing.
	for _, header := range []string{"X-DefenseClaw-Token", "X-DC-Auth"} {
		rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", "", `{}`, header, "Bearer "+f.claudeTok)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", header, rec.Code)
		}
	}
	// The binding credential in the query string is not a credential.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook?token="+f.claudeTok, strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query token: %d", rec.Code)
	}
	// Two Authorization headers are ambiguous.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{}`))
	req.Header.Add("Authorization", "Bearer "+f.claudeTok)
	req.Header.Add("Authorization", "Bearer "+f.codexTok)
	rec = httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate Authorization: %d", rec.Code)
	}
}

// TestSandboxIngressRefusesCredentialOutsideAuthorization covers a
// workload that puts its credential placeholder in some other header or in
// the query string, where OpenShell also substitutes it. Nothing that
// carries the real credential may reach a handler that echoes or persists
// request metadata.
func TestSandboxIngressRefusesCredentialOutsideAuthorization(t *testing.T) {
	f := newSandboxIngressFixture(t)
	st := f.api.sandboxIngressState()
	next := &recordingHandler{}
	h := f.api.sandboxIngressAuthenticate(st, sandboxRequestIDMiddleware(next))
	tok := f.claudeTok
	basic := base64.StdEncoding.EncodeToString([]byte("x:" + tok))
	escaped := strings.Replace(tok, "_", "%5F", 1)

	for _, tc := range []struct {
		name    string
		target  string
		headers []string
	}{
		{name: "request id header", target: "/api/v1/claude-code/hook", headers: []string{"X-Request-Id", tok}},
		{name: "canonical request id", target: "/api/v1/claude-code/hook", headers: []string{RequestIDHeader, "id-" + tok}},
		{name: "correlation id", target: "/v1/logs", headers: []string{"X-Correlation-Id", tok}},
		{name: "session id", target: "/api/v1/claude-code/hook", headers: []string{"X-DefenseClaw-Session-Id", tok}},
		{name: "idempotency key", target: "/api/v1/claude-code/hook", headers: []string{SandboxHookIdempotencyHeader, tok}},
		{name: "traceparent", target: "/api/v1/claude-code/hook", headers: []string{"Traceparent", tok}},
		{name: "header name", target: "/api/v1/claude-code/hook", headers: []string{"X-" + tok, "1"}},
		{name: "basic encoded", target: "/api/v1/claude-code/hook", headers: []string{"Proxy-Authorization", "Basic " + basic}},
		{name: "query", target: "/api/v1/claude-code/hook?session=" + tok},
		{name: "percent-encoded query", target: "/v1/logs?x=" + escaped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(next.reqs)
			req := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(`{}`))
			req.RemoteAddr = "127.0.0.1:43210"
			req.Header.Set("Authorization", "Bearer "+tok)
			for i := 0; i+1 < len(tc.headers); i += 2 {
				req.Header.Set(tc.headers[i], tc.headers[i+1])
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			if len(next.reqs) != before {
				t.Fatal("request reached the handler chain")
			}
			for name, values := range rec.Header() {
				for _, value := range values {
					if strings.Contains(value, tok) {
						t.Fatalf("response header %s echoes the credential", name)
					}
				}
			}
			if strings.Contains(rec.Body.String(), tok) {
				t.Fatal("response body echoes the credential")
			}
		})
	}

	// The full chain refuses it too, before any middleware echoes anything.
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", tok, `{}`, "X-Request-Id", tok)
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Header().Get(RequestIDHeader), tok) {
		t.Fatalf("full chain: status %d, request id %q", rec.Code, rec.Header().Get(RequestIDHeader))
	}
	// An ordinary request still passes.
	if rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", tok, `{}`); rec.Code == http.StatusBadRequest &&
		strings.Contains(rec.Body.String(), "Authorization header") {
		t.Fatal("a request with only an Authorization credential was refused")
	}
}

// TestSandboxIngressAlwaysMintsRequestIDs pins that a sandbox cannot choose
// the request ID that is echoed to it and stamped on every audit row.
func TestSandboxIngressAlwaysMintsRequestIDs(t *testing.T) {
	f := newSandboxIngressFixture(t)
	st := f.api.sandboxIngressState()
	var seen string
	var seenHeaders []string
	h := f.api.sandboxIngressAuthenticate(st, sandboxRequestIDMiddleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seen = RequestIDFromContext(r.Context())
			for _, name := range clientRequestIDHeaders {
				if v := r.Header.Get(name); v != "" {
					seenHeaders = append(seenHeaders, name)
				}
			}
			w.WriteHeader(http.StatusNoContent)
		})))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.claudeTok)
	req.Header.Set(RequestIDHeader, "client-chosen-1")
	req.Header.Set("X-Request-Id", "client-chosen-2")
	req.Header.Set("X-Correlation-Id", "client-chosen-3")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	echoed := rec.Header().Get(RequestIDHeader)
	if echoed == "" || strings.HasPrefix(echoed, "client-chosen") || echoed != seen {
		t.Fatalf("request id echoed=%q context=%q, want one minted id", echoed, seen)
	}
	if len(seenHeaders) != 0 {
		t.Fatalf("client request-id headers reached the handler: %v", seenHeaders)
	}
	// Host traffic keeps honouring a client request ID.
	host := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	req.Header.Set("X-Request-Id", "client-chosen-2")
	rec = httptest.NewRecorder()
	host.ServeHTTP(rec, req)
	if got := rec.Header().Get(RequestIDHeader); got != "client-chosen-2" {
		t.Fatalf("host request id = %q", got)
	}
}

// ingressServedPaths are the paths the ingress mux can reach at all.
func ingressServedPaths(t *testing.T, api *APIServer) map[string]sandboxIngressRoute {
	t.Helper()
	_, exact := api.sandboxIngressMux()
	return exact
}

func TestSandboxIngressServesOnlyItsAllowlist(t *testing.T) {
	f := newSandboxIngressFixture(t)
	exact := ingressServedPaths(t, f.api)
	for path, route := range exact {
		if route.class == sandboxauth.RouteHook && !strings.HasSuffix(path, "/hook") {
			t.Errorf("hook route %s is not a hook path", path)
		}
	}
	if route, ok := exact["/api/v1/codex/notify"]; !ok || route.class != sandboxauth.RouteNotify {
		t.Fatalf("codex notify missing from ingress: %+v", exact)
	}
	for _, path := range mainAPIRoutePaths(t) {
		served := exact[path].class != "" || slices.Contains(sandboxInspectPaths, path) || slices.Contains(sandboxOTLPPaths, path)
		rec := f.do(t, http.MethodPost, path, f.claudeTok, `{}`)
		switch {
		case !served:
			if rec.Code != http.StatusNotFound {
				t.Errorf("main-only route %s via ingress: status %d, want 404", path, rec.Code)
			}
		case path == "/api/v1/claude-code/hook" || slices.Contains(sandboxOTLPPaths, path):
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound {
				t.Errorf("allowed route %s via ingress: status %d", path, rec.Code)
			}
		case slices.Contains(sandboxInspectPaths, path):
			// Inspect requires the caller to name its connector.
			if rec.Code != http.StatusForbidden {
				t.Errorf("inspect %s without connector: status %d, want 403", path, rec.Code)
			}
			rec = f.do(t, http.MethodPost, path, f.claudeTok, `{}`, "X-DefenseClaw-Connector", "claudecode")
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound {
				t.Errorf("inspect %s for own connector: status %d", path, rec.Code)
			}
		default:
			if rec.Code != http.StatusForbidden {
				t.Errorf("other connector route %s via claude binding: status %d, want 403", path, rec.Code)
			}
		}
	}
	for _, path := range []string{"/otlp/claudecode/x/v1/logs", "/api/v1/admin/shutdown", "/api/v1/claude-code/hook/", "/", "/api/v1/inspect/"} {
		if rec := f.do(t, http.MethodPost, path, f.claudeTok, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, rec.Code)
		}
	}
}

func TestSandboxIngressCrossConnectorRefusal(t *testing.T) {
	f := newSandboxIngressFixture(t)
	cases := []struct {
		name    string
		token   string
		path    string
		headers []string
	}{
		{"claude binding on codex hook", f.claudeTok, "/api/v1/codex/hook", nil},
		{"claude binding on codex notify", f.claudeTok, "/api/v1/codex/notify", nil},
		{"claude binding on cursor hook", f.claudeTok, "/api/v1/cursor/hook", nil},
		{"codex binding on claude hook", f.codexTok, "/api/v1/claude-code/hook", nil},
		{"claude inspect as codex", f.claudeTok, "/api/v1/inspect/tool", []string{"X-DefenseClaw-Connector", "codex"}},
		{"codex binding without inspect route", f.codexTok, "/api/v1/inspect/tool", []string{"X-DefenseClaw-Connector", "codex"}},
		{"claude otlp as codex", f.claudeTok, "/v1/logs", []string{otelSourceHeader, "codex"}},
		{"claude otlp as unknown source", f.claudeTok, "/v1/metrics", []string{otelSourceHeader, "not-a-connector"}},
		{"codex otlp as claude", f.codexTok, "/v1/traces", []string{otelSourceHeader, "claude-code"}},
	}
	for _, tc := range cases {
		rec := f.do(t, http.MethodPost, tc.path, tc.token, `{}`, tc.headers...)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
	// Aliases of the binding's own connector are the same connector.
	rec := f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, `{}`, otelSourceHeader, "claude-code")
	if rec.Code == http.StatusForbidden {
		t.Fatalf("own connector alias refused: %s", rec.Body.String())
	}
}

// recordingHandler captures the request that reaches the mux.
type recordingHandler struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.reqs = append(h.reqs, r)
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func TestSandboxIngressAuthorizeScopesTheRequest(t *testing.T) {
	f := newSandboxIngressFixture(t)
	st := f.api.sandboxIngressState()
	_, exact := f.api.sandboxIngressMux()
	next := &recordingHandler{}
	h := f.api.sandboxIngressAuthenticate(st, f.api.sandboxIngressAuthorize(st, exact, next))

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.claudeTok)
	req.Header.Set(llmEventUserIDHeader, "0")
	req.Header.Set(llmEventUserNameHeader, "root")
	req.Header.Set("X-User-Id", "attacker")
	h.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.claudeTok)
	h.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.claudeTok)
	req.Header.Set("X-DefenseClaw-Connector", "claudecode")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(next.reqs) != 3 {
		t.Fatalf("reached mux %d times, want 3", len(next.reqs))
	}
	otlp, hook, inspect := next.reqs[0], next.reqs[1], next.reqs[2]
	if got := otlp.Header.Get(otelSourceHeader); got != "claudecode" {
		t.Fatalf("otlp source = %q, want the binding connector", got)
	}
	for _, header := range sandboxIdentityHeaders {
		if otlp.Header.Get(header) != "" {
			t.Fatalf("identity header %s reached the handler", header)
		}
	}
	binding, ok := sandboxauth.FromContext(otlp.Context())
	if !ok || binding.ID != f.claude.ID {
		t.Fatal("binding missing from request context")
	}
	if view, ok := sandboxauth.ViewFromContext(otlp.Context()); !ok || !view.HostAccess() {
		t.Fatal("mount-mode view missing from request context")
	}
	if got := authenticatedHookConnector(hook.Context()); got != "claudecode" {
		t.Fatalf("hook connector scope = %q", got)
	}
	if got := authenticatedInspectConnector(inspect.Context()); got != "claudecode" {
		t.Fatalf("inspect connector scope = %q", got)
	}
	if got := authenticatedHookConnector(otlp.Context()); got != "" {
		t.Fatalf("otlp request carries a hook scope %q", got)
	}
	id := AgentIdentityFromContext(hook.Context())
	if id.UserID != "1000" || id.UserName != "dev" || id.UserIDKind == "" {
		t.Fatalf("identity = %+v, want the binding host user", id)
	}
}

func TestSandboxIngressLimiterAndInFlight(t *testing.T) {
	inFlight := sandboxauth.NewInFlight(nil)
	f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
		cfg.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{HookRPS: 0.001, HookBurst: 2, OTLPRPS: 0.001, OTLPBurst: 1})
		cfg.InFlight = inFlight
	})
	if f.api.SandboxIngressInFlight() != inFlight {
		t.Fatal("configured in-flight tracker not used")
	}
	for i := 0; i < 2; i++ {
		if rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled early", i)
		}
	}
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("third hook: %d", rec.Code)
	}
	// Telemetry has its own bucket; another binding is unaffected.
	if rec := f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, `{}`); rec.Code == http.StatusTooManyRequests {
		t.Fatal("otlp throttled by hook budget")
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/codex/hook", f.codexTok, `{}`); rec.Code == http.StatusTooManyRequests {
		t.Fatal("codex throttled by claude budget")
	}
	if inFlight.LastActivity(f.claude.ID).IsZero() || inFlight.Active(f.claude.ID) != 0 {
		t.Fatalf("in-flight not tracked: active=%d", inFlight.Active(f.claude.ID))
	}
	// Refused requests are never counted as activity.
	before := inFlight.LastActivity(f.codex.ID)
	f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.codexTok, `{}`)
	if !inFlight.LastActivity(f.codex.ID).Equal(before) {
		t.Fatal("a refused route counted as activity")
	}
	f.api.ForgetSandboxBinding(f.claude.ID)
	if rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`); rec.Code == http.StatusTooManyRequests {
		t.Fatal("forget did not reset the limiter")
	}
}

// TestSandboxIngressOTLPBodyCap pins the sandbox OTLP body cap: the
// receiver buffers a whole upload before decoding, so a sandbox gets a few
// MiB rather than the host receiver's 64 MiB.
func TestSandboxIngressOTLPBodyCap(t *testing.T) {
	if defaultSandboxOTLPMaxBodyBytes > 8<<20 || defaultSandboxOTLPMaxBodyBytes >= otlpRequestBodyMaxBytes {
		t.Fatalf("default sandbox OTLP cap %d is not a few MiB", defaultSandboxOTLPMaxBodyBytes)
	}
	runtime := newSidecarRuntimeFixture(t, true)
	pad := func(n int64) string {
		return `{"resourceLogs":[],"pad":"` + strings.Repeat("a", int(n)) + `"}`
	}

	f := newSandboxIngressFixture(t)
	f.api.bindOTLPObservabilityRuntime(runtime.runtime)
	if st := f.api.sandboxIngressState(); st.otlpMaxBytes != defaultSandboxOTLPMaxBodyBytes {
		t.Fatalf("default cap = %d", st.otlpMaxBytes)
	}
	if rec := f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, pad(defaultSandboxOTLPMaxBodyBytes)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload over the default cap: %d", rec.Code)
	}

	f = newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) { cfg.OTLPMaxBodyBytes = 1 << 10 })
	f.api.bindOTLPObservabilityRuntime(runtime.runtime)
	if rec := f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, pad(2<<10)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload over a configured cap: %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, `{"resourceLogs":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("upload under the cap: %d %s", rec.Code, rec.Body.String())
	}
	// Hook bodies keep the ordinary API cap.
	hook := `{"hook_event_name":"UserPromptSubmit","prompt":"` + strings.Repeat("a", 4<<10) + `"}`
	if rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, hook); rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatal("hook body limited by the OTLP cap")
	}
}

// TestSandboxIngressSlowOTLPCannotStarveHooks holds a binding's every OTLP
// slot with uploads that never finish and checks its hooks still run.
func TestSandboxIngressSlowOTLPCannotStarveHooks(t *testing.T) {
	f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
		cfg.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{MaxInFlight: 2, OTLPMaxInFlight: 2})
	})
	st := f.api.sandboxIngressState()
	_, exact := f.api.sandboxIngressMux()
	unblock := make(chan struct{})
	entered := make(chan struct{}, 8)
	h := f.api.sandboxIngressAuthenticate(st, f.api.sandboxIngressAuthorize(st, exact, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/logs" {
				entered <- struct{}{}
				<-unblock
			}
			w.WriteHeader(http.StatusNoContent)
		})))
	send := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+f.claudeTok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			send("/v1/logs")
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("otlp upload never reached the handler")
		}
	}
	if got := send("/v1/logs"); got != http.StatusTooManyRequests {
		t.Fatalf("third concurrent upload: %d, want 429", got)
	}
	for i := 0; i < 3; i++ {
		if got := send("/api/v1/claude-code/hook"); got != http.StatusNoContent {
			t.Fatalf("hook %d while uploads are open: %d", i, got)
		}
	}
	close(unblock)
	wg.Wait()
}

func TestSandboxIngressRevokeAndRotate(t *testing.T) {
	f := newSandboxIngressFixture(t)
	hook := func(token string) int {
		return f.do(t, http.MethodPost, "/api/v1/claude-code/hook", token, `{}`).Code
	}
	if got := hook(f.claudeTok); got == http.StatusUnauthorized {
		t.Fatal("live binding refused")
	}
	_, rotated, err := f.store.Rotate(f.claude.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := hook(f.claudeTok); got != http.StatusUnauthorized {
		t.Fatalf("pre-rotation credential: %d", got)
	}
	if got := hook(rotated); got == http.StatusUnauthorized {
		t.Fatal("rotated credential refused")
	}
	if err := f.store.Revoke(f.claude.ID); err != nil {
		t.Fatal(err)
	}
	if got := hook(rotated); got != http.StatusUnauthorized {
		t.Fatalf("revoked credential: %d", got)
	}
}

func TestSandboxIngressCSRFAndBodyLimit(t *testing.T) {
	f := newSandboxIngressFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.claudeTok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing X-DefenseClaw-Client: %d", rec.Code)
	}
	rec = f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`, "Sec-Fetch-Site", "cross-site")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", rec.Code)
	}
	rec = f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`, "Content-Type", "text/plain")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", rec.Code)
	}
	big := `{"hook_event_name":"UserPromptSubmit","prompt":"` + strings.Repeat("a", int(apiRequestBodyMaxBytes)) + `"}`
	rec = f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized hook body: %d", rec.Code)
	}
}

func TestSandboxIngressCodexContractComesFromBinding(t *testing.T) {
	f := newSandboxIngressFixture(t)
	body := `{"hook_event_name":"SessionStart","session_id":"sess-1","cwd":"/work/app"}`
	post := func(contract string) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPost, "/api/v1/codex/hook", f.codexTok, body,
			"X-DefenseClaw-Hook-Event", "SessionStart", "X-DefenseClaw-Hook-Contract", contract)
	}
	host := f.api.hookProfileForConnector("codex").ContractID
	if host == "codex-hooks-v1" {
		t.Fatalf("host default contract %q must differ from the binding's for this test", host)
	}
	if rec := post(host); rec.Code != http.StatusConflict {
		t.Fatalf("host contract via sandbox: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("codex-hooks-v1"); rec.Code != http.StatusOK {
		t.Fatalf("binding contract via sandbox: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSandboxIngressIdempotentHookRetry(t *testing.T) {
	f := newSandboxIngressFixture(t)
	body := `{"hook_event_name":"UserPromptSubmit","session_id":"sess-idem","prompt":"hello","cwd":"/work/app"}`
	first := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, body, SandboxHookIdempotencyHeader, "retry-key-0001")
	if first.Code != http.StatusOK {
		t.Fatalf("first: %d %s", first.Code, first.Body.String())
	}
	if first.Header().Get(sandboxIdempotentReplayHeader) != "" {
		t.Fatal("first response marked as replay")
	}
	second := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, body, SandboxHookIdempotencyHeader, "retry-key-0001")
	if second.Code != first.Code || second.Body.String() != first.Body.String() ||
		second.Header().Get(sandboxIdempotentReplayHeader) != "true" {
		t.Fatalf("retry was not replayed: %d %q", second.Code, second.Header().Get(sandboxIdempotentReplayHeader))
	}
	other := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		strings.Replace(body, "hello", "rm -rf ~", 1), SandboxHookIdempotencyHeader, "retry-key-0001")
	if other.Code != http.StatusUnprocessableEntity {
		t.Fatalf("key reuse with a different body: %d", other.Code)
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, body, SandboxHookIdempotencyHeader, "bad key"); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed key: %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Idempotency cache unit tests
// ---------------------------------------------------------------------------

func idempotencyTestRequest(binding sandboxauth.Binding, route sandboxauth.Route, key, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
	if key != "" {
		req.Header.Set(SandboxHookIdempotencyHeader, key)
	}
	ctx := sandboxauth.WithRequest(req.Context(), binding, nil)
	ctx = withSandboxIngressRoute(ctx, route)
	return req.WithContext(ctx)
}

func TestHookIdempotencyCache(t *testing.T) {
	var calls atomic.Int32
	status := http.StatusOK
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"n":%d}`, calls.Load())
	})
	clock := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	cache := newHookIdempotencyCache(time.Minute, func() time.Time { return clock })
	h := cache.middleware(next)
	a := sandboxauth.Binding{ID: "sb_a", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}}
	b := sandboxauth.Binding{ID: "sb_b", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}}
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	r1 := serve(idempotencyTestRequest(a, sandboxauth.RouteHook, "key-00000001", `{"x":1}`))
	r2 := serve(idempotencyTestRequest(a, sandboxauth.RouteHook, "key-00000001", `{"x":1}`))
	if calls.Load() != 1 || r2.Body.String() != r1.Body.String() || r2.Header().Get(sandboxIdempotentReplayHeader) != "true" {
		t.Fatalf("replay: calls=%d first=%q second=%q", calls.Load(), r1.Body.String(), r2.Body.String())
	}
	// Keys are scoped per binding.
	serve(idempotencyTestRequest(b, sandboxauth.RouteHook, "key-00000001", `{"x":1}`))
	if calls.Load() != 2 {
		t.Fatal("another binding replayed a foreign key")
	}
	// No key, other routes and other methods pass straight through.
	serve(idempotencyTestRequest(a, sandboxauth.RouteHook, "", `{"x":1}`))
	serve(idempotencyTestRequest(a, sandboxauth.RouteOTLP, "key-00000001", `{"x":1}`))
	if calls.Load() != 4 {
		t.Fatalf("pass-through calls = %d", calls.Load())
	}
	// Expiry lets the key evaluate again.
	clock = clock.Add(2 * time.Minute)
	serve(idempotencyTestRequest(a, sandboxauth.RouteHook, "key-00000001", `{"x":1}`))
	if calls.Load() != 5 {
		t.Fatal("expired entry replayed")
	}
	// Server errors are not cached.
	status = http.StatusInternalServerError
	serve(idempotencyTestRequest(a, sandboxauth.RouteNotify, "key-00000002", `{}`))
	status = http.StatusOK
	serve(idempotencyTestRequest(a, sandboxauth.RouteNotify, "key-00000002", `{}`))
	if calls.Load() != 7 {
		t.Fatalf("5xx was replayed: calls=%d", calls.Load())
	}
	cache.forget("sb_a")
	cache.mu.Lock()
	for id := range cache.entries {
		if id.binding == "sb_a" {
			t.Error("forget left entries behind")
		}
	}
	cache.mu.Unlock()
}

func TestHookIdempotencyConcurrentRetryWaitsForLeader(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		_, _ = w.Write([]byte(`{"action":"block"}`))
	})
	cache := newHookIdempotencyCache(time.Minute, nil)
	h := cache.middleware(next)
	binding := sandboxauth.Binding{ID: "sb_a", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}}
	var wg sync.WaitGroup
	results := make([]string, 5)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, idempotencyTestRequest(binding, sandboxauth.RouteHook, "key-concurrent", `{"t":1}`))
			results[i] = rec.Body.String()
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times for one key", calls.Load())
	}
	for _, body := range results {
		if body != `{"action":"block"}` {
			t.Fatalf("follower got %q", body)
		}
	}
}

func TestHookIdempotencyBounds(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	cache := newHookIdempotencyCache(time.Hour, nil)
	h := cache.middleware(next)
	binding := sandboxauth.Binding{ID: "sb_a", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}}
	for i := 0; i < maxIdempotencyEntriesPerBinding+50; i++ {
		h.ServeHTTP(httptest.NewRecorder(), idempotencyTestRequest(binding, sandboxauth.RouteHook, fmt.Sprintf("key-%08d", i), `{}`))
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if n := cache.count["sb_a"]; n > maxIdempotencyEntriesPerBinding {
		t.Fatalf("per-binding entries = %d", n)
	}
	if len(cache.entries) != cache.count["sb_a"] {
		t.Fatalf("count drifted: entries=%d count=%d", len(cache.entries), cache.count["sb_a"])
	}
}

// ---------------------------------------------------------------------------
// Main API route matrix
// ---------------------------------------------------------------------------

// mainAPIRoutePaths returns every route the main API registers: the exact
// paths in APIServer.Run (proven complete by parsing api.go), provider
// routes and every builtin connector hook route.
func mainAPIRoutePaths(t *testing.T) []string {
	t.Helper()
	known := []string{
		"/health", "/status", "/api/v1/admin/shutdown", "/skill/disable", "/skill/enable",
		"/plugin/disable", "/plugin/enable", "/config/patch", "/scan/result", "/enforce/block",
		"/enforce/allow", "/enforce/blocked", "/enforce/allowed", "/alerts", "/audit/event",
		"/policy/evaluate", "/policy/evaluate/firewall", "/policy/evaluate/audit",
		"/policy/evaluate/skill-actions", "/policy/reload", "/skills", "/mcps", "/tools/catalog",
		"/v1/skill/scan", "/v1/plugin/scan", "/v1/mcp/scan", "/v1/skill/fetch", "/v1/guardrail/event",
		"/v1/guardrail/evaluate", "/v1/guardrail/config", "/api/v1/acp/challenge", "/api/v1/acp/evaluate",
		"/v1/acp/catalog", "/v1/acp/profiles", "/api/v1/inspect/tool", "/api/v1/inspect/request",
		"/api/v1/inspect/response", "/api/v1/inspect/tool-response", "/api/v1/scan/code",
		"/api/v1/network-egress", "/api/v1/telemetry/canary", "/api/v1/watchdog/recovery",
		destinationtest.EndpointPath, cliObservabilityV8Path, alertAcknowledgementV8Path,
		"/v1/logs", "/v1/metrics", "/v1/traces", "/api/v1/agents/discovery", "/api/v1/ai-usage",
		"/api/v1/ai-usage/scan", "/api/v1/ai-usage/discovery", "/api/v1/ai-usage/components",
		"/api/v1/ai-usage/runtime", "/api/v1/ai-usage/runtime/scan", "/api/v1/correlation/graph",
		"/api/v1/correlation/explain", "/api/v1/correlation/timeline", "/api/v1/correlation/conflicts",
		"/api/v1/ai-usage/confidence/policy", "/api/v1/ai-usage/confidence/policy/validate",
		"/api/v1/codex/notify", "/v1/connectors", "/v1/config/providers", "/v1/config/providers/reload",
		"/api/v1/ai-usage/components/x/y/locations", "/otlp/codex/token/v1/logs",
	}
	registered := routesRegisteredInRun(t)
	for _, path := range registered {
		probe := path
		if strings.HasSuffix(probe, "/") {
			continue // prefix routes are covered by concrete probes above
		}
		if !slices.Contains(known, probe) {
			t.Errorf("APIServer.Run registers %s; add it to the sandbox route matrix", path)
		}
	}
	reg := sharedDefaultRegistry()
	for _, name := range reg.Names() {
		conn, _ := reg.Get(name)
		if endpoint, ok := conn.(connector.HookEndpoint); ok && endpoint.HookAPIPath() != "" {
			known = append(known, endpoint.HookAPIPath())
		}
	}
	slices.Sort(known)
	return slices.Compact(known)
}

// routesRegisteredInRun parses APIServer.Run and returns every path it
// passes to mux.Handle/HandleFunc, resolving the package constants it uses.
func routesRegisteredInRun(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "api.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	constants := map[string]string{
		"cliObservabilityV8Path":       cliObservabilityV8Path,
		"alertAcknowledgementV8Path":   alertAcknowledgementV8Path,
		"destinationtest.EndpointPath": destinationtest.EndpointPath,
	}
	var paths []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" || fn.Recv == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
				return true
			}
			switch arg := call.Args[0].(type) {
			case *ast.BasicLit:
				value, err := strconv.Unquote(arg.Value)
				if err != nil {
					t.Fatalf("route literal %s: %v", arg.Value, err)
				}
				paths = append(paths, value)
			case *ast.Ident:
				value, ok := constants[arg.Name]
				if !ok {
					t.Fatalf("Run registers route constant %s; teach the sandbox route matrix about it", arg.Name)
				}
				paths = append(paths, value)
			case *ast.SelectorExpr:
				name := fmt.Sprint(arg.X) + "." + arg.Sel.Name
				value, ok := constants[name]
				if !ok {
					t.Fatalf("Run registers route %s; teach the sandbox route matrix about it", name)
				}
				paths = append(paths, value)
			default:
				t.Fatalf("Run registers a route through %T; teach the sandbox route matrix about it", arg)
			}
			return true
		})
	}
	if len(paths) < 40 {
		t.Fatalf("parsed only %d routes from APIServer.Run", len(paths))
	}
	return paths
}

// TestMainAPIRefusesSandboxCredentialsOnEveryRoute runs the real main API
// listener and presents a live binding credential, in every slot the main
// API reads, to every route it serves. Only unauthenticated GET /health may
// answer; everything else is 401.
func TestMainAPIRefusesSandboxCredentialsOnEveryRoute(t *testing.T) {
	f := newSandboxIngressFixture(t)
	// A connector hook token exists too, so the loopback hook carve-out is
	// live; the binding credential must still never match it.
	if _, err := connector.EnsureHookAPIToken(f.dataDir, "claudecode"); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg := &config.Config{DataDir: f.dataDir, Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	api := NewAPIServer(addr, NewSidecarHealth(), nil, nil, nil, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- api.Run(ctx) }()
	defer func() {
		cancel()
		<-errCh
	}()
	client := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(base + "/health")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("main API did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	send := func(method, path string, header http.Header) int {
		req, err := http.NewRequest(method, base+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = header
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
		req.Header.Set("X-DefenseClaw-Connector", "claudecode")
		req.Header.Set(otelSourceHeader, "claudecode")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	slots := map[string]func(string) http.Header{
		"Authorization": func(tok string) http.Header { return http.Header{"Authorization": {"Bearer " + tok}} },
		"X-DefenseClaw-Token": func(tok string) http.Header {
			return http.Header{"X-Defenseclaw-Token": {tok}}
		},
		"X-DC-Auth": func(tok string) http.Header { return http.Header{"X-Dc-Auth": {"Bearer " + tok}} },
	}
	for _, path := range mainAPIRoutePaths(t) {
		for slot, header := range slots {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				got := send(method, path, header(f.claudeTok))
				if method == http.MethodGet && path == "/health" {
					if got != http.StatusOK {
						t.Errorf("GET /health: %d", got)
					}
					continue
				}
				if got != http.StatusUnauthorized {
					t.Errorf("%s %s with binding credential in %s: status %d, want 401", method, path, slot, got)
				}
			}
		}
	}
	// The credential as an OTLP path token is refused too.
	if got := send(http.MethodPost, "/otlp/claudecode/"+f.claudeTok+"/v1/logs", http.Header{}); got != http.StatusUnauthorized {
		t.Fatalf("binding credential as OTLP path token: %d", got)
	}
	// Sanity: the master token still works on the main API.
	if got := send(http.MethodGet, "/status", http.Header{"Authorization": {"Bearer " + sandboxTestMasterToken}}); got == http.StatusUnauthorized {
		t.Fatal("master token refused; the matrix above proves nothing")
	}
}

func TestRequestCarriesSandboxCredential(t *testing.T) {
	tok := sandboxauth.TokenPrefix + strings.Repeat("A", 43)
	for name, build := range map[string]func(*http.Request){
		"authorization":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) },
		"lowercase scheme": func(r *http.Request) { r.Header.Set("Authorization", "bearer "+tok) },
		"second authorization": func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer other")
			r.Header.Add("Authorization", "Bearer "+tok)
		},
		"token header": func(r *http.Request) { r.Header.Set("X-DefenseClaw-Token", tok) },
		"dc auth":      func(r *http.Request) { r.Header.Set("X-DC-Auth", "Bearer "+tok) },
	} {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		build(req)
		if !requestCarriesSandboxCredential(req) {
			t.Errorf("%s: not detected", name)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer "+sandboxTestMasterToken)
	if requestCarriesSandboxCredential(req) {
		t.Fatal("master token misclassified")
	}
}

func TestRunSandboxIngressServesAndShutsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) { cfg.Addr = addr })
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- f.api.RunSandboxIngress(ctx) }()
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	var status int
	for {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/api/v1/claude-code/hook", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+f.claudeTok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
		resp, err := client.Do(req)
		if err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ingress did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status == http.StatusUnauthorized || status == http.StatusNotFound {
		t.Fatalf("ingress refused its own binding: %d", status)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("RunSandboxIngress: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ingress did not shut down")
	}
	if _, err := os.Stat(f.store.Path()); err != nil {
		t.Fatal(err)
	}
}

// TestSandboxIngressCopyModeNeverTouchesHostFS drives every path-reading
// Claude Code hook event of a copy-mode sandbox through the real ingress
// with an injected filesystem that counts calls: none may happen, even
// though the named host paths exist and would produce findings.
func TestSandboxIngressCopyModeNeverTouchesHostFS(t *testing.T) {
	p := newSandboxProject(t)
	p.write(t, "src/creds.go", "var k = \"AKIA"+"ABCDEFGHIJKLMNOP\"\n", 0o644)
	p.write(t, "build.sh", "#!/bin/sh\necho hi\n", 0o755)
	p.write(t, "CLAUDE.md", "instructions\n", 0o644)
	dataDir := t.TempDir()
	cfg := &config.Config{DataDir: dataDir, Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	cfg.Guardrail.Connector = "claudecode"
	cfg.ClaudeCode.ScanOnStop = true
	cfg.ClaudeCode.ScanPaths = []string{"src/creds.go", filepath.Join(p.root, "src", "creds.go")}
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, cfg)
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := store.Mint(sandboxauth.Spec{
		SandboxName: "dc-claude-copy", Connector: "claudecode",
		AgentVersion: "2.1.156", HookContractID: "claudecode-hooks-v1",
		Workdir: sandboxauth.Workdir{
			Mode: sandboxauth.WorkdirCopy,
			// A recorded context mount grants nothing in copy mode.
			Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: p.root, ReadOnly: true}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fsys := &countingFS{}
	if err := api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: store, FS: fsys}); err != nil {
		t.Fatal(err)
	}
	handler, err := api.SandboxIngressHandler()
	if err != nil {
		t.Fatal(err)
	}
	events := []string{
		`{"hook_event_name":"SessionStart","session_id":"c1","cwd":"/work/app","source":"startup"}`,
		`{"hook_event_name":"CwdChanged","session_id":"c1","cwd":"/work/app","old_cwd":"/work/app","new_cwd":"/work/app/src"}`,
		`{"hook_event_name":"InstructionsLoaded","session_id":"c1","cwd":"/work/app","file_path":"/work/app/CLAUDE.md"}`,
		`{"hook_event_name":"FileChanged","session_id":"c1","cwd":"/work/app","file_path":"/work/app/src/creds.go"}`,
		`{"hook_event_name":"FileChanged","session_id":"c1","cwd":"/work/app","file_path":"` + filepath.Join(p.root, "src", "creds.go") + `"}`,
		`{"hook_event_name":"PreToolUse","session_id":"c1","cwd":"/work/app","tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"bash ./build.sh"}}`,
		`{"hook_event_name":"PreToolUse","session_id":"c1","cwd":"/work/app","tool_name":"Bash","tool_use_id":"t2","tool_input":{"command":"sh ` + filepath.Join(p.root, "build.sh") + `"}}`,
		`{"hook_event_name":"Stop","session_id":"c1","cwd":"/work/app"}`,
	}
	for _, body := range events {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43210"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "claude-code-hook/1.0")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "CG-CRED-002") {
			t.Fatalf("copy-mode hook read a host file: %s", rec.Body.String())
		}
	}
	if fsys.calls != 0 {
		t.Fatalf("copy-mode sandbox hooks made %d host filesystem calls through the view", fsys.calls)
	}
}
