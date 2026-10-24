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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	osuser "os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

var relayTestPeer = managedHookPeer{UID: 1000, Name: "dev"}

func TestSandboxRelayNeverAdoptsSandboxTraceParent(t *testing.T) {
	const path = sandboxrelay.PathHookPrefix + "claudecode"
	var seen string
	var forwardedTrace bool
	routes := map[string]sandboxRelayRoute{path: {
		class: sandboxauth.RouteHook, connector: "claudecode", native: "/api/v1/claudecode/hook",
		handler: func(w http.ResponseWriter, r *http.Request) {
			seen = trace.SpanFromContext(r.Context()).SpanContext().TraceID().String()
			forwardedTrace = r.Header.Get("Traceparent") != "" || r.Header.Get("Tracestate") != ""
			w.WriteHeader(http.StatusOK)
		},
	}}
	f := newRelayFixtureWith(t, routes)
	reg := f.register(t, "trace", "claudecode", relayTestBindingID(401))
	resp, _ := f.post(t, path, reg.ID, `{}`, "Traceparent", wellFormedTraceparent)
	if resp.StatusCode != http.StatusOK || seen == "0af7651916cd43dd8448eb211c80319c" || forwardedTrace {
		t.Fatalf("sandbox trace adopted or forwarded: status %d trace %q headers %t", resp.StatusCode, seen, forwardedTrace)
	}
	seen = ""
	resp, _ = f.post(t, path, "unknown", `{}`, "Traceparent", wellFormedTraceparent)
	if resp.StatusCode == http.StatusOK || seen != "" {
		t.Fatalf("unregistered trace reached handler: status %d trace %q", resp.StatusCode, seen)
	}
}

// #1213 / GAP-0056: a hook the managed gateway answers 200 with a
// fail-closed block carries failed_closed in the verdict trailer, which
// the daemon counts as a hook failure (TestSandboxRelayForwarding); a
// normal block does not.
func TestSandboxRelayTrailerMarksAFailClosedBlock(t *testing.T) {
	const path = sandboxrelay.PathHookPrefix + "claudecode"
	failClosed := false
	var f *relayFixture
	routes := map[string]sandboxRelayRoute{path: {
		class: sandboxauth.RouteHook, connector: "claudecode", native: "/api/v1/claudecode/hook",
		handler: func(w http.ResponseWriter, r *http.Request) {
			if failClosed {
				markSandboxHookFailedClosed(r.Context())
			}
			f.api.observeSandboxHookDecision(r.Context(), agentHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
				agentHookResponse{Action: "block", WouldBlock: true})
			w.WriteHeader(http.StatusOK)
		},
	}}
	f = newRelayFixtureWith(t, routes)
	reg := f.register(t, "failclosed", "claudecode", relayTestBindingID(402))
	for _, want := range []bool{false, true} {
		failClosed = want
		resp, body := f.post(t, path, reg.ID, `{}`)
		d, ok := relayTrailer(t, resp)
		if resp.StatusCode != http.StatusOK || !ok || d.Action != "block" || d.FailedClosed != want {
			t.Fatalf("fail closed %t: status %d %s trailer %+v (%t)", want, resp.StatusCode, body, d, ok)
		}
	}
}

// relayTestKey is the sandbox authority key of the relay tests.
var relayTestKey = bytes.Repeat([]byte{7}, 32)

// relayTestID is a well-formed registration id built from tag.
func relayTestID(tag string) string {
	id := sandboxreg.IDPrefix + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7') {
			return r
		}
		return 'a'
	}, strings.ToLower(tag))
	for len(id) < len(sandboxreg.IDPrefix)+sandboxreg.IDRandomChars {
		id += "a"
	}
	return id[:len(sandboxreg.IDPrefix)+sandboxreg.IDRandomChars]
}

// relayTestBindingID is a well-formed binding id for n.
func relayTestBindingID(n int) string { return fmt.Sprintf("sb_%032x", n) }

// relayTestRegistration is a live registration of peer for connectorName,
// as the authority keeps it after resolve and bind.
func relayTestRegistration(t *testing.T, peer managedHookPeer, tag, connectorName, bindingID string) sandboxreg.Registration {
	t.Helper()
	spec, ok := harness.Get(connectorName)
	if !ok {
		t.Fatalf("no harness %s", connectorName)
	}
	contract := connector.ResolveSandboxHookContract(connectorName, spec.DefaultVersion).Contract.ContractID
	if contract == "" {
		t.Fatalf("%s %s has no sandbox hook contract", connectorName, spec.DefaultVersion)
	}
	return sandboxreg.Registration{
		V: sandboxreg.RecordVersion, ID: relayTestID(tag), UID: peer.UID, UserName: peer.Name,
		SubjectKey: sandboxSubjectKey(relayTestKey, peer.UID, peer.Name, ""), Connector: connectorName, Harness: connectorName,
		HarnessVersion: spec.DefaultVersion, HookContract: contract, TamperTier: spec.TamperTier,
		WorkdirMode: string(sandboxauth.WorkdirCopy), SandboxID: "sbx-" + tag, SandboxName: "dc-" + tag,
		BindingID: bindingID, State: sandboxreg.StateLive, CreatedAt: time.Now().Add(-time.Minute),
	}
}

// relayTestStore wraps the authority's store: err fails every lookup and
// unbound answers live registrations without their sandbox.
type relayTestStore struct {
	sandboxRegistrationStore
	mu      sync.Mutex
	err     error
	unbound bool
}

func (s *relayTestStore) Get(uid int, id string) (sandboxreg.Registration, bool, error) {
	s.mu.Lock()
	err, unbound := s.err, s.unbound
	s.mu.Unlock()
	if err != nil {
		return sandboxreg.Registration{}, false, err
	}
	reg, ok, err := s.sandboxRegistrationStore.Get(uid, id)
	if unbound && reg.State == sandboxreg.StateLive {
		reg.BindingID, reg.SandboxName, reg.SandboxID = "", "", ""
	}
	return reg, ok, err
}

// GetWithRun answers the registration as Get does.
func (s *relayTestStore) GetWithRun(uid int, id string) (sandboxreg.Registration, bool, sandboxreg.Run, bool, error) {
	reg, ok, err := s.Get(uid, id)
	if err != nil {
		return sandboxreg.Registration{}, false, sandboxreg.Run{}, false, err
	}
	run, hasRun, err := s.Run(uid, id)
	return reg, ok, run, hasRun, err
}

func (s *relayTestStore) set(err error, unbound bool) {
	s.mu.Lock()
	s.err, s.unbound = err, unbound
	s.mu.Unlock()
}

// relayFixture is a managed gateway serving the relayed routes behind the
// hook socket's own layers after the kernel peer: peer identity, peer
// authorization (uid 0, the route class's budget, the verified subject) and
// the hook-socket mux with its CSRF check and body limit. Registrations
// live in the sandbox authority's own file store.
type relayFixture struct {
	api    *APIServer
	auth   *sandboxAuthority
	store  *relayTestStore
	server *httptest.Server
	// local observes the managed gateway's own sandbox ingress: a relayed
	// call must never reach it.
	local *sandboxObserver

	mu   sync.Mutex
	peer *managedHookPeer
}

func newRelayFixture(t *testing.T, mutate ...func(*config.Config)) *relayFixture {
	return newRelayFixtureWith(t, nil, mutate...)
}

// newRelayFixtureWith serves the paths of routes through the relay with
// that route table, in place of the hook-socket mux's relay, when routes
// is not nil.
func newRelayFixtureWith(t *testing.T, routes map[string]sandboxRelayRoute, mutate ...func(*config.Config)) *relayFixture {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{DataDir: dataDir, Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	cfg.OpenShell.Enabled = true
	for _, m := range mutate {
		m(cfg)
	}
	prevKey, prevHook := sandboxAuthorityKey, sandboxBudgetLimits[sandboxBudgetHook]
	sandboxAuthorityKey = func(string) ([]byte, error) { return relayTestKey, nil }
	// Every harness's events from one uid; the class budget has its own test.
	sandboxBudgetLimits[sandboxBudgetHook] = sandboxBudgetLimit{Rate: 10000, Burst: 10000, InFlight: 64}
	t.Cleanup(func() {
		sandboxAuthorityKey = prevKey
		sandboxBudgetLimits[sandboxBudgetHook] = prevHook
	})
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, cfg)
	auth, err := api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	store := &relayTestStore{sandboxRegistrationStore: auth.store}
	auth.store = store
	bindings, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(dataDir), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	f := &relayFixture{api: api, auth: auth, store: store, local: &sandboxObserver{}}
	ingress := SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: bindings}
	f.local.observe(&ingress)
	if err := api.SetSandboxIngress(ingress); err != nil {
		t.Fatal(err)
	}
	peer := relayTestPeer
	f.peer = &peer
	authorizer := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, harness.Names(),
		func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	inner := api.managedHookSocketMux()
	if routes != nil {
		socket, relay := inner, api.apiCSRFProtect(api.sandboxRelayServe(routes))
		inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := routes[r.URL.Path]; ok {
				relay.ServeHTTP(w, r)
				return
			}
			socket.ServeHTTP(w, r)
		})
	}
	chain := managedHookPeerIdentityMiddleware(api.managedHookPeerAuth(authorizer, inner))
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		p := f.peer
		f.mu.Unlock()
		if p != nil {
			r = r.WithContext(withManagedHookPeer(r.Context(), *p))
		}
		chain.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *relayFixture) as(peer *managedHookPeer) {
	f.mu.Lock()
	f.peer = peer
	f.mu.Unlock()
}

// register stores reg (relayTestRegistration, adjusted by edit) through the
// authority's store: created pending, then bound live unless edit leaves
// it pending.
func (f *relayFixture) register(t *testing.T, tag, connectorName, bindingID string, edit ...func(*sandboxreg.Registration)) sandboxreg.Registration {
	t.Helper()
	reg := relayTestRegistration(t, relayTestPeer, tag, connectorName, bindingID)
	for _, e := range edit {
		e(&reg)
	}
	if err := f.auth.store.Create(reg.UID, reg); err != nil {
		t.Fatal(err)
	}
	if reg.State != sandboxreg.StateLive {
		stored, _, _ := f.auth.store.Get(reg.UID, reg.ID)
		return stored
	}
	stored, err := f.auth.store.Bind(reg.UID, reg.ID, sandboxrelay.BindRequest{
		V: 1, SandboxName: reg.SandboxName, SandboxID: reg.SandboxID, BindingID: reg.BindingID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// post sends a relayed call as the daemon does: the body unchanged and the
// registration header.
func (f *relayFixture) post(t *testing.T, path, registration, body string, headers ...string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sandboxrelay.ClientHeader, sandboxrelay.ClientHeaderValue)
	req.Header.Set(sandboxrelay.DaemonContractHeader, strconv.Itoa(sandboxrelay.DaemonContract))
	req.Header.Set(sandboxrelay.AgentSurfaceHeader, sandboxrelay.AgentSurfaceValue)
	if registration != "" {
		req.Header.Set(sandboxrelay.RegistrationHeader, registration)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(raw)
}

// currentGeneration is policy/current's generation for registration.
func (f *relayFixture) currentGeneration(t *testing.T, registration string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.server.URL+sandboxrelay.PathPolicyCurrent+"?registration="+registration, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Every sandbox route needs the CSRF client header, GET included.
	req.Header.Set(sandboxrelay.ClientHeader, sandboxrelay.ClientHeaderValue)
	req.Header.Set(sandboxrelay.DaemonContractHeader, strconv.Itoa(sandboxrelay.DaemonContract))
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var cur sandboxrelay.CurrentPolicy
	if err := json.NewDecoder(resp.Body).Decode(&cur); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("policy/current: %d %v", resp.StatusCode, err)
	}
	return strconv.FormatUint(cur.Generation, 10)
}

func relayTrailer(t *testing.T, resp *http.Response) (sandboxrelay.HookDecision, bool) {
	t.Helper()
	raw := resp.Trailer.Get(sandboxrelay.DecisionTrailer)
	if raw == "" {
		return sandboxrelay.HookDecision{}, false
	}
	if len(raw) > sandboxrelay.MaxHookDecisionBytes {
		t.Fatalf("trailer is %d bytes", len(raw))
	}
	var d sandboxrelay.HookDecision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("trailer %q: %v", raw, err)
	}
	return d, true
}

func relayRefusalReason(t *testing.T, body string) string {
	t.Helper()
	var e sandboxrelay.ErrorBody
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("refusal body %q: %v", body, err)
	}
	return e.Error
}

// relayHarnessHookBody is a hook event for any connector: the common field
// spellings of the event, session, tool and its input. Each connector
// reads the ones it knows.
func relayHarnessHookBody(event string, n int) string {
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": event, "hookEventName": event, "event": event,
		"session_id": "relay-s1", "sessionId": "relay-s1", "conversation_id": "relay-s1",
		"tool_name": "Bash", "toolName": "Bash", "tool_use_id": fmt.Sprintf("relay-t%d", n),
		"tool_input": map[string]any{"command": "echo dccert-relay-marker"},
		"toolArgs":   `{"command":"echo dccert-relay-marker"}`,
		"prompt":     "summarize the readme", "cwd": "/sandbox",
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// TestSandboxRelayMatchesLocalIngressForEveryHarness sends every hook
// event of every sandbox harness to a local sandbox ingress and, relayed,
// to the managed gateway. The relayed call gets the local status; the
// bound event and contract headers reach the handler (a Codex hook is
// answered, not refused 400); and every verdict the local observer records
// comes back in the trailer with the same fields, the tool input replaced
// by its content reference. The managed gateway's own observer sees none
// of it.
func TestSandboxRelayMatchesLocalIngressForEveryHarness(t *testing.T) {
	var localObs sandboxObserver
	local := newSandboxIngressFixture(t, localObs.observe)
	relay := newRelayFixture(t)

	names := harness.Names()
	if len(names) < 10 {
		t.Fatalf("harnesses = %v", names)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			spec, _ := harness.Get(name)
			contract := connector.ResolveSandboxHookContract(name, spec.DefaultVersion).Contract.ContractID
			binding, token := local.mint(t, "dc-relay-"+name, name, spec.DefaultVersion, contract, "")
			reg := relay.register(t, "h"+name, name, binding.ID)
			generation := relay.currentGeneration(t, reg.ID)
			profile := local.api.hookProfileForRequest(sandboxauth.WithRequest(context.Background(), binding, nil), name)
			conn, _ := sharedDefaultRegistry().Get(name)
			hookPath := conn.(connector.HookEndpoint).HookAPIPath()
			if len(profile.SupportedEvents) == 0 || hookPath == "" {
				t.Fatalf("%s: events %v, hook path %q", name, profile.SupportedEvents, hookPath)
			}
			recorded := 0
			// compare sends one event both ways and returns the relayed verdict
			// (nil when the local observer recorded none).
			compare := func(event, body string, headers ...string) *sandboxrelay.HookDecision {
				t.Helper()
				want := local.do(t, http.MethodPost, hookPath, token, body, headers...)
				localDecisions, _ := localObs.take()
				resp, got := relay.post(t, sandboxrelay.PathHookPrefix+name, reg.ID, body, headers...)
				if resp.StatusCode != want.Code {
					t.Fatalf("%s: relayed status %d %s, local %d %s", event, resp.StatusCode, got, want.Code, want.Body.String())
				}
				d, hasTrailer := relayTrailer(t, resp)
				if len(localDecisions) == 0 {
					if hasTrailer {
						t.Fatalf("%s: trailer %+v for an event the local observer did not record", event, d)
					}
					return nil
				}
				if resp.StatusCode/100 != 2 || resp.Header.Get("Content-Length") != "" || resp.ContentLength != -1 {
					t.Fatalf("%s: status %d, framed with Content-Length %q", event, resp.StatusCode, resp.Header.Get("Content-Length"))
				}
				if !hasTrailer {
					t.Fatalf("%s: no %s trailer (local recorded %+v)", event, sandboxrelay.DecisionTrailer, localDecisions)
				}
				l := localDecisions[len(localDecisions)-1]
				wantDecision := sandboxrelay.HookDecision{
					V: sandboxrelay.WireVersion, Event: l.Event, Tool: l.Tool, ToolUseID: l.ToolUseID, SessionID: l.SessionID,
					CallRef: manager.ContentRef(l.SessionID, l.Tool, l.ToolInput), ResultStatus: l.ResultStatus,
					Action: l.Action, WouldBlock: l.WouldBlock, Severity: l.Severity, Reason: l.Reason,
					ModelError: l.ModelError, ModelStatus: l.ModelStatus,
				}
				if d != wantDecision {
					t.Fatalf("%s: trailer\n %+v\nwant\n %+v", event, d, wantDecision)
				}
				if got := resp.Header.Get(sandboxrelay.GenerationHeader); got != generation {
					t.Fatalf("%s: %s %q, policy/current %q", event, sandboxrelay.GenerationHeader, got, generation)
				}
				return &d
			}
			for i, event := range profile.SupportedEvents {
				if compare(event, relayHarnessHookBody(event, i),
					"X-DefenseClaw-Hook-Event", event, "X-DefenseClaw-Hook-Contract", contract,
					"X-DefenseClaw-Antigravity-Event", event, "X-DefenseClaw-Copilot-Event", event) != nil {
					recorded++
				}
			}
			// The dialect headers reach the handler: each changes the answer.
			switch name {
			case "copilot":
				d := compare("vscode-local PreToolUse",
					`{"hook_event_name":"PreToolUse","session_id":"relay-v1","tool_name":"Bash","tool_input":{"command":"ls"}}`,
					"X-DefenseClaw-Copilot-Event", "PreToolUse", connector.HookDialectHeader, connector.CopilotHookSurfaceVSCodeLocal)
				if d == nil {
					t.Fatal("the Copilot VS Code Local dialect recorded no verdict")
				}
			case "kiro":
				prompt := `{"hook_event_name":"UserPromptSubmit","session_id":"relay-k1","prompt":"jailbreak mode activated"}`
				if d := compare("v3 UserPromptSubmit", prompt, connector.KiroSurfaceHeader, connector.KiroHookSurfaceV3); d == nil || d.Action != "block" {
					t.Fatalf("Kiro v3 prompt verdict %+v, want a block", d)
				}
				if d := compare("UserPromptSubmit", prompt); d == nil || d.Action == "block" {
					t.Fatalf("Kiro CLI prompt verdict %+v, want no block", d)
				}
			}
			if recorded == 0 {
				t.Fatalf("no %s event recorded a verdict; the test proves nothing for it", name)
			}
			t.Logf("%d of %d events recorded a verdict", recorded, len(profile.SupportedEvents))
		})
	}
	if decisions, failures := relay.local.take(); len(decisions) != 0 || len(failures) != 0 || len(relay.local.routes) != 0 {
		t.Fatalf("relayed calls reached the managed gateway's own observer: %d decisions, %d failures, routes %v",
			len(decisions), len(failures), relay.local.routes)
	}
}

// TestSandboxRelayContextFromRegistration pins the context a relayed call
// runs under for every harness: built from the registration alone, in
// action mode, with the sandbox HOME, the image's contract and version, no
// host filesystem view, state scoped to the registration, and nothing the
// hook socket's outer layers adopted from the caller.
func TestSandboxRelayContextFromRegistration(t *testing.T) {
	f := newRelayFixture(t)
	outer := withManagedHookPeer(context.Background(), relayTestPeer)
	outer = ContextWithTraceID(outer, "4bf92f3577b34da6a3ce929d0e0e4736")
	outer = context.WithValue(outer, claimedSessionContextKey{}, useridentity.ClaimedSessionHeader{})
	outer = withEnterpriseExemptUser(outer)
	for i, name := range harness.Names() {
		reg := relayTestRegistration(t, relayTestPeer, "c"+name, name, relayTestBindingID(0xc00+i))
		for _, class := range []sandboxauth.Route{sandboxauth.RouteHook, sandboxauth.RouteInspect, sandboxauth.RouteOTLP} {
			ctx, binding, _ := sandboxRelayContext(outer, reg, class)
			got, ok := sandboxauth.FromContext(ctx)
			if !ok || got.ID != reg.BindingID || got.RegistrationID != reg.ID || got.Connector != name ||
				got.AgentVersion != reg.HarnessVersion || got.HookContractID != reg.HookContract ||
				got.Workdir.Mode != sandboxauth.WorkdirCopy || !slices.Equal(got.Routes, []sandboxauth.Route{class}) ||
				got.HostUser != (sandboxauth.HostUser{UID: "1000", Name: "dev"}) || binding.ID != got.ID {
				t.Fatalf("%s/%s binding = %+v", name, class, got)
			}
			if !isRelayedSandboxRequest(ctx) || !isRelayVerifiedSandboxRequest(ctx) || hookActiveHome(ctx) != sandboxauth.SandboxHome ||
				sandboxHookMode(ctx, name, "observe") != "action" {
				t.Fatalf("%s/%s: relayed %v home %q mode %q", name, class, isRelayedSandboxRequest(ctx), hookActiveHome(ctx), sandboxHookMode(ctx, name, "observe"))
			}
			if view, ok := sandboxHookView(ctx); !ok || view.HostAccess() {
				t.Fatalf("%s/%s: host view granted", name, class)
			}
			if TraceIDFromContext(ctx) != "" {
				t.Fatalf("%s/%s: kept the caller's trace id", name, class)
			}
			if _, ok := claimedSessionFromContext(ctx); ok {
				t.Fatalf("%s/%s: kept the caller's claimed session facts", name, class)
			}
			if _, exempt := enterpriseEnrollmentV8(ctx).Get(); exempt {
				t.Fatalf("%s/%s: kept the host-hook enrollment exemption", name, class)
			}
			if route, _ := sandboxIngressRouteFrom(ctx); route != class {
				t.Fatalf("%s/%s: route %q", name, class, route)
			}
			switch class {
			case sandboxauth.RouteHook:
				if authenticatedHookConnector(ctx) != name {
					t.Fatalf("%s: hook connector %q", name, authenticatedHookConnector(ctx))
				}
				profile := f.api.hookProfileForRequest(ctx, name)
				if profile.ContractID != reg.HookContract {
					t.Fatalf("%s: profile contract %q, want the registration's %q", name, profile.ContractID, reg.HookContract)
				}
			case sandboxauth.RouteInspect:
				if authenticatedInspectConnector(ctx) != canonicalConnectorRulePackKey(name) {
					t.Fatalf("%s: inspect connector %q", name, authenticatedInspectConnector(ctx))
				}
			}
			extra := sandboxHookAuditExtra(ctx)
			if extra["sandbox_registration_id"] != reg.ID || extra["sandbox_tamper_tier"] != reg.TamperTier || extra["sandbox_workdir"] != "copy" {
				t.Fatalf("%s/%s audit extra = %v", name, class, extra)
			}
			if key := sandboxSessionStateKey(ctx, "s1"); !strings.Contains(key, reg.ID) {
				t.Fatalf("%s/%s session key %q is not scoped to the registration", name, class, key)
			}
		}
	}
	// A sandbox call to a local ingress is not relayed, and neither is a
	// rebuilt context without the registration's kernel peer.
	claude := relayTestRegistration(t, relayTestPeer, "alice", "claudecode", relayTestBindingID(0xc02))
	noPeer, _, _ := sandboxRelayContext(context.Background(), claude, sandboxauth.RouteHook)
	otherPeer, _, _ := sandboxRelayContext(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "bob"}), claude, sandboxauth.RouteHook)
	if isRelayedSandboxRequest(sandboxCtx(sandboxTestBinding("claudecode"))) || isRelayedSandboxRequest(context.Background()) ||
		isRelayedSandboxRequest(noPeer) || isRelayedSandboxRequest(otherPeer) {
		t.Fatal("a request the relay did not admit for its peer counts as relayed")
	}
	// Two accounts' daemons claiming the same binding ID get separate state.
	bob := claude
	bob.ID, bob.UID, bob.UserName = relayTestID("bob"), 1001, "bob"
	actx, ab, _ := sandboxRelayContext(context.Background(), claude, sandboxauth.RouteHook)
	bctx, bb, _ := sandboxRelayContext(context.Background(), bob, sandboxauth.RouteHook)
	if sandboxSessionStateKey(actx, "s1") == sandboxSessionStateKey(bctx, "s1") ||
		sandboxConnectorInstanceID(ab) == sandboxConnectorInstanceID(bb) {
		t.Fatal("two registrations with one claimed binding ID share session state")
	}
}

// TestSandboxRelayRefusals pins the relayed-call checks the relay adds to
// the authority's admission, and the answers both give through the hook
// socket's layers.
func TestSandboxRelayRefusals(t *testing.T) {
	f := newRelayFixture(t)
	claude := f.register(t, "refclaude", "claudecode", relayTestBindingID(0xd01))
	codex := f.register(t, "refcodex", "codex", relayTestBindingID(0xd02))
	other := relayTestRegistration(t, managedHookPeer{UID: 1001, Name: "carol"}, "refother", "claudecode", relayTestBindingID(0xd04))
	if err := f.auth.store.Create(other.UID, other); err != nil {
		t.Fatal(err)
	}
	revoked := f.register(t, "refrevoked", "claudecode", relayTestBindingID(0xd03))
	if err := f.auth.store.Revoke(revoked.UID, revoked.ID, "test"); err != nil {
		t.Fatal(err)
	}
	pending := f.register(t, "refpending", "claudecode", "", func(r *sandboxreg.Registration) {
		r.State, r.CreatedAt = sandboxreg.StatePending, time.Now()
	})
	stale := f.register(t, "refstale", "claudecode", "", func(r *sandboxreg.Registration) {
		r.State, r.CreatedAt = sandboxreg.StatePending, time.Now().Add(-sandboxreg.PendingTTL-time.Second)
	})

	hook := sandboxrelay.PathHookPrefix + "claudecode"
	body := `{"hook_event_name":"UserPromptSubmit","session_id":"r1","prompt":"hello"}`
	for _, tc := range []struct {
		name, path, registration string
		headers                  []string
		reason                   string
	}{
		{"no registration", hook, "", nil, sandboxrelay.ReasonRegistrationUnknown},
		{"malformed id", hook, "reg-../../etc", nil, sandboxrelay.ReasonRegistrationUnknown},
		{"made-up id", hook, relayTestID("nosuch"), nil, sandboxrelay.ReasonRegistrationUnknown},
		{"another uid's id", hook, other.ID, nil, sandboxrelay.ReasonRegistrationUnknown},
		{"two registrations", hook, claude.ID, []string{sandboxrelay.RegistrationHeader, codex.ID}, sandboxrelay.ReasonRegistrationUnknown},
		{"pending", hook, pending.ID, nil, sandboxrelay.ReasonNotAllowed},
		{"expired pending", hook, stale.ID, nil, sandboxrelay.ReasonRegistrationExpired},
		{"revoked", hook, revoked.ID, nil, sandboxrelay.ReasonRegistrationRevoked},
		{"connector mismatch", sandboxrelay.PathHookPrefix + "codex", claude.ID, nil, sandboxrelay.ReasonConnectorMismatch},
		{"notify for another connector", sandboxrelay.PathNotifyPrefix + "codex", claude.ID, nil, sandboxrelay.ReasonConnectorMismatch},
		{"files header", hook, claude.ID, []string{sandboxrelay.FilesHeader, "e30="}, sandboxrelay.ReasonRelayFilesUnsupported},
		{"empty files header", hook, claude.ID, []string{sandboxrelay.FilesHeader, ""}, sandboxrelay.ReasonRelayFilesUnsupported},
	} {
		resp, got := f.post(t, tc.path, tc.registration, body, tc.headers...)
		if resp.StatusCode != sandboxrelay.ReasonStatus(tc.reason) || relayRefusalReason(t, got) != tc.reason {
			t.Fatalf("%s: %d %s, want %d %s", tc.name, resp.StatusCode, got, sandboxrelay.ReasonStatus(tc.reason), tc.reason)
		}
		if resp.Trailer.Get(sandboxrelay.DecisionTrailer) != "" || resp.Header.Get(sandboxrelay.ProfileHeader) != "" ||
			resp.Header.Get(sandboxrelay.GenerationHeader) != "" {
			t.Fatalf("%s: a refusal carried relay answer headers", tc.name)
		}
	}
	// Paths the relay does not serve: aliases, extra segments, unknown kinds,
	// notify for a connector without one.
	for _, path := range []string{
		sandboxrelay.PathHookPrefix + "claude-code", sandboxrelay.PathHookPrefix + "claudecode/x",
		sandboxrelay.PathHookPrefix + "nosuch", sandboxrelay.PathNotifyPrefix + "claudecode",
		sandboxrelay.PathInspectPrefix + "files", sandboxrelay.PathOTLPPrefix + "profiles", sandboxrelay.PathHookPrefix,
	} {
		if resp, got := f.post(t, path, claude.ID, body); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, got)
		}
	}
	// A GET (with the CSRF client header every sandbox route needs) is
	// refused before any lookup.
	getReq, err := http.NewRequest(http.MethodGet, f.server.URL+hook, nil)
	if err != nil {
		t.Fatal(err)
	}
	getReq.Header.Set(sandboxrelay.ClientHeader, sandboxrelay.ClientHeaderValue)
	getReq.Header.Set(sandboxrelay.DaemonContractHeader, strconv.Itoa(sandboxrelay.DaemonContract))
	resp, err := f.server.Client().Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	// Root and an unverified peer are refused on every relayed route.
	f.as(&managedHookPeer{UID: 0, Name: "root"})
	if resp, got := f.post(t, hook, claude.ID, body); resp.StatusCode != http.StatusForbidden || !strings.Contains(got, managedHookReasonRootDenied) {
		t.Fatalf("root: %d %s", resp.StatusCode, got)
	}
	f.as(nil)
	if resp, got := f.post(t, hook, claude.ID, body); resp.StatusCode != http.StatusForbidden || !strings.Contains(got, managedHookReasonPeerUnverified) {
		t.Fatalf("no peer: %d %s", resp.StatusCode, got)
	}
	f.as(&relayTestPeer)
	// An unreadable store fails closed.
	f.store.set(errors.New("unreadable"), false)
	if resp, got := f.post(t, hook, claude.ID, body); resp.StatusCode != http.StatusServiceUnavailable || relayRefusalReason(t, got) != sandboxrelay.ReasonPolicyUnloadable {
		t.Fatalf("unreadable store: %d %s", resp.StatusCode, got)
	}
	// A live registration without its sandbox would act in the host's state
	// keyspace: refused, with no relay answer headers (GAP-0054).
	f.store.set(nil, true)
	resp, got := f.post(t, hook, claude.ID, body)
	if resp.StatusCode != http.StatusForbidden || relayRefusalReason(t, got) != sandboxrelay.ReasonNotAllowed ||
		resp.Header.Get(sandboxrelay.ProfileHeader) != "" || resp.Header.Get(sandboxrelay.GenerationHeader) != "" {
		t.Fatalf("unbound live registration: %d %s %v", resp.StatusCode, got, resp.Header)
	}
	f.store.set(nil, false)
	// A directory outage: the account database names no account for the
	// uid. The name the uid last resolved to stands in, so a running sandbox
	// keeps working; with no last name, or another one, the call is refused
	// (503) and the registration kept (GAP-0506).
	prevLast := managedHookPeerLastName
	t.Cleanup(func() { managedHookPeerLastName = prevLast })
	f.as(&managedHookPeer{UID: relayTestPeer.UID})
	for _, tc := range []struct {
		last   string
		status int
	}{{"", http.StatusServiceUnavailable}, {"mallory", http.StatusServiceUnavailable}, {relayTestPeer.Name, http.StatusOK}} {
		last := tc.last
		managedHookPeerLastName = func(uid int) string {
			if uid == relayTestPeer.UID {
				return last
			}
			return ""
		}
		if resp, got := f.post(t, hook, claude.ID, body); resp.StatusCode != tc.status ||
			tc.status != http.StatusOK && relayRefusalReason(t, got) != sandboxrelay.ReasonUnavailable {
			t.Fatalf("outage, last name %q: %d %s, want %d", last, resp.StatusCode, got, tc.status)
		}
	}
	if r, _, _ := f.auth.store.Get(claude.UID, claude.ID); r.State == sandboxreg.StateRevoked {
		t.Fatal("an outage revoked the registration")
	}
	_, _ = f.local.take() // the call that went through
	f.as(&relayTestPeer)
	// The same uid now named another account (a recycled uid): 409, and the
	// registration is revoked for good.
	f.as(&managedHookPeer{UID: relayTestPeer.UID, Name: "mallory"})
	if resp, got := f.post(t, sandboxrelay.PathHookPrefix+"codex", codex.ID, body); resp.StatusCode != http.StatusConflict || relayRefusalReason(t, got) != sandboxrelay.ReasonSubjectChanged {
		t.Fatalf("subject changed: %d %s", resp.StatusCode, got)
	}
	f.as(&relayTestPeer)
	if resp, got := f.post(t, sandboxrelay.PathHookPrefix+"codex", codex.ID, body); resp.StatusCode != http.StatusGone || relayRefusalReason(t, got) != sandboxrelay.ReasonRegistrationRevoked {
		t.Fatalf("after a subject change: %d %s", resp.StatusCode, got)
	}
	if r, _, _ := f.auth.store.Get(codex.UID, codex.ID); r.RevokedReason != sandboxrelay.ReasonSubjectChanged {
		t.Fatalf("revoked reason %q", r.RevokedReason)
	}
	if decisions, _ := f.local.take(); len(decisions) != 0 {
		t.Fatalf("refused calls reached the local observer: %+v", decisions)
	}
}

// TestSandboxRelayJudgesByTheCallersOwnProfile pins R4 on the relay: a
// relayed hook resolves the guardrail profile from the kernel peer's
// verified subject (the caller's own groups), not the default profile, and
// the generation it answers is the one policy/current gives that caller.
func TestSandboxRelayJudgesByTheCallersOwnProfile(t *testing.T) {
	restoreFacts, restoreBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	prevDirectory, prevRematched := managedHookPeerDirectory, sandboxRecordRematched
	identityFactsEnabled.Store(true)
	identityLookupBlocking.Store(true)
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if uid != relayTestPeer.UID {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Principal: "dev@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Groups: []string{"dc-sbx-contractors"}, Source: "sssd", ResolvedAt: time.Now(),
		}, true
	}
	sandboxRecordRematched = func(*APIServer, sandboxreg.Registration, sandboxreg.Registration, []string, string) {}
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		identityLookupBlocking.Store(restoreBlocking)
		managedHookPeerDirectory, sandboxRecordRematched = prevDirectory, prevRematched
	})

	type seen struct {
		decision profileDecision
		verified bool
		extra    map[string]string
	}
	var mu sync.Mutex
	var got []seen
	var f *relayFixture
	path := sandboxrelay.PathHookPrefix + "claudecode"
	f = newRelayFixtureWith(t, map[string]sandboxRelayRoute{path: {
		class: sandboxauth.RouteHook, connector: "claudecode", native: "/api/v1/claude-code/hook",
		handler: func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = append(got, seen{decision: f.api.resolveProfile(r.Context()), verified: isRelayedSandboxRequest(r.Context()),
				extra: sandboxHookAuditExtra(r.Context())})
			mu.Unlock()
			_, _ = w.Write([]byte("{}"))
		},
	}}, func(c *config.Config) {
		c.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"contractors":   {Description: "Contractors"},
			"offline-floor": {Description: "Offline floor"},
		}
		c.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
		}
		c.Guardrail.DefaultProfile = "offline-floor"
	})
	reg := f.register(t, "profclaude", "claudecode", relayTestBindingID(0xa01), func(r *sandboxreg.Registration) {
		r.Profile, r.ProfileMatch = "contractors", "group"
	})
	resp, body := f.post(t, path, reg.ID, `{"hook_event_name":"UserPromptSubmit","session_id":"p1","prompt":"hello"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relayed hook: %d %s", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !got[0].verified || got[0].decision.Name != "contractors" ||
		got[0].decision.SubjectSource != profileSubjectVerified || got[0].decision.Assignment != 1 {
		t.Fatalf("handler saw %+v, want contractors from the verified subject", got)
	}
	// The relayed call's audit row names the profile it was decided under,
	// like the host records of the same person (GAP-0482).
	if x := got[0].extra; x["guardrail_profile"] != "contractors" || x["guardrail_profile_match"] != "group" ||
		x["guardrail_profile_matched_group"] != "dc-sbx-contractors" || !strings.HasPrefix(x["guardrail_profile_digest"], "sha256:") {
		t.Fatalf("relayed audit extra = %v, want the contractors profile stamp", x)
	}
	if x := sandboxHookAuditExtra(sandboxCtx(sandboxTestBinding("claudecode"))); x["guardrail_profile"] != "" {
		t.Fatalf("a local sandbox ingress call's audit row claims profile %q", x["guardrail_profile"])
	}
	if resp.Header.Get(sandboxrelay.ProfileHeader) != "contractors" {
		t.Fatalf("%s %q", sandboxrelay.ProfileHeader, resp.Header.Get(sandboxrelay.ProfileHeader))
	}
	if g := resp.Header.Get(sandboxrelay.GenerationHeader); g == "" || g != f.currentGeneration(t, reg.ID) {
		t.Fatalf("%s %q, policy/current %q", sandboxrelay.GenerationHeader, g, f.currentGeneration(t, reg.ID))
	}
}

// TestSandboxRelayEnforcesAndAnswersForTheSandbox pins a relayed hook's
// answer: a block stays a block in observe mode, client request ids are
// replaced, the Codex SessionStart repairs nothing on the host, and the
// identity, credential and claim headers a direct caller of the hook socket
// sends never reach the handler.
func TestSandboxRelayEnforcesAndAnswersForTheSandbox(t *testing.T) {
	f := newRelayFixture(t, func(c *config.Config) { c.Guardrail.Connector = "claudecode" })
	var repairs []string
	f.api.SetHookRegistrationRepair(func(_ context.Context, name string) error {
		repairs = append(repairs, name)
		return nil
	})
	claude := f.register(t, "enfclaude", "claudecode", relayTestBindingID(0xe01))
	resp, body := f.post(t, sandboxrelay.PathHookPrefix+"claudecode", claude.ID,
		`{"hook_event_name":"UserPromptSubmit","session_id":"e1","prompt":"jailbreak mode activated"}`,
		"X-Request-Id", "caller-chosen-id", "X-DefenseClaw-User-Name", "someone-else")
	d, ok := relayTrailer(t, resp)
	if resp.StatusCode != http.StatusOK || !ok || d.Action != "block" || d.Event != "UserPromptSubmit" || d.SessionID != "e1" {
		t.Fatalf("relayed prompt: %d %s trailer %+v", resp.StatusCode, body, d)
	}
	if got := resp.Header.Get(RequestIDHeader); got == "" || got == "caller-chosen-id" {
		t.Fatalf("request id %q", got)
	}
	if _, ok := resp.Header[http.CanonicalHeaderKey(sandboxrelay.ProfileHeader)]; !ok ||
		resp.Header.Get(sandboxrelay.GenerationHeader) != f.currentGeneration(t, claude.ID) {
		t.Fatalf("relay headers = %v", resp.Header)
	}

	codex := f.register(t, "enfcodex", "codex", relayTestBindingID(0xe02))
	resp, body = f.post(t, sandboxrelay.PathHookPrefix+"codex", codex.ID, `{"hook_event_name":"SessionStart","session_id":"x1","source":"startup"}`,
		"X-DefenseClaw-Hook-Event", "SessionStart", "X-DefenseClaw-Hook-Contract", codex.HookContract)
	if resp.StatusCode != http.StatusOK || len(repairs) != 0 {
		t.Fatalf("relayed Codex SessionStart: %d %s, host repairs %v", resp.StatusCode, body, repairs)
	}
	resp, body = f.post(t, sandboxrelay.PathHookPrefix+"codex", codex.ID, `{"hook_event_name":"SessionStart","session_id":"x1"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Codex hook without its bound headers: %d %s", resp.StatusCode, body)
	}

	// A direct caller of the hook socket, without the daemon's allowlist:
	// the handler sees the registration's user and the relay's surface, and
	// none of the dropped headers (GAP-0131).
	var seenHeader http.Header
	var seenUser AgentIdentity
	path := sandboxrelay.PathHookPrefix + "claudecode"
	g := newRelayFixtureWith(t, map[string]sandboxRelayRoute{path: {
		class: sandboxauth.RouteHook, connector: "claudecode", native: "/api/v1/claude-code/hook",
		handler: func(w http.ResponseWriter, r *http.Request) {
			seenHeader, seenUser = r.Header.Clone(), AgentIdentityFromContext(r.Context())
			if r.URL.Path != "/api/v1/claude-code/hook" {
				t.Errorf("handler path %q", r.URL.Path)
			}
			w.Header().Set("Content-Length", "2")
			_, _ = w.Write([]byte("{}"))
		},
	}})
	direct := g.register(t, "dirclaude", "claudecode", relayTestBindingID(0xe03))
	forged := []string{"X-DefenseClaw-User-Id", "X-DefenseClaw-User-Name", "X-DefenseClaw-Sandbox-Other",
		useridentity.SessionFactsHeader, sandboxrelay.ConnectorHeader}
	for _, name := range sandboxrelay.DroppedHeaders {
		if name != http.CanonicalHeaderKey(sandboxrelay.ClientHeader) {
			forged = append(forged, name)
		}
	}
	var headers []string
	for _, name := range forged {
		value := "forged"
		if name == "Authorization" {
			value = "Bearer forged"
		}
		headers = append(headers, name, value)
	}
	resp, body = g.post(t, path, direct.ID, "{}", headers...)
	if resp.StatusCode != http.StatusOK || seenHeader == nil {
		t.Fatalf("direct caller: %d %s", resp.StatusCode, body)
	}
	for _, name := range forged {
		if name == http.CanonicalHeaderKey(sandboxrelay.AgentSurfaceHeader) || name == http.CanonicalHeaderKey(RequestIDHeader) {
			continue
		}
		if seenHeader.Get(name) != "" {
			t.Fatalf("%s reached the handler: %q", name, seenHeader.Get(name))
		}
	}
	if v := seenHeader.Get(RequestIDHeader); v == "forged" {
		t.Fatal("the caller's request id reached the handler")
	}
	if seenHeader.Get(sandboxrelay.AgentSurfaceHeader) != sandboxrelay.AgentSurfaceValue || seenUser.UserID != "1000" || seenUser.UserName != "dev" {
		t.Fatalf("handler saw surface %q user %+v", seenHeader.Get(sandboxrelay.AgentSurfaceHeader), seenUser)
	}
	if resp.Header.Get("Content-Length") != "" || resp.ContentLength != -1 {
		t.Fatal("a handler's Content-Length survived; it would drop the trailer")
	}
}

// TestSandboxRelayDecisionTrailerBounds pins the trailer's size and string
// bounds for hostile values.
func TestSandboxRelayDecisionTrailerBounds(t *testing.T) {
	long := strings.Repeat(`"\`, 400) + "\x00\r\nX-Injected: 1"
	sink := &sandboxRelayDecisionSink{}
	if _, ok := sink.trailer(); ok {
		t.Fatal("an empty sink has a trailer")
	}
	sink.put(SandboxHookDecision{
		Event: long, Tool: long, ToolUseID: long, SessionID: long, CallRef: long, ResultStatus: long,
		Action: "block", Severity: long, Reason: strings.Repeat("é", 400), ModelError: long, ModelStatus: 401,
	})
	sink.markFailedClosed()
	raw, ok := sink.trailer()
	if !ok || len(raw) > sandboxrelay.MaxHookDecisionBytes || strings.ContainsAny(raw, "\r\n\x00") {
		t.Fatalf("trailer %d bytes ok=%v: %q", len(raw), ok, raw)
	}
	var d sandboxrelay.HookDecision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	if d.V != 1 || d.Action != "block" || !d.FailedClosed || d.ModelStatus != 401 || len(d.Reason) > sandboxrelay.MaxHookDecisionReasonBytes ||
		len(d.Tool) > sandboxrelay.MaxHookDecisionStringBytes || !strings.HasPrefix(d.Reason, "é") || d.CallRef != "" {
		t.Fatalf("decision = %+v", d)
	}
	short := &sandboxRelayDecisionSink{}
	short.put(SandboxHookDecision{Event: "PreToolUse", Tool: "Bash", Action: "allow", Reason: "ok"})
	if raw, _ := short.trailer(); raw != `{"v":1,"event":"PreToolUse","tool":"Bash","action":"allow","reason":"ok"}` {
		t.Fatalf("short trailer %s", raw)
	}
	// Short strings that need escaping overflow the trailer; the call
	// reference is never the field that is cut (GAP-0129).
	ref := manager.ContentRef("s1", "Bash", json.RawMessage(`{"command":"ls"}`))
	esc := strings.Repeat("<", 60)
	escaped := &sandboxRelayDecisionSink{}
	escaped.put(SandboxHookDecision{
		Event: esc, Tool: esc, ToolUseID: esc, SessionID: esc, CallRef: ref, ResultStatus: esc,
		Action: "block", Severity: esc, Reason: strings.Repeat("<", 250), ModelError: esc,
	})
	raw, ok = escaped.trailer()
	if !ok || len(raw) > sandboxrelay.MaxHookDecisionBytes {
		t.Fatalf("escaped trailer %d bytes ok=%v", len(raw), ok)
	}
	d = sandboxrelay.HookDecision{}
	if err := json.Unmarshal([]byte(raw), &d); err != nil || d.CallRef != ref || d.Action != "block" {
		t.Fatalf("escaped decision %+v (%v), want call_ref %q intact", d, err, ref)
	}
}

// TestSandboxRelayInspectAndOTLP pins the relayed inspect route (the
// registration's connector, no connector header) and the relayed OTLP
// route (attributed to the registration's connector, at most
// MaxOTLPBodyBytes per export).
func TestSandboxRelayInspectAndOTLP(t *testing.T) {
	f := newRelayFixture(t)
	f.api.bindOTLPObservabilityRuntime(newSidecarRuntimeFixture(t, true).runtime)
	claude := f.register(t, "insclaude", "claudecode", relayTestBindingID(0xf01))
	resp, body := f.post(t, sandboxrelay.PathInspectPrefix+"tool", claude.ID,
		`{"tool":"Bash","args":{"command":"ls"}}`, sandboxrelay.ConnectorHeader, "codex")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relayed inspect: %d %s", resp.StatusCode, body)
	}
	if _, ok := relayTrailer(t, resp); ok {
		t.Fatal("inspect, which the local observer never records, carried a trailer")
	}

	resp, body = f.post(t, sandboxrelay.PathOTLPPrefix+"logs", claude.ID, `{"resourceLogs":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relayed OTLP: %d %s", resp.StatusCode, body)
	}
	pad := `{"resourceLogs":[],"pad":"` + strings.Repeat("a", sandboxrelay.MaxOTLPBodyBytes) + `"}`
	if resp, body = f.post(t, sandboxrelay.PathOTLPPrefix+"logs", claude.ID, pad); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("OTLP export over the relay cap: %d %s", resp.StatusCode, body)
	}
	if resp, body = f.post(t, sandboxrelay.PathOTLPPrefix+"traces", relayTestID("nosuch"), `{"resourceSpans":[]}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("OTLP for an unknown registration: %d %s", resp.StatusCode, body)
	}
	var source string
	route := sandboxRelayRoute{class: sandboxauth.RouteOTLP, handler: func(w http.ResponseWriter, r *http.Request) {
		source = r.Header.Get(otelSourceHeader)
	}}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("{}"))
	req.Header.Set(otelSourceHeader, "codex")
	f.api.serveSandboxRelayOTLP(httptest.NewRecorder(), req, route, sandboxRelayBinding(claude, sandboxauth.RouteOTLP))
	if source != "claudecode" {
		t.Fatalf("OTLP source %q, want the registration's connector", source)
	}
	for path, want := range map[string]bool{
		sandboxrelay.PathOTLPPrefix + "logs": true, sandboxrelay.PathOTLPPrefix + "metrics": true,
		sandboxrelay.PathOTLPPrefix + "traces": true, sandboxrelay.PathOTLPPrefix + "profiles": false,
		sandboxrelay.PathOTLPPrefix + "logs/x": false, "/v1/logs": false,
	} {
		if isSandboxRelayOTLPPath(path) != want {
			t.Fatalf("isSandboxRelayOTLPPath(%q) = %v", path, !want)
		}
	}
}

// TestSandboxRelayThroughTheHookSocketServer runs the real standalone hook
// socket server with the gateway's own base layers (metrics, correlation,
// request id, inbound trace): a relayed hook's verdict arrives as a trailer
// of a chunked answer without Content-Length, the caller's request id is
// replaced, and a 2 MiB protobuf OTLP export passes the socket's CSRF check
// and body limit (GAP-0053, GAP-0055).
func TestSandboxRelayThroughTheHookSocketServer(t *testing.T) {
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("the hook socket refuses uid 0 on the relayed routes")
	}
	dir := shortGatewaySocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	prevDescriptor, prevInherited, prevKey := loadStandaloneRuntimeDescriptor, inheritedHookListener, sandboxAuthorityKey
	t.Cleanup(func() {
		loadStandaloneRuntimeDescriptor, inheritedHookListener, sandboxAuthorityKey = prevDescriptor, prevInherited, prevKey
	})
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		return &managed.RuntimeDescriptor{
			SchemaVersion: managed.RuntimeDescriptorSchemaVersion, Profile: managed.ProfileStandalone,
			ServiceUser: current.Username, ServiceUID: uid, APIAddr: managed.StandaloneAPIAddr,
			HookSocket: socket, MachinePolicyConnectors: harness.Names(),
		}, nil
	}
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }
	sandboxAuthorityKey = func(string) ([]byte, error) { return relayTestKey, nil }

	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	cfg.OpenShell.Enabled = true
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	api.bindOTLPObservabilityRuntime(newSidecarRuntimeFixture(t, true).runtime)
	auth, err := api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	peer := managedHookPeer{UID: uid, Name: current.Username}
	reg := relayTestRegistration(t, peer, "sockclaude", "claudecode", relayTestBindingID(0xb01))
	if err := auth.store.Create(uid, reg); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.store.Bind(uid, reg.ID, sandboxrelay.BindRequest{V: 1, SandboxName: reg.SandboxName, SandboxID: reg.SandboxID, BindingID: reg.BindingID}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	registry := InstallSharedAgentRegistry("", "")
	server, listener, err := api.newManagedHookSocketServer(ctx, func(h http.Handler) http.Handler {
		h = api.metricsMiddleware(h)
		h = CorrelationMiddleware(registry)(h)
		h = requestIDMiddleware(h)
		return inboundTraceContextMiddleware(h)
	})
	if err != nil || server == nil {
		cancel()
		t.Fatalf("hook socket server: %v %v", server, err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})
	client := hookSocketClient(socket, 20*time.Second)
	post := func(path, contentType string, body []byte, headers ...string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set(sandboxrelay.ClientHeader, sandboxrelay.ClientHeaderValue)
		req.Header.Set(sandboxrelay.DaemonContractHeader, strconv.Itoa(sandboxrelay.DaemonContract))
		req.Header.Set(sandboxrelay.AgentSurfaceHeader, sandboxrelay.AgentSurfaceValue)
		req.Header.Set(sandboxrelay.RegistrationHeader, reg.ID)
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, raw
	}

	resp, body := post(sandboxrelay.PathHookPrefix+"claudecode", "application/json",
		[]byte(`{"hook_event_name":"UserPromptSubmit","session_id":"k1","prompt":"jailbreak mode activated"}`),
		"X-Request-Id", "caller-chosen-id")
	d, ok := relayTrailer(t, resp)
	if resp.StatusCode != http.StatusOK || !ok || d.Action != "block" {
		t.Fatalf("relayed hook over the socket: %d %s trailer %+v", resp.StatusCode, body, d)
	}
	if resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" || !slices.Contains(resp.TransferEncoding, "chunked") {
		t.Fatalf("framing: length %d transfer %v", resp.ContentLength, resp.TransferEncoding)
	}
	if got := resp.Header.Get(RequestIDHeader); got == "" || got == "caller-chosen-id" {
		t.Fatalf("request id %q", got)
	}

	export := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{}},
	}}}
	line := strings.Repeat("a", 1<<10)
	for range 2 << 10 {
		export.ResourceLogs[0].ScopeLogs[0].LogRecords = append(export.ResourceLogs[0].ScopeLogs[0].LogRecords, &logspb.LogRecord{
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: line}},
		})
	}
	raw, err := proto.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2<<20 || len(raw) > sandboxrelay.MaxOTLPBodyBytes {
		t.Fatalf("export is %d bytes", len(raw))
	}
	if resp, body := post(sandboxrelay.PathOTLPPrefix+"logs", "application/x-protobuf", raw); resp.StatusCode/100 != 2 {
		t.Fatalf("2 MiB protobuf OTLP export: %d %s", resp.StatusCode, body)
	}
}

// A relayed hook with an unproven group uses the observe default when the
// possible group profile also only observes. The registration's last proven
// profile is not assumed to be the caller's current policy (GAP-0522).
func TestSandboxRelayUsesObserveDefaultForUnprovenGroup(t *testing.T) {
	restoreFacts, restoreBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	prevDirectory, prevRematched := managedHookPeerDirectory, sandboxRecordRematched
	identityFactsEnabled.Store(true)
	identityLookupBlocking.Store(true)
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if uid != relayTestPeer.UID {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Principal: "dev@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			GroupsPartial: true, Source: "sssd", ResolvedAt: time.Now(),
		}, true
	}
	sandboxRecordRematched = func(*APIServer, sandboxreg.Registration, sandboxreg.Registration, []string, string) {}
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		identityLookupBlocking.Store(restoreBlocking)
		managedHookPeerDirectory, sandboxRecordRematched = prevDirectory, prevRematched
	})
	f := newRelayFixture(t, func(c *config.Config) {
		c.Guardrail.Connector = "claudecode"
		c.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"contractors":   {Description: "Contractors", Mode: "observe"},
			"offline-floor": {Description: "Offline floor", Mode: "observe"},
		}
		c.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
		}
		c.Guardrail.DefaultProfile = "offline-floor"
	})
	reg := f.register(t, "unproven", "claudecode", relayTestBindingID(0xa02), func(r *sandboxreg.Registration) {
		r.Profile, r.ProfileMatch = "contractors", "group"
	})
	resp, body := f.post(t, sandboxrelay.PathHookPrefix+"claudecode", reg.ID,
		`{"hook_event_name":"UserPromptSubmit","session_id":"u1","prompt":"hello"}`)
	d, ok := relayTrailer(t, resp)
	if resp.StatusCode != http.StatusOK || !ok || d.Action != "allow" || d.FailedClosed ||
		strings.Contains(body, "DefenseClaw refused this request") ||
		strings.Contains(body, "contractors") || strings.Contains(body, "offline-floor") {
		t.Fatalf("relayed hook: %d %s trailer %+v; want observe default without a profile name", resp.StatusCode, body, d)
	}
}
