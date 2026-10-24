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

//go:build linux || darwin

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0579: a request the relay client refused as invalid input is the
// user's to fix; it is not reported as an unreachable gateway.
func TestManagedRelayErrorKeepsInvalidInputApartFromAnUnreachableGateway(t *testing.T) {
	var apiErr *sandboxapi.Error
	err := managedRelayError(&sandboxrelay.InvalidRequestError{Message: `"../x" is not a pack name`})
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeInvalid || strings.Contains(apiErr.Message, "not reachable") {
		t.Fatalf("invalid input = %+v", apiErr)
	}
	err = managedRelayError(sandboxrelay.ErrGatewayUnreachable)
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeUnavailable || !strings.Contains(apiErr.Message, "not reachable") {
		t.Fatalf("unreachable = %+v", apiErr)
	}
}

// fakeManagedGateway serves handler on a unix socket the way the managed
// gateway's hook socket is served and returns a real relay client of it.
func fakeManagedGateway(t *testing.T, handler http.Handler) (*sandboxrelay.UnixClient, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "dmg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hook.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	stop := func() { _ = srv.Close() }
	t.Cleanup(stop)
	client, err := sandboxrelay.NewClient(sandboxrelay.ClientOptions{SocketPath: path, TrustedOwners: []int{os.Getuid()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, stop
}

func ingressHookPath(t *testing.T, api *APIServer, connectorName string) string {
	t.Helper()
	for path, route := range ingressServedPaths(t, api) {
		if route.class == sandboxauth.RouteHook && route.connector == connectorName {
			return path
		}
	}
	t.Fatalf("no ingress hook route for %s", connectorName)
	return ""
}

// Forwarding mode: only the allowlist leaves the daemon, the relay sets its
// own headers, the body is unchanged, the trailer reaches OnHookDecision,
// a 2xx without one records nothing, a 429 passes through with Retry-After
// and an unreachable gateway answers 502.
func TestSandboxRelayForwarding(t *testing.T) {
	decision := sandboxrelay.HookDecision{
		V: 1, Event: "PreToolUse", Tool: "Bash", ToolUseID: "toolu_1", SessionID: "s-1", CallRef: "ref-1",
		ResultStatus: "done", Action: "block", WouldBlock: true, Severity: "HIGH", Reason: "rule r1",
		ModelError: "rate_limit", ModelStatus: 429,
	}
	var (
		mu      sync.Mutex
		seen    *http.Request
		seenRaw []byte
		mode    = "trailer"
	)
	client, stop := fakeManagedGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = r.Clone(context.Background())
		seenRaw, _ = io.ReadAll(r.Body)
		switch mode {
		case "trailer":
			w.Header().Set("Trailer", sandboxrelay.DecisionTrailer)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(sandboxrelay.ProfileHeader, "contractors")
			w.Header().Set(sandboxrelay.GenerationHeader, "7")
			w.Header().Set("X-Unrelated", "x")
			_, _ = io.WriteString(w, `{"decision":"deny"}`)
			raw, _ := json.Marshal(decision)
			w.Header().Set(sandboxrelay.DecisionTrailer, string(raw))
		case "plain":
			_, _ = io.WriteString(w, `{}`)
		case "limited":
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"enterprise_managed_rate_limited"}`)
		}
	}))
	obs := &sandboxObserver{}
	var generation atomic.Uint64
	var generationOf atomic.Pointer[string]
	registered := true
	f := newSandboxIngressFixture(t, obs.observe, func(c *SandboxIngressConfig) {
		c.Relay = client
		c.Registration = func(b sandboxauth.Binding) (string, bool) {
			if !registered {
				return "", false
			}
			return "reg-" + strings.TrimPrefix(b.SandboxName, "dc-"), true
		}
		c.OnGeneration = func(registration string, g uint64) { generationOf.Store(&registration); generation.Store(g) }
	})
	path := ingressHookPath(t, f.api, "claudecode")
	body := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	headers := []string{"Traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", "X-DefenseClaw-Hook-Event", "PreToolUse"}
	for _, name := range sandboxrelay.DroppedHeaders {
		if name == "Authorization" {
			continue
		}
		headers = append(headers, name, "forged")
	}
	headers = append(headers, sandboxrelay.FilesHeader, "forged", sandboxrelay.RegistrationHeader, "reg-forged")

	rec := f.do(t, http.MethodPost, path, f.claudeTok, body, headers...)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"decision":"deny"}` {
		t.Fatalf("relayed hook: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(sandboxrelay.ProfileHeader) != "contractors" || rec.Header().Get(sandboxrelay.GenerationHeader) != "7" ||
		rec.Header().Get("X-Unrelated") != "" {
		t.Fatalf("answer headers: %v", rec.Header())
	}
	mu.Lock()
	if seen.URL.Path != sandboxrelay.PathHookPrefix+"claudecode" || string(seenRaw) != body {
		t.Fatalf("relayed %s with body %q", seen.URL.Path, seenRaw)
	}
	for _, name := range sandboxrelay.DroppedHeaders {
		v := seen.Header.Get(name)
		switch http.CanonicalHeaderKey(name) {
		case http.CanonicalHeaderKey(sandboxrelay.ClientHeader):
			if v != sandboxrelay.ClientHeaderValue {
				t.Fatalf("client header = %q", v)
			}
		case http.CanonicalHeaderKey(sandboxrelay.AgentSurfaceHeader):
			if v != sandboxrelay.AgentSurfaceValue {
				t.Fatalf("agent surface = %q", v)
			}
		default:
			if v != "" {
				t.Fatalf("%s reached the managed gateway: %q", name, v)
			}
		}
	}
	if seen.Header.Get(sandboxrelay.FilesHeader) != "" || seen.Header.Get(sandboxrelay.RegistrationHeader) != "reg-claude-app" {
		t.Fatalf("sandbox headers: files %q registration %q", seen.Header.Get(sandboxrelay.FilesHeader), seen.Header.Get(sandboxrelay.RegistrationHeader))
	}
	if seen.Header.Get("X-Defenseclaw-Hook-Event") != "PreToolUse" {
		t.Fatalf("hook event header missing: %v", seen.Header)
	}
	mu.Unlock()
	decisions, failures := obs.take()
	if len(decisions) != 1 || len(failures) != 0 {
		t.Fatalf("decisions %v failures %v", decisions, failures)
	}
	got := decisions[0]
	want := SandboxHookDecision{
		BindingID: f.claude.ID, SandboxName: f.claude.SandboxName, Connector: "claudecode",
		Event: decision.Event, Tool: decision.Tool, ToolUseID: decision.ToolUseID, SessionID: decision.SessionID,
		ResultStatus: decision.ResultStatus, Action: decision.Action, WouldBlock: true, Severity: decision.Severity,
		Reason: decision.Reason, ModelError: decision.ModelError, ModelStatus: decision.ModelStatus, CallRef: decision.CallRef,
	}
	if got.ToolInput != nil || got.BindingID != want.BindingID || got.CallRef != want.CallRef || got.Event != want.Event ||
		got.Tool != want.Tool || got.ToolUseID != want.ToolUseID || got.SessionID != want.SessionID ||
		got.ResultStatus != want.ResultStatus || got.Action != want.Action || !got.WouldBlock || got.Severity != want.Severity ||
		got.Reason != want.Reason || got.ModelError != want.ModelError || got.ModelStatus != want.ModelStatus {
		t.Fatalf("decision = %+v, want %+v", got, want)
	}
	if of := generationOf.Load(); generation.Load() != 7 || of == nil || *of != "reg-"+strings.TrimPrefix(f.claude.SandboxName, "dc-") {
		t.Fatalf("generation = %d of %v", generation.Load(), of)
	}

	// A 200 block caused by failed evaluation also counts as a hook failure.
	mu.Lock()
	decision.FailedClosed = true
	mu.Unlock()
	rec = f.do(t, http.MethodPost, path, f.claudeTok, body)
	if decisions, failures := obs.take(); rec.Code != http.StatusOK || len(decisions) != 1 || len(failures) != 1 || failures[0].Status != http.StatusInternalServerError {
		t.Fatalf("failed-closed relay: status %d decisions %v failures %v", rec.Code, decisions, failures)
	}
	mu.Lock()
	decision.FailedClosed = false
	mode = "plain"
	mu.Unlock()

	// A 2xx without a trailer records nothing.
	rec = f.do(t, http.MethodPost, path, f.claudeTok, `{"hook_event_name":"Stop"}`)
	if decisions, _ := obs.take(); rec.Code != http.StatusOK || len(decisions) != 0 {
		t.Fatalf("no trailer: %d, decisions %v", rec.Code, decisions)
	}

	// A gateway 429 passes through with Retry-After and fails the hook.
	mu.Lock()
	mode = "limited"
	mu.Unlock()
	rec = f.do(t, http.MethodPost, path, f.claudeTok, `{"hook_event_name":"Stop","n":2}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("429: %d %v", rec.Code, rec.Header())
	}
	if _, failures := obs.take(); len(failures) != 1 || failures[0].Status != http.StatusTooManyRequests {
		t.Fatalf("429 failures %v", failures)
	}

	// An unregistered sandbox is refused; nothing is evaluated locally.
	registered = false
	rec = f.do(t, http.MethodPost, path, f.claudeTok, `{"hook_event_name":"Stop","n":3}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unregistered: %d", rec.Code)
	}
	registered = true

	// An unreachable gateway answers 502.
	stop()
	rec = f.do(t, http.MethodPost, path, f.claudeTok, `{"hook_event_name":"Stop","n":4}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unreachable gateway: %d %s", rec.Code, rec.Body.String())
	}
	if _, failures := obs.take(); len(failures) != 2 || failures[len(failures)-1].Status != http.StatusBadGateway {
		t.Fatalf("failures %v", failures)
	}
}

func TestSandboxIngressForwardingNeedsRegistrations(t *testing.T) {
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil)
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: store, Relay: &fakeRelay{}}); err == nil {
		t.Fatal("forwarding mode without registrations was accepted")
	}
}

// fakeRelay is a sandboxrelay.Client whose calls the test sets.
type fakeRelay struct {
	settings func() (sandboxrelay.DaemonSettings, error)
	// unchanged answers Settings when settings is nil: the managed
	// gateway's settings as the daemon holds them (a create reads them).
	unchanged func() sandboxrelay.DaemonSettings
	resolve   func(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error)
	current   func(string) (sandboxrelay.CurrentPolicy, error)
	// rawCurrent lets a test exercise an incomplete wire answer. Ordinary
	// fake answers model the complete floor sent by the current gateway.
	rawCurrent bool
	explain    func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error)
	test       func(sandboxrelay.PolicyTestRequest) (sandboxapi.PolicyTestResult, error)
	packs      func(registration, connector, name string) ([]sandboxrelay.PackView, error)
	// decisions answers the saved-decisions list of a registration.
	decisions func(registration string) ([]sandboxrelay.Decision, error)
	deleted   atomic.Int64

	eventsMu sync.Mutex
	events   []sandboxrelay.EventBatch
	// eventsFail fails that many Events calls first.
	eventsFail atomic.Int64
	// reports are the state reports, "id=running" or "id=stopped".
	reports []string
}

var _ sandboxrelay.Client = (*fakeRelay)(nil)

func (f *fakeRelay) Settings(context.Context) (sandboxrelay.DaemonSettings, error) {
	if f.settings != nil {
		return f.settings()
	}
	if f.unchanged != nil {
		return f.unchanged(), nil
	}
	return sandboxrelay.DaemonSettings{}, errors.New("no settings")
}
func (f *fakeRelay) Resolve(_ context.Context, r sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
	if f.resolve != nil {
		return f.resolve(r)
	}
	return sandboxrelay.ResolveResponse{}, errors.New("no resolve")
}
func (f *fakeRelay) Bind(context.Context, string, sandboxrelay.BindRequest) (sandboxrelay.RegistrationView, error) {
	return sandboxrelay.RegistrationView{}, nil
}
func (f *fakeRelay) Deleted(context.Context, string) error { f.deleted.Add(1); return nil }
func (f *fakeRelay) Current(_ context.Context, id string) (sandboxrelay.CurrentPolicy, error) {
	var cp sandboxrelay.CurrentPolicy
	var err error
	if f.current != nil {
		cp, err = f.current(id)
	}
	if err == nil && !cp.Revoked && cp.Floor == nil && !f.rawCurrent {
		cp.Floor = &config.OpenShellAdminConfig{}
	}
	return cp, err
}

func TestSandboxDaemonRefusesIncompletePolicyAnswer(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	r := daemonRegistration{ID: "reg-1", Sandbox: "dc-a"}
	if err := f.d.regs.put(r); err != nil {
		t.Fatal(err)
	}
	f.relay.rawCurrent = true
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: sandboxrelay.WireVersion}, nil
	}
	ans := f.d.askPolicy(context.Background(), r, false, false)
	if ans.err == nil {
		t.Fatal("incomplete policy answer was accepted")
	}
	if got, _ := f.d.regs.get(r.Sandbox); got.Confirmed {
		t.Fatal("incomplete policy answer confirmed a cached floor")
	}
}

// Report records the state report and answers like Current.
func (f *fakeRelay) Report(ctx context.Context, id string, running bool) (sandboxrelay.CurrentPolicy, error) {
	state := "stopped"
	if running {
		state = "running"
	}
	f.eventsMu.Lock()
	f.reports = append(f.reports, id+"="+state)
	f.eventsMu.Unlock()
	return f.Current(ctx, id)
}

func (f *fakeRelay) reported() []string {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	return slices.Clone(f.reports)
}
func (f *fakeRelay) Explain(_ context.Context, r sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
	if f.explain != nil {
		return f.explain(r)
	}
	return sandboxapi.ManagedExplain{}, errors.New("no explain")
}
func (f *fakeRelay) PolicyTest(_ context.Context, r sandboxrelay.PolicyTestRequest) (sandboxapi.PolicyTestResult, error) {
	if f.test != nil {
		return f.test(r)
	}
	return sandboxapi.PolicyTestResult{}, nil
}
func (f *fakeRelay) Packs(_ context.Context, registration, connector string) ([]sandboxrelay.PackView, error) {
	if f.packs != nil {
		return f.packs(registration, connector, "")
	}
	return nil, nil
}
func (f *fakeRelay) Pack(_ context.Context, registration, connector, name string) (sandboxrelay.PackView, error) {
	if f.packs != nil {
		list, err := f.packs(registration, connector, name)
		if err != nil || len(list) == 0 {
			return sandboxrelay.PackView{}, err
		}
		return list[0], nil
	}
	return sandboxrelay.PackView{}, nil
}
func (f *fakeRelay) Decide(context.Context, sandboxrelay.DecisionRequest) (sandboxrelay.DecisionResult, error) {
	return sandboxrelay.DecisionResult{}, nil
}
func (f *fakeRelay) Decisions(_ context.Context, registration string) ([]sandboxrelay.Decision, error) {
	if f.decisions != nil {
		return f.decisions(registration)
	}
	return nil, nil
}
func (f *fakeRelay) Events(_ context.Context, batch sandboxrelay.EventBatch) error {
	if f.eventsFail.Load() > 0 {
		f.eventsFail.Add(-1)
		return errors.New("relay unavailable")
	}
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	f.events = append(f.events, batch)
	return nil
}

// fakeOpenShell is a daemonOpenShell whose answers the test sets; the zero
// value finds nothing to do.
type fakeOpenShell struct {
	drift    []openshell.SettingDrift
	driftErr error
	prepare  func(sandboxrelay.DaemonSettings) (bool, error)
	prepared atomic.Int64
	stopped  atomic.Int64
	// holder is the gateway port's listener: 0 free, else the uid.
	holder atomic.Int64
}

func (f *fakeOpenShell) PortHolder(sandboxrelay.DaemonSettings) (int, bool) {
	uid := int(f.holder.Load())
	return uid, uid != 0
}

func (f *fakeOpenShell) OtherGateways(context.Context, sandboxrelay.DaemonSettings) []string {
	return nil
}

func (f *fakeOpenShell) Drift(sandboxrelay.DaemonSettings) ([]openshell.SettingDrift, error) {
	return f.drift, f.driftErr
}
func (f *fakeOpenShell) Prepare(_ context.Context, s sandboxrelay.DaemonSettings) (bool, error) {
	f.prepared.Add(1)
	if f.prepare != nil {
		return f.prepare(s)
	}
	return false, nil
}
func (f *fakeOpenShell) Stop(context.Context, sandboxrelay.DaemonSettings) bool {
	f.stopped.Add(1)
	f.holder.Store(0)
	return true
}
func (f *fakeRelay) Relay(context.Context, sandboxrelay.RelayCall) (sandboxrelay.RelayResponse, error) {
	return sandboxrelay.RelayResponse{}, sandboxrelay.ErrGatewayUnreachable
}
func (f *fakeRelay) OTLP(context.Context, sandboxrelay.OTLPCall) error { return nil }
func (f *fakeRelay) Close() error                                      { return nil }

type sandboxDaemonFixture struct {
	d       *SandboxDaemon
	relay   *fakeRelay
	os      *fakeOpenShell
	socket  string
	running atomic.Int64
	exe     string
}

func newSandboxDaemonFixture(t *testing.T, mutate ...func(*SandboxDaemonOptions)) *sandboxDaemonFixture {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("the sandbox daemon refuses root")
	}
	dir, err := os.MkdirTemp("", "dsd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "run", "sandbox.sock")
	ln, err := BindSandboxDaemonSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	f := &sandboxDaemonFixture{relay: &fakeRelay{}, os: &fakeOpenShell{}, socket: socket, exe: filepath.Join(dir, "defenseclaw-gateway")}
	if err := os.WriteFile(f.exe, []byte("v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	settings := &sandboxrelay.DaemonSettings{
		V: 1, Enabled: true, Available: true, Generation: 3, RequestAccess: "it-help@example.com",
		Operational: sandboxrelay.OperationalSettings{IngressPort: freePort(t), EgressPort: freePort(t), GatewayName: "defenseclaw-test-missing"},
		Enterprise:  sandboxrelay.EnterpriseOpenShell{Install: "setup", Driver: "docker", Version: "0.1.3", GatewayPort: 17670},
	}
	opts := SandboxDaemonOptions{
		RuntimeOptions: RuntimeOptions{Managed: true, Relay: f.relay, Settings: settings},
		StateDir:       filepath.Join(dir, "state"),
		Listener:       ln,
		Tick:           time.Hour,
		PollInterval:   time.Hour,
		Executable:     f.exe,
		Logf:           func(string, ...any) {},
		countRunning:   func(context.Context) (int, error) { return int(f.running.Load()), nil },
		openShell:      f.os,
		// The fixture runs the Linux daemon on every platform: a Mac daemon
		// probes the account Docker and selects the MicroVM driver before
		// a create (dockerReady, selectDriver); tests of that set goos.
		goos: "linux",
	}
	for _, m := range mutate {
		m(&opts)
	}
	d, err := NewSandboxDaemon(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.d = d
	f.relay.unchanged = d.currentSettings
	return f
}

// run runs the daemon until the test ends and returns its result channel.
func (f *sandboxDaemonFixture) run(t *testing.T) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the sandbox daemon did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.d.listenMu.Lock()
		started := f.d.runCtx != nil
		f.d.listenMu.Unlock()
		if started || time.Now().After(deadline) {
			return done
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func portFree(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// The CLI socket is 0600 in a 0700 directory, a stale socket is replaced,
// a live one refused, and only the daemon's own uid is served.
func TestSandboxDaemonSocketAndPeerCheck(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	dirInfo, _ := os.Stat(filepath.Dir(f.socket))
	sockInfo, _ := os.Lstat(f.socket)
	if dirInfo.Mode().Perm() != 0o700 || sockInfo.Mode().Perm() != 0o600 || sockInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("modes: dir %o socket %o", dirInfo.Mode().Perm(), sockInfo.Mode().Perm())
	}
	f.run(t)
	if _, err := BindSandboxDaemonSocket(f.socket); err == nil {
		t.Fatal("a second daemon bound a live socket")
	}
	client := sandboxapi.NewUnixClient(f.socket)
	st, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("status over the socket: %v", err)
	}
	if st.Managed == nil || st.Managed.InstallMode != "setup" || st.Managed.Driver != "docker" ||
		st.Managed.OpenShellVersion != "0.1.3" || st.Managed.RequestAccess != "it-help@example.com" {
		t.Fatalf("managed status = %+v", st.Managed)
	}

	// Another uid on the same kind of connection is refused.
	srv := &http.Server{Handler: sandboxDaemonPeerCheck(os.Getuid()+1, http.NotFoundHandler()), ConnContext: sandboxDaemonConnContext}
	other := filepath.Join(filepath.Dir(f.socket), "other.sock")
	ln, err := net.Listen("unix", other)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if _, err := sandboxapi.NewUnixClient(other).Status(context.Background()); !sandboxapi.IsCode(err, sandboxapi.CodePolicyViolation) {
		t.Fatalf("another uid: %v", err)
	}
	// A request without peer credentials is refused too.
	rec := httptestRecorder(sandboxDaemonPeerCheck(os.Getuid(), http.NotFoundHandler()))
	if rec != http.StatusForbidden {
		t.Fatalf("no credentials: %d", rec)
	}

	// A stale socket left by a dead daemon is replaced.
	stale := filepath.Join(t.TempDir(), "s", "sandbox.sock")
	sl, err := BindSandboxDaemonSocket(stale)
	if err != nil {
		t.Fatal(err)
	}
	sl.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = sl.Close()
	again, err := BindSandboxDaemonSocket(stale)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	_ = again.Close()
}

func httptestRecorder(h http.Handler) int {
	rec := &statusOnly{header: http.Header{}}
	req, _ := http.NewRequest(http.MethodGet, "http://sandbox-daemon/api/v1/sandbox/status", nil)
	h.ServeHTTP(rec, req)
	return rec.status
}

type statusOnly struct {
	header http.Header
	status int
}

func (s *statusOnly) Header() http.Header         { return s.header }
func (s *statusOnly) Write(p []byte) (int, error) { return len(p), nil }
func (s *statusOnly) WriteHeader(code int)        { s.status = code }

// The ports are bound at the first create and released when no sandbox
// runs; a port another account holds refuses with the neutral text.
func TestSandboxDaemonLazyPortsAndAccountBusy(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ingress, egressAddr := f.d.api.SandboxIngressAddr(), f.d.rt.egressAddr
	if f.d.listening() || !portFree(ingress) || !portFree(egressAddr) {
		t.Fatal("the daemon holds its ports before any create")
	}
	if err := f.d.ensureListeners(); err != nil {
		t.Fatal(err)
	}
	if !f.d.listening() || portFree(ingress) || portFree(egressAddr) || f.d.rt.listenersReady() != nil {
		t.Fatal("the ports are not held after ensureListeners")
	}
	f.running.Store(1)
	if stop, _ := f.d.check(context.Background()); stop || !f.d.listening() {
		t.Fatal("ports released while a sandbox runs")
	}
	f.running.Store(0)
	if stop, _ := f.d.check(context.Background()); stop || f.d.listening() {
		t.Fatal("ports kept with no sandbox running")
	}
	if !portFree(ingress) || !portFree(egressAddr) {
		t.Fatal("the ports are still bound")
	}

	squatter, err := net.Listen("tcp", ingress)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	err = f.d.ensureListeners()
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) || apiErr.Detail != SandboxAccountBusyReason || apiErr.Message != sandboxAccountBusyMessage {
		t.Fatalf("busy port: %v", err)
	}
	if strings.Contains(apiErr.Message, "uid") || f.d.listening() || !portFree(egressAddr) {
		t.Fatalf("busy refusal leaked or kept a port: %+v", apiErr)
	}
}

// An upgrade waits for the user's sandboxes to stop; then the daemon exits
// for its restart. An idle daemon exits; an open CLI connection keeps it.
func TestSandboxDaemonDeferredRestartAndIdleExit(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	if err := os.WriteFile(f.exe, []byte("v2-upgraded"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.running.Store(1)
	if stop, _ := f.d.check(ctx); stop || !f.d.pendingRestart.Load() {
		t.Fatal("the upgrade was not deferred while a sandbox runs")
	}
	if st := f.d.managedStatus(ctx); !st.PendingRestart {
		t.Fatal("status does not report the pending restart")
	}
	f.d.lifecycle <- struct{}{} // a create in progress
	f.running.Store(0)
	if stop, _ := f.d.check(ctx); stop {
		t.Fatal("restarted during a create")
	}
	f.d.unlockLifecycle()
	if stop, err := f.d.check(ctx); !stop || !errors.Is(err, ErrSandboxDaemonRestart) {
		t.Fatalf("idle with a pending restart: %v %v", stop, err)
	}

	g := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) { o.IdleAfter = time.Millisecond })
	g.run(t)
	g.d.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	g.d.conns.Add(1)
	if stop, _ := g.d.check(ctx); stop {
		t.Fatal("exited with a CLI connection open")
	}
	g.d.conns.Add(-1)
	if stop, err := g.d.check(ctx); !stop || err != nil {
		t.Fatalf("idle exit: %v %v", stop, err)
	}

	// A settings change of the OpenShell install is a restart, deferred.
	h := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) { o.Executable = "-" })
	h.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		s := h.d.currentSettings()
		s.Enterprise.Version = "0.1.4"
		s.Generation = 4
		return s, nil
	}
	h.d.refreshSettings(ctx)
	if !h.d.pendingRestart.Load() {
		t.Fatal("an OpenShell version change was applied in place")
	}
}

// GAP-0335: the daemon's availability is the gateway's live verdict, the
// one the require-sandbox gate uses: settings older than the gateway's
// availability TTL are read again by status (and create), so a fixed
// /dev/kvm or a new group shows without a policy generation change.
func TestSandboxDaemonReadsStaleAvailabilityAgain(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	ctx := context.Background()
	verdict := sandboxrelay.DaemonSettings{}
	reads := 0
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		reads++
		s := f.d.currentSettings()
		s.Available, s.Unavailable = verdict.Available, verdict.Unavailable
		return s, nil
	}
	verdict.Unavailable = sandboxUnavailableDockerAccess
	if st := f.d.managedStatus(ctx); st.Unavailable != "" || reads != 0 {
		t.Fatalf("fresh settings were read again: %+v (reads %d)", st, reads)
	}
	age := func() {
		f.d.settingsAt.Store(time.Now().Add(-sandboxAvailabilityTTL).UnixNano())
	}
	age()
	if st := f.d.managedStatus(ctx); st.Unavailable != sandboxUnavailableDockerAccess || reads != 1 {
		t.Fatalf("stale availability kept: %+v (reads %d)", st, reads)
	}
	verdict = sandboxrelay.DaemonSettings{Available: true}
	age()
	if st := f.d.managedStatus(ctx); st.Unavailable != "" {
		t.Fatalf("a fixed account still reads unavailable: %+v", st)
	}
}

// A refused run is answered with the organization's text; the daemon never
// creates anything for it, and it holds no registration.
func TestSandboxDaemonCreateRefusals(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	var got sandboxrelay.ResolveRequest
	f.relay.resolve = func(r sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
		got = r
		return sandboxrelay.ResolveResponse{V: 1, Refusal: &sandboxrelay.Refusal{
			Reason: sandboxrelay.ReasonNotAllowed, Message: "Sandboxes for claude are not allowed for you.",
		}}, nil
	}
	f.run(t)
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	overlay := []byte("workdir:\n  mode: copy\n")
	if err := os.WriteFile(filepath.Join(project, ".defenseclaw", "sandbox.yaml"), overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	client := sandboxapi.NewUnixClient(f.socket)
	_, err := client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode", Project: project, Copy: true, Yolo: true})
	if !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) || !strings.Contains(err.Error(), "not allowed for you") {
		t.Fatalf("refused create: %v", err)
	}
	if got.Connector != "claudecode" || got.Harness != "claudecode" || !got.Flags.Yolo || !got.Flags.Copy ||
		!bytes.Equal(got.RepoOverlay, overlay) || got.OpenShell.InstallMode != "setup" || got.Driver != "docker" {
		t.Fatalf("resolve request = %+v", got)
	}
	if list := f.d.regs.list(); len(list) != 0 {
		t.Fatalf("registrations after a refusal: %v", list)
	}

	// An answer without an organization floor is not applied, and its
	// registration is released.
	f.relay.resolve = func(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
		return sandboxrelay.ResolveResponse{V: 1, Registration: sandboxrelay.RegistrationView{ID: "reg-1"}, Effective: json.RawMessage(`{"profile":"open"}`)}, nil
	}
	_, err = client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "codex", Project: project})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), "could not be loaded") || f.relay.deleted.Load() != 1 {
		t.Fatalf("floorless answer: %v (deleted %d)", err, f.relay.deleted.Load())
	}
}

func TestManagedResolveFloor(t *testing.T) {
	floor, err := managedResolveFloor(sandboxrelay.ResolveResponse{Effective: json.RawMessage(
		`{"profile":"balanced","floor":{"min_profile":"balanced","allow_yolo":false,"egress_allow_only":["*.github.com"],"required_for":["claudecode"]}}`)})
	if err != nil || floor.MinProfile != "balanced" || floor.AllowYolo == nil || *floor.AllowYolo ||
		len(floor.EgressAllowOnly) != 1 || len(floor.RequiredFor) != 1 {
		t.Fatalf("floor = %+v, %v", floor, err)
	}
	for _, bad := range []string{"", `{"profile":"open"}`, `{"floor":`} {
		if _, err := managedResolveFloor(sandboxrelay.ResolveResponse{Effective: json.RawMessage(bad)}); err == nil {
			t.Fatalf("effective %q gave a floor", bad)
		}
	}
}

// The policy poll reports each registration's sandbox state: one whose
// sandbox does not run (stopped, or gone from the list) is reported stopped,
// so the gateway refuses its relayed calls (GAP-0505).
func TestSandboxDaemonPollReportsTheSandboxState(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-1=stopped"}) {
		t.Fatalf("reports = %v, want the sandbox reported stopped", got)
	}
}

func TestSandboxDaemonConfirmationReplacesUserCachedFloor(t *testing.T) {
	regs := &daemonRegistrations{path: filepath.Join(t.TempDir(), "registrations.json"),
		byName: map[string]daemonRegistration{"sandbox": {
			ID: "reg-one", Sandbox: "sandbox",
			Floor: config.OpenShellAdminConfig{MinProfile: "open"},
		}}}
	if regs.applyLive("sandbox", sandboxrelay.CurrentPolicy{V: 1}) {
		t.Fatal("an answer without a full floor confirmed a user cached floor")
	}
	if got, _ := regs.get("sandbox"); got.Confirmed {
		t.Fatal("a partial answer marked a registration confirmed")
	}
	strict := config.OpenShellAdminConfig{MinProfile: "strict"}
	if !regs.applyLive("sandbox", sandboxrelay.CurrentPolicy{V: 1, Floor: &strict}) {
		t.Fatal("a complete answer did not confirm the registration")
	}
	if got, _ := regs.get("sandbox"); !got.Confirmed || got.Floor.MinProfile != "strict" {
		t.Fatalf("confirmed floor = %+v", got)
	}
}

// GAP-0693: the policy poll never adopts the floor of a stopped sandbox's
// registration. Its live fields follow each configuration change, so the
// poll saw it changed and put the daemon, and a sandbox created since under
// a newer profile, under the stopped sandbox's required pack.
func TestSandboxDaemonPollAdoptsOnlyARunningSandboxFloor(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	stale := config.OpenShellAdminConfig{RequiredPack: "/etc/defenseclaw/policies/sandbox/contractors/pack.yaml"}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-old", Sandbox: "dc-old", Floor: stale, Digest: "sha256:old",
		UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	fresh := config.OpenShellAdminConfig{MinProfile: "balanced"}
	f.d.floorMu.Lock()
	f.d.floor = &fresh
	f.d.floorMu.Unlock()
	f.d.reloadConfig()
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:new", Floor: &config.OpenShellAdminConfig{DeleteStoppedAfter: "14d"}}, nil
	}
	f.d.pollOnce(context.Background())
	if r, _ := f.d.regs.get("dc-old"); r.Digest != "sha256:new" || r.Floor.DeleteStoppedAfter != "14d" {
		t.Fatalf("the stopped sandbox's registration did not take the live fields: %+v", r)
	}
	if admin := f.d.config().OpenShell.Admin; admin.RequiredPack != "" || admin.MinProfile != "balanced" {
		t.Fatalf("the poll adopted the stopped sandbox's floor: %+v", admin)
	}
	if floor := f.d.regs.newestFloor(func(name string) bool { return name == "dc-old" }); floor == nil || floor.DeleteStoppedAfter != "14d" || floor.RequiredPack != "" {
		t.Fatalf("a running sandbox's floor = %+v", floor)
	}
	if floor := f.d.regs.newestFloor(func(string) bool { return false }); floor != nil {
		t.Fatalf("no sandbox runs, floor = %+v", floor)
	}
}

// GAP-0488: a phase OpenShell could not confirm renews no lease; a stopped
// or vanished sandbox is reported stopped, a ready one running.
func TestSandboxStateReportSkipsUnconfirmedPhases(t *testing.T) {
	phases := map[string]string{"a": "unknown", "b": "ready", "c": "stopped"}
	for _, tc := range []struct {
		name            string
		listed          bool
		running, report bool
	}{
		{"a", true, false, false}, {"b", true, true, true}, {"c", true, false, true},
		{"gone", true, false, true}, {"b", false, false, false},
	} {
		if running, report := sandboxStateReport(phases, tc.listed, tc.name); running != tc.running || report != tc.report {
			t.Fatalf("%s listed=%v: running %v report %v, want %v %v", tc.name, tc.listed, running, report, tc.running, tc.report)
		}
	}
}

// A managed daemon is copy-only and, before any registration, resolves
// against the strictest floor.
func TestSandboxDaemonConfigIsCopyOnlyAndClosed(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	cfg := f.d.config()
	admin := cfg.OpenShell.Admin
	if admin.AllowMount == nil || *admin.AllowMount || admin.MinProfile != "strict" || admin.Allowed == nil || *admin.Allowed ||
		cfg.OpenShell.Workdir.Mode != "copy" || cfg.DataDir != f.d.opts.StateDir || !cfg.OpenShell.Enabled {
		t.Fatalf("config = %+v", cfg.OpenShell)
	}
	open := true
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Floor: config.OpenShellAdminConfig{AllowYolo: &open, AllowMount: &open},
		UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.d.adoptFloor("dc-a")
	admin = f.d.config().OpenShell.Admin
	if admin.AllowMount == nil || *admin.AllowMount || admin.AllowYolo == nil || !*admin.AllowYolo {
		t.Fatalf("adopted floor = %+v", admin)
	}
	reloaded, err := loadDaemonRegistrations(f.d.regs.path)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := reloaded.get("dc-a"); !ok || r.ID != "reg-1" || r.Confirmed {
		t.Fatalf("registrations did not persist, or came back confirmed: %+v", r)
	}
	info, _ := os.Stat(f.d.regs.path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("registrations file mode %o", info.Mode().Perm())
	}
}

// Two concurrent managed sandboxes keep their own confirmed floors. A
// missing registration cannot inherit whichever floor was adopted last.
func TestSandboxDaemonConfigForEachConfirmedSandbox(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	for _, tc := range []struct{ name, profile string }{{"dc-claude", "balanced"}, {"dc-codex", "strict"}} {
		if err := f.d.regs.put(daemonRegistration{ID: "reg-" + tc.name, Sandbox: tc.name,
			Floor: config.OpenShellAdminConfig{MinProfile: tc.profile}, Confirmed: true, UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, profile string }{{"dc-claude", "balanced"}, {"dc-codex", "strict"}} {
		cfg := f.d.configForSandbox(tc.name)
		if cfg == nil || cfg.OpenShell.Admin.MinProfile != tc.profile {
			t.Fatalf("%s floor = %+v", tc.name, cfg)
		}
	}
	closed := f.d.configForSandbox("unregistered").OpenShell.Admin
	if closed.MinProfile != "strict" || closed.Allowed == nil || *closed.Allowed {
		t.Fatalf("unregistered sandbox did not receive the closed floor: %+v", closed)
	}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-pending", Sandbox: "dc-pending",
		Floor: config.OpenShellAdminConfig{MinProfile: "open"}, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dc-pending", "dc-claude"} {
		if name == "dc-claude" {
			f.d.regs.markRevoked(name, "profile removed")
		}
		cfg := f.d.configForSandbox(name)
		if cfg.OpenShell.Admin.Allowed == nil || *cfg.OpenShell.Admin.Allowed {
			t.Fatalf("%s borrowed a floor: %+v", name, cfg.OpenShell.Admin)
		}
	}
}

// #1195 (GAP-0123): on a managed computer the supported way to run agents on
// an image of the organization's own is openshell.image.base in the
// administrator config: every run of the daemon, a new one and an existing
// sandbox resolved under its registration's floor alike, builds its agent
// image on that base in the person's own Docker engine (docker build
// --pull=false). No run takes an image of the person's choosing.
func TestSandboxDaemonRunsOnTheAdministratorsBaseImage(t *testing.T) {
	const base = "corp-sandbox-base:1"
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.Settings.Operational.Image.Base = base
	})
	if got := f.d.config().OpenShell.Image.Base; got != base {
		t.Fatalf("a new run builds on %q, want %q", got, base)
	}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dc-a", "dc-unregistered"} {
		if got := f.d.configForSandbox(name).OpenShell.Image.Base; got != base {
			t.Fatalf("sandbox %s builds on %q, want %q", name, got, base)
		}
	}
}
