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

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestSandboxConfigPersister(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Gateway.Token = "test-token"
	cfg.Guardrail.Mode, cfg.Guardrail.ScannerMode = "observe", "local"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	bindTestConfigRuntime(t, api)
	p := sandboxConfigPersister{api: api}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := p.AllowAlways(ctx, "registry.example.org"); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.AllowAlways(ctx, "docs.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := p.BlockAlways(ctx, "paste.example.net"); err != nil {
		t.Fatal(err)
	}
	live := api.runtimeConfigSnapshot()
	// Always decisions are unblocks: they never become allow entries,
	// which would open the private addresses the names resolve to.
	if !slices.Equal(live.OpenShell.Egress.Unblocked, []string{"registry.example.org", "docs.example.org"}) ||
		len(live.OpenShell.Egress.Allow) != 0 || !slices.Equal(live.OpenShell.Egress.Block, []string{"paste.example.net"}) {
		t.Fatalf("persisted unblocked %v allow %v block %v", live.OpenShell.Egress.Unblocked, live.OpenShell.Egress.Allow, live.OpenShell.Egress.Block)
	}
	raw, err := os.ReadFile(configFilePathForSnapshot(live))
	if err != nil || !strings.Contains(string(raw), "registry.example.org") {
		t.Fatalf("config file = %s, %v", raw, err)
	}

	// An invalid entry is refused and the file restored.
	before, _ := os.ReadFile(configFilePathForSnapshot(live))
	if err := p.AllowAlways(ctx, "bad host name!"); err == nil {
		t.Fatal("invalid host persisted")
	}
	after, _ := os.ReadFile(configFilePathForSnapshot(live))
	if string(before) != string(after) {
		t.Fatal("config not restored after a refused patch")
	}
}

func TestSandboxConfigPersisterRefusals(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	if err := (sandboxConfigPersister{api: api}).AllowAlways(context.Background(), "a.example"); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("without a config runtime: %v", err)
	}
	api.SetConfigRuntime(func(context.Context, string) error { return nil }, func() *config.Config {
		return &config.Config{DeploymentMode: "managed_enterprise"}
	})
	if err := (sandboxConfigPersister{api: api}).AllowAlways(context.Background(), "a.example"); !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
		t.Fatalf("managed_enterprise: %v", err)
	}
}

func TestNewSandboxRuntimeDisabled(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	sc := &Sidecar{health: NewSidecarHealth(), logger: logger}
	sc.cfgCurrent.Store(cfg)
	api := NewAPIServer("127.0.0.1:0", sc.health, nil, store, logger, cfg)
	rt, err := sc.newSandboxRuntime(api)
	if err != nil || rt != nil {
		t.Fatalf("disabled runtime = %v, %v", rt, err)
	}
	if api.SandboxIngressAddr() != "" {
		t.Fatal("ingress configured while disabled")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// sandboxRuntimeFixture is the sandbox subsystem on free ports with no
// OpenShell gateway to reach; squatter, if set, is another program holding
// the egress port.
type sandboxRuntimeFixture struct {
	sc       *Sidecar
	api      *APIServer
	rt       *sandboxRuntime
	cfg      *config.Config
	squatter net.Listener
}

func newSandboxRuntimeFixture(t *testing.T, squat bool) *sandboxRuntimeFixture {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("sandboxes run on Linux and macOS only")
	}
	store, logger := testStoreAndLogger(t)
	f := &sandboxRuntimeFixture{cfg: &config.Config{DataDir: t.TempDir()}}
	f.cfg.Gateway.Token = "test-token"
	f.cfg.Gateway.APIPort = freePort(t)
	f.cfg.OpenShell.Enabled = true
	f.cfg.OpenShell.IngressPort = freePort(t)
	f.cfg.OpenShell.EgressPort = freePort(t)
	f.cfg.OpenShell.Gateway.Name = "defenseclaw-test-missing"
	if squat {
		var err error
		if f.squatter, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.squatter.Close() })
		f.cfg.OpenShell.EgressPort = f.squatter.Addr().(*net.TCPAddr).Port
	}
	f.sc = &Sidecar{health: NewSidecarHealth(), logger: logger}
	f.sc.cfgCurrent.Store(f.cfg)
	f.api = NewAPIServer("127.0.0.1:0", f.sc.health, nil, store, logger, f.cfg)
	rt, err := f.sc.newSandboxRuntime(f.api)
	if err != nil || rt == nil {
		t.Fatalf("runtime = %v, %v", rt, err)
	}
	f.rt = rt
	return f
}

// run runs the subsystem until the test ends, with serveAPI standing in
// for the API it serves with (nil: one that never reports running).
func (f *sandboxRuntimeFixture) run(t *testing.T, serveAPI func(context.Context) error) {
	if serveAPI == nil {
		serveAPI = func(ctx context.Context) error { <-ctx.Done(); return nil }
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.rt.run(ctx, serveAPI) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && f.squatter == nil {
			t.Errorf("run: %v", err)
		}
	})
}

// TestSandboxRuntimeServesListeners runs the sandbox subsystem without an
// OpenShell gateway: the ingress and the egress proxy still come up (hooks
// fail closed, egress needs a credential), and the API reports the
// subsystem as unavailable.
func TestSandboxRuntimeServesListeners(t *testing.T) {
	f := newSandboxRuntimeFixture(t, false)
	f.run(t, nil)
	ingress := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(f.cfg.OpenShell.IngressPort))
	eventuallyTrue(t, func() bool {
		resp, err := http.Post(ingress+"/api/v1/claude-code/hook", "application/json", strings.NewReader("{}"))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusUnauthorized
	})
	egressAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.cfg.OpenShell.EgressPort))
	eventuallyTrue(t, func() bool {
		conn, err := net.DialTimeout("tcp", egressAddr, time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
		line, _ := bufio.NewReader(conn).ReadString('\n')
		return strings.Contains(line, "407")
	})
	h := f.api.tokenAuth(f.api.apiCSRFProtect(f.api.sandboxAPIHandler()))
	w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathStatus, ""))
	var st sandboxapi.Status
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if w.Code != 200 || !st.Enabled || st.Available || st.Reason == "" {
		t.Fatalf("status = %d %+v", w.Code, st)
	}
	// The listeners run; the missing OpenShell gateway degrades the
	// subsystem and says why.
	eventuallyTrue(t, func() bool {
		snap := f.sc.health.Snapshot()
		return snap.Sandbox != nil && snap.Sandbox.State == StateDegraded && strings.Contains(snap.Sandbox.LastError, "openshell:")
	})
}

// TestSandboxRuntimeRefusesSandboxesWithoutItsListeners pins that no
// sandbox is created while another program holds a sandbox listener port:
// OpenShell would relay the sandbox's hooks (with its real ingress token)
// or egress to that program.
func TestSandboxRuntimeRefusesSandboxesWithoutItsListeners(t *testing.T) {
	f := newSandboxRuntimeFixture(t, true)
	rt := f.rt
	f.run(t, nil)
	eventuallyTrue(t, func() bool {
		rt.listenMu.Lock()
		defer rt.listenMu.Unlock()
		return rt.listening["ingress"]
	})
	if err := rt.listenersReady(); err == nil || !strings.Contains(err.Error(), "egress") {
		t.Fatalf("listeners ready while another program holds the egress port: %v", err)
	}
	_, err := rt.manager.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode", Project: t.TempDir()})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), "listeners") {
		t.Fatalf("create while the egress port is someone else's = %v", err)
	}
	// Once the port is free the proxy takes it, and creates are allowed
	// past this check again.
	_ = f.squatter.Close()
	eventuallyTrue(t, func() bool { return rt.listenersReady() == nil })
}

// fakeSandboxFleet is a sandboxFleet over fixed phases. Stop stops a
// sandbox unless failStops still counts failures for it.
type fakeSandboxFleet struct {
	mu        sync.Mutex
	phases    map[string]string
	failStops map[string]int
	stopped   []string
	listErr   error
}

func (f *fakeSandboxFleet) List(context.Context) ([]sandboxapi.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]sandboxapi.Sandbox, 0, len(f.phases))
	for name, phase := range f.phases {
		out = append(out, sandboxapi.Sandbox{Name: name, Phase: phase})
	}
	slices.SortFunc(out, func(a, b sandboxapi.Sandbox) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *fakeSandboxFleet) Stop(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStops[name] > 0 {
		f.failStops[name]--
		return nil, errors.New("openshell unavailable")
	}
	f.phases[name] = "stopped"
	f.stopped = append(f.stopped, name)
	return &sandboxapi.Sandbox{Name: name, Phase: "stopped"}, nil
}

func (f *fakeSandboxFleet) stops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.stopped)
}

// syncRecorder is a concurrency-safe list of what a fake was handed.
type syncRecorder[T any] struct {
	mu    sync.Mutex
	items []T
}

func (r *syncRecorder[T]) add(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, v)
}

func (r *syncRecorder[T]) snapshot() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.items)
}

type sandboxHealthRecords struct {
	syncRecorder[audit.SandboxHealthEvent]
}

func (r *sandboxHealthRecords) RecordSandboxHealth(_ context.Context, ev audit.SandboxHealthEvent) error {
	r.add(ev)
	return nil
}

// runContainment runs containListenerLoss until the test ends or the
// returned stop is called.
func runContainment(t *testing.T, fleet *fakeSandboxFleet, publish func(sandboxapi.ActivityEvent), part string,
	every time.Duration, serving func() bool) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		containListenerLoss(ctx, fleet, publish, part, every, serving)
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("containment did not end with its context")
		}
	}
	t.Cleanup(stop)
	return stop
}

// TestContainListenerLossStopsRunningSandboxes pins that while a sandbox
// listener is not held every sandbox that may be running is stopped (a
// sandbox that comes up later on the next pass), that each stop is on the
// activity feed, and that a sandbox that does not stop is reported once and
// tried again.
func TestContainListenerLossStopsRunningSandboxes(t *testing.T) {
	fleet := &fakeSandboxFleet{
		phases: map[string]string{
			"dc-ready": "ready", "dc-starting": "starting", "dc-provisioning": "provisioning", "dc-unknown": "unknown",
			"dc-stopped": "stopped", "dc-missing": "missing", "dc-deleted": "deleted", "dc-error": "error",
			"dc-stubborn": "ready",
		},
		failStops: map[string]int{"dc-stubborn": 3},
	}
	var feed syncRecorder[sandboxapi.ActivityEvent]
	stop := runContainment(t, fleet, feed.add, "ingress", 5*time.Millisecond, nil)
	eventuallyTrue(t, func() bool { return len(fleet.stops()) == 5 })
	// A sandbox adopted after the loss, or started outside DefenseClaw.
	fleet.mu.Lock()
	fleet.phases["dc-late"] = "ready"
	fleet.mu.Unlock()
	eventuallyTrue(t, func() bool { return len(fleet.stops()) == 6 })
	stop()

	got := fleet.stops()
	slices.Sort(got)
	want := []string{"dc-late", "dc-provisioning", "dc-ready", "dc-starting", "dc-stubborn", "dc-unknown"}
	if !slices.Equal(got, want) {
		t.Fatalf("stopped = %v, want %v", got, want)
	}
	stoppedMsgs, failures := map[string]int{}, map[string]int{}
	for _, ev := range feed.snapshot() {
		if ev.Kind != sandboxapi.ActivityFinding || ev.Severity != "CRITICAL" || ev.Reason != sandboxListenerLostReason ||
			!strings.Contains(ev.Message, "sandbox ingress port") {
			t.Fatalf("feed event = %+v", ev)
		}
		if strings.Contains(ev.Message, "stop it yourself") {
			failures[ev.Sandbox]++
		} else {
			stoppedMsgs[ev.Sandbox]++
		}
	}
	if len(failures) != 1 || failures["dc-stubborn"] != 1 {
		t.Fatalf("failed stops reported = %v, want dc-stubborn once", failures)
	}
	for _, name := range want {
		if stoppedMsgs[name] != 1 {
			t.Fatalf("stops reported = %v", stoppedMsgs)
		}
	}
}

// TestContainListenerLossEndsWithItsContext pins that containment returns
// once the runtime stops, even while the manager cannot list sandboxes.
func TestContainListenerLossEndsWithItsContext(t *testing.T) {
	fleet := &fakeSandboxFleet{phases: map[string]string{"dc-ready": "ready"}, listErr: errors.New("not reconciled yet")}
	runContainment(t, fleet, nil, "egress", time.Hour, nil)()
	if got := fleet.stops(); len(got) != 0 {
		t.Fatalf("stopped = %v", got)
	}
}

// TestContainListenerLossWaitsForItsAPI pins that nothing is stopped while
// this process does not serve its API: a second daemon started by mistake
// finds the running daemon's ports taken and must leave that daemon's
// sandboxes alone. Once the API serves, the sandboxes are stopped.
func TestContainListenerLossWaitsForItsAPI(t *testing.T) {
	fleet := &fakeSandboxFleet{phases: map[string]string{"dc-ready": "ready"}}
	var serving atomic.Bool
	var passes atomic.Int32
	runContainment(t, fleet, nil, "ingress", 5*time.Millisecond, func() bool {
		passes.Add(1)
		return serving.Load()
	})
	eventuallyTrue(t, func() bool { return passes.Load() >= 3 })
	if got := fleet.stops(); len(got) != 0 {
		t.Fatalf("stopped while another daemon may serve: %v", got)
	}
	serving.Store(true)
	eventuallyTrue(t, func() bool { return slices.Equal(fleet.stops(), []string{"dc-ready"}) })
}

// TestSandboxRuntimeStopsSandboxesWhenAListenerIsLost pins that when
// another program holds a sandbox listener port past the bind budget, the
// running sandboxes are stopped (OpenShell would relay their egress, or
// their hooks with the real ingress token, to that program), the subsystem
// reports why, and a durable health record says the listener failed.
func TestSandboxRuntimeStopsSandboxesWhenAListenerIsLost(t *testing.T) {
	f := newSandboxRuntimeFixture(t, true)
	rt := f.rt
	if rt.fleet == nil || rt.publish == nil || rt.tel == nil {
		t.Fatal("the runtime cannot contain a lost listener")
	}
	fleet := &fakeSandboxFleet{phases: map[string]string{"dc-claude-app": "ready", "dc-old": "stopped"}}
	var feed syncRecorder[sandboxapi.ActivityEvent]
	var records sandboxHealthRecords
	rt.fleet, rt.publish, rt.tel = fleet, feed.add, &records
	rt.listenBudget, rt.recheck = 50*time.Millisecond, 10*time.Millisecond
	// The API this runtime serves with, as api.Run reports it once bound.
	f.run(t, func(ctx context.Context) error {
		f.sc.health.SetAPI(StateRunning, "", nil)
		<-ctx.Done()
		return nil
	})
	eventuallyTrue(t, func() bool { return slices.Equal(fleet.stops(), []string{"dc-claude-app"}) })
	eventuallyTrue(t, func() bool {
		snap := f.sc.health.Snapshot()
		return snap.Sandbox != nil && snap.Sandbox.State == StateDegraded &&
			strings.Contains(snap.Sandbox.LastError, "egress:") &&
			strings.Contains(snap.Sandbox.LastError, "running sandboxes are stopped")
	})
	health := records.snapshot()
	if len(health) != 1 || health[0].State != audit.SandboxHealthFailed || health[0].ErrorCode != "openshell_listener_failed" ||
		!strings.Contains(health[0].ErrorSummary, "egress listener") {
		t.Fatalf("health records = %+v", health)
	}
	if events := feed.snapshot(); len(events) != 1 || events[0].Sandbox != "dc-claude-app" || events[0].Severity != "CRITICAL" {
		t.Fatalf("feed = %+v", events)
	}
}
