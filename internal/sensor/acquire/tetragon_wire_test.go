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

package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

func intPtr(v int) *int { return &v }

// TestWireEventCarriesTheTetragonFields round-trips every new field; uid 0
// (root) must survive as a value, an unobserved auid as an absence.
func TestWireEventCarriesTheTetragonFields(t *testing.T) {
	event := plane.Event{
		Kind: plane.KindFileRead, PID: 73001, PPID: 72934, ResponsiblePID: 72934, Name: "cat",
		Cmdline: "/usr/bin/cat /home/dcr-std1/.ssh/id_ed25519", Path: "/home/dcr-std1/.ssh/id_ed25519",
		User: "dcr-std1", At: time.Unix(0, 1791336304001000000),
		Exe: "/usr/bin/cat", UID: intPtr(0), ExecID: "ZGMtZmMtcmhlbC10ZzI6MTU=", ParentExecID: "ZGMtZmMtcmhlbC10ZzI6MTM=",
		StartNS: 1791336304000000000, ContainerID: "de1ac97706c124a9b5e56b74da1e629", Source: plane.SourceTetragon,
		Policy: "defenseclaw-controls-0a1b2c3d", Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read",
		Remote: "203.0.113.10:443", Self: true, Hook: plane.HookUnexpected, HookTools: 3,
	}
	raw, err := json.Marshal(encodeEvent(event))
	if err != nil {
		t.Fatal(err)
	}
	var wire wireEvent
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	decoded := decodeEvent(wire)
	if !reflect.DeepEqual(decoded, event) {
		t.Fatalf("round trip\n got %+v\nwant %+v", decoded, event)
	}
	if decoded.UID == event.UID {
		t.Fatal("the decoded uid aliases the encoded one")
	}
	if !strings.Contains(string(raw), `"uid":0`) || strings.Contains(string(raw), `"auid"`) {
		t.Fatalf("uid 0 must be sent and an unobserved auid omitted: %s", raw)
	}

	// An event of a backend that sets none of them encodes exactly as it
	// did before the fields existed.
	old, err := json.Marshal(encodeEvent(plane.Event{Kind: plane.KindExec, PID: 9, Name: "sh"}))
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != `{"kind":"exec","pid":9,"name":"sh"}` {
		t.Fatalf("a native event grew fields on the wire: %s", old)
	}
}

func TestWireCoverageCarriesTheBackend(t *testing.T) {
	coverage := plane.Coverage{
		Mechanism: "Tetragon v1.7.1 (gRPC) + fanotify",
		Kinds:     []plane.Kind{plane.KindExec, plane.KindExit},
		Backend: &plane.Backend{
			Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "observe", Socket: "/var/run/tetragon/tetragon.sock",
			EventsLost: 12, LossKnown: true, FallbackReason: "",
			Policies: []plane.BackendPolicy{{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: "enabled"}},
		},
	}
	raw, _ := json.Marshal(encodeCoverage(coverage))
	var wire wireCoverage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if got := decodeCoverage(wire); !reflect.DeepEqual(got, coverage) {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, coverage)
	}
	if bare, _ := json.Marshal(encodeCoverage(plane.Coverage{Mechanism: "fanotify only"})); strings.Contains(string(bare), "backend") {
		t.Fatalf("a coverage with no backend sent one: %s", bare)
	}
}

// stubSource is a plane source the tests drive: events and coverage changes
// on demand.
type stubSource struct {
	events  chan plane.Event
	changes chan struct{}
	mu      sync.Mutex
	cov     plane.Coverage
	closed  sync.Once
}

func newStubSource(coverage plane.Coverage) *stubSource {
	return &stubSource{events: make(chan plane.Event, 64), changes: make(chan struct{}, 1), cov: coverage}
}

func (s *stubSource) Start(context.Context) error      { return nil }
func (s *stubSource) Events() <-chan plane.Event       { return s.events }
func (s *stubSource) CoverageChanges() <-chan struct{} { return s.changes }
func (s *stubSource) Close() error                     { s.closed.Do(func() { close(s.events) }); return nil }
func (s *stubSource) Coverage() plane.Coverage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cov
}
func (s *stubSource) setCoverage(coverage plane.Coverage) {
	s.mu.Lock()
	s.cov = coverage
	s.mu.Unlock()
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

// stubAcquirer serves a stub source; everything else is unused here.
type stubAcquirer struct{ source plane.Source }

func (a stubAcquirer) Processes(context.Context) ([]procprobe.Process, int, error) {
	return nil, 0, nil
}
func (a stubAcquirer) Connections(context.Context) ([]netprobe.Connection, int, error) {
	return nil, 0, nil
}
func (a stubAcquirer) PlaneSource([]string) plane.Source { return a.source }
func (a stubAcquirer) DNSCapturer() dnscapture.Capturer  { return nil }
func (a stubAcquirer) Describe() string                  { return "stub" }
func (a stubAcquirer) WideCoverage() bool                { return true }
func (a stubAcquirer) Brokered() bool                    { return false }
func (a stubAcquirer) Close() error                      { return nil }

func serveStub(t *testing.T, config ServerConfig, acquirer Acquirer) *Helper {
	t.Helper()
	dir, err := os.MkdirTemp("", "acq")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	server := NewServer(config)
	server.acquirer = acquirer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("helper did not stop")
		}
	})
	return NewHelper(socket)
}

func shortCoverageInterval(t *testing.T, interval time.Duration) {
	saved := coverageUpdateInterval
	coverageUpdateInterval = interval
	t.Cleanup(func() { coverageUpdateInterval = saved })
}

func native(mechanism string) plane.Coverage {
	return plane.Coverage{Mechanism: mechanism, Kinds: []plane.Kind{plane.KindExec},
		Backend: &plane.Backend{Kind: plane.BackendNative, Mode: "consume", FallbackReason: "tetragon_unavailable: the event stream ended"}}
}

func tetragonCoverage() plane.Coverage {
	return plane.Coverage{Mechanism: "Tetragon v1.7.1 (gRPC)", Kinds: []plane.Kind{plane.KindExec},
		Backend: &plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "consume"}}
}

// TestNewClientFollowsCoverageUpdates: the gateway's brokered source picks
// up a backend change without reconnecting.
func TestNewClientFollowsCoverageUpdates(t *testing.T) {
	shortCoverageInterval(t, 50*time.Millisecond)
	stub := newStubSource(tetragonCoverage())
	helper := serveStub(t, ServerConfig{}, stubAcquirer{stub})
	source := helper.PlaneSource(nil)
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if got := source.Coverage(); got.Backend == nil || got.Backend.Kind != plane.BackendTetragon ||
		got.Mechanism != "Tetragon v1.7.1 (gRPC) (via the sensor helper)" {
		t.Fatalf("header coverage %+v", got)
	}
	stub.setCoverage(native("netlink process connector (cn_proc), Tetragon unavailable"))
	deadline := time.Now().Add(5 * time.Second)
	for source.Coverage().Backend.Kind != plane.BackendNative {
		if time.Now().After(deadline) {
			t.Fatalf("coverage never updated: %+v", source.Coverage())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reason := source.Coverage().Backend.FallbackReason; !strings.HasPrefix(reason, "tetragon_unavailable") {
		t.Fatalf("fallback reason %q", reason)
	}
	// Events still flow on the same stream.
	stub.events <- plane.Event{Kind: plane.KindExec, PID: 42, Source: plane.SourceCNProc}
	select {
	case event := <-source.Events():
		if event.PID != 42 || event.Source != plane.SourceCNProc {
			t.Fatalf("event %+v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event after the coverage update")
	}
}

// TestOldClientSkipsCoverageUpdateFrames runs the drain loop of a gateway
// that predates coverage updates against a helper that sends them: it must
// see every event and nothing else.
func TestOldClientSkipsCoverageUpdateFrames(t *testing.T) {
	shortCoverageInterval(t, time.Millisecond)
	stub := newStubSource(tetragonCoverage())
	helper := serveStub(t, ServerConfig{}, stubAcquirer{stub})
	conn, err := helper.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{Version: protocolVersion, Op: OpEvents}, requestDeadline); err != nil {
		t.Fatal(err)
	}
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		t.Fatal(err)
	}
	// The pre-update gateway's frame type: an event or nothing.
	type oldFrame struct {
		Event *struct {
			Kind string `json:"kind"`
			PID  int    `json:"pid"`
		} `json:"event"`
	}
	go func() {
		for i := 1; i <= 3; i++ {
			stub.setCoverage(native("cn_proc " + string(rune('0'+i))))
			time.Sleep(20 * time.Millisecond)
			stub.events <- plane.Event{Kind: plane.KindExec, PID: i}
		}
	}()
	var pids []int
	skipped := 0
	for len(pids) < 3 {
		var response Response
		if err := readFrame(conn, &response, 5*time.Second); err != nil {
			t.Fatalf("after %v: %v", pids, err)
		}
		var frame oldFrame
		if err := json.Unmarshal(response.Body, &frame); err != nil || frame.Event == nil {
			skipped++
			continue
		}
		pids = append(pids, frame.Event.PID)
	}
	if !reflect.DeepEqual(pids, []int{1, 2, 3}) || skipped == 0 {
		t.Fatalf("pids %v, %d coverage frames skipped", pids, skipped)
	}
}

// TestCoverageUpdatesAreRateLimited: a burst of changes inside one interval
// becomes one frame, carrying the latest coverage; an unchanged coverage
// sends nothing.
func TestCoverageUpdatesAreRateLimited(t *testing.T) {
	shortCoverageInterval(t, 300*time.Millisecond)
	stub := newStubSource(tetragonCoverage())
	helper := serveStub(t, ServerConfig{}, stubAcquirer{stub})
	conn, err := helper.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = writeFrame(conn, Request{Version: protocolVersion, Op: OpEvents}, requestDeadline)
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		t.Fatal(err)
	}
	stub.setCoverage(tetragonCoverage()) // unchanged: no frame
	for i := 0; i < 5; i++ {
		stub.setCoverage(native("burst " + string(rune('a'+i))))
		time.Sleep(10 * time.Millisecond)
	}
	var frames []string
	for {
		var response Response
		if err := readFrame(conn, &response, 800*time.Millisecond); err != nil {
			break
		}
		var frame eventStreamFrame
		if err := json.Unmarshal(response.Body, &frame); err == nil && frame.Coverage != nil {
			frames = append(frames, frame.Coverage.Mechanism)
		}
	}
	if len(frames) != 1 || frames[0] != "burst e" {
		t.Fatalf("coverage frames %v, want one with the latest coverage", frames)
	}
}

func TestKernelStatusOp(t *testing.T) {
	// A helper with no reconciler answers, unavailable.
	helper := serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "consume"}}, stubAcquirer{newStubSource(native("x"))})
	status, err := helper.KernelStatus(context.Background())
	if err != nil || status.Available || status.Mode != "consume" || status.Reason == "" {
		t.Fatalf("status %+v %v", status, err)
	}

	// The reconciler's answer crosses unchanged.
	want := KernelStatus{
		Available: true, Mode: "enforce", KernelPolicy: "sha256:3f9c2a7d41b0", Applied: true,
		Tetragon: &KernelTetragon{Version: "v1.7.1", Socket: "/var/run/tetragon/tetragon.sock", PID: 8754, Connected: true},
		Policies: []KernelPolicyStatus{{Name: "defenseclaw-controls-0a1b2c3d", Family: "controls", Mode: "enforce", State: "enabled", Recorded: true}},
		Users:    []KernelUserStatus{{UID: 1001, Mode: "enforce", Ready: true, CoveredSeconds: 604800, BurnInSeconds: 604800}},
		Counters: map[string]int64{"blocked": 2}, Pause: &KernelPause{UntilUnixNano: 1, SetByUID: 0, Reason: "incident"},
		Overrides: []string{"controls"}, Warnings: []string{"kernel_enforce_paused"}, UpdatedUnixNano: 2,
	}
	helper = serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "enforce",
		KernelStatus: func(context.Context) (KernelStatus, error) { return want, nil }}}, stubAcquirer{newStubSource(native("x"))})
	got, err := helper.KernelStatus(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("status\n got %+v %v\nwant %+v", got, err, want)
	}
	helper = serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "enforce",
		KernelStatus: func(context.Context) (KernelStatus, error) { return KernelStatus{}, errors.New("state unreadable") }}},
		stubAcquirer{newStubSource(native("x"))})
	if _, err := helper.KernelStatus(context.Background()); err == nil || !strings.Contains(err.Error(), "state unreadable") {
		t.Fatalf("reconciler error: %v", err)
	}
	if !strings.Contains(helper.Describe(), "brokered via") {
		t.Fatalf("a failed status read marked the helper unreachable: %s", helper.Describe())
	}
}

// TestKernelStatusAgainstAnOlderHelper: a helper that predates the op says
// "unsupported operation"; the gateway learns that and nothing else, and
// the helper is still reachable for everything it does serve.
func TestKernelStatusAgainstAnOlderHelper(t *testing.T) {
	dir, err := os.MkdirTemp("", "acq")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var request Request
			_ = readFrame(conn, &request, requestDeadline)
			_ = writeFrame(conn, Response{Version: protocolVersion, Op: request.Op, Error: "unsupported operation"}, responseDeadline)
			_ = conn.Close()
		}
	}()
	helper := NewHelper(socket)
	if _, err := helper.KernelStatus(context.Background()); !errors.Is(err, ErrKernelStatusUnsupported) {
		t.Fatalf("older helper: %v", err)
	}
	if strings.Contains(helper.Describe(), "unreachable") {
		t.Fatalf("Describe() = %q after a status read", helper.Describe())
	}
}

// TestOperationSetIsPinned pins the closed protocol: exactly these ops are
// served, each still fieldless.
func TestOperationSetIsPinned(t *testing.T) {
	ops := []string{OpProcesses, OpConnections, OpEvents, OpDNS, OpHealth, OpKernelStatus}
	if !reflect.DeepEqual(ops, []string{"processes", "connections", "events", "dns", "health", "kernel_status"}) {
		t.Fatalf("op names %v", ops)
	}
	if got := requestFieldCount(Request{Version: protocolVersion, Op: OpKernelStatus}); got != 2 {
		t.Fatalf("Request carries %d fields", got)
	}
	if protocolVersion != 1 {
		t.Fatalf("protocolVersion %d: the Tetragon fields are additive", protocolVersion)
	}
}

// TestModeOffServesTheNativeSourceLabelled: a Tetragon-aware helper in off
// never builds the Tetragon source and says so in the coverage.
func TestModeOffServesTheNativeSourceLabelled(t *testing.T) {
	dialled := false
	stub := newStubSource(plane.Coverage{Mechanism: "netlink process connector (cn_proc) + fanotify"})
	helper := serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "off",
		Dial: func(context.Context) (plane.KernelFeed, error) { dialled = true; return nil, errors.New("never") }}},
		stubAcquirer{stub})
	source := helper.PlaneSource(nil)
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	coverage := source.Coverage()
	if dialled || coverage.Backend == nil || coverage.Backend.Kind != plane.BackendNative || coverage.Backend.Mode != "off" {
		t.Fatalf("mode off: dialled %v, coverage %+v", dialled, coverage)
	}
	// No Tetragon block at all: the coverage is exactly the source's.
	helper = serveStub(t, ServerConfig{}, stubAcquirer{newStubSource(plane.Coverage{Mechanism: "fanotify only"})})
	source = helper.PlaneSource(nil)
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if coverage := source.Coverage(); coverage.Backend != nil {
		t.Fatalf("a helper without Tetragon reported a backend: %+v", coverage)
	}
}
