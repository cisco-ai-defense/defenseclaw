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

//go:build linux

package plane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// fakeHalf stands in for a native half (cn_proc or fanotify).
type fakeHalf struct {
	events chan Event
	once   sync.Once
	closed chan struct{}
}

func newFakeHalf() *fakeHalf {
	return &fakeHalf{events: make(chan Event, 64), closed: make(chan struct{})}
}

func (h *fakeHalf) Events() <-chan Event { return h.events }
func (h *fakeHalf) Close() error {
	h.once.Do(func() { close(h.closed); close(h.events) })
	return nil
}
func (h *fakeHalf) isClosed() bool {
	select {
	case <-h.closed:
		return true
	default:
		return false
	}
}

// fakeFeed stands in for a Tetragon session.
type fakeFeed struct {
	batches chan KernelBatch
	mu      sync.Mutex
	backend Backend
	err     error
	once    sync.Once
	done    chan struct{}
}

func newFakeFeed(backend Backend) *fakeFeed {
	return &fakeFeed{batches: make(chan KernelBatch, 64), backend: backend, done: make(chan struct{})}
}

func (f *fakeFeed) Recv() (KernelBatch, error) {
	select {
	case batch, ok := <-f.batches:
		if !ok {
			return KernelBatch{}, errors.New("stream ended")
		}
		return batch, nil
	case <-f.done:
		return KernelBatch{}, errors.New("closed")
	}
}
func (f *fakeFeed) Backend() Backend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.backend
}
func (f *fakeFeed) setPolicies(policies ...BackendPolicy) {
	f.mu.Lock()
	f.backend.Policies = policies
	f.mu.Unlock()
}
func (f *fakeFeed) Close() error { f.once.Do(func() { close(f.done) }); return nil }

// harness swaps the native halves and the clocks for the test's.
type harness struct {
	t       *testing.T
	mu      sync.Mutex
	procs   []*fakeHalf
	files   []*fakeHalf
	procErr error
	feeds   chan KernelFeed
	dialErr error
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, feeds: make(chan KernelFeed, 8)}
	saved := []any{startProcessHalf, startFileHalf, handoffWindow, handoffInterval, duplicateWindow, superviseTick, redialInitial, redialMax}
	startProcessHalf = func(context.Context) (nativeHalf, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.procErr != nil {
			return nil, h.procErr
		}
		half := newFakeHalf()
		h.procs = append(h.procs, half)
		return half, nil
	}
	startFileHalf = func(context.Context, []string) (nativeHalf, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		half := newFakeHalf()
		h.files = append(h.files, half)
		return half, nil
	}
	handoffWindow, handoffInterval = 150*time.Millisecond, 20*time.Millisecond
	duplicateWindow, superviseTick = 100*time.Millisecond, 10*time.Millisecond
	redialInitial, redialMax = 20*time.Millisecond, 40*time.Millisecond
	t.Cleanup(func() {
		startProcessHalf = saved[0].(func(context.Context) (nativeHalf, error))
		startFileHalf = saved[1].(func(context.Context, []string) (nativeHalf, error))
		handoffWindow, handoffInterval = saved[2].(time.Duration), saved[3].(time.Duration)
		duplicateWindow, superviseTick = saved[4].(time.Duration), saved[5].(time.Duration)
		redialInitial, redialMax = saved[6].(time.Duration), saved[7].(time.Duration)
	})
	return h
}

// dial hands out queued feeds, or fails with dialErr when none is queued.
func (h *harness) dial(context.Context) (KernelFeed, error) {
	select {
	case feed := <-h.feeds:
		return feed, nil
	default:
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dialErr != nil {
		return nil, h.dialErr
	}
	return nil, errors.New("tetragon_unavailable: no /var/run/tetragon/tetragon-info.json")
}

func (h *harness) lastProc() *fakeHalf {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.procs) == 0 {
		return nil
	}
	return h.procs[len(h.procs)-1]
}

func (h *harness) lastFiles() *fakeHalf {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.files) == 0 {
		return nil
	}
	return h.files[len(h.files)-1]
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func next(t *testing.T, source Source) Event {
	t.Helper()
	select {
	case event, ok := <-source.Events():
		if !ok {
			t.Fatal("the source closed")
		}
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func startSource(t *testing.T, h *harness, homes []string, observe func(string) bool) *tetragonSource {
	t.Helper()
	source := NewTetragonSource(homes, TetragonOptions{Mode: "observe", Dial: h.dial, OwnObservePolicy: observe}).(*tetragonSource)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = source.Close() })
	if err := source.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return source
}

func TestTetragonSourceFallsBackInStreamAndRecovers(t *testing.T) {
	h := newHarness(t)
	source := startSource(t, h, nil, nil)

	// No Tetragon: cn_proc runs, the coverage says why.
	coverage := source.Coverage()
	if coverage.Backend == nil || coverage.Backend.Kind != BackendNative ||
		!strings.HasPrefix(coverage.Backend.FallbackReason, "tetragon_unavailable: ") ||
		!strings.Contains(coverage.Mechanism, "cn_proc") || h.lastProc() == nil {
		t.Fatalf("fallback coverage %+v", coverage)
	}
	h.lastProc().events <- Event{Kind: KindExec, PID: 42, Name: "curl", Cmdline: "curl --token=dccertvalue https://example.invalid"}
	event := next(t, source)
	if event.Source != SourceCNProc || strings.Contains(event.Cmdline, "dccertvalue") {
		t.Fatalf("native event %+v", event)
	}
	h.lastProc().events <- Event{Kind: KindExec, PID: 78, Name: "bash",
		Cmdline: `bash -c "--token=dccert-first dccert-second"`}
	if event := next(t, source); strings.Contains(event.Cmdline, "dccert-first") || strings.Contains(event.Cmdline, "dccert-second") {
		t.Fatalf("native fallback leaked a quoted secret: %q", event.Cmdline)
	}
	// A Codex notify program's turn payload is withheld on the fallback too.
	h.lastProc().events <- Event{Kind: KindExec, PID: 77, Name: "bash",
		Cmdline: `/usr/bin/bash /home/u/.defenseclaw/notify-bridge.sh {"input-messages":["dccert-block-marker"]}`}
	if event := next(t, source); event.Cmdline != "/usr/bin/bash /home/u/.defenseclaw/notify-bridge.sh "+redaction.WithheldArgv {
		t.Fatalf("notify argv on the fallback %q", event.Cmdline)
	}

	// Tetragon comes up: the source switches without a reconnect, cn_proc
	// stops, the subscriber is told to read the coverage again.
	first := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1", Socket: "/var/run/tetragon/tetragon.sock"})
	h.feeds <- first
	waitFor(t, "the switch to Tetragon", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	select {
	case <-source.CoverageChanges():
	case <-time.After(time.Second):
		t.Fatal("no coverage change for the switch")
	}
	waitFor(t, "cn_proc to stop", func() bool { return h.lastProc().isClosed() })
	coverage = source.Coverage()
	if !strings.HasPrefix(coverage.Mechanism, "Tetragon v1.7.1 (gRPC)") || coverage.Backend.FallbackReason != "" ||
		coverage.Backend.Mode != "observe" {
		t.Fatalf("tetragon coverage %+v", coverage)
	}

	// The exec cn_proc just delivered is not delivered twice.
	first.batches <- KernelBatch{Events: []Event{{Kind: KindExec, PID: 42, Source: SourceTetragon}, {Kind: KindExec, PID: 43, Source: SourceTetragon}}}
	if event := next(t, source); event.PID != 43 {
		t.Fatalf("got pid %d, want the duplicate of 42 dropped", event.PID)
	}

	// Loss signals count.
	first.batches <- KernelBatch{Dropped: 5}
	first.batches <- KernelBatch{ThrottleStart: true}
	waitFor(t, "the drops in the coverage", func() bool { return source.Coverage().Backend.EventsLost == 5 })

	// The stream ends: back to cn_proc inside the same stream.
	close(first.batches)
	waitFor(t, "the fallback", func() bool { return source.Coverage().Backend.Kind == BackendNative })
	if !strings.Contains(source.Coverage().Backend.FallbackReason, "the event stream ended") || h.lastProc().isClosed() {
		t.Fatalf("after the stream ended: %+v", source.Coverage())
	}
	h.lastProc().events <- Event{Kind: KindExec, PID: 50, Name: "cat"}
	if event := next(t, source); event.PID != 50 || event.Source != SourceCNProc {
		t.Fatalf("native event after the fallback %+v", event)
	}

	// And back again.
	second := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
	h.feeds <- second
	waitFor(t, "the second switch", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	second.batches <- KernelBatch{Events: []Event{{Kind: KindExit, PID: 50, Source: SourceTetragon}}}
	if event := next(t, source); event.Kind != KindExit || event.Source != SourceTetragon {
		t.Fatalf("tetragon event after recovery %+v", event)
	}
	if lost := source.Coverage().Backend.EventsLost; lost != 5 {
		t.Fatalf("events lost %d across sessions, want 5", lost)
	}
}

func TestTetragonSourceRefusesToStartBlind(t *testing.T) {
	h := newHarness(t)
	h.procErr = errors.New("bind: operation not permitted")
	source := NewTetragonSource(nil, TetragonOptions{Mode: "consume", Dial: h.dial})
	err := source.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "tetragon_unavailable") || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("start with nothing to deliver: %v", err)
	}
	if err := NewTetragonSource(nil, TetragonOptions{Mode: "consume"}).Start(context.Background()); err == nil {
		t.Fatal("a source with no dialer started")
	}
}

func TestTetragonSourceHandsTheFileHalfOverAndTakesItBack(t *testing.T) {
	h := newHarness(t)
	observe := func(name string) bool { return name == "defenseclaw-observe-89abcdef" }
	feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
	h.feeds <- feed
	source := startSource(t, h, []string{"/home/dcr-std1"}, observe)
	files := h.lastFiles()
	if files == nil || !strings.HasSuffix(source.Coverage().Mechanism, " + fanotify") {
		t.Fatalf("fanotify did not start: %+v", source.Coverage())
	}

	// A customer policy with a look-alike name never hands anything over.
	feed.setPolicies(BackendPolicy{Name: "defenseclaw-observe-00000000", State: "enabled"})
	feed.batches <- KernelBatch{Events: []Event{{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.aws/credentials", Policy: "defenseclaw-observe-00000000"}}}
	next(t, source)
	time.Sleep(3 * handoffWindow)
	if files.isClosed() {
		t.Fatal("fanotify stopped for a policy DefenseClaw did not record")
	}

	// DefenseClaw's observe policy, enabled and delivering with no loss for
	// the window: fanotify stops.
	feed.setPolicies(BackendPolicy{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: "enabled"})
	time.Sleep(2 * handoffInterval)
	feed.batches <- KernelBatch{Events: []Event{{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.aws/config", Policy: "defenseclaw-observe-89abcdef"}}}
	next(t, source)
	waitFor(t, "the hand-off", func() bool { return files.isClosed() })
	if mechanism := source.Coverage().Mechanism; !strings.Contains(mechanism, "observe policy") || strings.Contains(mechanism, "fanotify") {
		t.Fatalf("after the hand-off: %q", mechanism)
	}

	// A loss signal brings fanotify straight back.
	feed.batches <- KernelBatch{ThrottleStart: true}
	waitFor(t, "fanotify to restart", func() bool { return h.lastFiles() != files && !h.lastFiles().isClosed() })
	if !strings.HasSuffix(source.Coverage().Mechanism, " + fanotify") {
		t.Fatalf("after the loss: %q", source.Coverage().Mechanism)
	}
}

func TestTetragonSourcePrefersTheTetragonFileEvent(t *testing.T) {
	h := newHarness(t)
	feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1",
		Policies: []BackendPolicy{{Name: "defenseclaw-observe-89abcdef", State: "enabled"}}})
	h.feeds <- feed
	handoffWindow = time.Hour // keep fanotify running
	source := startSource(t, h, []string{"/home/dcr-std1"}, func(name string) bool { return name == "defenseclaw-observe-89abcdef" })
	waitFor(t, "the observe policy", source.holdingFiles)

	now := time.Now()
	files := h.lastFiles()
	files.events <- Event{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.aws/credentials", At: now}
	files.events <- Event{Kind: KindFileRead, PID: 8, Path: "/home/dcr-std1/.kube/config", At: now}
	feed.batches <- KernelBatch{Events: []Event{{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.aws/credentials",
		Policy: "defenseclaw-observe-89abcdef", Source: SourceTetragon, At: now}}}

	got := map[EventSource][]int{}
	for i := 0; i < 2; i++ {
		event := next(t, source)
		got[event.Source] = append(got[event.Source], event.PID)
	}
	select {
	case event := <-source.Events():
		t.Fatalf("a duplicate was delivered: %+v", event)
	case <-time.After(3 * duplicateWindow):
	}
	if len(got[SourceTetragon]) != 1 || got[SourceTetragon][0] != 7 || len(got[SourceFanotify]) != 1 || got[SourceFanotify][0] != 8 {
		t.Fatalf("delivered %v: want Tetragon's pid 7 and fanotify's pid 8 only", got)
	}
}

// TestTetragonSourceTapsTheStreamForTheReconciler: the reconciler sees every
// Tetragon batch (its hit and loss tally) and the stream going up and down.
func TestTetragonSourceTapsTheStreamForTheReconciler(t *testing.T) {
	h := newHarness(t)
	feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1", PID: 4242})
	h.feeds <- feed
	var mu sync.Mutex
	var tapped []KernelBatch
	var stream []StreamState
	source := NewTetragonSource(nil, TetragonOptions{Mode: "enforce", Dial: h.dial,
		Tap:    func(batch KernelBatch) { mu.Lock(); tapped = append(tapped, batch); mu.Unlock() },
		Stream: func(state StreamState) { mu.Lock(); stream = append(stream, state); mu.Unlock() },
	})
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	hit := Event{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.ssh/id_ed25519", Policy: "defenseclaw-controls-0a1b2c3d",
		Outcome: OutcomeBlocked, Control: "kernel.ssh_private_key_read"}
	feed.batches <- KernelBatch{Events: []Event{hit}}
	feed.batches <- KernelBatch{ThrottleStart: true}
	next(t, source)
	close(feed.batches)
	waitFor(t, "the stream to end", func() bool { mu.Lock(); defer mu.Unlock(); return len(stream) == 2 })
	_ = source.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(tapped) != 2 || tapped[0].Events[0].Policy != hit.Policy || !tapped[1].ThrottleStart {
		t.Fatalf("tapped %+v", tapped)
	}
	if !stream[0].Connected || stream[0].Version != "v1.7.1" || stream[0].PID != 4242 {
		t.Fatalf("stream up %+v", stream[0])
	}
	if stream[1].Connected || !strings.HasPrefix(stream[1].Reason, "tetragon_unavailable: the event stream ended") {
		t.Fatalf("stream down %+v", stream[1])
	}
}
