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
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// fakeHalf stands in for a native half (cn_proc or fanotify).
type fakeHalf struct {
	events chan Event
	once   sync.Once
	closed chan struct{}
	// dropped stands in for the half's buffer drops (GAP-0071), overflows
	// for a process half's ENOBUFS overflows (cowork-1-0-8 GAP-0080).
	dropped, overflows atomic.Int64
	// onClose runs inside Close, before the half reports itself closed:
	// what a stopping half counts while its reader stops.
	hookMu  sync.Mutex
	onClose func()
}

func (h *fakeHalf) setOnClose(hook func()) {
	h.hookMu.Lock()
	h.onClose = hook
	h.hookMu.Unlock()
}

func (h *fakeHalf) bufferDropped() int64   { return h.dropped.Load() }
func (h *fakeHalf) kernelOverflows() int64 { return h.overflows.Load() }

func newFakeHalf() *fakeHalf {
	return &fakeHalf{events: make(chan Event, 64), closed: make(chan struct{})}
}

func (h *fakeHalf) Events() <-chan Event { return h.events }
func (h *fakeHalf) Close() error {
	h.once.Do(func() {
		h.hookMu.Lock()
		hook := h.onClose
		h.hookMu.Unlock()
		if hook != nil {
			hook()
		}
		close(h.closed)
		close(h.events)
	})
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
	// The cn_proc half dropped 3 events; the coverage keeps naming them once
	// it stops (S1 review 4 F5, GAP-0071).
	h.lastProc().dropped.Store(3)
	// It also overflowed twice: Tetragon's coverage named none of them
	// (cowork-1-0-8 GAP-0080).
	h.lastProc().overflows.Store(2)
	h.feeds <- first
	waitFor(t, "the switch to Tetragon", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	if limits := strings.Join(source.Coverage().Limitations, "; "); !strings.Contains(limits, "3 events were dropped from the sensor's event buffer") {
		t.Fatalf("after the switch: limitations %q, want the stopped cn_proc half's drops", limits)
	}
	if coverage := source.Coverage(); coverage.KernelOverflows != 2 || !strings.Contains(strings.Join(coverage.Limitations, "; "),
		"process events were lost 2 times when the netlink receive buffer overflowed (ENOBUFS)") {
		t.Fatalf("after the switch: overflows %d, limitations %q; want the stopped cn_proc half's 2",
			coverage.KernelOverflows, coverage.Limitations)
	}
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
	h.lastProc().overflows.Store(1)
	if got := source.Coverage().KernelOverflows; got != 3 {
		t.Fatalf("overflows of the running and the stopped cn_proc halves = %d, want 3", got)
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
	if got := source.Coverage().KernelOverflows; got != 3 {
		t.Fatalf("overflows after the second switch = %d, want both stopped halves' 3", got)
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
	// the window: fanotify stops, and its 5 buffer drops stay named
	// (S1 review 4 F5, GAP-0071).
	files.dropped.Store(5)
	const fileDrops = "5 events were dropped from the sensor's event buffer"
	feed.setPolicies(BackendPolicy{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: "enabled"})
	time.Sleep(2 * handoffInterval)
	feed.batches <- KernelBatch{Events: []Event{{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.aws/config", Policy: "defenseclaw-observe-89abcdef"}}}
	next(t, source)
	waitFor(t, "the hand-off", func() bool { return files.isClosed() })
	if mechanism := source.Coverage().Mechanism; !strings.Contains(mechanism, "observe policy") || strings.Contains(mechanism, "fanotify") {
		t.Fatalf("after the hand-off: %q", mechanism)
	}
	if limits := strings.Join(source.Coverage().Limitations, "; "); !strings.Contains(limits, fileDrops) {
		t.Fatalf("after the hand-off: limitations %q, want the stopped fanotify half's drops", limits)
	}

	// A loss signal brings fanotify straight back.
	feed.batches <- KernelBatch{ThrottleStart: true}
	waitFor(t, "fanotify to restart", func() bool { return h.lastFiles() != files && !h.lastFiles().isClosed() })
	if !strings.HasSuffix(source.Coverage().Mechanism, " + fanotify") {
		t.Fatalf("after the loss: %q", source.Coverage().Mechanism)
	}
	if limits := strings.Join(source.Coverage().Limitations, "; "); !strings.Contains(limits, fileDrops) {
		t.Fatalf("after fanotify restarted: limitations %q, want the first half's drops", limits)
	}
}

// cowork-1-0-8 GAP-0073: a feed end and a take-back can both start the file
// half at once. Only one starts and runs; a start while one is starting does
// nothing; a half whose start ends after Close is closed.
func TestTetragonSourceRunsAtMostOneFileHalf(t *testing.T) {
	saved := startFileHalf
	t.Cleanup(func() { startFileHalf = saved })
	entered, release := make(chan struct{}, 4), make(chan struct{})
	var mu sync.Mutex
	var started []*fakeHalf
	startFileHalf = func(context.Context, []string) (nativeHalf, error) {
		entered <- struct{}{}
		<-release
		half := newFakeHalf()
		mu.Lock()
		started = append(started, half)
		mu.Unlock()
		return half, nil
	}

	source := NewTetragonSource([]string{"/home/dcr-std1"}, TetragonOptions{Mode: "consume"}).(*tetragonSource)
	done := make(chan struct{})
	go func() { source.startFiles(context.Background()); close(done) }()
	<-entered // the first start is inside startFileHalf, outside s.mu
	var others sync.WaitGroup
	for range 2 {
		others.Add(1)
		go func() { defer others.Done(); source.startFiles(context.Background()) }()
	}
	returned := make(chan struct{})
	go func() { others.Wait(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(200 * time.Millisecond): // they started halves of their own
	}
	close(release)
	<-done
	others.Wait()
	source.startFiles(context.Background()) // one runs: nothing to start
	mu.Lock()
	count := len(started)
	mu.Unlock()
	source.mu.Lock()
	running := source.files
	source.mu.Unlock()
	if count != 1 || running != nativeHalf(started[0]) || started[0].isClosed() {
		t.Fatalf("started %d halves, running %v, want exactly one, running and open", count, running)
	}
	_ = source.Close()
	if !started[0].isClosed() {
		t.Fatal("Close left the file half open")
	}

	// A start that ends after Close closes its half.
	entered, release = make(chan struct{}, 1), make(chan struct{})
	late := NewTetragonSource([]string{"/home/dcr-std1"}, TetragonOptions{Mode: "consume"}).(*tetragonSource)
	finished := make(chan struct{})
	go func() { late.startFiles(context.Background()); close(finished) }()
	<-entered
	_ = late.Close()
	close(release)
	<-finished
	mu.Lock()
	last := started[len(started)-1]
	mu.Unlock()
	if !last.isClosed() {
		t.Fatal("a file half started after Close was left open")
	}
}

// GAP-0060: with no enrolled home (users enrolled only through vendor
// machine policy) fanotify never starts, so nothing was ever handed over and
// the coverage blamed CAP_SYS_ADMIN for ever. The observe policy is the file
// half as soon as it is enabled; without it the reason names the missing home.
func TestTetragonSourceWithoutAHomeTakesTheFileHalfFromTheObservePolicy(t *testing.T) {
	h := newHarness(t)
	observe := func(name string) bool { return name == "defenseclaw-observe-89abcdef" }
	feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
	h.feeds <- feed
	source := startSource(t, h, nil, observe)
	waitFor(t, "the Tetragon stream", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	coverage := source.Coverage()
	if coverage.Complete() || len(coverage.Limitations) != 1 ||
		coverage.Limitations[0] != "file events need DefenseClaw's observe policy (Tetragon mode observe or enforce); fanotify has no enrolled home to watch" {
		t.Fatalf("before the observe policy: %+v", coverage)
	}
	if h.lastFiles() != nil {
		t.Fatal("fanotify started with no home to watch")
	}
	feed.setPolicies(BackendPolicy{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: "enabled"})
	waitFor(t, "the observe policy as the file half", func() bool { return source.Coverage().Complete() })
	if mechanism := source.Coverage().Mechanism; !strings.HasSuffix(mechanism, " + file opens from the DefenseClaw observe policy") {
		t.Fatalf("mechanism %q", mechanism)
	}
}

// #1240: the reconciler records its observe policy as its own after Tetragon
// lists it, so the observe policy can become the file half (and stop being
// it) while the listing stays the same. The coverage changed, but only a
// handoff or a policy-list change announced it, so the gateway kept the
// partial coverage of its first frame for good. The source now signals every
// such change, both ways.
func TestTetragonSourceSignalsWhenTheObservePolicyBecomesTheFileHalf(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	recorded := false
	observe := func(name string) bool {
		mu.Lock()
		defer mu.Unlock()
		return recorded && name == "defenseclaw-observe-89abcdef"
	}
	setRecorded := func(v bool) { mu.Lock(); recorded = v; mu.Unlock() }
	feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1",
		Policies: []BackendPolicy{{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: "enabled"}}})
	h.feeds <- feed
	source := startSource(t, h, nil, observe)
	waitFor(t, "the Tetragon stream", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	time.Sleep(3 * handoffInterval) // let a hand-off evaluation see the unrecorded policy
	drain := func() {
		for {
			select {
			case <-source.CoverageChanges():
			default:
				return
			}
		}
	}
	drain()
	if source.Coverage().Complete() {
		t.Fatalf("a policy the reconciler has not recorded is the file half: %+v", source.Coverage())
	}
	changed := func(what string, complete bool) {
		t.Helper()
		select {
		case <-source.CoverageChanges():
		case <-time.After(2 * time.Second):
			t.Fatalf("no coverage change when %s (coverage now %+v)", what, source.Coverage())
		}
		if got := source.Coverage().Complete(); got != complete {
			t.Fatalf("after %s: complete %v, want %v: %+v", what, got, complete, source.Coverage())
		}
	}
	setRecorded(true)
	changed("the observe policy became the file half", true)
	if mechanism := source.Coverage().Mechanism; !strings.HasSuffix(mechanism, " + file opens from the DefenseClaw observe policy") {
		t.Fatalf("mechanism %q", mechanism)
	}
	drain()
	setRecorded(false)
	changed("the observe policy stopped being the file half", false)
}

// #1240: an observe policy already loaded when the session dials (every
// gateway subscription after the first) is the file half from the first
// coverage, not from the first hand-off evaluation.
func TestTetragonSourceTakesALoadedObservePolicyAtTheDial(t *testing.T) {
	observe := func(name string) bool { return name == "defenseclaw-observe-89abcdef" }
	for _, tc := range []struct {
		state    string
		complete bool
	}{{"enabled", true}, {"disabled", false}} {
		t.Run(tc.state, func(t *testing.T) {
			h := newHarness(t)
			handoffInterval = time.Hour // no hand-off evaluation in this test
			h.feeds <- newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1",
				Policies: []BackendPolicy{{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: tc.state}}})
			coverage := startSource(t, h, nil, observe).Coverage()
			if coverage.Complete() != tc.complete ||
				(tc.complete && !strings.HasSuffix(coverage.Mechanism, " + file opens from the DefenseClaw observe policy")) {
				t.Fatalf("first coverage with the observe policy %s: %+v", tc.state, coverage)
			}
		})
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

// #1156: while the reconciler keeps a replaced controls policy for the
// sessions only it marked, a session started from a binary in both anchors
// is marked by both policies, and Tetragon reports each denied open twice.
// The stream delivers, and taps, one event per open; two real opens stay two,
// and other processes, files and policies are untouched.
func TestTetragonSourceDeliversOneEventPerDeniedOpen(t *testing.T) {
	h := newHarness(t)
	feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
	h.feeds <- feed
	var mu sync.Mutex
	tapped := 0
	source := NewTetragonSource(nil, TetragonOptions{Mode: "enforce", Dial: h.dial,
		Tap: func(batch KernelBatch) { mu.Lock(); tapped += len(batch.Events); mu.Unlock() }})
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	at := time.Unix(1791336304, 0)
	deny := func(policy, exec, path string, offset time.Duration) Event {
		return Event{Kind: KindFileRead, PID: 7, ExecID: exec, Path: path, Policy: policy, PolicyOwner: PolicyOwnerDefenseClaw,
			Outcome: OutcomeBlocked, Control: "kernel.ssh_private_key_read", Source: SourceTetragon, At: at.Add(offset)}
	}
	const kept, replacement, key = "defenseclaw-controls-0a1b2c3d", "defenseclaw-controls-4e5f6a7b", "/home/dcr-std1/.ssh/id_ed25519"
	feed.batches <- KernelBatch{Events: []Event{
		deny(kept, "e1", key, 0), deny(replacement, "e1", key, time.Microsecond), // one open, two reports
		deny(kept, "e1", key, 10*time.Millisecond), // the same process opens it again
	}}
	feed.batches <- KernelBatch{Events: []Event{
		deny(replacement, "e1", key, 10*time.Millisecond+time.Microsecond),  // the second open's twin, in the next batch
		deny(replacement, "e2", key, 20*time.Millisecond),                   // another process
		deny(kept, "e1", "/home/dcr-std1/.ssh/id_rsa", 30*time.Millisecond), // another file
		{Kind: KindFileRead, PID: 7, ExecID: "e1", Path: key, Policy: "customer-ssh", PolicyOwner: PolicyOwnerCustomer,
			Outcome: OutcomeBlocked, Source: SourceTetragon, At: at.Add(time.Microsecond)}, // the host's own policy
	}}
	var got []Event
	for i := 0; i < 5; i++ {
		got = append(got, next(t, source))
	}
	select {
	case extra := <-source.Events():
		t.Fatalf("a twin was delivered: %+v (after %+v)", extra, got)
	case <-time.After(200 * time.Millisecond):
	}
	if got[0].Policy != kept || got[1].Policy != kept || got[2].ExecID != "e2" || got[3].Path != "/home/dcr-std1/.ssh/id_rsa" ||
		got[4].PolicyOwner != PolicyOwnerCustomer {
		t.Fatalf("delivered %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if tapped != 5 {
		t.Fatalf("tapped %d events, want 5", tapped)
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
	// The first redial after the end fails with another reason and reports
	// again 20-40 ms later, so wait for the end report, not for a count.
	ended := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for i := 1; i < len(stream); i++ {
			if !stream[i].Connected && strings.HasPrefix(stream[i].Reason, "tetragon_unavailable: the event stream ended") {
				return true
			}
		}
		return false
	}
	waitFor(t, "the stream to end", ended)
	_ = source.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(tapped) != 2 || tapped[0].Events[0].Policy != hit.Policy || !tapped[1].ThrottleStart {
		t.Fatalf("tapped %+v", tapped)
	}
	if !stream[0].Connected || stream[0].Version != "v1.7.1" || stream[0].PID != 4242 {
		t.Fatalf("stream up %+v", stream[0])
	}
	for _, state := range stream[1:] {
		if state.Connected {
			t.Fatalf("the stream came back without a new feed: %+v", stream)
		}
	}
}

// cowork-1-0-8 GAP-0080 review S1: a session whose first metrics read
// failed (Tetragon's loopback metrics not up yet, as after a boot or an
// upgrade that restarts Tetragon with the helper) started from 0 and took
// its first readable count, Tetragon's whole lifetime total, as its own
// loss; the host plane then carried it across every reconnect. The first
// readable count of a session is its baseline. Growth after it counts, and
// so does growth across a later failed read.
func TestTetragonSourceBaselinesTheFirstReadableLossCount(t *testing.T) {
	h := newHarness(t)
	setLoss := func(feed *fakeFeed, lost int64, known bool) {
		feed.mu.Lock()
		feed.backend.EventsLost, feed.backend.LossKnown = lost, known
		feed.mu.Unlock()
	}
	lossKnown := func(source *tetragonSource) bool { return source.Coverage().Backend.LossKnown }
	first := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
	h.feeds <- first
	source := startSource(t, h, nil, nil)
	lost := func() int64 { return source.Coverage().Backend.EventsLost }
	if lossKnown(source) {
		t.Fatal("loss known before Tetragon's counters were read")
	}

	setLoss(first, 10000, true)
	waitFor(t, "the first readable loss count", func() bool { return lossKnown(source) })
	if got := lost(); got != 0 {
		t.Fatalf("events lost after the first readable count = %d, want 0: Tetragon's lifetime 10000 is the baseline", got)
	}
	setLoss(first, 10003, true)
	waitFor(t, "the growth after the baseline", func() bool { return lost() == 3 })
	setLoss(first, 10003, false)
	waitFor(t, "a failed read", func() bool { return !lossKnown(source) })
	setLoss(first, 10005, true)
	waitFor(t, "the growth across the failed read", func() bool { return lost() == 5 })

	// A new session whose first read fails too: its first readable count is
	// a baseline again, not 20000 more.
	close(first.batches)
	waitFor(t, "the fallback", func() bool { return source.Coverage().Backend.Kind == BackendNative })
	second := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
	h.feeds <- second
	waitFor(t, "the redial", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	setLoss(second, 20000, true)
	waitFor(t, "the second session's first readable count", func() bool { return lossKnown(source) })
	if got := lost(); got != 5 {
		t.Fatalf("events lost after the second session's first readable count = %d, want the first session's 5", got)
	}
	setLoss(second, 20001, true)
	waitFor(t, "the second session's growth", func() bool { return lost() == 6 })

	// A session whose first read succeeded keeps that read as its baseline.
	close(second.batches)
	waitFor(t, "the second fallback", func() bool { return source.Coverage().Backend.Kind == BackendNative })
	third := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1", EventsLost: 30000, LossKnown: true})
	h.feeds <- third
	waitFor(t, "the third session", func() bool { return source.Coverage().Backend.Kind == BackendTetragon })
	setLoss(third, 30002, true)
	waitFor(t, "the third session's growth", func() bool { return lost() == 8 })
}

// cowork-1-0-8 GAP-0080 review S2: a native half taken out of the source
// (cn_proc when Tetragon is back, fanotify at the hand-off, both at Close)
// was counted from a snapshot taken as it left, so what it counted while its
// reader stopped was lost, and Close took the running halves' counts out of
// the coverage altogether. A half is now read live until it has closed and
// then from its final counts, once.
func TestTetragonSourceCountsWhatAStoppingHalfCountedLast(t *testing.T) {
	settled := func(t *testing.T, what string, got func() int64, want int64) {
		t.Helper()
		waitFor(t, what, func() bool { return got() == want })
		time.Sleep(5 * superviseTick)
		if value := got(); value != want {
			t.Fatalf("%s: %d after it settled, want %d (counted twice?)", what, value, want)
		}
	}
	t.Run("cn_proc when Tetragon comes back", func(t *testing.T) {
		h := newHarness(t)
		source := startSource(t, h, nil, nil)
		proc := h.lastProc()
		proc.overflows.Store(2)
		proc.dropped.Store(3)
		proc.setOnClose(func() { proc.overflows.Add(1); proc.dropped.Add(4) })
		h.feeds <- newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
		waitFor(t, "cn_proc to stop", proc.isClosed)
		settled(t, "the stopped cn_proc half's overflows", func() int64 { return source.Coverage().KernelOverflows }, 3)
		settled(t, "the stopped cn_proc half's drops", func() int64 { return source.Coverage().BufferDropped }, 7)
	})
	t.Run("fanotify at the hand-off", func(t *testing.T) {
		h := newHarness(t)
		observe := func(name string) bool { return name == "defenseclaw-observe-89abcdef" }
		feed := newFakeFeed(Backend{Kind: BackendTetragon, Version: "v1.7.1"})
		h.feeds <- feed
		source := startSource(t, h, []string{"/home/dcr-std1"}, observe)
		files := h.lastFiles()
		files.dropped.Store(5)
		files.setOnClose(func() { files.dropped.Add(2) })
		feed.setPolicies(BackendPolicy{Name: "defenseclaw-observe-89abcdef", Mode: "monitor", State: "enabled"})
		time.Sleep(2 * handoffInterval)
		feed.batches <- KernelBatch{Events: []Event{{Kind: KindFileRead, PID: 7, Path: "/home/dcr-std1/.aws/config", Policy: "defenseclaw-observe-89abcdef"}}}
		next(t, source)
		waitFor(t, "the hand-off", files.isClosed)
		settled(t, "the handed-over fanotify half's drops", func() int64 { return source.Coverage().BufferDropped }, 7)
	})
	t.Run("both halves at Close", func(t *testing.T) {
		h := newHarness(t)
		source := startSource(t, h, []string{"/home/dcr-std1"}, nil)
		proc, files := h.lastProc(), h.lastFiles()
		if proc == nil || files == nil {
			t.Fatalf("halves running: cn_proc %v, fanotify %v", proc != nil, files != nil)
		}
		proc.overflows.Store(2)
		proc.dropped.Store(1)
		files.dropped.Store(4)
		proc.setOnClose(func() { proc.overflows.Add(1); proc.dropped.Add(1) })
		files.setOnClose(func() { files.dropped.Add(1) })
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if coverage := source.Coverage(); coverage.KernelOverflows != 3 || coverage.BufferDropped != 7 {
			t.Fatalf("after Close: overflows %d, drops %d; want 3 and 7", coverage.KernelOverflows, coverage.BufferDropped)
		}
	})
}
