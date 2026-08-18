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

package runtimegraph

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type fakeClock struct{ now time.Time }

func (clock fakeClock) Now() time.Time { return clock.now }

type deadlineMarker struct{}

type fakeDeadlines struct {
	mu        sync.Mutex
	durations []time.Duration
	cancels   []context.CancelFunc
}

func (deadlines *fakeDeadlines) Context(
	parent context.Context,
	duration time.Duration,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	deadlines.mu.Lock()
	deadlines.durations = append(deadlines.durations, duration)
	deadlines.cancels = append(deadlines.cancels, cancel)
	deadlines.mu.Unlock()
	return context.WithValue(ctx, deadlineMarker{}, true), cancel
}

func (deadlines *fakeDeadlines) calls() []time.Duration {
	deadlines.mu.Lock()
	defer deadlines.mu.Unlock()
	return append([]time.Duration(nil), deadlines.durations...)
}

func (deadlines *fakeDeadlines) expire(index int) {
	deadlines.mu.Lock()
	cancel := deadlines.cancels[index]
	deadlines.mu.Unlock()
	cancel()
}

type fakeRetryScheduler struct {
	mu    sync.Mutex
	waits []chan time.Time
}

func (scheduler *fakeRetryScheduler) After(time.Duration) <-chan time.Time {
	wake := make(chan time.Time, 1)
	scheduler.mu.Lock()
	scheduler.waits = append(scheduler.waits, wake)
	scheduler.mu.Unlock()
	return wake
}

func (scheduler *fakeRetryScheduler) count() int {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return len(scheduler.waits)
}

func (scheduler *fakeRetryScheduler) trigger(index int) {
	scheduler.mu.Lock()
	wake := scheduler.waits[index]
	scheduler.mu.Unlock()
	wake <- time.Now()
}

type lifecycleLog struct {
	mu     sync.Mutex
	events []string
}

func (log *lifecycleLog) add(event string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.events = append(log.events, event)
}

func (log *lifecycleLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

type queuedProjection struct {
	graphDigest string
	profile     string
}

type fakeComponent struct {
	name                 string
	log                  *lifecycleLog
	stopErr              error
	activateEnter        chan struct{}
	activateAllow        chan struct{}
	activateCheck        func()
	drainErr             error
	closeErr             error
	closeFailures        atomic.Int64
	closeAttempts        atomic.Int64
	childCleanupFailures atomic.Int64
	children             atomic.Int64
	mu                   sync.Mutex
	queue                []queuedProjection
	drained              []queuedProjection
	drainEnter           chan struct{}
	drainAllow           chan struct{}
	closeNotify          chan struct{}
}

func (component *fakeComponent) Activate() {
	component.log.add("activate:" + component.name)
	if component.activateEnter != nil {
		close(component.activateEnter)
		<-component.activateAllow
	}
	if component.activateCheck != nil {
		component.activateCheck()
	}
}

func (component *fakeComponent) StopIntake(ctx context.Context) error {
	component.log.add("stop:" + component.name)
	if ctx.Value(deadlineMarker{}) != true {
		return errors.New("missing bounded context")
	}
	return component.stopErr
}

func (component *fakeComponent) Drain(ctx context.Context) error {
	component.log.add("drain:" + component.name)
	if component.drainEnter != nil {
		close(component.drainEnter)
		select {
		case <-component.drainAllow:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	component.mu.Lock()
	component.drained = append(component.drained, component.queue...)
	component.queue = nil
	component.mu.Unlock()
	return component.drainErr
}

func (component *fakeComponent) Close(ctx context.Context) error {
	component.log.add("close:" + component.name)
	component.closeAttempts.Add(1)
	if ctx.Value(deadlineMarker{}) != true {
		return errors.New("missing bounded context")
	}
	if component.closeFailures.Load() > 0 {
		component.closeFailures.Add(-1)
		return errors.New("injected close failure")
	}
	if component.closeNotify != nil {
		close(component.closeNotify)
	}
	return component.closeErr
}

func (component *fakeComponent) drainedSnapshot() []queuedProjection {
	component.mu.Lock()
	defer component.mu.Unlock()
	return append([]queuedProjection(nil), component.drained...)
}

func (component *fakeComponent) enqueue(projection queuedProjection) {
	component.mu.Lock()
	defer component.mu.Unlock()
	component.queue = append(component.queue, projection)
}

type fakeFactory struct {
	name     string
	log      *lifecycleLog
	make     func(BuildInput) (*fakeComponent, error)
	needs    func(Config, Config) bool
	mu       sync.Mutex
	all      []*fakeComponent
	rebuilds []bool
}

type orphanChildFactory struct {
	live atomic.Int64
	log  *lifecycleLog
}

func (factory *orphanChildFactory) Name() string { return "orphan" }

func (factory *orphanChildFactory) Prepare(
	_ context.Context,
	_ BuildInput,
	acquisitions *Acquisitions,
) (Component, error) {
	factory.live.Store(1)
	if err := acquisitions.Register("orphan-worker", func(context.Context) error {
		factory.log.add("child-close:orphan-worker")
		factory.live.Store(0)
		return nil
	}); err != nil {
		return nil, err
	}
	return nil, errors.New("failure after child acquisition")
}

func (factory *fakeFactory) Name() string { return factory.name }

func (factory *fakeFactory) NeedsRebuild(previous Config, candidate Config) bool {
	if factory.needs == nil {
		return true
	}
	return factory.needs(previous, candidate)
}

func (factory *fakeFactory) Prepare(
	_ context.Context,
	input BuildInput,
	acquisitions *Acquisitions,
) (Component, error) {
	factory.log.add(fmt.Sprintf("init:%s:%d", factory.name, input.Generation))
	factory.mu.Lock()
	factory.rebuilds = append(factory.rebuilds, input.Rebuild)
	factory.mu.Unlock()
	component, err := factory.make(input)
	if component != nil {
		for childIndex := int64(0); childIndex < component.children.Load(); childIndex++ {
			index := childIndex
			if registerErr := acquisitions.Register(
				fmt.Sprintf("child-%d", index),
				func(context.Context) error {
					factory.log.add(fmt.Sprintf("child-close:%s:%d", component.name, index))
					if component.childCleanupFailures.Load() > 0 {
						component.childCleanupFailures.Add(-1)
						return errors.New("injected child cleanup failure")
					}
					component.children.Add(-1)
					return nil
				},
			); registerErr != nil {
				return component, registerErr
			}
		}
		factory.mu.Lock()
		factory.all = append(factory.all, component)
		factory.mu.Unlock()
	}
	return component, err
}

func (factory *fakeFactory) generation(index int) *fakeComponent {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.all[index]
}

func (factory *fakeFactory) rebuildSnapshot() []bool {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return append([]bool(nil), factory.rebuilds...)
}

type recordedReport struct {
	kind  string
	graph *Graph
	value Report
}

type fakeReporter struct {
	mu      sync.Mutex
	reports []recordedReport
	applied chan *Graph
}

type reentrantReporter struct {
	manager   *Manager
	candidate Config
	once      atomic.Bool
	done      chan reloadResultForTest
}

type reloadResultForTest struct {
	result ReloadResult
	err    *Error
}

func (reporter *reentrantReporter) PlatformHealth(_ *Graph, report Report) error {
	if report.Code != ReportValidationRejected || !reporter.once.CompareAndSwap(false, true) {
		return nil
	}
	result, err := reporter.manager.Reload(context.Background(), reporter.candidate)
	reporter.done <- reloadResultForTest{result: result, err: err}
	return nil
}

func (*reentrantReporter) ComplianceActivity(*Graph, Report) error { return nil }

type blockingReporter struct {
	entered chan struct{}
	allow   chan struct{}
	once    atomic.Bool
}

type panicOnceReporter struct {
	fakeReporter
	panicHealth atomic.Bool
	mu          sync.Mutex
	seen        map[[2]uint64]struct{}
	attempts    [][2]uint64
}

type spoolReentrantReporter struct {
	fakeReporter
	manager   *Manager
	candidate Config
	entered   chan struct{}
	proceed   chan struct{}
	done      chan reloadResultForTest
	once      atomic.Bool
}

func (reporter *spoolReentrantReporter) PlatformHealth(graph *Graph, report Report) error {
	if reporter.once.CompareAndSwap(false, true) {
		close(reporter.entered)
		<-reporter.proceed
		result, err := reporter.manager.Reload(context.Background(), reporter.candidate)
		reporter.done <- reloadResultForTest{result: result, err: err}
	}
	return reporter.fakeReporter.PlatformHealth(graph, report)
}

func (reporter *panicOnceReporter) PlatformHealth(graph *Graph, report Report) error {
	identity := [2]uint64{report.DeliverySequence, uint64(report.DeliveryIndex)}
	reporter.mu.Lock()
	reporter.attempts = append(reporter.attempts, identity)
	if reporter.seen == nil {
		reporter.seen = make(map[[2]uint64]struct{})
	}
	_, duplicate := reporter.seen[identity]
	if !duplicate {
		reporter.seen[identity] = struct{}{}
	}
	reporter.mu.Unlock()
	if !duplicate {
		_ = reporter.fakeReporter.PlatformHealth(graph, report)
	}
	if reporter.panicHealth.CompareAndSwap(true, false) {
		panic("injected reporter panic")
	}
	return nil
}

func (reporter *panicOnceReporter) attemptSnapshot() [][2]uint64 {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return append([][2]uint64(nil), reporter.attempts...)
}

func (reporter *blockingReporter) PlatformHealth(_ *Graph, _ Report) error {
	if reporter.once.CompareAndSwap(false, true) {
		close(reporter.entered)
		<-reporter.allow
	}
	return nil
}

func (*blockingReporter) ComplianceActivity(*Graph, Report) error { return nil }

func (reporter *fakeReporter) PlatformHealth(graph *Graph, report Report) error {
	reporter.record("health", graph, report)
	return nil
}

func (reporter *fakeReporter) ComplianceActivity(graph *Graph, report Report) error {
	reporter.record("compliance", graph, report)
	if reporter.applied != nil && report.Code == ReportReloadApplied {
		reporter.applied <- graph
	}
	return nil
}

func (reporter *fakeReporter) record(kind string, graph *Graph, report Report) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.reports = append(reporter.reports, recordedReport{kind: kind, graph: graph, value: report})
}

func (reporter *fakeReporter) snapshot() []recordedReport {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return append([]recordedReport(nil), reporter.reports...)
}

func newTestManager(
	t *testing.T,
	initial Config,
	factories []ComponentFactory,
) (*Manager, *fakeReporter, *fakeDeadlines) {
	t.Helper()
	reporter := &fakeReporter{applied: make(chan *Graph, 8)}
	deadlines := &fakeDeadlines{}
	retries := &fakeRetryScheduler{}
	manager, err := New(t.Context(), initial, factories, Options{
		DrainTimeout: 7 * time.Second, CleanupRetryDelay: time.Second,
		Clock:     fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)},
		Deadlines: deadlines, RetryScheduler: retries, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, reporter, deadlines
}

func testConfig(t *testing.T, suffix string, retention int, retain bool) Config {
	t.Helper()
	value := retention
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            "/var/lib/defenseclaw/audit-" + suffix + ".db",
			JudgeBodiesPath: "/var/lib/defenseclaw/judge-" + suffix + ".db",
			RetentionDays:   &value,
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "console-" + suffix, Kind: config.ObservabilityV8DestinationConsole,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ConfigFromPlan(plan, retain)
}

func prometheusTestConfig(t *testing.T, retention int, listen string) Config {
	t.Helper()
	value := retention
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: "/var/lib/defenseclaw/audit-prometheus.db", JudgeBodiesPath: "/var/lib/defenseclaw/judge-prometheus.db",
			RetentionDays: &value,
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "metrics", Kind: config.ObservabilityV8DestinationPrometheus,
			Listen: listen, Path: "/metrics",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ConfigFromPlan(plan, true)
}

func successfulFactory(name string, log *lifecycleLog) *fakeFactory {
	factory := &fakeFactory{name: name, log: log}
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("%s-%d", name, input.Generation), log: log}
		component.children.Store(2)
		return component, nil
	}
	return factory
}

func TestReloadPublishesOnceThenReverseDrainsOldGraph(t *testing.T) {
	log := &lifecycleLog{}
	factories := []ComponentFactory{
		successfulFactory("alpha", log), successfulFactory("beta", log), successfulFactory("gamma", log),
	}
	initial := testConfig(t, "shared", 90, true)
	manager, reporter, deadlines := newTestManager(t, initial, factories)
	old := manager.Active()
	candidate := testConfig(t, "shared", 30, true)

	result, err := manager.Reload(t.Context(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	active := result.ActiveGraph()
	if active == old || manager.Active() != active || active.Generation() != 2 ||
		active.RetentionDays() != 30 || active.Digest() != candidate.PlanDigest ||
		result.Status() != ReloadApplied {
		t.Fatalf("active graph = old:%t generation:%d retention:%d digest:%s",
			active == old, active.Generation(), active.RetentionDays(), active.Digest())
	}
	wantTail := []string{
		"init:alpha:2", "init:beta:2", "init:gamma:2",
		"activate:alpha-2", "activate:beta-2", "activate:gamma-2",
		"stop:gamma-1", "stop:beta-1", "stop:alpha-1",
		"drain:gamma-1", "close:gamma-1", "child-close:gamma-1:1", "child-close:gamma-1:0",
		"drain:beta-1", "close:beta-1", "child-close:beta-1:1", "child-close:beta-1:0",
		"drain:alpha-1", "close:alpha-1", "child-close:alpha-1:1", "child-close:alpha-1:0",
	}
	events := log.snapshot()
	if len(events) < len(wantTail) ||
		!equalStrings(events[len(events)-len(wantTail):], wantTail) {
		t.Fatalf("reload lifecycle = %#v, want tail %#v", events, wantTail)
	}
	if got := deadlines.calls(); len(got) != 1 || got[0] != 7*time.Second {
		t.Fatalf("deadline calls = %#v", got)
	}
	flushReports(t, manager)
	reports := reporter.snapshot()
	if len(reports) != 2 || reports[1].kind != "compliance" ||
		reports[1].graph != active || reports[1].value.Code != ReportReloadApplied {
		t.Fatalf("reload reports = %#v", reports)
	}
}

func TestReloadRejectsInvalidAndRestartRequiredFieldsWithoutInitialization(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	initial := testConfig(t, "stable", 90, true)
	manager, reporter, _ := newTestManager(t, initial, []ComponentFactory{factory})
	old := manager.Active()
	initialBuildEvents := len(log.snapshot())

	invalidAge := initial
	invalidAge.RetentionDays = -1
	invalidDigest := initial
	invalidDigest.PlanDigest = strings.Repeat("0", 64)
	for name, candidate := range map[string]Config{
		"retention age": invalidAge,
		"plan digest":   invalidDigest,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := manager.Reload(t.Context(), candidate)
			if err == nil || result.ActiveGraph() != old || result.Status() != ReloadRejected ||
				manager.Active() != old || err.Code() != ErrorInvalidConfig {
				t.Fatalf("invalid reload active=%p old=%p err=%v", result.ActiveGraph(), old, err)
			}
		})
	}

	changedLocal := testConfig(t, "new-local", 90, true)
	retention := 90
	judgePlan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: initial.LocalPath, JudgeBodiesPath: "/var/lib/defenseclaw/judge-new.db", RetentionDays: &retention,
	}})
	if err != nil {
		t.Fatal(err)
	}
	changedJudge := ConfigFromPlan(judgePlan, true)
	changedRetain := initial
	changedRetain.RetainJudgeBodies = false

	for _, test := range []struct {
		candidate Config
		field     string
	}{
		{changedLocal, FieldLocalPath},
		{changedJudge, FieldJudgeBodiesPath},
		{changedRetain, FieldRetainJudgeBodies},
	} {
		result, reloadErr := manager.Reload(t.Context(), test.candidate)
		if reloadErr == nil || reloadErr.Code() != ErrorRestartRequired ||
			reloadErr.FieldPath() != test.field || result.ActiveGraph() != old ||
			result.Status() != ReloadRejected || manager.Active() != old {
			t.Fatalf("restart field %s active=%p err=%v", test.field, result.ActiveGraph(), reloadErr)
		}
	}
	if len(log.snapshot()) != initialBuildEvents {
		t.Fatalf("rejected reload initialized resources: %#v", log.snapshot())
	}
	flushReports(t, manager)
	for _, report := range reporter.snapshot()[1:] {
		if report.graph != old || report.value.Outcome != "rejected" {
			t.Fatalf("rejection report escaped old graph: %#v", report)
		}
	}
}

func TestReloadRejectsSamePrometheusBindingBeforeCandidateInitialization(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("prometheus", log)
	initial := prometheusTestConfig(t, 90, "127.0.0.1:9464")
	manager, reporter, _ := newTestManager(t, initial, []ComponentFactory{factory})
	old := manager.Active()
	initialBuildEvents := len(log.snapshot())

	result, reloadErr := manager.Reload(
		t.Context(), prometheusTestConfig(t, 30, "127.0.0.1:9464"),
	)
	if reloadErr == nil || reloadErr.Code() != ErrorRestartRequired ||
		reloadErr.FieldPath() != "observability.destinations.metrics.listen" ||
		result.ActiveGraph() != old || result.Status() != ReloadRejected || manager.Active() != old {
		t.Fatalf("same-binding reload active=%p old=%p err=%v", result.ActiveGraph(), old, reloadErr)
	}
	if events := log.snapshot(); len(events) != initialBuildEvents {
		t.Fatalf("same-binding reload initialized candidate resources: %#v", events)
	}
	flushReports(t, manager)
	reports := reporter.snapshot()
	if len(reports) < 3 {
		t.Fatalf("same-binding rejection reports = %#v", reports)
	}
	for _, report := range reports[len(reports)-2:] {
		if report.graph != old || report.value.Code != ReportRestartRequired ||
			report.value.FieldPath != "observability.destinations.metrics.listen" {
			t.Fatalf("same-binding rejection report = %#v", report)
		}
	}
}

func TestInitializationFailureReverseCleansPartialResourcesAndReportsOldGraph(t *testing.T) {
	log := &lifecycleLog{}
	alpha := successfulFactory("alpha", log)
	beta := successfulFactory("beta", log)
	gamma := successfulFactory("gamma", log)
	gamma.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("gamma-%d", input.Generation), log: log}
		component.children.Store(3)
		if input.Generation == 2 {
			component.closeErr = errors.New("secret cleanup diagnostic")
			return component, errors.New("secret initialization diagnostic")
		}
		return component, nil
	}
	initial := testConfig(t, "shared", 90, true)
	manager, reporter, deadlines := newTestManager(t, initial, []ComponentFactory{alpha, beta, gamma})
	old := manager.Active()

	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 45, true))
	if err == nil || err.Code() != ErrorInitialization || err.ComponentName() != "gamma" ||
		result.ActiveGraph() != old || result.Status() != ReloadRejected || manager.Active() != old {
		t.Fatalf("failed candidate active=%p old=%p err=%v", result.ActiveGraph(), old, err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("reload error leaked component diagnostics: %v", err)
	}
	wantTail := []string{
		"init:alpha:2", "init:beta:2", "init:gamma:2",
		"close:gamma-2", "child-close:gamma-2:2", "child-close:gamma-2:1", "child-close:gamma-2:0",
		"close:beta-2", "child-close:beta-2:1", "child-close:beta-2:0",
		"close:alpha-2", "child-close:alpha-2:1", "child-close:alpha-2:0",
	}
	events := log.snapshot()
	if !equalStrings(events[len(events)-len(wantTail):], wantTail) {
		t.Fatalf("failed candidate cleanup = %#v", events)
	}
	for _, factory := range []*fakeFactory{alpha, beta, gamma} {
		if children := factory.generation(1).children.Load(); children != 0 {
			t.Fatalf("partial %s children still live = %d", factory.name, children)
		}
	}
	if got := deadlines.calls(); len(got) != 1 || got[0] != 7*time.Second {
		t.Fatalf("candidate cleanup deadlines = %#v", got)
	}
	flushReports(t, manager)
	reports := reporter.snapshot()
	var cleanupHealth, cleanupCompliance bool
	for _, report := range reports {
		if report.graph != old || report.value.ComponentName != "gamma" {
			continue
		}
		cleanupHealth = cleanupHealth || report.kind == "health" && report.value.Code == ReportCleanupFailed
		cleanupCompliance = cleanupCompliance || report.kind == "compliance" && report.value.Code == ReportCleanupFailed
	}
	if !cleanupHealth || !cleanupCompliance {
		t.Fatalf("cleanup failure reports = %#v", reports)
	}
}

func TestQueuedProjectionRemainsOnOldGraphDuringAtomicSwap(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	initial := testConfig(t, "shared", 90, true)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		component.children.Store(1)
		if input.Generation == 1 {
			component.queue = []queuedProjection{{graphDigest: input.Config.PlanDigest, profile: "old-profile"}}
		}
		return component, nil
	}
	manager, _, _ := newTestManager(t, initial, []ComponentFactory{factory})
	old := manager.Active()
	oldComponent := factory.generation(0)

	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 15, true))
	if err != nil {
		t.Fatal(err)
	}
	if result.ActiveGraph() == old || result.Status() != ReloadApplied {
		t.Fatalf("queued projection reload = %#v", result)
	}
	newComponent := factory.generation(1)
	drained := oldComponent.drainedSnapshot()
	if len(drained) != 1 || drained[0].graphDigest != old.Digest() || drained[0].profile != "old-profile" {
		t.Fatalf("old queued projection = %#v", drained)
	}
	if got := newComponent.drainedSnapshot(); len(got) != 0 {
		t.Fatalf("old queue moved into new graph: %#v", got)
	}
}

func TestConcurrentReadersObserveOnlyCompleteOldOrNewGraphs(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	drainEntered := make(chan struct{})
	drainAllowed := make(chan struct{})
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		if input.Generation == 1 {
			component.drainEnter = drainEntered
			component.drainAllow = drainAllowed
		}
		return component, nil
	}
	initial := testConfig(t, "shared", 90, true)
	manager, _, _ := newTestManager(t, initial, []ComponentFactory{factory})
	old := manager.Active()
	candidate := testConfig(t, "shared", 20, true)
	reloadDone := make(chan *Error, 1)
	go func() {
		_, err := manager.Reload(t.Context(), candidate)
		reloadDone <- err
	}()
	<-drainEntered // Swap has occurred; retirement is deliberately paused.
	newGraph := manager.Active()
	if newGraph == old || newGraph.Generation() != 2 {
		t.Fatalf("graph was not atomically published before drain: %#v", newGraph)
	}

	var readers sync.WaitGroup
	failures := make(chan string, 128)
	for index := 0; index < 64; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for attempt := 0; attempt < 100; attempt++ {
				graph := manager.Active()
				if graph != old && graph != newGraph {
					failures <- "reader observed an unknown graph pointer"
					return
				}
				if graph.Generation() == 1 && graph.RetentionDays() != 90 {
					failures <- "reader observed mixed old graph fields"
					return
				}
				if graph.Generation() == 2 && graph.RetentionDays() != 20 {
					failures <- "reader observed mixed new graph fields"
					return
				}
			}
		}()
	}
	readers.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	close(drainAllowed)
	if err := <-reloadDone; err != nil {
		t.Fatal(err)
	}
}

func TestGenerationLeasePreventsEnqueueAfterOldComponentRetirement(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	manager, reporter, _ := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	<-reporter.applied // Initial publication.
	old := manager.Active()
	lease, acquireErr := manager.Acquire(t.Context())
	if acquireErr != nil || lease.Graph() != old {
		t.Fatal("failed to acquire the initial graph")
	}
	oldComponent, ok := lease.Component("exporter")
	if !ok {
		t.Fatal("leased old component is unavailable")
	}

	type reloadOutcome struct {
		result ReloadResult
		err    *Error
	}
	done := make(chan reloadOutcome, 1)
	go func() {
		result, err := manager.Reload(t.Context(), testConfig(t, "shared", 25, true))
		done <- reloadOutcome{result: result, err: err}
	}()
	var newGraph *Graph
	for {
		newGraph = manager.Active()
		if newGraph != old {
			break
		}
		runtime.Gosched()
	}
	if newGraph == old || manager.Active() != newGraph {
		t.Fatal("new graph was not published while old lease was active")
	}
	for {
		old.activation.mu.Lock()
		retired := old.activation.retired
		old.activation.mu.Unlock()
		if retired {
			break
		}
		runtime.Gosched()
	}
	acquired, err := old.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if acquired {
		old.release()
		t.Fatal("retired graph accepted a new producer")
	}
	newLease, acquireErr := manager.Acquire(t.Context())
	if acquireErr != nil || newLease.Graph() != newGraph {
		t.Fatal("new producer did not acquire the published graph")
	}
	newLease.Release()

	// The old component must remain open until this pre-swap producer finishes.
	for _, event := range log.snapshot() {
		if event == "stop:exporter-1" || event == "close:exporter-1" {
			t.Fatalf("old component retired while producer lease was active: %#v", log.snapshot())
		}
	}
	oldComponent.(*fakeComponent).enqueue(queuedProjection{
		graphDigest: old.Digest(), profile: "old-profile",
	})
	fork := lease.Fork()
	if fork == nil || fork.Graph() != old {
		t.Fatal("live lease could not fork its retired generation")
	}
	lease.Release()
	if _, ok := lease.Component("exporter"); ok || lease.Graph() != nil {
		t.Fatal("released lease still exposes runtime components")
	}
	select {
	case result := <-done:
		t.Fatalf("reload completed before fork released old generation: %+v", result)
	default:
	}
	if component, ok := fork.Component("exporter"); !ok || component != oldComponent {
		t.Fatal("fork lost access to the pinned old component")
	}
	fork.Release()

	outcome := <-done
	if outcome.err != nil || outcome.result.Status() != ReloadApplied ||
		outcome.result.ActiveGraph() != newGraph {
		t.Fatalf("leased reload result=%#v err=%v", outcome.result, outcome.err)
	}
	drained := oldComponent.(*fakeComponent).drainedSnapshot()
	if len(drained) != 1 || drained[0].graphDigest != old.Digest() || drained[0].profile != "old-profile" {
		t.Fatalf("leased old projection was not drained by its owner: %#v", drained)
	}
}

func TestAcquireRevalidatesOldGraphWhenReloadSwapsBeforeRetirement(t *testing.T) {
	log := &lifecycleLog{}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true),
		[]ComponentFactory{successfulFactory("exporter", log)},
	)
	old := manager.Active()
	loadEntered := make(chan struct{})
	allowIncrement := make(chan struct{})
	incrementEntered := make(chan struct{})
	allowRevalidate := make(chan struct{})
	swapEntered := make(chan struct{})
	allowRetirement := make(chan struct{})
	var loadOnce, incrementOnce atomic.Bool
	manager.testHooks = &managerTestHooks{
		afterAcquireLoad: func(graph *Graph) {
			if graph == old && loadOnce.CompareAndSwap(false, true) {
				close(loadEntered)
				<-allowIncrement
			}
		},
		afterAcquireIncrement: func(graph *Graph) {
			if graph == old && incrementOnce.CompareAndSwap(false, true) {
				close(incrementEntered)
				<-allowRevalidate
			}
		},
		afterSwapBeforeRetire: func(previous, next *Graph) {
			if previous != old || next == nil {
				t.Errorf("reload swap previous=%p next=%p old=%p", previous, next, old)
			}
			close(swapEntered)
			<-allowRetirement
		},
	}
	type acquireOutcome struct {
		lease *Lease
		err   *Error
	}
	acquired := make(chan acquireOutcome, 1)
	go func() {
		lease, err := manager.Acquire(t.Context())
		acquired <- acquireOutcome{lease: lease, err: err}
	}()
	<-loadEntered
	type reloadOutcome struct {
		result ReloadResult
		err    *Error
	}
	reloaded := make(chan reloadOutcome, 1)
	go func() {
		result, err := manager.Reload(t.Context(), testConfig(t, "shared", 30, true))
		reloaded <- reloadOutcome{result: result, err: err}
	}()
	<-swapEntered
	close(allowIncrement)
	<-incrementEntered // Old refcount increment happened after the active swap.
	close(allowRevalidate)
	close(allowRetirement)

	producer := <-acquired
	if producer.err != nil || producer.lease.Graph() == old ||
		producer.lease.Graph() != manager.Active() {
		t.Fatalf("post-swap acquisition lease=%v graph=%p old=%p err=%v",
			producer.lease, producer.lease.Graph(), old, producer.err)
	}
	producer.lease.Release()
	reload := <-reloaded
	if reload.err != nil || reload.result.Status() != ReloadApplied ||
		reload.result.ActiveGraph() != manager.Active() {
		t.Fatalf("reload result=%#v err=%v", reload.result, reload.err)
	}
}

func TestAcquireRevalidatesClosedManagerWhenCloseSwapsBeforeRetirement(t *testing.T) {
	log := &lifecycleLog{}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true),
		[]ComponentFactory{successfulFactory("exporter", log)},
	)
	old := manager.Active()
	loadEntered := make(chan struct{})
	allowIncrement := make(chan struct{})
	incrementEntered := make(chan struct{})
	allowRevalidate := make(chan struct{})
	swapEntered := make(chan struct{})
	allowRetirement := make(chan struct{})
	var loadOnce, incrementOnce atomic.Bool
	manager.testHooks = &managerTestHooks{
		afterAcquireLoad: func(graph *Graph) {
			if graph == old && loadOnce.CompareAndSwap(false, true) {
				close(loadEntered)
				<-allowIncrement
			}
		},
		afterAcquireIncrement: func(graph *Graph) {
			if graph == old && incrementOnce.CompareAndSwap(false, true) {
				close(incrementEntered)
				<-allowRevalidate
			}
		},
		afterSwapBeforeRetire: func(previous, next *Graph) {
			if previous != old || next != nil {
				t.Errorf("close swap previous=%p next=%p old=%p", previous, next, old)
			}
			close(swapEntered)
			<-allowRetirement
		},
	}
	type acquireOutcome struct {
		lease *Lease
		err   *Error
	}
	acquired := make(chan acquireOutcome, 1)
	go func() {
		lease, err := manager.Acquire(t.Context())
		acquired <- acquireOutcome{lease: lease, err: err}
	}()
	<-loadEntered
	closed := make(chan *Error, 1)
	go func() { closed <- manager.Close(t.Context()) }()
	<-swapEntered
	close(allowIncrement)
	<-incrementEntered // Old refcount increment happened after active became nil.
	close(allowRevalidate)
	producer := <-acquired
	if producer.lease != nil || producer.err == nil || producer.err.Code() != ErrorClosed {
		t.Fatalf("post-close acquisition lease=%v err=%v", producer.lease, producer.err)
	}
	close(allowRetirement)
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestAcquireReadsClosedAfterActiveRevalidationDuringClose(t *testing.T) {
	log := &lifecycleLog{}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true),
		[]ComponentFactory{successfulFactory("exporter", log)},
	)
	old := manager.Active()
	validationEntered := make(chan struct{})
	allowClosedLoad := make(chan struct{})
	var once atomic.Bool
	manager.testHooks = &managerTestHooks{
		afterAcquireActiveRevalidation: func(graph *Graph) {
			if graph == old && once.CompareAndSwap(false, true) {
				close(validationEntered)
				<-allowClosedLoad
			}
		},
	}
	type acquireOutcome struct {
		lease *Lease
		err   *Error
	}
	acquired := make(chan acquireOutcome, 1)
	go func() {
		lease, err := manager.Acquire(t.Context())
		acquired <- acquireOutcome{lease: lease, err: err}
	}()
	<-validationEntered // active.Load()==old has already evaluated true.
	closed := make(chan *Error, 1)
	go func() { closed <- manager.Close(t.Context()) }()
	for !manager.closed.Load() || manager.Active() != nil {
		runtime.Gosched()
	}
	close(allowClosedLoad) // The required second load must now observe closed.
	producer := <-acquired
	if producer.lease != nil || producer.err == nil || producer.err.Code() != ErrorClosed {
		t.Fatalf("between-load shutdown acquisition lease=%v err=%v", producer.lease, producer.err)
	}
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestCandidateActivationOccursAfterPublicationAndAcquireIsCancellableWhileDormant(t *testing.T) {
	log := &lifecycleLog{}
	activateEntered := make(chan struct{})
	activateAllowed := make(chan struct{})
	factory := successfulFactory("exporter", log)
	var manager *Manager
	var activatedBeforePublication atomic.Bool
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		if input.Generation == 2 {
			component.activateEnter = activateEntered
			component.activateAllow = activateAllowed
			component.activateCheck = func() {
				if manager.Active().Generation() != 2 {
					activatedBeforePublication.Store(true)
				}
			}
		}
		return component, nil
	}
	manager, _, _ = newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	type outcome struct {
		result ReloadResult
		err    *Error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := manager.Reload(t.Context(), testConfig(t, "shared", 50, true))
		done <- outcome{result: result, err: err}
	}()
	<-activateEntered
	if manager.Active().Generation() != 2 {
		t.Fatal("candidate activation began before publication")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if lease, err := manager.Acquire(cancelled); lease != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("dormant acquisition lease=%v err=%v", lease, err)
	}
	close(activateAllowed)
	reloaded := <-done
	if reloaded.err != nil || reloaded.result.Status() != ReloadApplied {
		t.Fatalf("activation reload=%#v err=%v", reloaded.result, reloaded.err)
	}
	if activatedBeforePublication.Load() {
		t.Fatal("candidate activation ran before publication")
	}
	lease, err := manager.Acquire(t.Context())
	if err != nil || lease.Graph() != reloaded.result.ActiveGraph() {
		t.Fatalf("activated graph acquisition lease=%v err=%v", lease, err)
	}
	lease.Release()
}

func TestRetentionOnlyReloadSignalsStableDispatcherReuseButCreatesNewQueueComponent(t *testing.T) {
	log := &lifecycleLog{}
	var transportBuilds atomic.Int64
	factory := successfulFactory("stable-dispatcher", log)
	factory.needs = func(previous Config, candidate Config) bool {
		return previous.LocalPath != candidate.LocalPath ||
			previous.JudgeBodiesPath != candidate.JudgeBodiesPath ||
			previous.RetainJudgeBodies != candidate.RetainJudgeBodies
	}
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		if input.Rebuild {
			transportBuilds.Add(1)
		}
		return &fakeComponent{name: fmt.Sprintf("stable-%d", input.Generation), log: log}, nil
	}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	oldComponent := factory.generation(0)
	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 20, true))
	if err != nil || result.Status() != ReloadApplied {
		t.Fatalf("retention-only reload=%#v err=%v", result, err)
	}
	newComponent := factory.generation(1)
	if oldComponent == newComponent {
		t.Fatal("retention-only reload reused a generation-owned queue component")
	}
	if transportBuilds.Load() != 1 || !equalBools(factory.rebuildSnapshot(), []bool{true, false}) {
		t.Fatalf("transport builds=%d rebuild flags=%#v", transportBuilds.Load(), factory.rebuildSnapshot())
	}
}

func TestLeaseDeadlineReturnsAppliedDegradedThenCleansOldGraphAfterRelease(t *testing.T) {
	log := &lifecycleLog{}
	closed := make(chan struct{})
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		if input.Generation == 1 {
			component.closeNotify = closed
		}
		return component, nil
	}
	manager, reporter, deadlines := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	lease, err := manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result ReloadResult
		err    *Error
	}
	done := make(chan outcome, 1)
	go func() {
		result, reloadErr := manager.Reload(t.Context(), testConfig(t, "shared", 35, true))
		done <- outcome{result: result, err: reloadErr}
	}()
	waitForDeadlineCalls(deadlines, 1)
	deadlines.expire(0)
	reloaded := <-done
	if reloaded.err != nil || reloaded.result.Status() != ReloadAppliedDegraded ||
		reloaded.result.ActiveGraph() != manager.Active() {
		t.Fatalf("lease-timeout reload=%#v err=%v", reloaded.result, reloaded.err)
	}
	select {
	case <-closed:
		t.Fatal("old graph closed under a live producer lease")
	default:
	}
	flushReports(t, manager)
	var canonicalApplied bool
	for _, report := range reporter.snapshot() {
		if report.graph == reloaded.result.ActiveGraph() && report.value.Code == ReportReloadApplied &&
			report.value.Outcome == "applied" {
			canonicalApplied = true
		}
		if report.value.Outcome == "applied_degraded" {
			t.Fatalf("noncanonical compliance outcome: %#v", report)
		}
	}
	if !canonicalApplied {
		t.Fatalf("missing canonical applied report: %#v", reporter.snapshot())
	}
	lease.Release()
	<-closed
	if len(deadlines.calls()) != 2 {
		t.Fatalf("eventual cleanup did not receive its own bound: %#v", deadlines.calls())
	}
}

func TestCloseSerializesReloadAndAcquireAndRetiresActiveGraphOnce(t *testing.T) {
	log := &lifecycleLog{}
	closed := make(chan struct{})
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		return &fakeComponent{
			name: fmt.Sprintf("exporter-%d", input.Generation), log: log, closeNotify: closed,
		}, nil
	}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	lease, err := manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan *Error, 1)
	go func() { closeDone <- manager.Close(t.Context()) }()
	for !manager.closed.Load() || manager.Active() != nil {
		runtime.Gosched()
	}
	if acquired, acquireErr := manager.Acquire(t.Context()); acquired != nil ||
		acquireErr == nil || acquireErr.Code() != ErrorClosed {
		t.Fatalf("post-close acquisition lease=%v err=%v", acquired, acquireErr)
	}
	type reloadOutcome struct {
		result ReloadResult
		err    *Error
	}
	reloadDone := make(chan reloadOutcome, 1)
	go func() {
		result, reloadErr := manager.Reload(t.Context(), testConfig(t, "shared", 30, true))
		reloadDone <- reloadOutcome{result: result, err: reloadErr}
	}()
	select {
	case <-closed:
		t.Fatal("Close retired active component before lease release")
	default:
	}
	lease.Release()
	if closeErr := <-closeDone; closeErr != nil {
		t.Fatal(closeErr)
	}
	<-closed
	reloaded := <-reloadDone
	if reloaded.err == nil || reloaded.err.Code() != ErrorClosed ||
		reloaded.result.Status() != ReloadRejected || reloaded.result.ActiveGraph() != nil {
		t.Fatalf("reload after close=%#v err=%v", reloaded.result, reloaded.err)
	}
	if err := manager.Close(t.Context()); err != nil {
		t.Fatalf("idempotent close error = %v", err)
	}
	closeCount := 0
	for _, event := range log.snapshot() {
		if event == "close:exporter-1" {
			closeCount++
		}
	}
	if closeCount != 1 {
		t.Fatalf("active component close count = %d events=%#v", closeCount, log.snapshot())
	}
}

func TestCloseDeadlineNeverClosesUnderLeaseAndEventuallyCleans(t *testing.T) {
	log := &lifecycleLog{}
	closed := make(chan struct{})
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		return &fakeComponent{
			name: fmt.Sprintf("exporter-%d", input.Generation), log: log, closeNotify: closed,
		}, nil
	}
	manager, _, deadlines := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	lease, err := manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *Error, 1)
	go func() { done <- manager.Close(t.Context()) }()
	waitForDeadlineCalls(deadlines, 1)
	deadlines.expire(0)
	closeErr := <-done
	if closeErr == nil || closeErr.Code() != ErrorShutdown || closeErr.ComponentName() != "inflight-users" {
		t.Fatalf("bounded close error = %v", closeErr)
	}
	select {
	case <-closed:
		t.Fatal("bounded Close closed component under lease")
	default:
	}
	lease.Release()
	<-closed
	if len(deadlines.calls()) != 2 {
		t.Fatalf("eventual shutdown cleanup bounds = %#v", deadlines.calls())
	}
}

func TestPostSwapDrainFailureKeepsNewGraphActiveAndReportsThroughIt(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		if input.Generation == 1 {
			component.drainErr = errors.New("secret drain detail")
		}
		return component, nil
	}
	manager, reporter, _ := newTestManager(t, testConfig(t, "shared", 90, true), []ComponentFactory{factory})
	old := manager.Active()
	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 10, true))
	newGraph := result.ActiveGraph()
	if err != nil || result.Status() != ReloadAppliedDegraded ||
		manager.Active() != newGraph || newGraph == old {
		t.Fatalf("post-swap drain active=%p new=%p old=%p status=%s err=%v",
			manager.Active(), newGraph, old, result.Status(), err)
	}
	flushReports(t, manager)
	reports := reporter.snapshot()
	var health, compliance bool
	for _, report := range reports {
		if report.graph != newGraph || report.value.Code != ReportDrainFailed {
			continue
		}
		health = health || report.kind == "health"
		compliance = compliance || report.kind == "compliance"
	}
	if !health || !compliance {
		t.Fatalf("post-swap drain reports = %#v", reports)
	}
}

func TestConstructorRejectsUnsafeDependenciesAndCleansPartialInitialGraph(t *testing.T) {
	reporter := &fakeReporter{}
	deadlines := &fakeDeadlines{}
	options := Options{
		DrainTimeout: time.Second, Clock: fakeClock{now: time.Now()},
		Deadlines: deadlines, Reporter: reporter,
	}
	configValue := testConfig(t, "initial", 90, true)
	if _, err := New(t.Context(), configValue, nil, Options{}); err == nil {
		t.Fatal("zero lifecycle dependencies were accepted")
	}
	log := &lifecycleLog{}
	partial := &fakeFactory{name: "partial", log: log}
	partial.make = func(BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: "partial-1", log: log}
		component.children.Store(4)
		return component, errors.New("initial failure")
	}
	if _, err := New(t.Context(), configValue, []ComponentFactory{partial}, options); err == nil {
		t.Fatal("partial initial failure was hidden")
	}
	if partial.generation(0).children.Load() != 0 {
		t.Fatal("partial initial children remained live")
	}
	if got := deadlines.calls(); len(got) != 1 || got[0] != time.Second {
		t.Fatalf("initial cleanup deadline = %#v", got)
	}
}

func TestInitialCleanupFailureReturnsOwnerWithoutStartingReporterWorker(t *testing.T) {
	log := &lifecycleLog{}
	factory := &fakeFactory{name: "partial", log: log}
	factory.make = func(BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: "partial-1", log: log}
		component.closeFailures.Store(1)
		return component, errors.New("initial failure")
	}
	reporter := &fakeReporter{}
	retries := &fakeRetryScheduler{}
	manager, err := New(
		t.Context(), testConfig(t, "initial-retry", 90, true), []ComponentFactory{factory},
		Options{
			DrainTimeout: time.Second, CleanupRetryDelay: time.Second,
			Clock: fakeClock{now: time.Now()}, Deadlines: &fakeDeadlines{},
			RetryScheduler: retries, Reporter: reporter,
		},
	)
	if err == nil || manager == nil {
		t.Fatalf("initial failure manager=%p err=%v", manager, err)
	}
	if manager.reporterStarted.Load() || pendingCount(manager) != 1 || ownershipCount(manager) != 1 {
		t.Fatalf("started=%v pending=%d owned=%d",
			manager.reporterStarted.Load(), pendingCount(manager), ownershipCount(manager))
	}
	waitForRetryCount(retries, 1)
	retries.trigger(0)
	if cleanupErr := manager.WaitCleanup(t.Context()); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	if pendingCount(manager) != 0 || ownershipCount(manager) != 0 {
		t.Fatalf("eventual cleanup pending=%d owned=%d", pendingCount(manager), ownershipCount(manager))
	}
	if waitErr := manager.WaitReporter(t.Context()); waitErr != nil {
		t.Fatal(waitErr)
	}
}

func TestAcquisitionRegistryCleansChildWhenFactoryReturnsNoComponent(t *testing.T) {
	reporter := &fakeReporter{}
	deadlines := &fakeDeadlines{}
	log := &lifecycleLog{}
	factory := &orphanChildFactory{log: log}
	_, err := New(
		t.Context(), testConfig(t, "orphan", 90, true), []ComponentFactory{factory},
		Options{
			DrainTimeout: time.Second, Clock: fakeClock{now: time.Now()},
			Deadlines: deadlines, Reporter: reporter,
		},
	)
	if err == nil {
		t.Fatal("factory failure after hidden child acquisition was accepted")
	}
	if factory.live.Load() != 0 || !equalStrings(log.snapshot(), []string{"child-close:orphan-worker"}) {
		t.Fatalf("orphan child cleanup live=%d events=%#v", factory.live.Load(), log.snapshot())
	}
	if got := deadlines.calls(); len(got) != 1 || got[0] != time.Second {
		t.Fatalf("orphan cleanup deadline = %#v", got)
	}
}

func TestRejectedCandidateRetainsFailedCloseOwnershipUntilBoundedRetrySucceeds(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		if input.Generation == 2 {
			component.closeFailures.Store(1)
			return component, errors.New("prepare failed after acquisition")
		}
		return component, nil
	}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	old := manager.Active()
	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 80, true))
	if err == nil || result.Status() != ReloadRejected || result.ActiveGraph() != old {
		t.Fatalf("rejected candidate result=%#v err=%v", result, err)
	}
	failed := factory.generation(1)
	if failed.closeAttempts.Load() != 1 || ownershipCount(manager) != 2 || pendingCount(manager) != 1 {
		t.Fatalf("failed close attempts=%d owned=%d pending=%d",
			failed.closeAttempts.Load(), ownershipCount(manager), pendingCount(manager))
	}
	retries := manager.retryScheduler.(*fakeRetryScheduler)
	waitForRetryCount(retries, 1)
	retries.trigger(0)
	for failed.closeAttempts.Load() < 2 || pendingCount(manager) != 0 {
		runtime.Gosched()
	}
	if ownershipCount(manager) != 1 {
		t.Fatalf("successful retry retained rejected ownership: %d", ownershipCount(manager))
	}
}

func TestRetirementRetainsFailedChildCleanupUntilRetrySucceeds(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		component.children.Store(2)
		if input.Generation == 1 {
			component.childCleanupFailures.Store(1)
		}
		return component, nil
	}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 70, true))
	if err != nil || result.Status() != ReloadAppliedDegraded {
		t.Fatalf("child cleanup reload=%#v err=%v", result, err)
	}
	retired := factory.generation(0)
	if retired.children.Load() != 1 || ownershipCount(manager) != 2 || pendingCount(manager) != 1 {
		t.Fatalf("failed child cleanup children=%d owned=%d pending=%d",
			retired.children.Load(), ownershipCount(manager), pendingCount(manager))
	}
	retries := manager.retryScheduler.(*fakeRetryScheduler)
	waitForRetryCount(retries, 1)
	retries.trigger(0)
	for retired.children.Load() != 0 || pendingCount(manager) != 0 {
		runtime.Gosched()
	}
	if ownershipCount(manager) != 1 {
		t.Fatalf("successful child retry retained old ownership: %d", ownershipCount(manager))
	}
}

func TestCleanupRetryOnlyRepeatsIncompleteLifecyclePhases(t *testing.T) {
	log := &lifecycleLog{}
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		component := &fakeComponent{name: fmt.Sprintf("exporter-%d", input.Generation), log: log}
		if input.Generation == 1 {
			component.closeFailures.Store(1)
		}
		return component, nil
	}
	manager, _, _ := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	result, err := manager.Reload(t.Context(), testConfig(t, "shared", 80, true))
	if err != nil || result.Status() != ReloadAppliedDegraded {
		t.Fatalf("reload=%#v err=%v", result, err)
	}
	retries := manager.retryScheduler.(*fakeRetryScheduler)
	waitForRetryCount(retries, 1)
	retries.trigger(0)
	for pendingCount(manager) != 0 {
		runtime.Gosched()
	}
	events := log.snapshot()
	if countString(events, "stop:exporter-1") != 1 ||
		countString(events, "drain:exporter-1") != 1 ||
		countString(events, "close:exporter-1") != 2 {
		t.Fatalf("completed lifecycle phases were repeated: %#v", events)
	}
}

func TestReporterCanReenterReloadWithoutLifecycleLockDeadlock(t *testing.T) {
	log := &lifecycleLog{}
	reporter := &reentrantReporter{done: make(chan reloadResultForTest, 1)}
	initial := testConfig(t, "shared", 90, true)
	manager, err := New(t.Context(), initial, []ComponentFactory{successfulFactory("exporter", log)}, Options{
		DrainTimeout: 7 * time.Second, CleanupRetryDelay: time.Second,
		Clock:     fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)},
		Deadlines: &fakeDeadlines{}, RetryScheduler: &fakeRetryScheduler{}, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	reporter.manager = manager
	reporter.candidate = testConfig(t, "shared", 80, true)
	invalid := initial
	invalid.RetentionDays = -1
	result, reloadErr := manager.Reload(t.Context(), invalid)
	if reloadErr == nil || result.Status() != ReloadRejected {
		t.Fatalf("invalid reload=%#v err=%v", result, reloadErr)
	}
	reentered := <-reporter.done
	if reentered.err != nil || reentered.result.Status() != ReloadApplied ||
		reentered.result.ActiveGraph() != manager.Active() {
		t.Fatalf("reentrant reload=%#v err=%v", reentered.result, reentered.err)
	}
	flushReports(t, manager)
}

func TestBlockedReporterCannotBlockReloadOrLifecycleLock(t *testing.T) {
	log := &lifecycleLog{}
	reporter := &blockingReporter{entered: make(chan struct{}), allow: make(chan struct{})}
	initial := testConfig(t, "shared", 90, true)
	manager, err := New(t.Context(), initial, []ComponentFactory{successfulFactory("exporter", log)}, Options{
		DrainTimeout: 7 * time.Second, CleanupRetryDelay: time.Second,
		Clock:     fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)},
		Deadlines: &fakeDeadlines{}, RetryScheduler: &fakeRetryScheduler{}, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	invalid := initial
	invalid.RetentionDays = -1
	result, reloadErr := manager.Reload(t.Context(), invalid)
	if reloadErr == nil || result.Status() != ReloadRejected {
		t.Fatalf("invalid reload=%#v err=%v", result, reloadErr)
	}
	<-reporter.entered
	// The reporter worker is blocked, but lifecycle serialization remains free.
	applied, reloadErr := manager.Reload(t.Context(), testConfig(t, "shared", 60, true))
	if reloadErr != nil || applied.Status() != ReloadApplied {
		t.Fatalf("reload behind blocked reporter=%#v err=%v", applied, reloadErr)
	}
	close(reporter.allow)
	flushReports(t, manager)
}

func TestReportSpoolStaysNonblockingPastLegacyCapacityAndAllowsReentrantReload(t *testing.T) {
	log := &lifecycleLog{}
	reporter := &spoolReentrantReporter{
		entered: make(chan struct{}), proceed: make(chan struct{}),
		done: make(chan reloadResultForTest, 1),
	}
	initial := testConfig(t, "shared", 90, true)
	manager, err := New(t.Context(), initial, []ComponentFactory{successfulFactory("exporter", log)}, Options{
		DrainTimeout: 7 * time.Second, CleanupRetryDelay: time.Second,
		Clock:     fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)},
		Deadlines: &fakeDeadlines{}, RetryScheduler: &fakeRetryScheduler{}, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	reporter.manager = manager
	reporter.candidate = testConfig(t, "shared", 80, true)
	invalid := initial
	invalid.RetentionDays = -1
	if _, reloadErr := manager.Reload(t.Context(), invalid); reloadErr == nil {
		t.Fatal("invalid reload accepted")
	}
	<-reporter.entered

	const queuedReloads = 300
	queued := make(chan error, 1)
	go func() {
		for index := 0; index < queuedReloads; index++ {
			_, reloadErr := manager.Reload(context.Background(), invalid)
			if reloadErr == nil {
				queued <- errors.New("invalid reload accepted")
				return
			}
			if reloadErr.Code() != ErrorInvalidConfig {
				queued <- reloadErr
				return
			}
		}
		queued <- nil
	}()
	select {
	case queuedErr := <-queued:
		if queuedErr != nil {
			t.Fatalf("queued reload err=%v", queuedErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle blocked behind reporter consumption")
	}
	manager.reportSpoolMu.Lock()
	spooled := len(manager.reportSpool)
	manager.reportSpoolMu.Unlock()
	if spooled != queuedReloads {
		t.Fatalf("spooled batches=%d want=%d", spooled, queuedReloads)
	}
	close(reporter.proceed)
	reentered := <-reporter.done
	if reentered.err != nil || reentered.result.Status() != ReloadApplied ||
		reentered.result.ActiveGraph() != manager.Active() {
		t.Fatalf("reentrant reload=%#v err=%v", reentered.result, reentered.err)
	}
	flushReports(t, manager)
	wantReports := 1 + 2*(queuedReloads+1) + 1
	if got := len(reporter.snapshot()); got != wantReports {
		t.Fatalf("delivered reports=%d want=%d", got, wantReports)
	}
}

func TestReporterBatchesRemainInLifecycleOrderWhenHandoffsRace(t *testing.T) {
	log := &lifecycleLog{}
	initial := testConfig(t, "shared", 90, true)
	manager, reporter, _ := newTestManager(
		t, initial, []ComponentFactory{successfulFactory("exporter", log)},
	)
	flushReports(t, manager)
	firstSequenced := make(chan struct{})
	allowFirst := make(chan struct{})
	var blocked atomic.Bool
	manager.testHooks = &managerTestHooks{beforeReportDispatch: func(sequence uint64) {
		if sequence == 2 && blocked.CompareAndSwap(false, true) {
			close(firstSequenced)
			<-allowFirst
		}
	}}

	firstDone := make(chan *Error, 1)
	go func() {
		invalid := initial
		invalid.RetentionDays = -1
		_, err := manager.Reload(t.Context(), invalid)
		firstDone <- err
	}()
	<-firstSequenced
	secondDone := make(chan *Error, 1)
	go func() {
		_, err := manager.Reload(t.Context(), testConfig(t, "different-path", 90, true))
		secondDone <- err
	}()
	for manager.reportBatchSeq.Load() < 3 {
		runtime.Gosched()
	}
	if err := <-secondDone; err == nil || err.Code() != ErrorRestartRequired {
		t.Fatalf("second reload err=%v", err)
	}
	// Sequence three can append and return first, but the single worker waits
	// for sequence two rather than delivering transactions out of order.
	if got := len(reporter.snapshot()); got != 1 {
		t.Fatalf("out-of-order batch delivered before predecessor: %d reports", got)
	}
	close(allowFirst)
	if err := <-firstDone; err == nil || err.Code() != ErrorInvalidConfig {
		t.Fatalf("first reload err=%v", err)
	}
	flushReports(t, manager)
	reports := reporter.snapshot()
	if len(reports) != 5 {
		t.Fatalf("reports=%#v", reports)
	}
	for index, code := range []ReportCode{
		ReportValidationRejected, ReportValidationRejected,
		ReportRestartRequired, ReportRestartRequired,
	} {
		if reports[index+1].value.Code != code {
			t.Fatalf("report %d code=%s want=%s", index+1, reports[index+1].value.Code, code)
		}
	}
}

func TestCloseWaitsForSequencedReloadBatchBeforeClosingReporter(t *testing.T) {
	manager, reporter, _ := newTestManager(t, testConfig(t, "shared", 90, true), nil)
	flushReports(t, manager)
	sequenced := make(chan struct{})
	allowDispatch := make(chan struct{})
	manager.testHooks = &managerTestHooks{beforeReportDispatch: func(sequence uint64) {
		if sequence == 2 {
			close(sequenced)
			<-allowDispatch
		}
	}}
	invalid := testConfig(t, "shared", 90, true)
	invalid.RetentionDays = -1
	reloadDone := make(chan *Error, 1)
	go func() {
		_, err := manager.Reload(t.Context(), invalid)
		reloadDone <- err
	}()
	<-sequenced
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	manager.reportSpoolMu.Lock()
	closedEarly := manager.reportSpoolClosed
	manager.reportSpoolMu.Unlock()
	if closedEarly {
		t.Fatal("reporter closed before a previously sequenced batch was accepted")
	}
	close(allowDispatch)
	if err := <-reloadDone; err == nil || err.Code() != ErrorInvalidConfig {
		t.Fatalf("reload err=%v", err)
	}
	if err := manager.WaitReporter(t.Context()); err != nil {
		t.Fatal(err)
	}
	reports := reporter.snapshot()
	if len(reports) != 3 || reports[1].value.Code != ReportValidationRejected ||
		reports[2].value.Code != ReportValidationRejected {
		t.Fatalf("reports=%#v", reports)
	}
}

func TestReporterPanicIsRetainedForRetryAndVisibleToFlush(t *testing.T) {
	log := &lifecycleLog{}
	reporter := &panicOnceReporter{}
	retries := &fakeRetryScheduler{}
	initial := testConfig(t, "shared", 90, true)
	manager, err := New(t.Context(), initial, []ComponentFactory{successfulFactory("exporter", log)}, Options{
		DrainTimeout: 7 * time.Second, CleanupRetryDelay: time.Second,
		Clock:     fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)},
		Deadlines: &fakeDeadlines{}, RetryScheduler: retries, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	flushReports(t, manager)
	reporter.panicHealth.Store(true)
	invalid := initial
	invalid.RetentionDays = -1
	if _, reloadErr := manager.Reload(t.Context(), invalid); reloadErr == nil {
		t.Fatal("invalid reload accepted")
	}
	waitForRetryCount(retries, 1)
	if flushErr := manager.FlushReports(t.Context()); flushErr == nil || flushErr.Code() != ErrorReporting {
		t.Fatalf("reporter failure was not surfaced: %v", flushErr)
	}
	retries.trigger(0)
	for manager.reportCompleted.Load() < manager.reportBatchSeq.Load() {
		runtime.Gosched()
	}
	flushReports(t, manager)
	reports := reporter.snapshot()
	if len(reports) != 3 || reports[1].value.Code != ReportValidationRejected ||
		reports[2].value.Code != ReportValidationRejected {
		t.Fatalf("retried reports=%#v", reports)
	}
	attempts := reporter.attemptSnapshot()
	if len(attempts) != 2 || attempts[0] != attempts[1] || attempts[0] == [2]uint64{} {
		t.Fatalf("retry delivery identities=%#v", attempts)
	}
}

func TestCloseTerminatesReporterWorkerAfterQueuedReports(t *testing.T) {
	manager, _, _ := newTestManager(t, testConfig(t, "shared", 90, true), nil)
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitReporter(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestComponentOwnershipRejectsReuseFromStillRetiringGeneration(t *testing.T) {
	log := &lifecycleLog{}
	closedFirst := make(chan struct{})
	var first *fakeComponent
	factory := successfulFactory("exporter", log)
	factory.make = func(input BuildInput) (*fakeComponent, error) {
		switch input.Generation {
		case 1:
			first = &fakeComponent{name: "exporter-1", log: log, closeNotify: closedFirst}
			return first, nil
		case 2:
			return &fakeComponent{name: "exporter-2", log: log}, nil
		default:
			return first, nil // Adversarial factory attempts cross-generation reuse.
		}
	}
	manager, _, deadlines := newTestManager(
		t, testConfig(t, "shared", 90, true), []ComponentFactory{factory},
	)
	lease, err := manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result ReloadResult
		err    *Error
	}
	secondDone := make(chan outcome, 1)
	go func() {
		result, reloadErr := manager.Reload(t.Context(), testConfig(t, "shared", 80, true))
		secondDone <- outcome{result: result, err: reloadErr}
	}()
	waitForDeadlineCalls(deadlines, 1)
	deadlines.expire(0)
	second := <-secondDone
	if second.err != nil || second.result.Status() != ReloadAppliedDegraded {
		t.Fatalf("generation two reload=%#v err=%v", second.result, second.err)
	}
	third, thirdErr := manager.Reload(t.Context(), testConfig(t, "shared", 70, true))
	if thirdErr == nil || thirdErr.Code() != ErrorInitialization ||
		third.Status() != ReloadRejected || third.ActiveGraph() != second.result.ActiveGraph() {
		t.Fatalf("generation three reuse=%#v err=%v", third, thirdErr)
	}
	if first.closeAttempts.Load() != 0 || ownershipCount(manager) != 2 {
		t.Fatalf("retiring component changed attempts=%d owned=%d",
			first.closeAttempts.Load(), ownershipCount(manager))
	}
	lease.Release()
	<-closedFirst
	for ownershipCount(manager) != 1 {
		runtime.Gosched()
	}
	if manager.Active() != second.result.ActiveGraph() || ownershipCount(manager) != 1 {
		t.Fatalf("eventual gen1 cleanup disturbed active=%p want=%p owned=%d",
			manager.Active(), second.result.ActiveGraph(), ownershipCount(manager))
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}

func equalBools(left, right []bool) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func waitForDeadlineCalls(deadlines *fakeDeadlines, count int) {
	for len(deadlines.calls()) < count {
		runtime.Gosched()
	}
}

func waitForRetryCount(retries *fakeRetryScheduler, count int) {
	for retries.count() < count {
		runtime.Gosched()
	}
}

func ownershipCount(manager *Manager) int {
	manager.ownershipMu.Lock()
	defer manager.ownershipMu.Unlock()
	return len(manager.owned)
}

func pendingCount(manager *Manager) int {
	manager.cleanupMu.Lock()
	defer manager.cleanupMu.Unlock()
	return len(manager.pending)
}

func flushReports(t *testing.T, manager *Manager) {
	t.Helper()
	if err := manager.FlushReports(t.Context()); err != nil {
		t.Fatal(err)
	}
}
