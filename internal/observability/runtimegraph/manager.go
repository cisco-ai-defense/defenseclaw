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

// Package runtimegraph owns atomic publication and bounded retirement of one
// immutable observability-v8 policy/runtime graph.
package runtimegraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	FieldLocalPath         = "observability.local.path"
	FieldJudgeBodiesPath   = "observability.local.judge_bodies_path"
	FieldRetainJudgeBodies = "guardrail.retain_judge_bodies"
)

// Config is the complete immutable input captured by one graph. Duplicated
// effective values are checked against Plan so integration cannot accidentally
// pair a plan with paths, retention, or a digest from another generation.
type Config struct {
	Plan              *config.ObservabilityV8Plan
	PlanDigest        string
	LocalPath         string
	JudgeBodiesPath   string
	RetentionDays     int
	RetainJudgeBodies bool
}

// ConfigFromPlan creates a coherent graph input from one compiled plan.
func ConfigFromPlan(plan *config.ObservabilityV8Plan, retainJudgeBodies bool) Config {
	if plan == nil {
		return Config{RetainJudgeBodies: retainJudgeBodies}
	}
	local := plan.Snapshot().Local
	return Config{
		Plan: plan, PlanDigest: plan.Digest(), LocalPath: local.Path,
		JudgeBodiesPath: local.JudgeBodiesPath, RetentionDays: local.RetentionDays,
		RetainJudgeBodies: retainJudgeBodies,
	}
}

// Component owns one generation's intake and queue and must be implemented by
// a non-nil pointer so generation identity can be checked. Activate is
// infallible and must be nonblocking; all fallible work belongs in Prepare. Child workers,
// transports, listeners, timers, and connections acquired during initialization
// are also registered independently through Acquisitions.
type Component interface {
	Activate()
	StopIntake(context.Context) error
	Drain(context.Context) error
	Close(context.Context) error
}

// ComponentFactory is invoked in configured order while a candidate remains
// unreachable by producers.
type ComponentFactory interface {
	Name() string
	Prepare(context.Context, BuildInput, *Acquisitions) (Component, error)
}

// RebuildDecider lets a factory preserve an out-of-graph process-stable
// dispatcher on policy-only reloads. Prepare is still called and MUST return a
// distinct generation-owned queue/component wrapper; runtime components are
// never shared across graphs.
type RebuildDecider interface {
	NeedsRebuild(previous Config, candidate Config) bool
}

// CleanupFunc releases one acquired child. It must be idempotent because a
// backend may also defensively release a child during its own failed startup.
type CleanupFunc func(context.Context) error

type acquiredChild struct {
	name    string
	cleanup CleanupFunc
}

// Acquisitions is scoped to one synchronous factory initialization. Register
// must be called immediately after each child acquisition. The manager seals
// the scope when Prepare returns and always cleans registered children in
// reverse acquisition order, including when Prepare returns nil or error.
type Acquisitions struct {
	mu       sync.Mutex
	sealed   bool
	children []acquiredChild
}

func (acquisitions *Acquisitions) Register(name string, cleanup CleanupFunc) error {
	if acquisitions == nil || !observability.IsStableToken(name) || cleanup == nil {
		return &Error{code: ErrorInvalidDependency}
	}
	acquisitions.mu.Lock()
	defer acquisitions.mu.Unlock()
	if acquisitions.sealed {
		return &Error{code: ErrorInitialization}
	}
	acquisitions.children = append(acquisitions.children, acquiredChild{name: name, cleanup: cleanup})
	return nil
}

func (acquisitions *Acquisitions) seal() []acquiredChild {
	acquisitions.mu.Lock()
	defer acquisitions.mu.Unlock()
	acquisitions.sealed = true
	return append([]acquiredChild(nil), acquisitions.children...)
}

// BuildInput is a value-safe generation snapshot. Only the previous digest is
// exposed: candidate factories cannot reach or mutate active old components.
type BuildInput struct {
	Config         Config
	Generation     uint64
	PreviousDigest string
	Rebuild        bool
}

// Clock and DeadlineFactory make cleanup/report timing deterministic in tests.
type Clock interface{ Now() time.Time }

type DeadlineFactory interface {
	Context(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

// RetryScheduler separates cleanup retry timing from lifecycle deadlines.
type RetryScheduler interface {
	After(time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type timeoutDeadlineFactory struct{}

func (timeoutDeadlineFactory) Context(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

type timerRetryScheduler struct{}

func (timerRetryScheduler) After(delay time.Duration) <-chan time.Time { return time.After(delay) }

// ReportCode is deliberately closed and contains no config value, endpoint,
// payload, or underlying error text.
type ReportCode string

const (
	ReportReloadApplied      ReportCode = "reload_applied"
	ReportValidationRejected ReportCode = "reload_validation_rejected"
	ReportRestartRequired    ReportCode = "reload_restart_required"
	ReportInitializationFail ReportCode = "reload_initialization_failed"
	ReportCleanupFailed      ReportCode = "reload_cleanup_failed"
	ReportDrainFailed        ReportCode = "reload_drain_failed"
)

// Report is safe for both mandatory compliance activity and platform health.
type Report struct {
	Code          ReportCode
	Outcome       string
	FieldPath     string
	ComponentName string
	Generation    uint64
	OccurredAt    time.Time
	// DeliverySequence and DeliveryIndex form a manager-scoped stable
	// envelope identity. Production reporters combine them with their process
	// run ID and idempotently deduplicate retries.
	DeliverySequence uint64
	DeliveryIndex    uint32
}

// Reporter emits bounded reload state through the graph supplied by Manager.
// A rejected candidate is always reported through the exact still-active old
// graph. A successful swap and post-swap drain failures use the new graph.
// Methods may be retried after returning an error or panicking, including when
// the first call committed before it failed. Implementations MUST idempotently
// deduplicate the Report delivery identity and return errors without embedding
// sensitive backend diagnostics.
type Reporter interface {
	PlatformHealth(*Graph, Report) error
	ComplianceActivity(*Graph, Report) error
}

// ErrorCode is a bounded reload failure identity.
type ErrorCode string

const (
	ErrorInvalidDependency ErrorCode = "invalid_dependency"
	ErrorInvalidConfig     ErrorCode = "invalid_config"
	ErrorRestartRequired   ErrorCode = "restart_required"
	ErrorInitialization    ErrorCode = "initialization_failed"
	ErrorReporting         ErrorCode = "reporting_failed"
	ErrorClosed            ErrorCode = "manager_closed"
	ErrorShutdown          ErrorCode = "shutdown_degraded"
)

// Error never unwraps arbitrary component/config diagnostics. Context
// cancellation remains detectable without retaining an error message.
type Error struct {
	code          ErrorCode
	fieldPath     string
	componentName string
	contextCause  error
}

func (err *Error) Error() string {
	if err == nil {
		return "observability runtime graph operation failed"
	}
	message := "observability runtime graph operation failed: " + string(err.code)
	if err.fieldPath != "" {
		message += ": " + err.fieldPath
	}
	if err.componentName != "" {
		message += ": " + err.componentName
	}
	return message
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func (err *Error) FieldPath() string {
	if err == nil {
		return ""
	}
	return err.fieldPath
}

func (err *Error) ComponentName() string {
	if err == nil {
		return ""
	}
	return err.componentName
}

func (err *Error) Is(target error) bool {
	return err != nil && err.contextCause != nil && errors.Is(err.contextCause, target)
}

type componentEntry struct {
	name      string
	component Component
	children  []acquiredChild
	started   bool
	stopped   bool
	drained   bool
	available bool
	closed    bool
	identity  componentIdentity
	claimed   bool
}

// Graph is immutable after construction. Component ownership and membership
// are fixed; component internals may process their own generation-local queue.
type Graph struct {
	config     Config
	generation uint64
	components []*componentEntry
	byName     map[string]*componentEntry
	activation graphActivation
}

type graphActivation struct {
	mu        sync.Mutex
	retired   bool
	ready     bool
	users     int
	quiescent chan struct{}
	readyCh   chan struct{}
}

func (graph *Graph) Plan() *config.ObservabilityV8Plan {
	if graph == nil {
		return nil
	}
	return graph.config.Plan
}

func (graph *Graph) Digest() string {
	if graph == nil {
		return ""
	}
	return graph.config.PlanDigest
}

func (graph *Graph) Generation() uint64 {
	if graph == nil {
		return 0
	}
	return graph.generation
}

func (graph *Graph) RetentionDays() int {
	if graph == nil {
		return 0
	}
	return graph.config.RetentionDays
}

func (graph *Graph) RetainJudgeBodies() bool {
	return graph != nil && graph.config.RetainJudgeBodies
}

func (graph *Graph) LocalPath() string {
	if graph == nil {
		return ""
	}
	return graph.config.LocalPath
}

func (graph *Graph) JudgeBodiesPath() string {
	if graph == nil {
		return ""
	}
	return graph.config.JudgeBodiesPath
}

// Lease pins one graph generation while a producer reads policy and submits
// work. Release must be called exactly once; retirement waits for all leases.
type Lease struct {
	graph    *Graph
	released atomic.Bool
}

func (lease *Lease) Graph() *Graph {
	if lease == nil || lease.released.Load() {
		return nil
	}
	return lease.graph
}

// Component returns the fixed generation-local instance only while the lease
// is live. A queued projection therefore cannot race component retirement.
func (lease *Lease) Component(name string) (Component, bool) {
	graph := lease.Graph()
	if graph == nil {
		return nil, false
	}
	entry, ok := graph.byName[name]
	if !ok || !entry.available || entry.closed {
		return nil, false
	}
	return entry.component, true
}

// Fork creates an independently releasable lease on the exact same graph
// generation. It is valid while the source lease is live, including after a
// replacement generation has begun retirement. This lets a bounded child
// operation release producer locks before invoking callbacks without allowing
// the retired graph to close underneath that work.
func (lease *Lease) Fork() *Lease {
	if lease == nil || lease.graph == nil || lease.released.Load() {
		return nil
	}
	graph := lease.graph
	graph.activation.mu.Lock()
	defer graph.activation.mu.Unlock()
	if lease.released.Load() || graph.activation.users <= 0 {
		return nil
	}
	graph.activation.users++
	return &Lease{graph: graph}
}

func (lease *Lease) Release() {
	if lease == nil || lease.graph == nil || !lease.released.CompareAndSwap(false, true) {
		return
	}
	lease.graph.release()
}

// Options controls deterministic graph lifecycle behavior.
type Options struct {
	DrainTimeout      time.Duration
	CleanupRetryDelay time.Duration
	Clock             Clock
	Deadlines         DeadlineFactory
	RetryScheduler    RetryScheduler
	Reporter          Reporter
}

// Manager serializes reload transactions while readers use one atomic load.
type Manager struct {
	active            atomic.Pointer[Graph]
	reloadMu          sync.Mutex
	factories         []ComponentFactory
	drainTimeout      time.Duration
	cleanupRetryDelay time.Duration
	clock             Clock
	deadlines         DeadlineFactory
	retryScheduler    RetryScheduler
	reporter          Reporter
	closed            atomic.Bool
	testHooks         *managerTestHooks
	reporterStarted   atomic.Bool
	reporterStopped   chan struct{}
	reportBatchSeq    atomic.Uint64
	reportAccepted    atomic.Uint64
	reportCompleted   atomic.Uint64
	reportFailed      atomic.Bool
	reportProgressMu  sync.Mutex
	reportProgress    chan struct{}
	// reportSpool is an ordered, lossless process-memory handoff. Appenders
	// never wait for the single reporter consumer, which keeps Reporter
	// callbacks safely reentrant into Reload even during an exporter stall.
	reportSpoolMu     sync.Mutex
	reportSpool       map[uint64]reportBatch
	reportSpoolWake   chan struct{}
	reportSpoolClosed bool
	reportDelivering  uint64
	ownershipMu       sync.Mutex
	owned             map[componentIdentity]struct{}
	cleanupMu         sync.Mutex
	pending           map[*cleanupBatch]struct{}
	cleanupProgress   chan struct{}
	asyncCleanup      atomic.Int64
}

type cleanupBatch struct {
	entries []*componentEntry
}

type reportKind uint8

const (
	reportHealthKind reportKind = iota + 1
	reportComplianceKind
)

type reportEnvelope struct {
	kind   reportKind
	graph  *Graph
	report Report
}

type reportBatch struct {
	sequence  uint64
	envelopes []reportEnvelope
}

type componentIdentity struct {
	typeName string
	pointer  uintptr
}

// managerTestHooks is intentionally unexported and nil in production. It lets
// same-package tests suspend the exact lock-free acquisition windows without
// adding sleeps or changing the public runtime contract.
type managerTestHooks struct {
	afterAcquireLoad               func(*Graph)
	afterAcquireIncrement          func(*Graph)
	afterAcquireActiveRevalidation func(*Graph)
	afterSwapBeforeRetire          func(*Graph, *Graph)
	beforeReportDispatch           func(uint64)
}

// New initializes and publishes generation one only after every factory has
// completed. No partially built initial graph is ever observable.
func New(
	ctx context.Context,
	initial Config,
	factories []ComponentFactory,
	options Options,
) (*Manager, error) {
	manager, err := newManager(factories, options)
	if err != nil {
		return nil, err
	}
	if err := validateConfig(initial); err != nil {
		return nil, err
	}
	graph, buildErr := manager.build(ctx, initial, 1, nil, nil)
	if buildErr != nil {
		// A component that could not be released remains owned by this
		// manager and is retried on the bounded scheduler. Return the handle
		// with the error so the caller can WaitCleanup or Close it; a failed
		// initial build never starts the reporter worker.
		if manager.hasPendingCleanup() {
			manager.closed.Store(true)
			return manager, buildErr
		}
		return nil, buildErr
	}
	manager.active.Store(graph)
	manager.activate(graph)
	manager.startReporter()
	initialReports := reportBatch{}
	manager.addCompliance(&initialReports, graph, ReportReloadApplied, "applied", "", "")
	manager.sequenceReports(&initialReports)
	if dispatchErr := manager.dispatchReports(context.Background(), initialReports); dispatchErr != nil {
		manager.closed.Store(true)
		manager.active.Store(nil)
		_ = manager.retire(graph, graph, context.Background())
		manager.requestReporterClose()
		return manager, dispatchErr
	}
	return manager, nil
}

func newManager(factories []ComponentFactory, options Options) (*Manager, error) {
	if options.CleanupRetryDelay <= 0 {
		options.CleanupRetryDelay = time.Second
	}
	if isNil(options.RetryScheduler) {
		options.RetryScheduler = timerRetryScheduler{}
	}
	if options.DrainTimeout <= 0 || isNil(options.Clock) || isNil(options.Deadlines) || isNil(options.Reporter) {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	copyFactories := append([]ComponentFactory(nil), factories...)
	seen := make(map[string]struct{}, len(copyFactories))
	for _, factory := range copyFactories {
		if isNil(factory) || !observability.IsStableToken(factory.Name()) {
			return nil, &Error{code: ErrorInvalidDependency}
		}
		if _, duplicate := seen[factory.Name()]; duplicate {
			return nil, &Error{code: ErrorInvalidDependency}
		}
		seen[factory.Name()] = struct{}{}
	}
	manager := &Manager{
		factories: copyFactories, drainTimeout: options.DrainTimeout,
		clock: options.Clock, deadlines: options.Deadlines, reporter: options.Reporter,
		reporterStopped: make(chan struct{}), reportProgress: make(chan struct{}),
		reportSpool: make(map[uint64]reportBatch), reportSpoolWake: make(chan struct{}),
		cleanupProgress: make(chan struct{}),
		owned:           make(map[componentIdentity]struct{}), pending: make(map[*cleanupBatch]struct{}),
	}
	manager.cleanupRetryDelay = options.CleanupRetryDelay
	manager.retryScheduler = options.RetryScheduler
	return manager, nil
}

// Active returns exactly the old or new immutable pointer with one atomic load.
func (manager *Manager) Active() *Graph {
	if manager == nil {
		return nil
	}
	return manager.active.Load()
}

// Acquire returns a lease on exactly one complete active generation. It loops
// only when its first load raced retirement; it never acquires a retired graph.
func (manager *Manager) Acquire(ctx context.Context) (*Lease, *Error) {
	if manager == nil || ctx == nil {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	for {
		if manager.closed.Load() {
			return nil, &Error{code: ErrorClosed}
		}
		graph := manager.active.Load()
		if graph == nil {
			return nil, &Error{code: ErrorClosed}
		}
		if manager.testHooks != nil && manager.testHooks.afterAcquireLoad != nil {
			manager.testHooks.afterAcquireLoad(graph)
		}
		acquired, err := graph.acquire(ctx)
		if err != nil {
			return nil, &Error{code: ErrorInitialization, contextCause: contextIdentity(err)}
		}
		if acquired {
			if manager.testHooks != nil && manager.testHooks.afterAcquireIncrement != nil {
				manager.testHooks.afterAcquireIncrement(graph)
			}
			// Linearize producer acquisition only after proving that the graph
			// remains active and shutdown has not started. If swap/Close won the
			// race, immediately undo the refcount before retrying or returning.
			sameActive := manager.active.Load() == graph
			if manager.testHooks != nil && manager.testHooks.afterAcquireActiveRevalidation != nil {
				manager.testHooks.afterAcquireActiveRevalidation(graph)
			}
			if sameActive && !manager.closed.Load() {
				return &Lease{graph: graph}, nil
			}
			graph.release()
			if manager.closed.Load() {
				return nil, &Error{code: ErrorClosed}
			}
			continue
		}
		if manager.closed.Load() {
			return nil, &Error{code: ErrorClosed}
		}
		if manager.active.Load() == graph {
			return nil, &Error{code: ErrorInitialization}
		}
	}
}

// ReloadStatus makes publication state unambiguous to config owners.
type ReloadStatus string

const (
	ReloadRejected        ReloadStatus = "rejected"
	ReloadApplied         ReloadStatus = "applied"
	ReloadAppliedDegraded ReloadStatus = "applied_degraded"
)

// ReloadResult always identifies the graph that remains active on return.
// Post-publish drain failure is AppliedDegraded with no rejection error.
type ReloadResult struct {
	active *Graph
	status ReloadStatus
}

func (result ReloadResult) ActiveGraph() *Graph  { return result.active }
func (result ReloadResult) Status() ReloadStatus { return result.status }

// Reload builds a complete candidate off-path, publishes it with exactly one
// atomic swap, then retires the old graph. Every pre-swap failure preserves the
// exact old pointer.
func (manager *Manager) Reload(ctx context.Context, candidate Config) (ReloadResult, *Error) {
	if manager == nil || ctx == nil {
		return ReloadResult{status: ReloadRejected}, &Error{code: ErrorInvalidDependency}
	}
	manager.reloadMu.Lock()
	reports := reportBatch{}
	finish := func(result ReloadResult, err *Error) (ReloadResult, *Error) {
		// Allocate the transaction sequence while lifecycle serialization is
		// still held. Delivery happens outside the lock; ordered admission and
		// worker-side sequence checks preserve this order under concurrency.
		manager.sequenceReports(&reports)
		manager.reloadMu.Unlock()
		if manager.testHooks != nil && manager.testHooks.beforeReportDispatch != nil {
			manager.testHooks.beforeReportDispatch(reports.sequence)
		}
		_ = manager.dispatchReports(context.Background(), reports)
		return result, err
	}
	if manager.closed.Load() {
		return finish(ReloadResult{active: manager.active.Load(), status: ReloadRejected}, &Error{code: ErrorClosed})
	}

	old := manager.active.Load()
	if old == nil {
		return finish(ReloadResult{status: ReloadRejected}, &Error{code: ErrorInvalidDependency})
	}
	if err := validateConfig(candidate); err != nil {
		manager.addRejected(&reports, old, err, "")
		return finish(ReloadResult{active: old, status: ReloadRejected}, err)
	}
	if field := restartRequiredField(old, candidate); field != "" {
		err := &Error{code: ErrorRestartRequired, fieldPath: field}
		manager.addRejected(&reports, old, err, "")
		return finish(ReloadResult{active: old, status: ReloadRejected}, err)
	}
	if err := ctx.Err(); err != nil {
		bounded := &Error{code: ErrorInitialization, contextCause: contextIdentity(err)}
		manager.addRejected(&reports, old, bounded, "")
		return finish(ReloadResult{active: old, status: ReloadRejected}, bounded)
	}

	newGraph, err := manager.build(ctx, candidate, old.generation+1, old, &reports)
	if err != nil {
		manager.addRejected(&reports, old, err, err.ComponentName())
		return finish(ReloadResult{active: old, status: ReloadRejected}, err)
	}

	previous := manager.active.Swap(newGraph)
	if manager.testHooks != nil && manager.testHooks.afterSwapBeforeRetire != nil {
		manager.testHooks.afterSwapBeforeRetire(previous, newGraph)
	}
	if previous != old {
		// Reloads are serialized; reaching this branch indicates an external
		// invariant violation. Keep the newly published complete graph active.
		manager.addHealth(&reports, newGraph, ReportDrainFailed, "failed", "", "")
	}
	manager.activate(newGraph)
	degraded := false
	cleanup := manager.retire(previous, newGraph, context.Background())
	if cleanup.failed {
		degraded = true
		manager.addHealth(&reports, newGraph, ReportDrainFailed, "failed", "", cleanup.componentName)
		manager.addCompliance(&reports, newGraph, ReportDrainFailed, "failed", "", cleanup.componentName)
	}
	if degraded {
		manager.addCompliance(&reports, newGraph, ReportReloadApplied, "applied", "", "")
		return finish(ReloadResult{active: newGraph, status: ReloadAppliedDegraded}, nil)
	}
	manager.addCompliance(&reports, newGraph, ReportReloadApplied, "applied", "", "")
	return finish(ReloadResult{active: newGraph, status: ReloadApplied}, nil)
}

// Close prevents new reloads and acquisitions, atomically detaches the active
// graph, and retires it exactly once. If an in-flight lease exceeds the bounded
// wait, Close returns a degraded shutdown error and cleanup continues safely
// after that lease releases; components are never closed under a live lease.
func (manager *Manager) Close(ctx context.Context) *Error {
	if manager == nil || ctx == nil {
		return &Error{code: ErrorInvalidDependency}
	}
	manager.reloadMu.Lock()
	reports := reportBatch{}
	finish := func(err *Error) *Error {
		manager.sequenceReports(&reports)
		manager.reloadMu.Unlock()
		if manager.testHooks != nil && manager.testHooks.beforeReportDispatch != nil {
			manager.testHooks.beforeReportDispatch(reports.sequence)
		}
		_ = manager.dispatchReports(context.Background(), reports)
		manager.maybeCloseReporter()
		return err
	}
	if manager.closed.Swap(true) {
		return finish(nil)
	}
	graph := manager.active.Swap(nil)
	if manager.testHooks != nil && manager.testHooks.afterSwapBeforeRetire != nil {
		manager.testHooks.afterSwapBeforeRetire(graph, nil)
	}
	cleanup := manager.retire(graph, graph, ctx)
	if !cleanup.failed {
		return finish(nil)
	}
	manager.addHealth(&reports, graph, ReportDrainFailed, "failed", "", cleanup.componentName)
	manager.addCompliance(&reports, graph, ReportDrainFailed, "failed", "", cleanup.componentName)
	return finish(&Error{code: ErrorShutdown, componentName: cleanup.componentName})
}

func (manager *Manager) build(
	ctx context.Context,
	candidate Config,
	generation uint64,
	previous *Graph,
	reports *reportBatch,
) (*Graph, *Error) {
	entries := make([]*componentEntry, 0, len(manager.factories))
	for _, factory := range manager.factories {
		acquisitions := &Acquisitions{}
		previousDigest := ""
		rebuild := true
		if previous != nil {
			previousDigest = previous.Digest()
			if decider, ok := factory.(RebuildDecider); ok {
				rebuild = decider.NeedsRebuild(previous.config, candidate)
			}
		}
		component, err := factory.Prepare(ctx, BuildInput{
			Config: candidate, Generation: generation, PreviousDigest: previousDigest, Rebuild: rebuild,
		}, acquisitions)
		children := acquisitions.seal()
		componentValid := validComponent(component)
		identity := componentIdentity{}
		claimed := false
		if componentValid {
			identity, claimed = manager.claimComponent(component)
			if !claimed {
				// Ownership spans active, retiring, and rejected graphs. Never
				// cleanup a component still owned by another generation.
				component = nil
				componentValid = false
				if err == nil {
					err = &Error{code: ErrorInitialization}
				}
			}
		}
		if componentValid || len(children) > 0 {
			entries = append(entries, &componentEntry{
				name: factory.Name(), component: component, children: children,
				identity: identity, claimed: claimed,
			})
		}
		if err != nil || !componentValid {
			cleanup := manager.cleanup(entries)
			if cleanup.failed {
				if previous != nil {
					manager.addHealth(reports, previous, ReportCleanupFailed, "failed", "", cleanup.componentName)
					manager.addCompliance(reports, previous, ReportCleanupFailed, "rejected", "", cleanup.componentName)
				}
				manager.scheduleCleanupRetry(entries)
			}
			bounded := &Error{code: ErrorInitialization, componentName: factory.Name()}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				bounded.contextCause = contextIdentity(err)
			}
			return nil, bounded
		}
	}
	if err := ctx.Err(); err != nil {
		cleanup := manager.cleanup(entries)
		if cleanup.failed {
			if previous != nil {
				manager.addHealth(reports, previous, ReportCleanupFailed, "failed", "", cleanup.componentName)
				manager.addCompliance(reports, previous, ReportCleanupFailed, "rejected", "", cleanup.componentName)
			}
			manager.scheduleCleanupRetry(entries)
		}
		return nil, &Error{code: ErrorInitialization, contextCause: contextIdentity(err)}
	}
	byName := make(map[string]*componentEntry, len(entries))
	for _, entry := range entries {
		if entry.component != nil {
			byName[entry.name] = entry
		}
	}
	return &Graph{
		config: candidate, generation: generation,
		components: append([]*componentEntry(nil), entries...), byName: byName,
		activation: graphActivation{readyCh: make(chan struct{})},
	}, nil
}

type cleanupResult struct {
	failed        bool
	componentName string
}

func (manager *Manager) activate(graph *Graph) {
	for _, entry := range graph.components {
		entry.started = true
		entry.component.Activate()
		entry.available = true
	}
	graph.finishActivation()
}

func (manager *Manager) cleanup(entries []*componentEntry) cleanupResult {
	return manager.teardown(entries)
}

func (manager *Manager) retire(graph, reportGraph *Graph, parent context.Context) cleanupResult {
	if graph == nil {
		return cleanupResult{}
	}
	ctx, cancel := manager.deadlines.Context(parent, manager.drainTimeout)
	defer cancel()
	quiescent := graph.beginRetirement()
	select {
	case <-quiescent:
		cleanup := manager.teardownEntries(ctx, graph.components)
		if cleanup.failed {
			manager.scheduleCleanupRetry(graph.components)
		}
		return cleanup
	case <-ctx.Done():
		manager.asyncCleanup.Add(1)
		go manager.cleanupAfterQuiescence(graph, reportGraph, quiescent)
		return cleanupResult{failed: true, componentName: "inflight-users"}
	}
}

func (manager *Manager) cleanupAfterQuiescence(
	graph, reportGraph *Graph,
	quiescent <-chan struct{},
) {
	defer func() {
		manager.asyncCleanup.Add(-1)
		manager.cleanupMu.Lock()
		manager.notifyCleanupProgressLocked()
		manager.cleanupMu.Unlock()
		manager.maybeCloseReporter()
	}()
	<-quiescent
	cleanup := manager.teardown(graph.components)
	if !cleanup.failed {
		return
	}
	active := manager.Active()
	if active == nil {
		active = reportGraph
	}
	reports := reportBatch{}
	manager.addHealth(&reports, active, ReportDrainFailed, "failed", "", cleanup.componentName)
	manager.addCompliance(&reports, active, ReportDrainFailed, "failed", "", cleanup.componentName)
	manager.sequenceReports(&reports)
	_ = manager.dispatchReports(context.Background(), reports)
	manager.scheduleCleanupRetry(graph.components)
}

func (manager *Manager) scheduleCleanupRetry(entries []*componentEntry) {
	if !hasCleanupOwnership(entries) {
		return
	}
	batch := &cleanupBatch{entries: entries}
	manager.cleanupMu.Lock()
	manager.pending[batch] = struct{}{}
	manager.notifyCleanupProgressLocked()
	manager.cleanupMu.Unlock()
	go manager.retryCleanup(batch)
}

func hasCleanupOwnership(entries []*componentEntry) bool {
	for _, entry := range entries {
		if (entry.component != nil && !entry.closed) || len(entry.children) > 0 || entry.claimed {
			return true
		}
	}
	return false
}

func (manager *Manager) retryCleanup(batch *cleanupBatch) {
	for {
		<-manager.retryScheduler.After(manager.cleanupRetryDelay)
		cleanup := manager.teardown(batch.entries)
		if !cleanup.failed {
			manager.cleanupMu.Lock()
			delete(manager.pending, batch)
			manager.notifyCleanupProgressLocked()
			manager.cleanupMu.Unlock()
			manager.maybeCloseReporter()
			return
		}
		// The originating failure already emitted one bounded report. Retrying
		// on the configured scheduler is deliberately silent to prevent a
		// permanent backend failure from flooding mandatory telemetry.
	}
}

func (manager *Manager) hasPendingCleanup() bool {
	manager.cleanupMu.Lock()
	defer manager.cleanupMu.Unlock()
	return len(manager.pending) != 0
}

func (manager *Manager) notifyCleanupProgressLocked() {
	close(manager.cleanupProgress)
	manager.cleanupProgress = make(chan struct{})
}

// WaitCleanup waits until all component and child cleanup ownership has been
// released. It is primarily useful when New returns both a manager and an
// initialization error because an acquired resource needs eventual retry.
func (manager *Manager) WaitCleanup(ctx context.Context) *Error {
	if manager == nil || ctx == nil {
		return &Error{code: ErrorInvalidDependency}
	}
	for {
		manager.cleanupMu.Lock()
		if len(manager.pending) == 0 && manager.asyncCleanup.Load() == 0 {
			manager.cleanupMu.Unlock()
			return nil
		}
		progress := manager.cleanupProgress
		manager.cleanupMu.Unlock()
		select {
		case <-progress:
		case <-ctx.Done():
			return &Error{code: ErrorShutdown, contextCause: contextIdentity(ctx.Err())}
		}
	}
}

func (manager *Manager) maybeCloseReporter() {
	if manager == nil || !manager.closed.Load() || manager.asyncCleanup.Load() != 0 {
		return
	}
	manager.cleanupMu.Lock()
	pending := len(manager.pending)
	manager.cleanupMu.Unlock()
	if pending == 0 && manager.reportAccepted.Load() == manager.reportBatchSeq.Load() {
		manager.requestReporterClose()
	}
}

func (manager *Manager) teardown(entries []*componentEntry) cleanupResult {
	ctx, cancel := manager.deadlines.Context(context.Background(), manager.drainTimeout)
	defer cancel()
	return manager.teardownEntries(ctx, entries)
}

func (manager *Manager) teardownEntries(ctx context.Context, entries []*componentEntry) cleanupResult {
	result := cleanupResult{}
	record := func(name string, err error) {
		if err != nil && !result.failed {
			result.failed = true
			result.componentName = name
		}
	}
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if entry.component != nil && entry.started && !entry.stopped && !entry.closed {
			stopErr := entry.component.StopIntake(ctx)
			record(entry.name, stopErr)
			if stopErr == nil {
				entry.stopped = true
			}
		}
	}
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if entry.component != nil && !entry.closed {
			if entry.started && !entry.drained {
				drainErr := entry.component.Drain(ctx)
				record(entry.name, drainErr)
				if drainErr == nil {
					entry.drained = true
				}
			}
			closeErr := entry.component.Close(ctx)
			record(entry.name, closeErr)
			if closeErr == nil {
				entry.closed = true
			}
		}
		failedChildren := make([]acquiredChild, 0, len(entry.children))
		for childIndex := len(entry.children) - 1; childIndex >= 0; childIndex-- {
			child := entry.children[childIndex]
			if cleanupErr := child.cleanup(ctx); cleanupErr != nil {
				record(entry.name, cleanupErr)
				failedChildren = append(failedChildren, child)
			}
		}
		for left, right := 0, len(failedChildren)-1; left < right; left, right = left+1, right-1 {
			failedChildren[left], failedChildren[right] = failedChildren[right], failedChildren[left]
		}
		entry.children = failedChildren
		if entry.claimed && entry.closed && len(entry.children) == 0 {
			manager.releaseComponent(entry.identity)
			entry.claimed = false
		}
	}
	return result
}

func (graph *Graph) finishActivation() {
	graph.activation.mu.Lock()
	defer graph.activation.mu.Unlock()
	if graph.activation.ready {
		return
	}
	graph.activation.ready = true
	close(graph.activation.readyCh)
}

func (graph *Graph) acquire(ctx context.Context) (bool, error) {
	for {
		graph.activation.mu.Lock()
		if graph.activation.retired {
			graph.activation.mu.Unlock()
			return false, nil
		}
		if graph.activation.ready {
			graph.activation.users++
			graph.activation.mu.Unlock()
			return true, nil
		}
		ready := graph.activation.readyCh
		graph.activation.mu.Unlock()
		select {
		case <-ready:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

func (graph *Graph) release() {
	graph.activation.mu.Lock()
	defer graph.activation.mu.Unlock()
	if graph.activation.users <= 0 {
		return
	}
	graph.activation.users--
	if graph.activation.retired && graph.activation.users == 0 && graph.activation.quiescent != nil {
		close(graph.activation.quiescent)
		graph.activation.quiescent = nil
	}
}

func (graph *Graph) beginRetirement() <-chan struct{} {
	graph.activation.mu.Lock()
	defer graph.activation.mu.Unlock()
	graph.activation.retired = true
	quiescent := make(chan struct{})
	if graph.activation.users == 0 {
		close(quiescent)
		return quiescent
	}
	graph.activation.quiescent = quiescent
	return quiescent
}

func (manager *Manager) claimComponent(component Component) (componentIdentity, bool) {
	value := reflect.ValueOf(component)
	identity := componentIdentity{typeName: value.Type().String(), pointer: value.Pointer()}
	manager.ownershipMu.Lock()
	defer manager.ownershipMu.Unlock()
	if _, exists := manager.owned[identity]; exists {
		return identity, false
	}
	manager.owned[identity] = struct{}{}
	return identity, true
}

func (manager *Manager) releaseComponent(identity componentIdentity) {
	manager.ownershipMu.Lock()
	delete(manager.owned, identity)
	manager.ownershipMu.Unlock()
}

func validComponent(component Component) bool {
	if isNil(component) {
		return false
	}
	value := reflect.ValueOf(component)
	return value.Kind() == reflect.Pointer && !value.IsNil()
}

func validateConfig(candidate Config) *Error {
	if candidate.Plan == nil || !validDigest(candidate.PlanDigest) ||
		candidate.PlanDigest != candidate.Plan.Digest() || candidate.RetentionDays < 0 ||
		candidate.LocalPath == "" || candidate.JudgeBodiesPath == "" ||
		candidate.LocalPath == candidate.JudgeBodiesPath {
		return &Error{code: ErrorInvalidConfig}
	}
	local := candidate.Plan.Snapshot().Local
	if candidate.LocalPath != local.Path || candidate.JudgeBodiesPath != local.JudgeBodiesPath ||
		candidate.RetentionDays != local.RetentionDays {
		return &Error{code: ErrorInvalidConfig}
	}
	return nil
}

func restartRequiredField(old *Graph, candidate Config) string {
	if old.config.LocalPath != candidate.LocalPath {
		return FieldLocalPath
	}
	if old.config.JudgeBodiesPath != candidate.JudgeBodiesPath {
		return FieldJudgeBodiesPath
	}
	if old.config.RetainJudgeBodies != candidate.RetainJudgeBodies {
		return FieldRetainJudgeBodies
	}
	oldDestinations := old.config.Plan.Snapshot().Destinations
	candidateDestinations := candidate.Plan.Snapshot().Destinations
	for _, candidateDestination := range candidateDestinations {
		if candidateDestination.Kind != config.ObservabilityV8DestinationPrometheus ||
			!candidateDestination.Enabled || candidateDestination.Transport.Listen == "" {
			continue
		}
		for _, oldDestination := range oldDestinations {
			if oldDestination.Kind == config.ObservabilityV8DestinationPrometheus &&
				oldDestination.Enabled &&
				oldDestination.Transport.Listen == candidateDestination.Transport.Listen {
				return "observability.destinations." + candidateDestination.Name + ".listen"
			}
		}
	}
	return ""
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || !observability.IsStableToken(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (manager *Manager) addRejected(batch *reportBatch, graph *Graph, err *Error, component string) {
	code := ReportValidationRejected
	if err.Code() == ErrorRestartRequired {
		code = ReportRestartRequired
	} else if err.Code() == ErrorInitialization {
		code = ReportInitializationFail
	}
	manager.addHealth(batch, graph, code, "rejected", err.FieldPath(), component)
	manager.addCompliance(batch, graph, code, "rejected", err.FieldPath(), component)
}

func (manager *Manager) addHealth(
	batch *reportBatch,
	graph *Graph,
	code ReportCode,
	outcome, fieldPath, component string,
) {
	batch.envelopes = append(batch.envelopes, reportEnvelope{
		kind: reportHealthKind, graph: graph,
		report: manager.newReport(graph, code, outcome, fieldPath, component),
	})
}

func (manager *Manager) addCompliance(
	batch *reportBatch,
	graph *Graph,
	code ReportCode,
	outcome, fieldPath, component string,
) {
	batch.envelopes = append(batch.envelopes, reportEnvelope{
		kind: reportComplianceKind, graph: graph,
		report: manager.newReport(graph, code, outcome, fieldPath, component),
	})
}

func (manager *Manager) startReporter() {
	if manager.reporterStarted.CompareAndSwap(false, true) {
		go manager.deliverReports()
	}
}

func (manager *Manager) deliverReports() {
	defer close(manager.reporterStopped)
	expected := uint64(1)
	for {
		manager.reportSpoolMu.Lock()
		batch, exists := manager.reportSpool[expected]
		if exists {
			delete(manager.reportSpool, expected)
			manager.reportDelivering = expected
			manager.reportSpoolMu.Unlock()
			manager.deliverReportBatch(batch)
			manager.markReportsCompleted(expected)
			expected++
			continue
		}
		if manager.reportSpoolClosed {
			manager.reportSpoolMu.Unlock()
			return
		}
		wake := manager.reportSpoolWake
		manager.reportSpoolMu.Unlock()
		<-wake
	}
}

func (manager *Manager) deliverReportBatch(batch reportBatch) {
	for _, envelope := range batch.envelopes {
		for {
			err := manager.deliverReport(envelope)
			if err == nil {
				manager.reportFailed.Store(false)
				break
			}
			manager.reportFailed.Store(true)
			manager.notifyReportProgress()
			<-manager.retryScheduler.After(manager.cleanupRetryDelay)
		}
	}
}

func (manager *Manager) deliverReport(envelope reportEnvelope) (err error) {
	defer func() {
		if recover() != nil {
			err = &Error{code: ErrorReporting}
		}
	}()
	switch envelope.kind {
	case reportHealthKind:
		return manager.reporter.PlatformHealth(envelope.graph, envelope.report)
	case reportComplianceKind:
		return manager.reporter.ComplianceActivity(envelope.graph, envelope.report)
	default:
		return &Error{code: ErrorReporting}
	}
}

func (manager *Manager) sequenceReports(batch *reportBatch) {
	if batch == nil || len(batch.envelopes) == 0 || batch.sequence != 0 {
		return
	}
	batch.sequence = manager.reportBatchSeq.Add(1)
	for index := range batch.envelopes {
		batch.envelopes[index].report.DeliverySequence = batch.sequence
		batch.envelopes[index].report.DeliveryIndex = uint32(index)
	}
}

func (manager *Manager) markReportsCompleted(sequence uint64) {
	manager.reportCompleted.Store(sequence)
	manager.notifyReportProgress()
}

func (manager *Manager) notifyReportProgress() {
	manager.reportProgressMu.Lock()
	close(manager.reportProgress)
	manager.reportProgress = make(chan struct{})
	manager.reportProgressMu.Unlock()
}

func (manager *Manager) requestReporterClose() {
	if !manager.reporterStarted.Load() {
		return
	}
	manager.reportSpoolMu.Lock()
	if !manager.reportSpoolClosed {
		manager.reportSpoolClosed = true
		manager.notifyReportSpoolLocked()
	}
	manager.reportSpoolMu.Unlock()
}

func (manager *Manager) dispatchReports(ctx context.Context, batch reportBatch) *Error {
	if ctx == nil {
		return &Error{code: ErrorInvalidDependency}
	}
	if len(batch.envelopes) == 0 {
		return nil
	}
	if batch.sequence == 0 {
		return &Error{code: ErrorReporting}
	}
	manager.reportSpoolMu.Lock()
	if manager.reportSpoolClosed || batch.sequence <= manager.reportCompleted.Load() ||
		batch.sequence == manager.reportDelivering {
		manager.reportSpoolMu.Unlock()
		return &Error{code: ErrorReporting}
	}
	if _, duplicate := manager.reportSpool[batch.sequence]; duplicate {
		manager.reportSpoolMu.Unlock()
		return &Error{code: ErrorReporting}
	}
	manager.reportSpool[batch.sequence] = batch
	manager.reportAccepted.Add(1)
	manager.notifyReportSpoolLocked()
	manager.reportSpoolMu.Unlock()
	manager.maybeCloseReporter()
	return nil
}

func (manager *Manager) notifyReportSpoolLocked() {
	close(manager.reportSpoolWake)
	manager.reportSpoolWake = make(chan struct{})
}

// FlushReports waits until every report sequenced before the call has been
// delivered. A reporter error or panic is exposed immediately while the
// worker retains the batch and retries it without reordering or dropping it.
func (manager *Manager) FlushReports(ctx context.Context) *Error {
	if manager == nil || ctx == nil {
		return &Error{code: ErrorInvalidDependency}
	}
	target := manager.reportBatchSeq.Load()
	for manager.reportCompleted.Load() < target {
		manager.reportProgressMu.Lock()
		progress := manager.reportProgress
		if manager.reportCompleted.Load() >= target {
			manager.reportProgressMu.Unlock()
			return nil
		}
		if manager.reportFailed.Load() {
			manager.reportProgressMu.Unlock()
			return &Error{code: ErrorReporting}
		}
		manager.reportProgressMu.Unlock()
		select {
		case <-progress:
		case <-ctx.Done():
			return &Error{code: ErrorReporting, contextCause: contextIdentity(ctx.Err())}
		}
	}
	return nil
}

// WaitReporter waits for the delivery worker to terminate after Close. A
// reporter callback is part of the Reporter contract and must itself return;
// the context bounds how long a caller waits for a broken implementation.
func (manager *Manager) WaitReporter(ctx context.Context) *Error {
	if manager == nil || ctx == nil {
		return &Error{code: ErrorInvalidDependency}
	}
	if !manager.reporterStarted.Load() {
		return nil
	}
	select {
	case <-manager.reporterStopped:
		return nil
	case <-ctx.Done():
		return &Error{code: ErrorReporting, contextCause: contextIdentity(ctx.Err())}
	}
}

func (manager *Manager) newReport(
	graph *Graph,
	code ReportCode,
	outcome, fieldPath, component string,
) Report {
	generation := uint64(0)
	if graph != nil {
		generation = graph.Generation()
	}
	return Report{
		Code: code, Outcome: outcome, FieldPath: fieldPath, ComponentName: component,
		Generation: generation, OccurredAt: manager.clock.Now().UTC(),
	}
}

func contextIdentity(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return context.Canceled
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// DefaultOptions is the production lifecycle policy. Tests should inject a
// fake clock and deadline factory rather than waiting for this timeout.
func DefaultOptions(reporter Reporter) Options {
	return Options{
		DrainTimeout: 30 * time.Second, CleanupRetryDelay: time.Second,
		Clock: systemClock{}, Deadlines: timeoutDeadlineFactory{},
		RetryScheduler: timerRetryScheduler{}, Reporter: reporter,
	}
}
