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

package runtime

import (
	"context"
	"math"
	"reflect"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// ErrorCode is a closed, content-free runtime-assembly failure identity.
type ErrorCode string

const (
	ErrorInvalidDependency    ErrorCode = "invalid_dependency"
	ErrorStorePathMismatch    ErrorCode = "store_path_mismatch"
	ErrorComponentUnavailable ErrorCode = "component_unavailable"
	ErrorShutdown             ErrorCode = "shutdown_degraded"
)

// Error never retains a configured path, endpoint, record, projection, or
// underlying persistence diagnostic.
type Error struct{ code ErrorCode }

type emitBuilderError struct{}

func (*emitBuilderError) Error() string {
	return "observability runtime record graph binding failed"
}

func (err *Error) Error() string {
	if err == nil {
		return "observability runtime operation failed"
	}
	return "observability runtime operation failed: " + string(err.code)
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// Options supplies dependencies whose lifetime is the whole gateway process,
// not one reload generation. RetentionController is required and its lifecycle
// becomes exclusively Runtime-owned after New succeeds. The Store's immutable
// constructor path binds the already-open caller-owned Store to the compiled
// local destination. A nil Signer is an explicit unavailable-integrity state
// supported by audit storage; callers should provide
// EventHistoryHealthReporter when they need that degraded state bridged into
// mandatory health telemetry.
type Options struct {
	Store                      *audit.Store
	Engine                     *redaction.Engine
	Signer                     audit.ProjectionIntegritySigner
	RecordBuilder              *observability.RecordBuilder
	Reporter                   runtimegraph.Reporter
	EventHistoryHealthReporter audit.EventHistoryHealthReporter
	RetentionController        *RetentionController
	// DestinationAdapterFactory is required only when the compiled plan enables
	// an optional destination that selects logs. Disabled and non-log-only
	// destinations allocate no adapter or queue in this runtime component.
	DestinationAdapterFactory DestinationAdapterFactory
	// DestinationObserver receives bounded, content-free queue health and
	// invariant transitions. Observer panics are isolated from producers and
	// destination workers.
	DestinationObserver delivery.Observer
	// TelemetryProviderFactory is optional. When supplied, the exact plan-bound
	// OTel provider is prepared and retired inside the same runtime graph as
	// local persistence and destination dispatch; reload can therefore never
	// pair producers with processors/readers from another generation. It is
	// required when an enabled OTLP destination selects logs because that
	// adapter must use the same generation's immutable v8 resource snapshot.
	TelemetryProviderFactory *telemetry.V8ProviderFactory
	// GraphOptions is optional. When supplied, Reporter is still replaced by
	// the process-stable Reporter above so one runtime cannot split reporting
	// across inconsistent owners.
	GraphOptions *runtimegraph.Options
}

// Runtime owns the immutable runtimegraph manager and the lifecycle of the
// supplied process-stable retention controller after New succeeds. It does not
// own caller-supplied stores or key material; Close must return before callers
// close either SQLite store.
type Runtime struct {
	manager             *runtimegraph.Manager
	store               *audit.Store
	retention           *RetentionController
	destinationObserver *safeDeliveryObserver
	lifecycleMu         sync.Mutex
}

// EmitContext is the exact immutable graph snapshot pinned for one Emit call.
// Producers use its generation and digest when constructing provenance instead
// of reading a separately mutable configuration object.
type EmitContext struct {
	plan                 *config.ObservabilityV8Plan
	digest               string
	generation           uint64
	inboundTraceResource observability.InboundLocalTraceResource
	inboundTraceReady    bool
	inboundBinaryVersion string
	inboundInstanceID    string
}

func (snapshot EmitContext) Plan() *config.ObservabilityV8Plan { return snapshot.plan }
func (snapshot EmitContext) Digest() string                    { return snapshot.digest }
func (snapshot EmitContext) Generation() uint64                { return snapshot.generation }

// InboundLocalTraceResource returns the sealed local resource prepared from the
// same provider generation that admitted an imported trace target. Ordinary
// emit contexts and non-trace callbacks never carry this capability.
func (snapshot EmitContext) InboundLocalTraceResource() (observability.InboundLocalTraceResource, bool) {
	if !snapshot.inboundTraceReady || snapshot.inboundBinaryVersion == "" || snapshot.inboundInstanceID == "" {
		return observability.InboundLocalTraceResource{}, false
	}
	return snapshot.inboundTraceResource, true
}

// InboundLocalProvenance returns generation-pinned local reconstruction facts.
// It is available only on private inbound signal callbacks.
func (snapshot EmitContext) InboundLocalProvenance() (observability.InboundLocalProvenanceInput, bool) {
	if snapshot.inboundBinaryVersion == "" || snapshot.digest == "" || snapshot.generation == 0 {
		return observability.InboundLocalProvenanceInput{}, false
	}
	if snapshot.generation > math.MaxInt64 {
		return observability.InboundLocalProvenanceInput{}, false
	}
	return observability.InboundLocalProvenanceInput{
		BinaryVersion:    snapshot.inboundBinaryVersion,
		ConfigGeneration: int64(snapshot.generation), ConfigDigest: snapshot.digest,
	}, true
}

func (snapshot EmitContext) InboundLocalInstanceID() (string, bool) {
	return snapshot.inboundInstanceID, snapshot.inboundInstanceID != ""
}

// EmitBuilder is invoked at most once and only after collection admits the
// signal. It receives the same graph generation whose local component persists
// the resulting record. It is never called for AdmissionDrop.
type EmitBuilder func(EmitContext, router.Admission) (observability.Record, error)

// LogBatchItem is one independently collected and routed log occurrence in a
// short-lived producer batch. Context is per occurrence because SQLite's
// additive legacy projection is carried on the context; Metadata and Builder
// retain the same authority and laziness rules as Emit.
type LogBatchItem struct {
	Context  context.Context
	Metadata router.Metadata
	Builder  EmitBuilder
}

// MaxLogBatchItems bounds one generation-pinned producer batch. The bound is
// intentionally well above every built-in scanner limit while preventing an
// untrusted adapter from retaining an unbounded slice under a graph lease.
const MaxLogBatchItems = 65_536

// New builds and publishes generation one only after the local coordinator is
// complete. The caller owns Store, Engine, Signer, RecordBuilder, and Reporter.
func New(ctx context.Context, initial runtimegraph.Config, options Options) (*Runtime, error) {
	if ctx == nil || options.Store == nil || !options.Store.Ready() ||
		options.Store.DatabasePath() == "" || options.Engine == nil || options.RecordBuilder == nil ||
		options.RetentionController == nil ||
		nilInterface(options.Reporter) ||
		options.Signer != nil && nilInterface(options.Signer) ||
		options.EventHistoryHealthReporter != nil && nilInterface(options.EventHistoryHealthReporter) ||
		initial.Plan == nil {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	storePath := options.Store.DatabasePath()
	if initial.LocalPath != storePath || initial.Plan.Snapshot().Local.Path != storePath {
		return nil, &Error{code: ErrorStorePathMismatch}
	}
	if err := options.RetentionController.claimRuntimeOwnership(); err != nil {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	owned := false
	defer func() {
		if !owned {
			options.RetentionController.releaseRuntimeOwnership()
		}
	}()

	graphOptions := runtimegraph.DefaultOptions(options.Reporter)
	if options.GraphOptions != nil {
		graphOptions = *options.GraphOptions
		graphOptions.Reporter = options.Reporter
	}
	factory := &localLogFactory{
		store: options.Store, storePath: storePath,
		engine: options.Engine, signer: options.Signer,
		recordBuilder:  options.RecordBuilder,
		healthReporter: options.EventHistoryHealthReporter,
	}
	destinationObserver := newSafeDeliveryObserver(options.DestinationObserver)
	dispatchFactory := &destinationDispatchFactory{
		adapters:  options.DestinationAdapterFactory,
		resources: options.TelemetryProviderFactory,
		observer:  destinationObserver,
	}
	factories := []runtimegraph.ComponentFactory{
		&retentionPolicyFactory{controller: options.RetentionController},
	}
	if options.TelemetryProviderFactory != nil {
		factories = append(factories, options.TelemetryProviderFactory)
	}
	factories = append(factories,
		factory,
		dispatchFactory,
	)
	manager, err := runtimegraph.New(
		ctx,
		initial,
		factories,
		graphOptions,
	)
	if err != nil {
		_ = destinationObserver.Close(context.Background())
		return nil, err
	}
	// runtimegraph.New returns only after every generation-one component has
	// activated and the graph readiness gate is open. Starting here guarantees
	// the retention worker's one startup run cannot race incomplete graph/store
	// initialization.
	if err := options.RetentionController.startRuntime(context.Background()); err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), graphOptions.DrainTimeout)
		defer cancel()
		_ = manager.Close(cleanupContext)
		_ = manager.WaitCleanup(cleanupContext)
		_ = manager.FlushReports(cleanupContext)
		_ = manager.WaitReporter(cleanupContext)
		_ = destinationObserver.Close(cleanupContext)
		return nil, &Error{code: ErrorInvalidDependency}
	}
	owned = true
	return &Runtime{
		manager: manager, store: options.Store, retention: options.RetentionController,
		destinationObserver: destinationObserver,
	}, nil
}

// Active returns the exact currently published graph pointer.
func (runtime *Runtime) Active() *runtimegraph.Graph {
	if runtime == nil || runtime.manager == nil {
		return nil
	}
	return runtime.manager.Active()
}

// Emit pins exactly one graph, resolves that generation's local-log component,
// processes once, hands independently projected optional work to that same
// generation's bounded dispatchers only after local persistence, and releases
// the lease on every path. Optional projection/enqueue failures never change
// the producer result or trigger legacy fallback.
func (runtime *Runtime) Emit(
	ctx context.Context,
	metadata router.Metadata,
	builder EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return runtime.emit(ctx, metadata, builder, false)
}

// EmitLocalOnly pins the same immutable graph and persists through the same
// central local pipeline as Emit, but it never constructs or enqueues optional
// destination work. It is intentionally separate from ordinary routing so a
// connectivity test cannot export the audit record to the destination under
// test or to any sibling destination.
func (runtime *Runtime) EmitLocalOnly(
	ctx context.Context,
	metadata router.Metadata,
	builder EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return runtime.emit(ctx, metadata, builder, true)
}

// EmitBatch pins one graph generation for a bounded sequence of related log
// occurrences. Each item still evaluates collection independently and runs
// through the ordinary SQLite-first pipeline. Items are processed in order;
// the first error stops the batch and the returned outcomes describe exactly
// the completed prefix. Already-persisted occurrences are never rolled back or
// rebuilt on a newer generation.
func (runtime *Runtime) EmitBatch(
	ctx context.Context,
	items []LogBatchItem,
) ([]pipeline.LocalLogOutcome, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || len(items) == 0 ||
		len(items) > MaxLogBatchItems {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	for index := range items {
		if items[index].Context == nil || items[index].Builder == nil {
			return nil, &Error{code: ErrorInvalidDependency}
		}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	outcomes := make([]pipeline.LocalLogOutcome, 0, len(items))
	for index := range items {
		outcome, emitErr := runtime.emitWithLease(
			items[index].Context, lease, items[index].Metadata, items[index].Builder, false,
		)
		if emitErr != nil {
			return outcomes, emitErr
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

func (runtime *Runtime) emit(
	ctx context.Context,
	metadata router.Metadata,
	builder EmitBuilder,
	localOnly bool,
) (pipeline.LocalLogOutcome, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || builder == nil {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return pipeline.LocalLogOutcome{}, err
	}
	defer lease.Release()
	return runtime.emitWithLease(ctx, lease, metadata, builder, localOnly)
}

// emitWithLease is the single log-processing implementation for ordinary
// one-record producers and request-scoped inbound batches. The caller owns the
// live lease. Keeping construction, SQLite persistence, projection, and
// destination enqueue on that lease prevents reload from mixing generations.
func (runtime *Runtime) emitWithLease(
	ctx context.Context,
	lease *runtimegraph.Lease,
	metadata router.Metadata,
	builder EmitBuilder,
	localOnly bool,
) (pipeline.LocalLogOutcome, error) {
	return runtime.emitWithLeaseControls(ctx, lease, metadata, builder, localOnly, "", false, false)
}

// emitImportedWithLease is reserved for normalized inbound logs. The origin
// and terminal-hop controls remain outside the canonical record and are
// consumed only by the generation-local optional routing path.
func (runtime *Runtime) emitImportedWithLease(
	ctx context.Context,
	lease *runtimegraph.Lease,
	metadata router.Metadata,
	builder EmitBuilder,
	originDestination string,
	suppressAll bool,
) (pipeline.LocalLogOutcome, error) {
	return runtime.emitWithLeaseControls(
		ctx, lease, metadata, builder, false, originDestination, suppressAll, true,
	)
}

func (runtime *Runtime) emitWithLeaseControls(
	ctx context.Context,
	lease *runtimegraph.Lease,
	metadata router.Metadata,
	builder EmitBuilder,
	localOnly bool,
	originDestination string,
	suppressAll bool,
	inbound bool,
) (pipeline.LocalLogOutcome, error) {
	if runtime == nil || ctx == nil || lease == nil || builder == nil {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	if (originDestination != "" && !observability.IsStableToken(originDestination)) ||
		(suppressAll && originDestination != "") || (localOnly && originDestination != "") {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	graph := lease.Graph()
	component, ok := lease.Component(LocalLogComponentName)
	if graph == nil || !ok {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorComponentUnavailable}
	}
	local, ok := component.(*localLogComponent)
	if !ok || local.digest != graph.Digest() {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorComponentUnavailable}
	}
	baseSnapshot := EmitContext{
		plan: graph.Plan(), digest: graph.Digest(), generation: graph.Generation(),
	}
	processBuilder := func(admission router.Admission) (observability.Record, error) {
		snapshot := baseSnapshot
		if inbound {
			provider, providerOK := telemetry.V8ProviderFromLease(lease)
			if !providerOK {
				return observability.Record{}, &emitBuilderError{}
			}
			resource, resourceOK := provider.V8ResourceContext()
			if !resourceOK {
				return observability.Record{}, &emitBuilderError{}
			}
			snapshot.inboundBinaryVersion = resource.ServiceVersion()
			snapshot.inboundInstanceID = resource.TraceResourceFields().DefenseClawInstanceID
			if snapshot.inboundBinaryVersion == "" || snapshot.inboundInstanceID == "" {
				return observability.Record{}, &emitBuilderError{}
			}
		}
		record, err := builder(snapshot, admission)
		if err != nil {
			return observability.Record{}, err
		}
		provenance := record.Provenance()
		if provenance.ConfigDigest != snapshot.Digest() || provenance.ConfigGeneration < 0 ||
			uint64(provenance.ConfigGeneration) != snapshot.Generation() {
			return observability.Record{}, &emitBuilderError{}
		}
		return record, nil
	}
	var outcome pipeline.LocalLogOutcome
	var processErr error
	switch {
	case localOnly:
		outcome, processErr = local.ProcessLocalOnly(ctx, metadata, processBuilder)
	case originDestination != "" || suppressAll:
		outcome, processErr = local.ProcessImported(
			ctx, metadata, originDestination, suppressAll, processBuilder,
		)
	default:
		outcome, processErr = local.Process(ctx, metadata, processBuilder)
	}
	if processErr != nil {
		return outcome, processErr
	}
	if !outcome.LocalPersisted() {
		return outcome, nil
	}
	if localOnly || suppressAll {
		return outcome, nil
	}
	dispatchValue, dispatchOK := lease.Component(DestinationDispatchComponentName)
	dispatch, typedDispatch := dispatchValue.(*destinationDispatchComponent)
	if !dispatchOK || !typedDispatch || dispatch == nil || dispatch.digest != graph.Digest() {
		// A valid graph always contains this component. Treat corruption as
		// bounded optional health and preserve the successful local result.
		for _, work := range outcome.OptionalWork() {
			observeBoundedDestinationFailure(
				runtime.destinationObserver, work.Delivery().DestinationName,
			)
		}
		for _, failure := range outcome.OptionalFailures() {
			observeBoundedDestinationFailure(runtime.destinationObserver, failure.DestinationName())
		}
		return outcome, nil
	}
	for _, failure := range outcome.OptionalFailures() {
		dispatch.ObserveProjectionFailure(failure)
	}
	for _, work := range outcome.OptionalWork() {
		dispatch.Enqueue(work)
	}
	return outcome, nil
}

// Reload exposes runtimegraph's exact rejected/applied/applied-degraded result.
func (runtime *Runtime) Reload(
	ctx context.Context,
	candidate runtimegraph.Config,
) (runtimegraph.ReloadResult, *runtimegraph.Error) {
	if runtime == nil || runtime.manager == nil {
		return runtimegraph.ReloadResult{}, invalidManagerError(ctx)
	}
	runtime.lifecycleMu.Lock()
	defer runtime.lifecycleMu.Unlock()
	return runtime.manager.Reload(ctx, candidate)
}

// FlushReports waits for every report accepted before this call.
func (runtime *Runtime) FlushReports(ctx context.Context) *runtimegraph.Error {
	if runtime == nil || runtime.manager == nil {
		return invalidManagerError(ctx)
	}
	return runtime.manager.FlushReports(ctx)
}

// Close first cancels and waits for retention, then attempts every graph
// cleanup/report phase even when an earlier phase fails. A non-nil result means
// store ownership has not been safely returned: callers MUST retry Close with
// a fresh context and MUST NOT close either SQLite store in the meantime.
func (runtime *Runtime) Close(ctx context.Context) error {
	if runtime == nil || runtime.manager == nil {
		return nil
	}
	runtime.lifecycleMu.Lock()
	defer runtime.lifecycleMu.Unlock()
	var first error
	if runtime.retention != nil {
		if err := runtime.retention.stopRuntime(ctx); err != nil {
			first = &Error{code: ErrorShutdown}
		}
	}
	if err := runtime.manager.Close(ctx); first == nil && err != nil {
		first = err
	}
	if err := runtime.manager.WaitCleanup(ctx); first == nil && err != nil {
		first = err
	}
	if err := runtime.manager.FlushReports(ctx); first == nil && err != nil {
		first = err
	}
	if err := runtime.manager.WaitReporter(ctx); first == nil && err != nil {
		first = err
	}
	if runtime.destinationObserver != nil {
		if err := runtime.destinationObserver.Close(ctx); first == nil && err != nil {
			first = &Error{code: ErrorShutdown}
		}
	}
	return first
}

// runtimegraph.Error deliberately has no public constructor. Reusing Acquire
// on a nil manager returns the package's bounded invalid-dependency result.
func invalidManagerError(ctx context.Context) *runtimegraph.Error {
	var manager *runtimegraph.Manager
	_, err := manager.Acquire(ctx)
	return err
}

func nilInterface(value any) bool {
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

var _ error = (*Error)(nil)
