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
	"errors"
	"math"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// LocalLogComponentName is the exact immutable-graph component resolved by
// Runtime.Emit. Optional destinations get independent components in Phase 3;
// they are never hidden behind this local durability boundary.
const LocalLogComponentName = "local-log"

type localFactoryError struct{}

func (*localFactoryError) Error() string {
	return "observability local runtime initialization failed"
}

// localLogFactory holds process-stable dependencies only. Prepare creates a
// fresh evaluator, sealed projection binding, writer, and coordinator for each
// immutable graph generation. The audit Store itself is deliberately reused.
type localLogFactory struct {
	store          *audit.Store
	storePath      string
	engine         *redaction.Engine
	signer         audit.ProjectionIntegritySigner
	recordBuilder  *observability.RecordBuilder
	healthReporter audit.EventHistoryHealthReporter
	// lostWrites counts, across generations, the log records whose mandatory
	// SQLite append failed and that no sqlite.write_failed record reported
	// yet, in the loss journal that survives a restart (GAP-1129).
	lostWrites *localWriteLossJournal
}

func (factory *localLogFactory) Name() string { return LocalLogComponentName }

func (factory *localLogFactory) Prepare(
	ctx context.Context,
	input runtimegraph.BuildInput,
	_ *runtimegraph.Acquisitions,
) (runtimegraph.Component, error) {
	if factory == nil || ctx == nil || factory.store == nil || !factory.store.Ready() ||
		factory.storePath == "" || factory.engine == nil || factory.recordBuilder == nil ||
		input.Config.Plan == nil || input.Config.LocalPath != factory.storePath {
		return nil, &localFactoryError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	evaluator, err := router.New(input.Config.Plan)
	if err != nil {
		return nil, &localFactoryError{}
	}
	binding, err := pipeline.NewLocalProjectionBinding(input.Config.Plan, factory.engine)
	if err != nil {
		return nil, &localFactoryError{}
	}
	writer, err := audit.NewEventHistoryWriterForGeneration(
		factory.store,
		factory.signer,
		factory.healthReporter,
		binding,
		input.Generation,
	)
	if err != nil {
		return nil, &localFactoryError{}
	}
	if input.Generation > math.MaxInt64 {
		return nil, &localFactoryError{}
	}
	alertEvents, err := pipeline.NewAlertCanonicalEventFactory(
		input.Config.Plan,
		factory.engine,
		factory.recordBuilder,
		observability.Provenance{
			Producer:              "observability_alert_projection",
			BinaryVersion:         version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(input.Generation),
			ConfigDigest:          input.Config.PlanDigest,
		},
	)
	if err != nil {
		return nil, &localFactoryError{}
	}
	alertWriter, err := audit.NewAlertAcknowledgementWriter(factory.store, writer, alertEvents)
	if err != nil && !errors.Is(err, audit.ErrAlertCommandFingerprintUnavailable) {
		return nil, &localFactoryError{}
	}
	failures, err := pipeline.NewCanonicalProjectionFailureFactory(factory.recordBuilder)
	if err != nil {
		return nil, &localFactoryError{}
	}
	coordinator, err := pipeline.NewLocalLogPipeline(
		input.Config.Plan,
		evaluator,
		factory.engine,
		writer,
		failures,
	)
	if err != nil {
		return nil, &localFactoryError{}
	}
	return &localLogComponent{
		pipeline:    coordinator,
		store:       factory.store,
		history:     writer,
		digest:      input.Config.PlanDigest,
		alertWriter: alertWriter,
		lostWrites:  factory.lostWrites,
	}, nil
}

// localLogComponent is generation-owned even though its Store is process
// owned. Runtimegraph waits for every lease before invoking lifecycle methods,
// so StopIntake never races a Process call admitted through Runtime.Emit.
type localLogComponent struct {
	pipeline    *pipeline.LocalLogPipeline
	store       *audit.Store
	history     *audit.EventHistoryWriter
	digest      string
	alertWriter *audit.AlertAcknowledgementWriter

	active atomic.Bool
	closed atomic.Bool

	// writes are this generation's mandatory SQLite appends, reported as the
	// local-sqlite destination's counters (GAP-1100).
	writes     localWriteCounters
	lostWrites *localWriteLossJournal
}

type localWriteCounters struct {
	accepted  atomic.Uint64
	delivered atomic.Uint64
	dropped   atomic.Uint64
}

func (counters *localWriteCounters) snapshot() delivery.Counters {
	return delivery.Counters{
		Accepted: counters.accepted.Load(), Delivered: counters.delivered.Load(), Dropped: counters.dropped.Load(),
	}
}

// localWriteFailed reports a failed mandatory SQLite append (disk full,
// read-only store), not a cancelled or rejected record.
func localWriteFailed(err error) bool {
	var pipelineErr *pipeline.Error
	return errors.As(err, &pipelineErr) && pipelineErr.Code() == pipeline.ErrorLocalWrite &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// countWrite counts one Process result: a persisted record is delivered, a
// failed append is dropped. Records that never reached the append (dropped by
// collection, managed-only, invalid) are not local-sqlite work.
func (component *localLogComponent) countWrite(outcome pipeline.LocalLogOutcome, err error) {
	switch {
	case localWriteFailed(err):
		component.writes.accepted.Add(1)
		component.writes.dropped.Add(1)
		component.lostWrites.add(localWriteFailureReason(err))
	case err == nil && outcome.LocalPersisted():
		component.writes.accepted.Add(1)
		component.writes.delivered.Add(1)
	}
}

// countBatch counts one atomic batch: when its commit fails every admitted
// record of the batch is lost from local history.
func (component *localLogComponent) countBatch(outcomes []pipeline.LocalLogOutcome, err error) {
	failed := localWriteFailed(err)
	for _, outcome := range outcomes {
		switch {
		case outcome.LocalPersisted():
			component.countWrite(outcome, nil)
		case failed && outcome.Admission() != router.AdmissionDrop && !outcome.ManagedOnly():
			component.countWrite(outcome, err)
		}
	}
}

func (component *localLogComponent) applyAlertAcknowledgement(
	ctx context.Context,
	command audit.AlertAcknowledgementCommand,
) (audit.AlertAcknowledgementResult, pipeline.LocalLogOutcome, error) {
	if component == nil || component.alertWriter == nil || !component.active.Load() || component.closed.Load() {
		return audit.AlertAcknowledgementResult{}, pipeline.LocalLogOutcome{}, &localFactoryError{}
	}
	result, committed, err := component.alertWriter.ApplyAlertAcknowledgementForExport(ctx, command)
	if err != nil || committed == nil || component.pipeline == nil {
		return result, pipeline.LocalLogOutcome{}, err
	}
	// The compliance event is already in SQLite; route it to the optional
	// destinations like any other log (GAP-1635).
	return result, component.pipeline.ProjectCommitted(ctx, *committed), nil
}

func (component *localLogComponent) Activate() {
	if component != nil && !component.closed.Load() {
		component.history.ActivateHealthGeneration()
		component.active.Store(true)
	}
}

func (component *localLogComponent) Process(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
) (pipeline.LocalLogOutcome, error) {
	if component == nil || component.pipeline == nil || component.store == nil ||
		!component.active.Load() || component.closed.Load() {
		return pipeline.LocalLogOutcome{}, &localFactoryError{}
	}
	outcome, err := component.pipeline.Process(ctx, metadata, builder)
	component.countWrite(outcome, err)
	return outcome, err
}

func (component *localLogComponent) ProcessAtomicBatch(
	ctx context.Context,
	items []pipeline.AtomicBatchItem,
) ([]pipeline.LocalLogOutcome, error) {
	if component == nil || component.pipeline == nil || component.store == nil ||
		!component.active.Load() || component.closed.Load() {
		return nil, &localFactoryError{}
	}
	outcomes, err := component.pipeline.ProcessAtomicBatch(ctx, items)
	component.countBatch(outcomes, err)
	return outcomes, err
}

func (component *localLogComponent) ProcessLocalOnly(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
) (pipeline.LocalLogOutcome, error) {
	if component == nil || component.pipeline == nil || component.store == nil ||
		!component.active.Load() || component.closed.Load() {
		return pipeline.LocalLogOutcome{}, &localFactoryError{}
	}
	outcome, err := component.pipeline.ProcessLocalOnly(ctx, metadata, builder)
	component.countWrite(outcome, err)
	return outcome, err
}

func (component *localLogComponent) ProcessImported(
	ctx context.Context,
	metadata router.Metadata,
	originDestination string,
	suppressAll bool,
	builder router.RecordBuilder,
) (pipeline.LocalLogOutcome, error) {
	if component == nil || component.pipeline == nil || component.store == nil ||
		!component.active.Load() || component.closed.Load() {
		return pipeline.LocalLogOutcome{}, &localFactoryError{}
	}
	outcome, err := component.pipeline.ProcessImported(ctx, metadata, originDestination, suppressAll, builder)
	component.countWrite(outcome, err)
	return outcome, err
}

func (component *localLogComponent) ProcessManagedLogFallback(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
) (pipeline.LocalLogOutcome, error) {
	if component == nil || component.pipeline == nil || component.store == nil ||
		!component.active.Load() || component.closed.Load() {
		return pipeline.LocalLogOutcome{}, &localFactoryError{}
	}
	outcome, err := component.pipeline.ProcessManagedLogFallback(ctx, metadata, builder)
	component.countWrite(outcome, err)
	return outcome, err
}

func (component *localLogComponent) StopIntake(context.Context) error {
	if component == nil {
		return errors.New("observability local runtime component is unavailable")
	}
	component.active.Store(false)
	return nil
}

func (component *localLogComponent) Drain(context.Context) error {
	if component == nil {
		return errors.New("observability local runtime component is unavailable")
	}
	return nil
}

func (component *localLogComponent) Close(context.Context) error {
	if component == nil {
		return errors.New("observability local runtime component is unavailable")
	}
	component.active.Store(false)
	component.closed.Store(true)
	// The Store, engine, signer, and canonical failure RecordBuilder are
	// caller-owned process dependencies and intentionally remain live.
	component.pipeline = nil
	component.history = nil
	return nil
}

var _ runtimegraph.ComponentFactory = (*localLogFactory)(nil)
var _ runtimegraph.Component = (*localLogComponent)(nil)
