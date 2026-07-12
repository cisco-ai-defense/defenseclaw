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
	writer, err := audit.NewEventHistoryWriter(
		factory.store,
		factory.signer,
		factory.healthReporter,
		binding,
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
}

func (component *localLogComponent) applyAlertAcknowledgement(
	ctx context.Context,
	command audit.AlertAcknowledgementCommand,
) (audit.AlertAcknowledgementResult, error) {
	if component == nil || component.alertWriter == nil || !component.active.Load() || component.closed.Load() {
		return audit.AlertAcknowledgementResult{}, &localFactoryError{}
	}
	return component.alertWriter.ApplyAlertAcknowledgement(ctx, command)
}

func (component *localLogComponent) Activate() {
	if component != nil && !component.closed.Load() {
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
	return component.pipeline.Process(ctx, metadata, builder)
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
	return component.pipeline.ProcessLocalOnly(ctx, metadata, builder)
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
	return component.pipeline.ProcessImported(ctx, metadata, originDestination, suppressAll, builder)
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
