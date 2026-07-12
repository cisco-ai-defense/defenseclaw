// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// TraceProjectionOutcome contains only independently projected optional work.
// Traces never enter the mandatory SQLite log destination, and a failure for one
// destination cannot suppress another destination's projection.
type TraceProjectionOutcome struct {
	admission       router.Admission
	optionalWork    []ProjectedDelivery
	optionalFailure []OptionalFailure
}

func (outcome TraceProjectionOutcome) Admission() router.Admission { return outcome.admission }
func (outcome TraceProjectionOutcome) OptionalWork() []ProjectedDelivery {
	return append([]ProjectedDelivery(nil), outcome.optionalWork...)
}
func (outcome TraceProjectionOutcome) OptionalFailures() []OptionalFailure {
	return append([]OptionalFailure(nil), outcome.optionalFailure...)
}

// TraceProjectionPipeline binds already-generated canonical trace records to
// one immutable routing/redaction generation. Producers still perform the
// collection gate before span construction; this boundary revalidates that
// decision and creates no route that could resurrect a dropped/unsampled span.
type TraceProjectionPipeline struct {
	evaluator *router.Evaluator
	catalog   redaction.ProfileCatalog
	projector Projector
	digest    string
}

func NewTraceProjectionPipeline(
	plan *config.ObservabilityV8Plan,
	evaluator *router.Evaluator,
	projector Projector,
) (*TraceProjectionPipeline, error) {
	if plan == nil || evaluator == nil || projector == nil ||
		evaluator.PlanDigest() == "" || evaluator.PlanDigest() != plan.Digest() {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	catalog, err := plan.RedactionProfileCatalog()
	if err != nil {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	return &TraceProjectionPipeline{
		evaluator: evaluator,
		catalog:   catalog,
		projector: projector,
		digest:    plan.Digest(),
	}, nil
}

func (pipeline *TraceProjectionPipeline) PlanDigest() string {
	if pipeline == nil {
		return ""
	}
	return pipeline.digest
}

// Process validates one schema-derived trace record against the same graph
// generation that created it, evaluates ordered destination routes once, and
// returns immutable per-destination projections. It performs no network or
// SQLite I/O.
func (pipeline *TraceProjectionPipeline) Process(
	record observability.Record,
) (TraceProjectionOutcome, error) {
	if pipeline == nil || pipeline.evaluator == nil || pipeline.projector == nil ||
		pipeline.digest == "" {
		return TraceProjectionOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	if record.Signal() != observability.SignalTraces || !record.SchemaDerivedFieldClasses() ||
		record.Provenance().ConfigDigest != pipeline.digest {
		return TraceProjectionOutcome{}, &Error{code: ErrorInvalidInput}
	}
	var severity *observability.Severity
	if value, present := record.Severity(); present {
		copy := value
		severity = &copy
	}
	metadata, err := router.NewMetadata(
		record.Identity(), severity, record.Source(), record.Connector(),
		observability.ProducerKey(record.Action()),
	)
	if err != nil {
		return TraceProjectionOutcome{}, &Error{code: ErrorInvalidInput}
	}
	result, err := pipeline.evaluator.Evaluate(metadata, func(admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, &recordBuildFailure{}
		}
		return record.Clone(), nil
	})
	if err != nil {
		return TraceProjectionOutcome{}, &Error{code: ErrorEvaluation}
	}
	outcome := TraceProjectionOutcome{admission: result.Admission()}
	if result.Admission() == router.AdmissionDrop {
		return outcome, nil
	}
	verified, present := result.Record()
	if !present || verified.RecordID() != record.RecordID() ||
		verified.Signal() != observability.SignalTraces {
		return TraceProjectionOutcome{}, &Error{code: ErrorEvaluation}
	}
	for _, delivery := range result.Deliveries() {
		// The implicit local destination is logs-only. Seeing it here means the
		// compiled capability boundary was violated; fail this route closed.
		if delivery.DestinationKind == config.ObservabilityV8DestinationLocalSQLite {
			outcome.optionalFailure = append(outcome.optionalFailure, newOptionalFailure(
				delivery, OptionalFailureProjection,
			))
			continue
		}
		profile, found := pipeline.catalog.Resolve(redaction.ProfileName(delivery.RedactionProfile))
		if !found {
			outcome.optionalFailure = append(outcome.optionalFailure, newOptionalFailure(
				delivery, OptionalFailureProfile,
			))
			continue
		}
		projection, _, projectErr := pipeline.projector.Project(record, profile)
		if projectErr != nil {
			outcome.optionalFailure = append(outcome.optionalFailure, newOptionalFailure(
				delivery, boundedProjectionFailure(projectErr),
			))
			continue
		}
		outcome.optionalWork = append(outcome.optionalWork, ProjectedDelivery{
			delivery:   delivery,
			projection: projection,
			identity: ProjectedDeliveryIdentity{
				recordID: record.RecordID(), bucket: record.Bucket(),
				signal: record.Signal(), eventName: record.EventName(),
			},
		})
	}
	return outcome, nil
}
