// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package pipeline coordinates canonical observability records across the
// mandatory local event history and independently projected optional work.
package pipeline

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	v8redaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

// LocalEventAppender is the mandatory local durability boundary. The
// coordinator, rather than a producer, owns profile resolution and passes only
// the trusted projection built from the active immutable graph.
type LocalEventAppender interface {
	GraphDigest() string
	AppendContext(context.Context, observability.Record, v8redaction.Projection) error
}

// Projector is the immutable v8 redaction-engine seam. Production passes one
// *v8redaction.Engine; the interface keeps destination-failure isolation
// independently testable without exposing projection constructors.
type Projector interface {
	Project(observability.Record, v8redaction.Profile) (v8redaction.Projection, v8redaction.SafeReport, error)
}

// ProjectionFailureRecord contains only bounded identities and already-
// validated correlation/provenance. It never carries the failed body, field
// pointer, destination endpoint, exception text, or projection report.
type ProjectionFailureRecord struct {
	FailedBucket     observability.Bucket
	RedactionProfile v8redaction.ProfileName
	FailureCode      OptionalFailureCode
	Correlation      observability.Correlation
	Provenance       observability.Provenance
}

// ProjectionFailureRecordFactory builds the recursion-safe mandatory
// platform.health record used when the local projection cannot be serialized.
type ProjectionFailureRecordFactory interface {
	BuildProjectionFailure(context.Context, ProjectionFailureRecord) (observability.Record, error)
}

// ErrorCode is a bounded, content-free coordinator failure identity.
type ErrorCode string

const (
	ErrorInvalidDependency ErrorCode = "invalid_dependency"
	ErrorInvalidInput      ErrorCode = "invalid_input"
	ErrorContextDone       ErrorCode = "context_done"
	ErrorEvaluation        ErrorCode = "evaluation_failed"
	ErrorRecordBuild       ErrorCode = "record_build_failed"
	ErrorLocalDelivery     ErrorCode = "local_delivery_invalid"
	ErrorLocalProfile      ErrorCode = "local_profile_invalid"
	ErrorLocalProjection   ErrorCode = "local_projection_failed"
	ErrorLocalWrite        ErrorCode = "local_write_failed"
	ErrorFailureRecord     ErrorCode = "failure_record_failed"
)

// Error never retains or unwraps producer content, persistence diagnostics, or
// projection details. Context cancellation remains discoverable through Is.
type Error struct {
	code         ErrorCode
	contextCause error
}

func (err *Error) Error() string {
	if err == nil {
		return "observability local-log pipeline failed"
	}
	return "observability local-log pipeline failed: " + string(err.code)
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func (err *Error) Is(target error) bool {
	return err != nil && err.contextCause != nil && errors.Is(err.contextCause, target)
}

// OptionalFailureCode is the closed set of value-free optional-projection
// failures returned to the destination dispatcher.
type OptionalFailureCode string

const (
	OptionalFailureProfile        OptionalFailureCode = "profile_invalid"
	OptionalFailureClassification OptionalFailureCode = "classification_failed"
	OptionalFailureMetricClass    OptionalFailureCode = "metric_classification_failed"
	OptionalFailureContext        OptionalFailureCode = "projection_context_mismatch"
	OptionalFailureOutputLimit    OptionalFailureCode = "output_limit"
	OptionalFailureSerialization  OptionalFailureCode = "serialization_failed"
	OptionalFailureProjection     OptionalFailureCode = "projection_failed"
)

// OptionalFailure contains only bounded graph and failure identities. It never
// retains a canonical record, projection, body, exception, or raw error.
type OptionalFailure struct {
	destinationName string
	destinationKind config.ObservabilityV8DestinationKind
	routeName       string
	routeIndex      int
	code            OptionalFailureCode
}

func (failure OptionalFailure) DestinationName() string { return failure.destinationName }
func (failure OptionalFailure) DestinationKind() config.ObservabilityV8DestinationKind {
	return failure.destinationKind
}
func (failure OptionalFailure) RouteName() string         { return failure.routeName }
func (failure OptionalFailure) RouteIndex() int           { return failure.routeIndex }
func (failure OptionalFailure) Code() OptionalFailureCode { return failure.code }

// ProjectedDeliveryIdentity is the complete bounded, non-content identity
// retained beside one optional projection. It is derived only from the
// already-validated canonical Record and never retains a producer input or the
// canonical record itself. OriginDestination is reserved for normalized
// inbound telemetry and is empty for locally produced records.
type ProjectedDeliveryIdentity struct {
	recordID          string
	bucket            observability.Bucket
	signal            observability.Signal
	eventName         observability.EventName
	originDestination string
}

func (identity ProjectedDeliveryIdentity) RecordID() string { return identity.recordID }
func (identity ProjectedDeliveryIdentity) Bucket() observability.Bucket {
	return identity.bucket
}
func (identity ProjectedDeliveryIdentity) Signal() observability.Signal {
	return identity.signal
}
func (identity ProjectedDeliveryIdentity) EventName() observability.EventName {
	return identity.eventName
}
func (identity ProjectedDeliveryIdentity) OriginDestination() string {
	return identity.originDestination
}

// ProjectedDelivery is one independently projected optional-destination work
// item. Its accessors return value-safe immutable types.
type ProjectedDelivery struct {
	delivery   router.Delivery
	projection v8redaction.Projection
	identity   ProjectedDeliveryIdentity
}

func (work ProjectedDelivery) Delivery() router.Delivery { return work.delivery }
func (work ProjectedDelivery) Projection() v8redaction.Projection {
	return work.projection
}
func (work ProjectedDelivery) Identity() ProjectedDeliveryIdentity { return work.identity }

// LocalLogOutcome is an immutable snapshot of one coordinator invocation.
// OptionalWork and OptionalFailures return detached slices.
type LocalLogOutcome struct {
	admission       router.Admission
	localPersisted  bool
	managedOnly     bool
	optionalWork    []ProjectedDelivery
	optionalFailure []OptionalFailure
}

func (outcome LocalLogOutcome) Admission() router.Admission { return outcome.admission }
func (outcome LocalLogOutcome) LocalPersisted() bool        { return outcome.localPersisted }

// ManagedOnly reports the narrow release-owned path where ordinary collection
// remained disabled and only the generated managed-enterprise destination was
// projected. Such an outcome is never locally persisted or fanned out.
func (outcome LocalLogOutcome) ManagedOnly() bool { return outcome.managedOnly }
func (outcome LocalLogOutcome) OptionalWork() []ProjectedDelivery {
	return append([]ProjectedDelivery(nil), outcome.optionalWork...)
}
func (outcome LocalLogOutcome) OptionalFailures() []OptionalFailure {
	return append([]OptionalFailure(nil), outcome.optionalFailure...)
}

// LocalLogPipeline owns the immutable evaluator, graph-owned profile catalog,
// redaction engine, and mandatory local appender for one runtime generation.
type LocalLogPipeline struct {
	evaluator *router.Evaluator
	catalog   v8redaction.ProfileCatalog
	local     map[observability.Bucket]v8redaction.ProfileName
	projector Projector
	appender  LocalEventAppender
	failures  ProjectionFailureRecordFactory
}

// NewLocalLogPipeline assembles one immutable runtime-generation coordinator.
// The plan digest check prevents an evaluator from another graph generation
// from selecting routes against this plan's redaction catalog.
func NewLocalLogPipeline(
	plan *config.ObservabilityV8Plan,
	evaluator *router.Evaluator,
	projector Projector,
	appender LocalEventAppender,
	failures ProjectionFailureRecordFactory,
) (*LocalLogPipeline, error) {
	if plan == nil || evaluator == nil || projector == nil || appender == nil || failures == nil ||
		evaluator.PlanDigest() == "" || evaluator.PlanDigest() != plan.Digest() ||
		appender.GraphDigest() == "" || appender.GraphDigest() != plan.Digest() {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	catalog, err := plan.RedactionProfileCatalog()
	if err != nil {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	local := make(map[observability.Bucket]v8redaction.ProfileName, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		profile, resolveErr := plan.ResolveLocalRedactionProfile(bucket)
		if resolveErr != nil {
			return nil, &Error{code: ErrorInvalidDependency}
		}
		local[bucket] = profile
	}
	return &LocalLogPipeline{
		evaluator: evaluator,
		catalog:   catalog,
		local:     local,
		projector: projector,
		appender:  appender,
		failures:  failures,
	}, nil
}

type recordBuildFailure struct{}

func (*recordBuildFailure) Error() string { return "canonical log record build failed" }

// Process evaluates collection exactly once through the router, persists the
// required local projection, and only then creates optional destination work.
// Optional projection failures are isolated and returned as bounded identities.
func (pipeline *LocalLogPipeline) Process(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
) (LocalLogOutcome, error) {
	return pipeline.process(ctx, metadata, builder, false, "")
}

// ProcessLocalOnly applies the same collection, mandatory-floor, generated
// record, central-redaction, and SQLite contracts as Process while refusing to
// construct optional destination projections. It is reserved for explicitly
// local control-plane evidence such as destination connectivity tests.
func (pipeline *LocalLogPipeline) ProcessLocalOnly(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
) (LocalLogOutcome, error) {
	return pipeline.process(ctx, metadata, builder, true, "")
}

// ProcessImported applies the ordinary collection, construction, local
// persistence, and projection contracts to one normalized inbound log. A
// validated origin is carried only in the private delivery identity so the
// matching dispatcher can reject a recursive export after SQLite succeeds.
// suppressAll preserves the local durable leg while declining to construct any
// optional projections (the four-hop terminal behavior).
func (pipeline *LocalLogPipeline) ProcessImported(
	ctx context.Context,
	metadata router.Metadata,
	originDestination string,
	suppressAll bool,
	builder router.RecordBuilder,
) (LocalLogOutcome, error) {
	if (originDestination != "" && !observability.IsStableToken(originDestination)) ||
		(suppressAll && originDestination != "") {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidInput}
	}
	return pipeline.process(ctx, metadata, builder, suppressAll, originDestination)
}

// ProcessManagedLogFallback projects a locally produced canonical log only to
// the exact generated managed-enterprise destination after ordinary collection
// returned AdmissionDrop. This narrow release-owned exception never appends to
// SQLite, never evaluates operator-authored destinations, and is not used by
// imported or local-only runtime calls. The request SinkPolicy is applied to
// the destination's centrally compiled sensitive profile.
func (pipeline *LocalLogPipeline) ProcessManagedLogFallback(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
) (LocalLogOutcome, error) {
	if pipeline == nil || pipeline.evaluator == nil || pipeline.projector == nil ||
		pipeline.appender == nil || pipeline.failures == nil {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	if ctx == nil || metadata.Identity().Signal != observability.SignalLogs {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidInput}
	}
	if err := ctx.Err(); err != nil {
		return LocalLogOutcome{}, &Error{code: ErrorContextDone, contextCause: err}
	}
	safeBuilder := func(admission router.Admission) (observability.Record, error) {
		if builder == nil {
			return observability.Record{}, &recordBuildFailure{}
		}
		record, err := builder(admission)
		if err != nil {
			return observability.Record{}, &recordBuildFailure{}
		}
		return record, nil
	}
	result, err := pipeline.evaluator.EvaluateManagedLogFallback(metadata, safeBuilder)
	if err != nil {
		var buildFailure *recordBuildFailure
		if errors.As(err, &buildFailure) {
			return LocalLogOutcome{}, &Error{code: ErrorRecordBuild}
		}
		return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
	}
	outcome := LocalLogOutcome{admission: router.AdmissionDrop}
	record, ok := result.Record()
	if !ok {
		return outcome, nil
	}
	delivery, ok := result.Delivery()
	if !ok || delivery.DestinationName != config.ObservabilityV8ManagedAIDDestinationName ||
		delivery.DestinationKind != config.ObservabilityV8DestinationOTLP ||
		delivery.MandatoryFloor || delivery.RedactionProfile != string(v8redaction.ProfileSensitive) {
		return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
	}
	outcome.managedOnly = true
	profile, found := pipeline.resolveProjectionProfile(
		v8redaction.ProfileSensitive, legacyredaction.SinkPolicyFromContext(ctx),
	)
	if !found {
		outcome.optionalFailure = append(outcome.optionalFailure, newOptionalFailure(
			delivery, OptionalFailureProfile,
		))
		return outcome, nil
	}
	projection, _, projectErr := pipeline.projector.Project(record, profile)
	if projectErr != nil {
		outcome.optionalFailure = append(outcome.optionalFailure, newOptionalFailure(
			delivery, boundedProjectionFailure(projectErr),
		))
		return outcome, nil
	}
	outcome.optionalWork = append(outcome.optionalWork, ProjectedDelivery{
		delivery: delivery, projection: projection,
		identity: ProjectedDeliveryIdentity{
			recordID: record.RecordID(), bucket: record.Bucket(), signal: record.Signal(),
			eventName: record.EventName(),
		},
	})
	return outcome, nil
}

func (pipeline *LocalLogPipeline) process(
	ctx context.Context,
	metadata router.Metadata,
	builder router.RecordBuilder,
	localOnly bool,
	originDestination string,
) (LocalLogOutcome, error) {
	if pipeline == nil || pipeline.evaluator == nil || pipeline.projector == nil ||
		pipeline.appender == nil || pipeline.failures == nil {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	if ctx == nil {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidInput}
	}
	if err := ctx.Err(); err != nil {
		return LocalLogOutcome{}, &Error{code: ErrorContextDone, contextCause: err}
	}
	if metadata.Identity().Signal != observability.SignalLogs {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidInput}
	}

	safeBuilder := func(admission router.Admission) (observability.Record, error) {
		if builder == nil {
			return observability.Record{}, &recordBuildFailure{}
		}
		record, err := builder(admission)
		if err != nil {
			return observability.Record{}, &recordBuildFailure{}
		}
		return record, nil
	}
	result, err := pipeline.evaluator.Evaluate(metadata, safeBuilder)
	if err != nil {
		var buildFailure *recordBuildFailure
		if errors.As(err, &buildFailure) {
			return LocalLogOutcome{}, &Error{code: ErrorRecordBuild}
		}
		return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
	}
	outcome := LocalLogOutcome{admission: result.Admission()}
	if result.Admission() == router.AdmissionDrop {
		return outcome, nil
	}
	record, ok := result.Record()
	if !ok || record.Signal() != observability.SignalLogs {
		return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
	}

	local, optional, ok := splitLocalDelivery(result.Deliveries(), result.Admission())
	if !ok {
		return LocalLogOutcome{}, &Error{code: ErrorLocalDelivery}
	}
	sinkPolicy := legacyredaction.SinkPolicyFromContext(ctx)
	localProfile, ok := pipeline.resolveProjectionProfile(
		v8redaction.ProfileName(local.RedactionProfile), sinkPolicy,
	)
	if !ok {
		return LocalLogOutcome{}, &Error{code: ErrorLocalProfile}
	}
	localProjection, _, err := pipeline.projector.Project(record, localProfile)
	if err != nil {
		failureErr := pipeline.persistLocalProjectionFailure(
			ctx, record, localProfile.Name(), boundedProjectionFailure(err),
		)
		if failureErr != nil {
			return LocalLogOutcome{}, failureErr
		}
		return LocalLogOutcome{}, &Error{code: ErrorLocalProjection}
	}
	if err := pipeline.appender.AppendContext(ctx, record.Clone(), localProjection); err != nil {
		return LocalLogOutcome{}, boundedPipelineError(ErrorLocalWrite, err)
	}
	outcome.localPersisted = true
	if localOnly {
		return outcome, nil
	}

	for _, delivery := range optional {
		profile, found := pipeline.resolveProjectionProfile(
			v8redaction.ProfileName(delivery.RedactionProfile), sinkPolicy,
		)
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
			delivery: delivery, projection: projection,
			identity: ProjectedDeliveryIdentity{
				recordID: record.RecordID(), bucket: record.Bucket(), signal: record.Signal(),
				eventName: record.EventName(), originDestination: originDestination,
			},
		})
	}
	return outcome, nil
}

// resolveProjectionProfile applies the request-scoped managed inspection
// policy only to the projection selected for this occurrence. The compiled
// delivery and plan remain immutable so a policy can never leak into another
// record or runtime generation.
func (pipeline *LocalLogPipeline) resolveProjectionProfile(
	configured v8redaction.ProfileName,
	policy legacyredaction.SinkPolicy,
) (v8redaction.Profile, bool) {
	if pipeline == nil {
		return v8redaction.Profile{}, false
	}
	profileName := configured
	switch policy {
	case legacyredaction.SinkPolicyDefault:
	case legacyredaction.SinkPolicyRaw:
		profileName = v8redaction.ProfileNone
	case legacyredaction.SinkPolicyRedact:
		profileName = v8redaction.ProfileSensitive
	default:
		return v8redaction.Profile{}, false
	}
	return pipeline.catalog.Resolve(profileName)
}

func (pipeline *LocalLogPipeline) persistLocalProjectionFailure(
	ctx context.Context,
	failed observability.Record,
	profile v8redaction.ProfileName,
	code OptionalFailureCode,
) error {
	failureRecord, err := pipeline.failures.BuildProjectionFailure(ctx, ProjectionFailureRecord{
		FailedBucket: failed.Bucket(), RedactionProfile: profile, FailureCode: code,
		Correlation: failed.Correlation(), Provenance: failed.Provenance(),
	})
	if err != nil {
		return boundedPipelineError(ErrorFailureRecord, err)
	}
	severity, hasSeverity := failureRecord.Severity()
	if failureRecord.Signal() != observability.SignalLogs ||
		failureRecord.Bucket() != observability.BucketPlatformHealth ||
		failureRecord.EventName() != "redaction.failed_closed" ||
		!failureRecord.Mandatory() || failureRecord.IsFloorOnly() ||
		!hasSeverity || severity != observability.SeverityInfo {
		return &Error{code: ErrorFailureRecord}
	}
	profileName, ok := pipeline.local[observability.BucketPlatformHealth]
	if !ok {
		return &Error{code: ErrorFailureRecord}
	}
	localProfile, ok := pipeline.catalog.Resolve(profileName)
	if !ok {
		return &Error{code: ErrorFailureRecord}
	}
	projection, _, err := pipeline.projector.Project(failureRecord, localProfile)
	if err != nil {
		return boundedPipelineError(ErrorFailureRecord, err)
	}
	if err := pipeline.appender.AppendContext(ctx, failureRecord, projection); err != nil {
		return boundedPipelineError(ErrorLocalWrite, err)
	}
	return nil
}

func boundedPipelineError(code ErrorCode, err error) *Error {
	result := &Error{code: code}
	switch {
	case errors.Is(err, context.Canceled):
		result.contextCause = context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		result.contextCause = context.DeadlineExceeded
	}
	return result
}

func splitLocalDelivery(
	deliveries []router.Delivery,
	admission router.Admission,
) (router.Delivery, []router.Delivery, bool) {
	var local router.Delivery
	optional := make([]router.Delivery, 0, len(deliveries))
	localCount := 0
	for _, delivery := range deliveries {
		if delivery.DestinationName == config.ObservabilityV8LocalDestinationName &&
			delivery.DestinationKind == config.ObservabilityV8DestinationLocalSQLite {
			local = delivery
			localCount++
			continue
		}
		optional = append(optional, delivery)
	}
	if localCount != 1 {
		return router.Delivery{}, nil, false
	}
	switch admission {
	case router.AdmissionOrdinary:
		if local.MandatoryFloor {
			return router.Delivery{}, nil, false
		}
	case router.AdmissionFloor:
		if !local.MandatoryFloor || len(optional) != 0 {
			return router.Delivery{}, nil, false
		}
	default:
		return router.Delivery{}, nil, false
	}
	return local, optional, true
}

func newOptionalFailure(delivery router.Delivery, code OptionalFailureCode) OptionalFailure {
	return OptionalFailure{
		destinationName: delivery.DestinationName,
		destinationKind: delivery.DestinationKind,
		routeName:       delivery.RouteName,
		routeIndex:      delivery.RouteIndex,
		code:            code,
	}
}

func boundedProjectionFailure(err error) OptionalFailureCode {
	var projectionError *v8redaction.ProjectionError
	if !errors.As(err, &projectionError) {
		return OptionalFailureProjection
	}
	switch projectionError.Code {
	case v8redaction.ProjectionFailureClassification:
		return OptionalFailureClassification
	case v8redaction.ProjectionFailureMetricClass:
		return OptionalFailureMetricClass
	case v8redaction.ProjectionFailureContext:
		return OptionalFailureContext
	case v8redaction.ProjectionFailureOutputLimit:
		return OptionalFailureOutputLimit
	case v8redaction.ProjectionFailureSerialization:
		return OptionalFailureSerialization
	default:
		return OptionalFailureProjection
	}
}
