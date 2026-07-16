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

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// RuntimeV8BuildContext is the exact graph generation pinned by the
// unified runtime for one emission. The runtime adapter must populate it from
// runtime.EmitContext; legacy version.ContentHash is not a graph digest.
type RuntimeV8BuildContext struct {
	ConfigGeneration uint64
	ConfigDigest     string
}

// RuntimeV8Builder is lazy: collection is evaluated before the generated
// family builder runs. AdmissionFloor selects the authenticated minimal floor
// record and never constructs the ordinary family body.
type RuntimeV8Builder func(
	RuntimeV8BuildContext,
	router.Admission,
) (observability.Record, error)

type RuntimeV8EmitOutcome struct {
	Admission      router.Admission
	LocalPersisted bool
}

// RuntimeV8LogOperation is an opaque audit-owned batch item. Private fields
// prevent callers outside this package from substituting metadata or a
// handwritten builder after the producer has selected a generated family.
type RuntimeV8LogOperation struct {
	ctx      context.Context
	metadata router.Metadata
	build    RuntimeV8Builder
}

func (operation RuntimeV8LogOperation) Context() context.Context  { return operation.ctx }
func (operation RuntimeV8LogOperation) Metadata() router.Metadata { return operation.metadata }
func (operation RuntimeV8LogOperation) Build(
	snapshot RuntimeV8BuildContext,
	admission router.Admission,
) (observability.Record, error) {
	if operation.ctx == nil || operation.build == nil {
		return observability.Record{}, fmt.Errorf("audit: generated log operation is unavailable")
	}
	return operation.build(snapshot, admission)
}

// RuntimeV8Emitter is the audit-owned, cycle-free runtime seam. A runtime
// adapter calls runtime.Emit with metadata and translates its pinned
// EmitContext into RuntimeV8BuildContext.
type RuntimeV8Emitter interface {
	EmitRuntimeV8(
		context.Context,
		router.Metadata,
		RuntimeV8Builder,
	) (RuntimeV8EmitOutcome, error)
}

// RuntimeV8LogBatchEmitter pins one immutable runtime generation across a
// bounded ordered set of related generated log occurrences.
type RuntimeV8LogBatchEmitter interface {
	EmitRuntimeV8LogBatch(
		context.Context,
		[]RuntimeV8LogOperation,
	) ([]RuntimeV8EmitOutcome, error)
}

// RuntimeV8AssetScanTraceEmitter is the optional cycle-free trace capability
// used after a scanner result has been forensically persisted. The concrete
// runtime owns collection, sampling, W3C identity, resource fields, generated
// family construction, routing, and export.
type RuntimeV8AssetScanTraceEmitter interface {
	EmitRuntimeV8AssetScanTrace(context.Context, observability.SpanAssetScanInput) error
}

type auditV8Disposition uint8

const (
	auditV8Unhandled auditV8Disposition = iota
	auditV8Persisted
	auditV8Dropped
)

type controlPlaneV8Family uint8

// controlPlaneV8Evidence keeps secret-free summaries separate from source
// content. Content fields remain unmodified until the unified runtime applies
// the route-selected projection independently for each destination.
type controlPlaneV8Evidence struct {
	actorRef        observability.Optional[string]
	origin          observability.Optional[string]
	targetRef       observability.Optional[string]
	beforeSummary   observability.Optional[string]
	afterSummary    observability.Optional[string]
	beforeState     observability.Optional[string]
	afterState      observability.Optional[string]
	diff            observability.Optional[string]
	reason          observability.Optional[string]
	reasonDetail    observability.Optional[string]
	revision        observability.Optional[string]
	currentRevision observability.Optional[string]
	changeCount     observability.Optional[int64]
}

var controlPlaneV8PrincipalPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

const (
	controlPlaneV8FamilyNone controlPlaneV8Family = iota
	controlPlaneV8FamilyConfigApplied
	controlPlaneV8FamilyPolicyUpdated
	controlPlaneV8FamilyAuthenticationFailed
	controlPlaneV8FamilyApprovalResolved
)

// emitControlPlaneV8 sends one selected v7 Event through the canonical runtime.
// Any handled disposition means the runtime exclusively owns persistence and
// fanout, including an intentional non-mandatory collection drop.
func (l *Logger) emitControlPlaneV8(ctx context.Context, event Event) (auditV8Disposition, error) {
	return l.emitControlPlaneV8WithEvidence(ctx, event, controlPlaneV8Evidence{})
}

func (l *Logger) emitControlPlaneV8WithEvidence(
	ctx context.Context,
	event Event,
	evidence controlPlaneV8Evidence,
) (auditV8Disposition, error) {
	return l.emitControlPlaneV8WithEvidenceAndMetrics(ctx, event, evidence, nil)
}

func (l *Logger) emitControlPlaneV8WithEvidenceAndMetrics(
	ctx context.Context,
	event Event,
	evidence controlPlaneV8Evidence,
	companionMetrics []RuntimeV8GeneratedMetric,
) (auditV8Disposition, error) {
	family := controlPlaneV8FamilyForAction(event.Action)
	if family == controlPlaneV8FamilyNone {
		return auditV8Unhandled, nil
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.emitter == nil {
		return auditV8Persisted, fmt.Errorf("audit: v8 control-plane runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	normalized := observability.NormalizeSeverity(event.Severity)
	if !normalized.Valid || !normalized.Present {
		return auditV8Persisted, fmt.Errorf("audit: v8 control-plane severity %q is not canonical", event.Severity)
	}
	source := controlPlaneV8Source(event, family)
	classification := controlPlaneV8Classification(family, event.Severity)
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(event.Action),
		classification,
		source,
		event.Connector,
		observability.ProducerKey(event.Action),
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: classify v8 control-plane action %q: %w", event.Action, err)
	}

	build := func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
		return buildControlPlaneV8Record(
			event, family, source, classification, normalized, snapshot, admission, evidence,
		)
	}
	result, err := binding.emitter.EmitRuntimeV8(
		contextWithLegacyEventProjection(ctx, event), metadata, build,
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit v8 control-plane action %q: %w", event.Action, err)
	}
	disposition, outcomeErr := runtimeV8Disposition(result, true)
	if outcomeErr != nil {
		return auditV8Persisted, fmt.Errorf("audit: v8 control-plane action %q: %w", event.Action, outcomeErr)
	}
	if disposition == auditV8Persisted {
		auditMetric, metricErr := newAuditEventRuntimeV8GeneratedMetric(event)
		if metricErr == nil {
			metrics := make([]RuntimeV8GeneratedMetric, 0, 1+len(companionMetrics))
			metrics = append(metrics, auditMetric)
			metrics = append(metrics, companionMetrics...)
			// Metrics are an independent best-effort signal. Once the canonical
			// log is durably persisted, a metric-path failure must not report the
			// operator mutation as failed or invite a retry that duplicates it.
			_ = l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, metrics)
		}
	}
	return disposition, nil
}

func runtimeV8Disposition(outcome RuntimeV8EmitOutcome, mandatory bool) (auditV8Disposition, error) {
	switch outcome.Admission {
	case router.AdmissionDrop:
		if outcome.LocalPersisted {
			return auditV8Persisted, fmt.Errorf("drop admission reported local persistence")
		}
		if mandatory {
			return auditV8Persisted, fmt.Errorf("mandatory occurrence received drop admission")
		}
		return auditV8Dropped, nil
	case router.AdmissionOrdinary, router.AdmissionFloor:
		if !outcome.LocalPersisted {
			return auditV8Persisted, fmt.Errorf("admitted occurrence was not persisted locally")
		}
		return auditV8Persisted, nil
	default:
		return auditV8Persisted, fmt.Errorf("runtime returned an invalid admission")
	}
}

func buildControlPlaneV8Record(
	event Event,
	family controlPlaneV8Family,
	source observability.Source,
	classification observability.ClassificationContext,
	normalized observability.SeverityNormalization,
	snapshot RuntimeV8BuildContext,
	admission router.Admission,
	evidence controlPlaneV8Evidence,
) (observability.Record, error) {
	if event.ID == "" || event.Timestamp.IsZero() || event.BinaryVersion == "" ||
		snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 control-plane build context")
	}
	clock := observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() })
	ids := observability.OccurrenceIDGeneratorFunc(func() (string, error) { return event.ID, nil })
	correlation := controlPlaneV8Correlation(event)
	provenance := observability.FamilyProvenanceInput{
		Producer:         "audit_logger",
		BinaryVersion:    event.BinaryVersion,
		ConfigGeneration: int64(snapshot.ConfigGeneration),
		ConfigDigest:     snapshot.ConfigDigest,
	}
	if admission == router.AdmissionFloor {
		builder, err := observability.NewRecordBuilder(clock, ids)
		if err != nil {
			return observability.Record{}, err
		}
		return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
			ProducerKind:          observability.ProducerAuditAction,
			ProducerKey:           observability.ProducerKey(event.Action),
			ClassificationContext: classification,
			ObservedAt:            timePointer(event.Timestamp.UTC()),
			Source:                source,
			Connector:             event.Connector,
			Action:                event.Action,
			Phase:                 controlPlaneV8Phase(family),
			Outcome:               controlPlaneV8Outcome(family, event.Action),
			Correlation:           correlation,
			Provenance: observability.Provenance{
				Producer:              provenance.Producer,
				BinaryVersion:         provenance.BinaryVersion,
				RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
				ConfigGeneration:      provenance.ConfigGeneration,
				ConfigDigest:          provenance.ConfigDigest,
			},
		})
	}
	if admission != router.AdmissionOrdinary {
		return observability.Record{}, fmt.Errorf("audit: v8 control-plane record has no admitted path")
	}

	builder, err := observability.NewFamilyBuilder(clock, ids)
	if err != nil {
		return observability.Record{}, err
	}
	severity := observability.Present(normalized.Severity)
	logLevel := observability.Absent[observability.LogLevel]()
	if normalized.LogLevel != "" {
		logLevel = observability.Present(normalized.LogLevel)
	}
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt:  observability.Present(event.Timestamp.UTC()),
		Source:      source,
		Connector:   event.Connector,
		Action:      event.Action,
		Phase:       controlPlaneV8Phase(family),
		Correlation: correlation,
		Provenance:  provenance,
	}
	principal, principalKnown := controlPlaneV8Principal(event.Actor)
	actorRef := evidence.actorRef
	if !actorRef.IsPresent() {
		actorRef = optionalControlPlaneV8Actor(event.Actor)
	}
	origin := evidence.origin
	if !origin.IsPresent() {
		origin = controlPlaneV8Origin(source)
	}
	targetRef := evidence.targetRef
	if !targetRef.IsPresent() {
		targetRef = optionalControlPlaneV8Target(event.Target)
	}

	var record observability.Record
	switch family {
	case controlPlaneV8FamilyConfigApplied:
		record, err = builder.BuildLogConfigChangeApplied(observability.LogConfigChangeAppliedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: observability.OutcomeApplied, DefenseClawAdminOperation: event.Action,
			DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
			DefenseClawAdminActorRef: actorRef, DefenseClawAdminOrigin: origin,
			DefenseClawAdminTargetRef:       targetRef,
			DefenseClawAdminBeforeSummary:   evidence.beforeSummary,
			DefenseClawAdminAfterSummary:    evidence.afterSummary,
			DefenseClawAdminBeforeState:     evidence.beforeState,
			DefenseClawAdminAfterState:      evidence.afterState,
			DefenseClawAdminDiff:            evidence.diff,
			DefenseClawAdminReason:          evidence.reason,
			DefenseClawAdminReasonDetail:    evidence.reasonDetail,
			DefenseClawAdminRevision:        evidence.revision,
			DefenseClawAdminCurrentRevision: evidence.currentRevision,
			DefenseClawAdminChangeCount:     evidence.changeCount,
			MandatoryControlPlaneMutation:   true,
		})
	case controlPlaneV8FamilyPolicyUpdated:
		record, err = builder.BuildLogPolicyUpdated(observability.LogPolicyUpdatedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: observability.OutcomeApplied, DefenseClawAdminOperation: event.Action,
			DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
			DefenseClawAdminActorRef: actorRef, DefenseClawAdminOrigin: origin,
			DefenseClawAdminTargetRef:       targetRef,
			DefenseClawAdminBeforeSummary:   evidence.beforeSummary,
			DefenseClawAdminAfterSummary:    evidence.afterSummary,
			DefenseClawAdminBeforeState:     evidence.beforeState,
			DefenseClawAdminAfterState:      evidence.afterState,
			DefenseClawAdminDiff:            evidence.diff,
			DefenseClawAdminReason:          evidence.reason,
			DefenseClawAdminReasonDetail:    evidence.reasonDetail,
			DefenseClawAdminRevision:        evidence.revision,
			DefenseClawAdminCurrentRevision: evidence.currentRevision,
			DefenseClawAdminChangeCount:     evidence.changeCount,
			MandatoryControlPlaneMutation:   true,
		})
	case controlPlaneV8FamilyAuthenticationFailed:
		record, err = builder.BuildLogAuthenticationFailed(observability.LogAuthenticationFailedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: observability.OutcomeRejected, DefenseClawAdminOperation: event.Action,
			DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
			DefenseClawAdminActorRef: actorRef, DefenseClawAdminOrigin: origin,
			DefenseClawAdminTargetRef: targetRef, DefenseClawAdminReason: evidence.reason,
			MandatoryProtectedBoundaryAuthFailure: true,
		})
	case controlPlaneV8FamilyApprovalResolved:
		result, outcome, ok := controlPlaneV8ApprovalResolution(event.Action)
		if !ok {
			return observability.Record{}, fmt.Errorf("audit: approval action does not identify a resolution")
		}
		record, err = builder.BuildLogApprovalResolved(observability.LogApprovalResolvedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
			DefenseClawApprovalID: event.Target, DefenseClawApprovalResult: result,
			DefenseClawPolicyID:         optionalControlPlaneV8Identifier(event.PolicyID),
			MandatoryApprovalResolution: true,
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported v8 control-plane family")
	}
	if err != nil {
		return observability.Record{}, err
	}
	if !record.Mandatory() || record.IsFloorOnly() || record.RecordID() != event.ID ||
		!record.Timestamp().Equal(event.Timestamp.UTC()) {
		return observability.Record{}, fmt.Errorf("audit: generated v8 control-plane record violated its identity contract")
	}
	return record, nil
}

func controlPlaneV8FamilyForAction(action string) controlPlaneV8Family {
	switch Action(action) {
	case ActionConfigUpdate, ActionAPIConfigPatch, ActionGuardrailConfigReload:
		return controlPlaneV8FamilyConfigApplied
	case ActionPolicyUpdate, ActionPolicyReload:
		return controlPlaneV8FamilyPolicyUpdated
	case ActionAPIAuthFailure:
		return controlPlaneV8FamilyAuthenticationFailed
	case ActionApprovalGranted, ActionApprovalDenied,
		ActionGatewayApprovalGranted, ActionGatewayApprovalDenied:
		return controlPlaneV8FamilyApprovalResolved
	default:
		return controlPlaneV8FamilyNone
	}
}

func controlPlaneV8Classification(family controlPlaneV8Family, severity string) observability.ClassificationContext {
	context := observability.ClassificationContext{RawSeverity: severity}
	switch family {
	case controlPlaneV8FamilyConfigApplied:
		context.EventName = observability.EventName(observability.TelemetryEventConfigChangeApplied)
		context.MandatoryFacts.ControlPlaneMutation = true
	case controlPlaneV8FamilyPolicyUpdated:
		context.EventName = observability.EventName(observability.TelemetryEventPolicyUpdated)
		context.MandatoryFacts.ControlPlaneMutation = true
	case controlPlaneV8FamilyAuthenticationFailed:
		context.EventName = observability.EventName(observability.TelemetryEventAuthenticationFailed)
		context.MandatoryFacts.ProtectedBoundaryAuthFailure = true
	case controlPlaneV8FamilyApprovalResolved:
		context.EventName = observability.EventName(observability.TelemetryEventApprovalResolved)
		context.MandatoryFacts.ApprovalResolution = true
	}
	return context
}

func controlPlaneV8Phase(family controlPlaneV8Family) string {
	if family == controlPlaneV8FamilyAuthenticationFailed {
		return "authentication"
	}
	if family == controlPlaneV8FamilyApprovalResolved {
		return "resolve"
	}
	return "apply"
}

func controlPlaneV8Outcome(family controlPlaneV8Family, action string) observability.Outcome {
	if family == controlPlaneV8FamilyAuthenticationFailed {
		return observability.OutcomeRejected
	}
	if family == controlPlaneV8FamilyApprovalResolved {
		// Floor records intentionally omit the ordinary resolution body. The
		// action still supplies the exact outcome without inspecting details.
		_, outcome, _ := controlPlaneV8ApprovalResolution(action)
		return outcome
	}
	return observability.OutcomeApplied
}

func controlPlaneV8Source(event Event, family controlPlaneV8Family) observability.Source {
	if family == controlPlaneV8FamilyApprovalResolved {
		return observability.SourceGateway
	}
	action := Action(event.Action)
	if action == ActionAPIAuthFailure || action == ActionAPIConfigPatch {
		return observability.SourceOperatorAPI
	}
	actor := strings.ToLower(strings.TrimSpace(event.Actor))
	switch {
	case strings.HasPrefix(actor, "cli:") || actor == "cli":
		return observability.SourceCLI
	case actor == "watcher":
		return observability.SourceWatcher
	case event.RequestID != "":
		return observability.SourceOperatorAPI
	case actor != "" && actor != "system" && actor != "defenseclaw":
		return observability.SourceOperator
	default:
		return observability.SourceSystem
	}
}

func controlPlaneV8ApprovalResolution(action string) (string, observability.Outcome, bool) {
	switch Action(action) {
	case ActionApprovalGranted, ActionGatewayApprovalGranted:
		return "approved", observability.OutcomeApproved, true
	case ActionApprovalDenied, ActionGatewayApprovalDenied:
		return "denied", observability.OutcomeDenied, true
	default:
		return "", "", false
	}
}

func optionalControlPlaneV8Identifier(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || !utf8.ValidString(value) ||
		!controlPlaneV8PrincipalPattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalControlPlaneV8Actor(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || !utf8.ValidString(value) ||
		!controlPlaneV8PrincipalPattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalControlPlaneV8Target(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) ||
		!controlPlaneV8PrincipalPattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalControlPlaneV8Reason(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || !utf8.ValidString(value) ||
		!observability.IsStableToken(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalControlPlaneV8ReasonDetail(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	const maxBytes = 4096
	if len(value) > maxBytes {
		const suffix = "…[truncated]"
		value = truncateUTF8(value, maxBytes-len(suffix)) + suffix
	}
	return observability.Present(value)
}

func optionalControlPlaneV8Revision(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "gen=") {
		digits := strings.TrimPrefix(value, "gen=")
		valid := digits != ""
		for _, character := range digits {
			valid = valid && character >= '0' && character <= '9'
		}
		if valid {
			value = "generation:" + digits
		}
	}
	return optionalControlPlaneV8Identifier(value)
}

func controlPlaneV8Origin(source observability.Source) observability.Optional[string] {
	var origin string
	switch source {
	case observability.SourceOperatorAPI:
		origin = "api"
	case observability.SourceCLI:
		origin = "cli"
	case observability.SourceWatcher:
		origin = "config_file"
	case observability.SourceOperator:
		origin = "operator"
	default:
		origin = "internal"
	}
	return observability.Present(origin)
}

func controlPlaneV8ActivityEvidence(input ActivityInput) (controlPlaneV8Evidence, error) {
	beforeState, err := controlPlaneV8JSONEvidence(input.Before)
	if err != nil {
		return controlPlaneV8Evidence{}, fmt.Errorf("audit: encode administrative before state: %w", err)
	}
	afterState, err := controlPlaneV8JSONEvidence(input.After)
	if err != nil {
		return controlPlaneV8Evidence{}, fmt.Errorf("audit: encode administrative after state: %w", err)
	}
	diff, err := controlPlaneV8JSONEvidence(input.Diff)
	if err != nil {
		return controlPlaneV8Evidence{}, fmt.Errorf("audit: encode administrative diff: %w", err)
	}
	return controlPlaneV8Evidence{
		actorRef:        optionalControlPlaneV8Actor(input.Actor),
		targetRef:       optionalControlPlaneV8Target(activityTargetReference(input.TargetType, input.TargetID)),
		beforeSummary:   controlPlaneV8StateSummary(input.Before),
		afterSummary:    controlPlaneV8StateSummary(input.After),
		beforeState:     beforeState,
		afterState:      afterState,
		diff:            diff,
		reason:          optionalControlPlaneV8Reason(input.Reason),
		reasonDetail:    optionalControlPlaneV8ReasonDetail(input.Reason),
		revision:        optionalControlPlaneV8Revision(input.VersionTo),
		currentRevision: optionalControlPlaneV8Revision(input.VersionFrom),
		changeCount:     observability.Present(int64(len(input.Diff))),
	}, nil
}

func controlPlaneV8JSONEvidence(value any) (observability.Optional[string], error) {
	if value == nil {
		return observability.Absent[string](), nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return observability.Absent[string](), err
	}
	const maxBytes = 256 * 1024
	if len(encoded) > maxBytes {
		digest := sha256.Sum256(encoded)
		encoded, err = json.Marshal(map[string]any{
			"truncated":      true,
			"original_bytes": len(encoded),
			"sha256":         fmt.Sprintf("sha256:%x", digest),
		})
		if err != nil {
			return observability.Absent[string](), err
		}
	}
	return observability.Present(string(encoded)), nil
}

func activityTargetReference(targetType, targetID string) string {
	targetType = strings.TrimSpace(targetType)
	targetID = strings.TrimSpace(targetID)
	if targetType == "" || targetID == "" {
		return ""
	}
	return targetType + ":" + targetID
}

func controlPlaneV8StateSummary(value map[string]any) observability.Optional[string] {
	if value == nil {
		return observability.Absent[string]()
	}
	// Counts are intentionally the only generic summary. Field names and values
	// may themselves disclose credentials, paths, tenant data, or governed
	// content, so richer summaries require an explicit producer-owned allowlist.
	return observability.Present(fmt.Sprintf("object_fields=%d", len(value)))
}

func controlPlaneV8Correlation(event Event) observability.Correlation {
	return observability.Correlation{
		RunID:               event.RunID,
		RequestID:           event.RequestID,
		SessionID:           event.SessionID,
		TurnID:              event.TurnID,
		TraceID:             event.TraceID,
		SpanID:              event.SpanID,
		AgentID:             event.AgentID,
		AgentInstanceID:     event.AgentInstanceID,
		PolicyID:            event.PolicyID,
		EvaluationID:        event.EvaluationID,
		ScanID:              event.ScanID,
		FindingOccurrenceID: event.FindingOccurrenceID,
		ConnectorID:         event.Connector,
		SidecarInstanceID:   event.SidecarInstanceID,
	}
}

func controlPlaneV8Principal(actor string) (observability.Optional[string], bool) {
	actor = strings.TrimSpace(actor)
	trustedPrincipal := strings.HasPrefix(actor, "principal:") ||
		strings.HasPrefix(actor, "operator:") || strings.HasPrefix(actor, "cli:")
	if !trustedPrincipal || len(actor) > 256 || !utf8.ValidString(actor) ||
		!controlPlaneV8PrincipalPattern.MatchString(actor) {
		return observability.Absent[string](), false
	}
	return observability.Present(actor), true
}

func timePointer(value time.Time) *time.Time { return &value }
