// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

const eventRouterApprovalV8Producer = "gateway.event_router.approval"

type eventRouterApprovalObservation struct {
	id                string
	connector         string
	sessionKey        string
	sessionID         string
	rootSessionID     string
	parentSessionID   string
	runID             string
	requestID         string
	turnID            string
	operationID       string
	agentID           string
	agentName         string
	agentType         string
	agentInstanceID   string
	rootAgentID       string
	parentAgentID     string
	lineageProvenance string
	lifecycleID       string
	executionID       string
	phase             string
	depth             int64
	depthSet          bool
	sequence          int64
	sequenceSet       bool
	userID            string
	userName          string
	policyID          string
	policyVersion     string
	destinationApp    string
	toolID            string
	toolName          string
	toolType          string
	toolCallID        string
	toolProvider      string
	toolSkillKey      string
	commandName       string
	command           string
	argv              []string
	cwd               string
	result            string
	actorType         string
	reason            string
	ruleIDs           []string
	dangerous         bool
	startedAt         time.Time
	finishedAt        time.Time
}

type eventRouterApprovalEmission uint8

const (
	eventRouterApprovalUnavailable eventRouterApprovalEmission = iota
	eventRouterApprovalRejected
	eventRouterApprovalDropped
	eventRouterApprovalEmitted
	eventRouterApprovalFailed
)

func (r *EventRouter) emitApprovalResolutionV8(
	ctx context.Context,
	observation eventRouterApprovalObservation,
) eventRouterApprovalEmission {
	emitter, runtime, authoritative := r.observabilityV8CapabilitiesSnapshot()
	if !authoritative || runtime == nil {
		return eventRouterApprovalUnavailable
	}
	observation = r.normalizeEventRouterApprovalObservation(observation)
	if ctx == nil || !validEventRouterApprovalObservation(observation) {
		return eventRouterApprovalRejected
	}
	if emitter != nil {
		if err := r.emitEventRouterApprovalLogV8(ctx, emitter, false, observation); err != nil {
			return eventRouterApprovalFailed
		}
		metricRuntime, ok := emitter.(hookLifecycleMetricV8Runtime)
		if !ok {
			return eventRouterApprovalFailed
		}
		if err := r.recordEventRouterApprovalMetricsV8(ctx, metricRuntime, observation); err != nil {
			return eventRouterApprovalFailed
		}
	}
	requested, err := observability.NewSpanApprovalResolveApprovalRequestedEvent(
		observability.SpanApprovalResolveApprovalRequestedEventInput{
			TimeUnixNano:          uint64(observation.startedAt.UnixNano()),
			DefenseClawApprovalID: observability.Present(observation.id),
		},
	)
	if err != nil {
		return eventRouterApprovalFailed
	}
	resolved, err := observability.NewSpanApprovalResolveApprovalResolvedEvent(
		observability.SpanApprovalResolveApprovalResolvedEventInput{
			TimeUnixNano:                 uint64(observation.finishedAt.UnixNano()),
			DefenseClawApprovalID:        observability.Present(observation.id),
			DefenseClawApprovalResult:    observability.Present(observation.result),
			DefenseClawApprovalActorType: observability.Present(observation.actorType),
		},
	)
	if err != nil {
		return eventRouterApprovalFailed
	}
	outcome := observability.OutcomeDenied
	if observation.result == "approved" {
		outcome = observability.OutcomeApproved
	} else if observation.result == "cancelled" {
		outcome = observability.OutcomeCancelled
	} else if observation.result == "expired" {
		outcome = observability.OutcomeTimedOut
	}
	input := observability.SpanApprovalResolveInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceConnector, Connector: observation.connector,
			Action: "exec.approval", Phase: "approval",
			Correlation: correlationWithSpanContext(eventRouterApprovalCorrelation(observation), ctx),
			Provenance:  observability.FamilyProvenanceInput{Producer: eventRouterApprovalV8Producer},
		},
		Outcome: outcome, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(observation.startedAt.UnixNano()),
		EndTimeUnixNano:   uint64(observation.finishedAt.UnixNano()),
		Status:            observability.NewTraceStatusOK(), Events: []observability.TraceEventInput{requested, resolved},
		DefenseClawConnectorSource:        observability.Present(observation.connector),
		DefenseClawRunID:                  hookModelV8OptionalID(observation.runID),
		DefenseClawOperationID:            hookModelV8OptionalID(observation.operationID),
		DefenseClawRequestID:              hookModelV8OptionalID(observation.requestID),
		DefenseClawTurnID:                 hookModelV8OptionalID(observation.turnID),
		UserID:                            hookModelV8OptionalID(observation.userID),
		DefenseClawUserName:               hookModelV8OptionalID(observation.userName),
		GenAIConversationID:               hookModelV8OptionalID(observation.sessionID),
		GenAIAgentID:                      hookModelV8OptionalID(observation.agentID),
		GenAIAgentName:                    hookModelV8OptionalID(observation.agentName),
		DefenseClawAgentType:              hookModelV8OptionalID(observation.agentType),
		DefenseClawAgentInstanceID:        hookModelV8OptionalID(observation.agentInstanceID),
		DefenseClawAgentRootID:            hookModelV8OptionalID(observation.rootAgentID),
		DefenseClawAgentParentID:          hookModelV8OptionalID(observation.parentAgentID),
		DefenseClawAgentLineageProvenance: hookV8OptionalLineageProvenance(observation.lineageProvenance),
		DefenseClawSessionRootID:          hookModelV8OptionalID(observation.rootSessionID),
		DefenseClawSessionParentID:        hookModelV8OptionalID(observation.parentSessionID),
		DefenseClawAgentLifecycleID:       hookModelV8OptionalID(observation.lifecycleID),
		DefenseClawAgentExecutionID:       hookModelV8OptionalID(observation.executionID),
		DefenseClawAgentDepth:             eventRouterApprovalDepth(observation),
		DefenseClawAgentPhase:             hookV8OptionalPhase(observation.phase),
		DefenseClawAgentPhaseCode:         hookV8OptionalPhaseCode(observation.phase),
		DefenseClawAgentSequence:          eventRouterApprovalSequence(observation),
		DefenseClawPolicyID:               hookModelV8OptionalID(observation.policyID),
		DefenseClawPolicyVersion:          hookModelV8OptionalID(observation.policyVersion),
		DefenseClawDestinationApp:         hookModelV8OptionalID(observation.destinationApp),
		DefenseClawToolID:                 hookModelV8OptionalID(observation.toolID),
		GenAIToolName:                     hookModelV8OptionalID(observation.toolName),
		GenAIToolType:                     hookModelV8OptionalText(observation.toolType),
		GenAIToolCallID:                   hookModelV8OptionalID(observation.toolCallID),
		DefenseClawToolProvider:           hookModelV8OptionalText(observation.toolProvider),
		DefenseClawToolSkillKey:           hookModelV8OptionalID(observation.toolSkillKey),
		DefenseClawApprovalID:             observability.Present(observation.id),
		DefenseClawApprovalCommandName:    hookModelV8OptionalText(observation.commandName),
		DefenseClawApprovalArgc:           observability.Present(int64(len(observation.argv))),
		DefenseClawApprovalCommand:        optionalApprovalContent(observation.command),
		DefenseClawApprovalArgv:           optionalApprovalArgv(observation.argv),
		DefenseClawApprovalCwd:            optionalApprovalPath(observation.cwd),
		DefenseClawApprovalActorType:      observability.Present(observation.actorType),
		DefenseClawApprovalResult:         observability.Present(observation.result),
		DefenseClawApprovalDangerous:      observability.Present(observation.dangerous),
		DefenseClawGuardrailReason:        optionalApprovalReason(observation.reason),
		DefenseClawGuardrailRuleIds:       optionalApprovalRuleIDs(observation.ruleIDs),
		ConditionConnectorKnown:           true, ConditionOperationTerminal: true,
	}
	_, span, err := runtime.StartApprovalTrace(ctx, input)
	if err != nil {
		return eventRouterApprovalFailed
	}
	if span == nil {
		return eventRouterApprovalDropped
	}
	defer span.Abort()
	if err := span.End(input); err != nil {
		return eventRouterApprovalFailed
	}
	return eventRouterApprovalEmitted
}

func (r *EventRouter) emitApprovalRequestedV8(
	ctx context.Context,
	observation eventRouterApprovalObservation,
) eventRouterApprovalEmission {
	emitter, _, authoritative := r.observabilityV8CapabilitiesSnapshot()
	if !authoritative || emitter == nil {
		return eventRouterApprovalUnavailable
	}
	observation = r.normalizeEventRouterApprovalObservation(observation)
	if ctx == nil || !validEventRouterApprovalRequest(observation) {
		return eventRouterApprovalRejected
	}
	if err := r.emitEventRouterApprovalLogV8(ctx, emitter, true, observation); err != nil {
		return eventRouterApprovalFailed
	}
	return eventRouterApprovalEmitted
}

func (r *EventRouter) emitApprovalPendingMetricsV8(
	ctx context.Context,
	observation eventRouterApprovalObservation,
) eventRouterApprovalEmission {
	emitter, _, authoritative := r.observabilityV8CapabilitiesSnapshot()
	if !authoritative || emitter == nil {
		return eventRouterApprovalUnavailable
	}
	observation = r.normalizeEventRouterApprovalObservation(observation)
	metricRuntime, ok := emitter.(hookLifecycleMetricV8Runtime)
	if !ok || ctx == nil || !validEventRouterApprovalRequest(observation) {
		return eventRouterApprovalRejected
	}
	observation.result = "pending"
	observation.actorType = "operator"
	observation.finishedAt = observation.startedAt
	if err := r.recordEventRouterApprovalMetricsV8(ctx, metricRuntime, observation); err != nil {
		return eventRouterApprovalFailed
	}
	return eventRouterApprovalEmitted
}

func (r *EventRouter) emitEventRouterApprovalLogV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	requested bool,
	observation eventRouterApprovalObservation,
) error {
	if ctx == nil || emitter == nil {
		return errors.New("event router approval log runtime is unavailable")
	}
	eventName := observability.EventName(observability.TelemetryEventApprovalResolved)
	producerKey := observability.ProducerKey(audit.ActionGatewayApprovalDenied)
	rawSeverity := "INFO"
	classification := observability.ClassificationContext{
		Bucket: observability.BucketComplianceActivity, EventName: eventName,
		RawSeverity: rawSeverity, MandatoryFacts: observability.MandatoryFacts{ApprovalResolution: true},
	}
	observedAt := observation.finishedAt
	if requested {
		eventName = observability.EventName(observability.TelemetryEventApprovalRequested)
		producerKey = observability.ProducerKey(audit.ActionGatewayApprovalRequested)
		classification.EventName = eventName
		classification.MandatoryFacts = observability.MandatoryFacts{}
		observedAt = observation.startedAt
	} else if observation.result == "approved" {
		producerKey = observability.ProducerKey(audit.ActionGatewayApprovalGranted)
	} else {
		rawSeverity = "HIGH"
		classification.RawSeverity = rawSeverity
	}
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, observation.connector, producerKey,
	)
	if err != nil {
		return err
	}
	correlation := correlationWithSpanContext(eventRouterApprovalCorrelation(observation), ctx)
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 || !observability.IsStableToken(snapshot.Digest()) {
			return observability.Record{}, errors.New("event router approval generation is invalid")
		}
		provenance := observability.Provenance{
			Producer: eventRouterApprovalV8Producer, BinaryVersion: version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		}
		if admission == observabilityrouter.AdmissionFloor {
			if requested {
				return observability.Record{}, errors.New("approval request cannot enter the compliance floor")
			}
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: observability.ProducerAuditAction, ProducerKey: producerKey,
				ClassificationContext: classification, Source: observability.SourceGateway,
				Connector: observation.connector, Action: string(producerKey), Phase: "resolve",
				Outcome:     eventRouterApprovalOutcome(observation.result),
				Correlation: correlation, Provenance: provenance,
			})
		}
		if admission != observabilityrouter.AdmissionOrdinary {
			return observability.Record{}, errors.New("event router approval log admission is invalid")
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := eventRouterApprovalEnvelope(ctx, observation, observedAt, snapshot)
		envelope.Action = string(producerKey)
		if requested {
			envelope.Phase = "request"
		} else {
			envelope.Phase = "resolve"
		}
		severity := observability.SeverityInfo
		if rawSeverity == "HIGH" {
			severity = observability.SeverityHigh
		}
		if requested {
			return builder.BuildLogApprovalRequested(observability.LogApprovalRequestedInput{
				Envelope: envelope, Severity: observability.Present(severity), Outcome: observability.OutcomeAttempted,
				DefenseClawRequestID:   hookModelV8OptionalID(observation.requestID),
				DefenseClawTurnID:      hookModelV8OptionalID(observation.turnID),
				DefenseClawOperationID: hookModelV8OptionalID(observation.operationID),
				DefenseClawRunID:       hookModelV8OptionalID(observation.runID),
				UserID:                 hookModelV8OptionalID(observation.userID), DefenseClawUserName: hookModelV8OptionalID(observation.userName),
				GenAIConversationID: hookModelV8OptionalID(observation.sessionID),
				GenAIAgentID:        hookModelV8OptionalID(observation.agentID), GenAIAgentName: hookModelV8OptionalID(observation.agentName),
				DefenseClawAgentType:              hookModelV8OptionalID(observation.agentType),
				DefenseClawAgentInstanceID:        hookModelV8OptionalID(observation.agentInstanceID),
				DefenseClawAgentRootID:            hookModelV8OptionalID(observation.rootAgentID),
				DefenseClawAgentParentID:          hookModelV8OptionalID(observation.parentAgentID),
				DefenseClawAgentLineageProvenance: hookV8OptionalLineageProvenance(observation.lineageProvenance),
				DefenseClawSessionRootID:          hookModelV8OptionalID(observation.rootSessionID),
				DefenseClawSessionParentID:        hookModelV8OptionalID(observation.parentSessionID),
				DefenseClawAgentLifecycleID:       hookModelV8OptionalID(observation.lifecycleID),
				DefenseClawAgentExecutionID:       hookModelV8OptionalID(observation.executionID),
				DefenseClawAgentDepth:             eventRouterApprovalDepth(observation),
				DefenseClawAgentPhase:             hookV8OptionalPhase(observation.phase),
				DefenseClawAgentPhaseCode:         hookV8OptionalPhaseCode(observation.phase),
				DefenseClawAgentSequence:          eventRouterApprovalSequence(observation),
				DefenseClawPolicyID:               hookModelV8OptionalID(observation.policyID),
				DefenseClawPolicyVersion:          hookModelV8OptionalID(observation.policyVersion),
				DefenseClawDestinationApp:         hookModelV8OptionalID(observation.destinationApp),
				DefenseClawToolID:                 hookModelV8OptionalID(observation.toolID),
				GenAIToolName:                     hookModelV8OptionalID(observation.toolName),
				GenAIToolType:                     hookModelV8OptionalText(observation.toolType),
				GenAIToolCallID:                   hookModelV8OptionalID(observation.toolCallID),
				DefenseClawToolProvider:           hookModelV8OptionalText(observation.toolProvider),
				DefenseClawToolSkillKey:           hookModelV8OptionalID(observation.toolSkillKey),
				DefenseClawApprovalID:             observation.id,
				DefenseClawApprovalCommandName:    hookModelV8OptionalText(observation.commandName),
				DefenseClawApprovalArgc:           observability.Present(int64(len(observation.argv))),
				DefenseClawApprovalCommand:        optionalApprovalContent(observation.command),
				DefenseClawApprovalArgv:           optionalApprovalArgv(observation.argv), DefenseClawApprovalCwd: optionalApprovalPath(observation.cwd),
			})
		}
		record, recordErr := builder.BuildLogApprovalResolved(observability.LogApprovalResolvedInput{
			Envelope: envelope, Severity: observability.Present(severity), Outcome: eventRouterApprovalOutcome(observation.result),
			DefenseClawRequestID:   hookModelV8OptionalID(observation.requestID),
			DefenseClawTurnID:      hookModelV8OptionalID(observation.turnID),
			DefenseClawOperationID: hookModelV8OptionalID(observation.operationID),
			DefenseClawRunID:       hookModelV8OptionalID(observation.runID),
			UserID:                 hookModelV8OptionalID(observation.userID), DefenseClawUserName: hookModelV8OptionalID(observation.userName),
			GenAIConversationID: hookModelV8OptionalID(observation.sessionID),
			GenAIAgentID:        hookModelV8OptionalID(observation.agentID), GenAIAgentName: hookModelV8OptionalID(observation.agentName),
			DefenseClawAgentType:              hookModelV8OptionalID(observation.agentType),
			DefenseClawAgentInstanceID:        hookModelV8OptionalID(observation.agentInstanceID),
			DefenseClawAgentRootID:            hookModelV8OptionalID(observation.rootAgentID),
			DefenseClawAgentParentID:          hookModelV8OptionalID(observation.parentAgentID),
			DefenseClawAgentLineageProvenance: hookV8OptionalLineageProvenance(observation.lineageProvenance),
			DefenseClawSessionRootID:          hookModelV8OptionalID(observation.rootSessionID),
			DefenseClawSessionParentID:        hookModelV8OptionalID(observation.parentSessionID),
			DefenseClawAgentLifecycleID:       hookModelV8OptionalID(observation.lifecycleID),
			DefenseClawAgentExecutionID:       hookModelV8OptionalID(observation.executionID),
			DefenseClawAgentDepth:             eventRouterApprovalDepth(observation),
			DefenseClawAgentPhase:             hookV8OptionalPhase(observation.phase),
			DefenseClawAgentPhaseCode:         hookV8OptionalPhaseCode(observation.phase),
			DefenseClawAgentSequence:          eventRouterApprovalSequence(observation),
			DefenseClawPolicyID:               hookModelV8OptionalID(observation.policyID),
			DefenseClawPolicyVersion:          hookModelV8OptionalID(observation.policyVersion),
			DefenseClawDestinationApp:         hookModelV8OptionalID(observation.destinationApp),
			DefenseClawToolID:                 hookModelV8OptionalID(observation.toolID),
			GenAIToolName:                     hookModelV8OptionalID(observation.toolName),
			GenAIToolType:                     hookModelV8OptionalText(observation.toolType),
			GenAIToolCallID:                   hookModelV8OptionalID(observation.toolCallID),
			DefenseClawToolProvider:           hookModelV8OptionalText(observation.toolProvider),
			DefenseClawToolSkillKey:           hookModelV8OptionalID(observation.toolSkillKey),
			DefenseClawApprovalID:             observation.id,
			DefenseClawApprovalCommandName:    hookModelV8OptionalText(observation.commandName),
			DefenseClawApprovalArgc:           observability.Present(int64(len(observation.argv))),
			DefenseClawApprovalCommand:        optionalApprovalContent(observation.command), DefenseClawApprovalArgv: optionalApprovalArgv(observation.argv),
			DefenseClawApprovalCwd: optionalApprovalPath(observation.cwd), DefenseClawApprovalActorType: observability.Present(observation.actorType),
			DefenseClawApprovalResult: observation.result, DefenseClawApprovalDangerous: observability.Present(observation.dangerous),
			DefenseClawGuardrailReason: optionalApprovalReason(observation.reason), DefenseClawGuardrailRuleIds: optionalApprovalRuleIDs(observation.ruleIDs),
			MandatoryApprovalResolution: true,
		})
		return record, recordErr
	})
	return err
}

func (r *EventRouter) recordEventRouterApprovalMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	observation eventRouterApprovalObservation,
) error {
	if ctx == nil || runtime == nil {
		return errors.New("event router approval metric runtime is unavailable")
	}
	buildEnvelope := func(snapshot observabilityruntime.EmitContext) observability.FamilyEnvelopeInput {
		return eventRouterApprovalEnvelope(ctx, observation, observation.finishedAt, snapshot)
	}
	items := []observabilityruntime.GeneratedMetricBatchItem{
		{
			Family: observability.EventName(observability.TelemetryInstrumentDefenseClawApprovalLifecycle),
			Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
				if snapshot.Generation() > math.MaxInt64 {
					return observability.Record{}, errors.New("event router approval metric generation is invalid")
				}
				builder, err := eventRouterApprovalMetricBuilder(observation.finishedAt)
				if err != nil {
					return observability.Record{}, err
				}
				return builder.BuildMetricDefenseClawApprovalLifecycle(observability.MetricDefenseClawApprovalLifecycleInput{
					Envelope: buildEnvelope(snapshot), Value: 1,
					DefenseClawApprovalLifecycleResult: observation.result, DefenseClawApprovalSurface: "exec",
					DefenseClawConnectorSource: observability.Present(observation.connector),
				})
			},
		},
		{
			Family: observability.EventName(observability.TelemetryInstrumentDefenseClawApprovalCount),
			Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
				if snapshot.Generation() > math.MaxInt64 {
					return observability.Record{}, errors.New("event router approval metric generation is invalid")
				}
				builder, err := eventRouterApprovalMetricBuilder(observation.finishedAt)
				if err != nil {
					return observability.Record{}, err
				}
				return builder.BuildMetricDefenseClawApprovalCount(observability.MetricDefenseClawApprovalCountInput{
					Envelope: buildEnvelope(snapshot), Value: 1,
					DefenseClawMetricResult:    observability.Present(observation.result),
					DefenseClawMetricAuto:      observability.Present(observation.actorType == "automatic"),
					DefenseClawMetricDangerous: observability.Present(observation.dangerous),
				})
			},
		},
	}
	_, err := runtime.RecordGeneratedMetricBatch(ctx, items)
	return err
}

func eventRouterApprovalMetricBuilder(observedAt time.Time) (*observability.FamilyBuilder, error) {
	return observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return observedAt }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
}

func eventRouterApprovalEnvelope(
	ctx context.Context,
	observation eventRouterApprovalObservation,
	observedAt time.Time,
	snapshot observabilityruntime.EmitContext,
) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Connector: observation.connector, Action: "exec.approval", Phase: "approval",
		ObservedAt:  observability.Present(observedAt),
		Correlation: correlationWithSpanContext(eventRouterApprovalCorrelation(observation), ctx),
		Provenance: observability.FamilyProvenanceInput{
			Producer: eventRouterApprovalV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
}

func eventRouterApprovalCorrelation(observation eventRouterApprovalObservation) observability.Correlation {
	return observability.Correlation{
		RunID:     observation.runID,
		RequestID: observation.requestID, TurnID: observation.turnID,
		SessionID: firstNonEmpty(observation.sessionID, observation.sessionKey),
		AgentID:   observation.agentID, AgentInstanceID: observation.agentInstanceID,
		PolicyID: observation.policyID, PolicyVersion: observation.policyVersion,
		ToolInvocationID: observation.toolCallID,
		ConnectorID:      observation.connector, SidecarInstanceID: gatewaylog.SidecarInstanceID(),
	}
}

func (r *EventRouter) normalizeEventRouterApprovalObservation(
	observation eventRouterApprovalObservation,
) eventRouterApprovalObservation {
	if observation.connector == "" {
		observation.connector = "openclaw"
	}
	return observation
}

func (r *EventRouter) enrichEventRouterApprovalTopology(
	observation eventRouterApprovalObservation,
) eventRouterApprovalObservation {
	if r == nil || observation.sessionKey == "" || observation.sessionID == "" || observation.agentID == "" {
		return observation
	}
	now := time.Now()
	if r.agentRunObservationNow != nil {
		now = r.agentRunObservationNow()
	}
	r.agentRunObservationMu.Lock()
	defer r.agentRunObservationMu.Unlock()
	r.evictAgentRunObservationsLocked(now)
	state, found := r.agentRunTopologies[observation.sessionKey]
	if !found || state.topology.agentID != observation.agentID ||
		state.topology.conversationID != observation.sessionID {
		return observation
	}
	topology := state.topology
	observation.rootAgentID = firstNonEmpty(observation.rootAgentID, topology.rootAgentID)
	observation.parentAgentID = firstNonEmpty(observation.parentAgentID, topology.parentAgentID)
	observation.rootSessionID = firstNonEmpty(observation.rootSessionID, topology.rootSessionID)
	observation.parentSessionID = firstNonEmpty(observation.parentSessionID, topology.parentSessionID)
	observation.lifecycleID = firstNonEmpty(observation.lifecycleID, topology.lifecycleID)
	observation.executionID = firstNonEmpty(observation.executionID, topology.executionID)
	if observation.lineageProvenance == "" &&
		(observation.rootAgentID != "" || observation.parentAgentID != "") {
		observation.lineageProvenance = "inferred"
	}
	if !observation.depthSet {
		if depth, present := topology.depth.Get(); present {
			observation.depth, observation.depthSet = depth, true
		}
	}
	return observation
}

func eventRouterApprovalOutcome(result string) observability.Outcome {
	switch result {
	case "approved":
		return observability.OutcomeApproved
	case "cancelled":
		return observability.OutcomeCancelled
	case "expired":
		return observability.OutcomeTimedOut
	default:
		return observability.OutcomeDenied
	}
}

func validEventRouterApprovalObservation(observation eventRouterApprovalObservation) bool {
	if !validEventRouterApprovalRequest(observation) ||
		observation.finishedAt.Before(observation.startedAt) || observation.startedAt.UnixNano() <= 0 {
		return false
	}
	switch observation.result {
	case "approved", "denied", "cancelled", "expired":
	default:
		return false
	}
	switch observation.actorType {
	case "operator", "automatic", "policy":
	default:
		return false
	}
	if !boundedApprovalString(observation.reason, 65_536) || len(observation.ruleIDs) > 256 {
		return false
	}
	for _, ruleID := range observation.ruleIDs {
		if !hookModelV8Identifier(ruleID) {
			return false
		}
	}
	return true
}

func validEventRouterApprovalRequest(observation eventRouterApprovalObservation) bool {
	if !hookModelV8Identifier(observation.id) || observation.startedAt.IsZero() || observation.startedAt.UnixNano() <= 0 ||
		!boundedApprovalString(observation.commandName, 4096) ||
		!boundedApprovalString(observation.command, 65536) ||
		!boundedApprovalString(observation.cwd, 4096) || len(observation.argv) > 256 {
		return false
	}
	for _, value := range []string{
		observation.connector,
		observation.sessionKey,
		observation.rootSessionID,
		observation.parentSessionID,
		observation.requestID,
		observation.turnID,
		observation.operationID,
		observation.agentInstanceID,
		observation.agentType,
		observation.rootAgentID,
		observation.parentAgentID,
		observation.lifecycleID,
		observation.executionID,
		observation.userID,
		observation.userName,
		observation.policyVersion,
		observation.destinationApp,
		observation.toolID,
		observation.toolName,
		observation.toolCallID,
		observation.toolSkillKey,
	} {
		if value != "" && !hookModelV8Identifier(value) {
			return false
		}
	}
	if observation.lineageProvenance != "" &&
		!hookV8OptionalLineageProvenance(observation.lineageProvenance).IsPresent() {
		return false
	}
	if observation.phase != "" && !hookV8OptionalPhase(observation.phase).IsPresent() {
		return false
	}
	if observation.depth < 0 || observation.depth > 64 || observation.sequence < 0 ||
		!boundedApprovalString(observation.toolType, 4096) ||
		!boundedApprovalString(observation.toolProvider, 4096) {
		return false
	}
	total := 0
	for _, arg := range observation.argv {
		if !boundedApprovalString(arg, 4096) {
			return false
		}
		total += len(arg)
		if total > 65536 {
			return false
		}
	}
	return (hookModelV8Identifier(observation.sessionID) || observation.sessionID == "") &&
		(hookModelV8Identifier(observation.runID) || observation.runID == "") &&
		(hookModelV8Identifier(observation.agentID) || observation.agentID == "") &&
		(hookModelV8Identifier(observation.agentName) || observation.agentName == "") &&
		(hookModelV8Identifier(observation.policyID) || observation.policyID == "")
}

func eventRouterApprovalDepth(observation eventRouterApprovalObservation) observability.Optional[int64] {
	if !observation.depthSet && observation.rootAgentID == "" {
		return observability.Absent[int64]()
	}
	return observability.Present(observation.depth)
}

func eventRouterApprovalSequence(observation eventRouterApprovalObservation) observability.Optional[int64] {
	if observation.sequenceSet {
		return observability.Present(observation.sequence)
	}
	return hookV8OptionalPositiveInt64(observation.sequence)
}

func boundedApprovalString(value string, limit int) bool {
	return utf8.ValidString(value) && len(value) <= limit
}

func optionalApprovalContent(value string) observability.Optional[string] {
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalApprovalArgv(value []string) observability.Optional[[]string] {
	if len(value) == 0 {
		return observability.Absent[[]string]()
	}
	return observability.Present(append([]string(nil), value...))
}

func optionalApprovalPath(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}
