// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

// hookLifecycleMetricV8Runtime is the generation-pinned metric capability used
// by hook producers. It deliberately exposes no SDK meter or Provider pointer:
// producers submit exact generated families and cannot retain a generation
// across occurrences or bypass collection policy.
type hookLifecycleMetricV8Runtime interface {
	RecordGeneratedMetricBatch(
		context.Context,
		[]observabilityruntime.GeneratedMetricBatchItem,
	) ([]telemetry.V8MetricRecordResult, error)
}

func (owner *sidecarOwnedObservabilityV8Runtime) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []observabilityruntime.GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if owner == nil || owner.runtime == nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.RecordGeneratedMetricBatch(ctx, items)
}

func (owner *sidecarOwnedObservabilityV8Runtime) GeneratedMetricFamilyEnabled(
	ctx context.Context,
	family observability.EventName,
) (bool, error) {
	if owner == nil || owner.runtime == nil {
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.GeneratedMetricFamilyEnabled(ctx, family)
}

func (a *APIServer) recordHookLifecycleMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	meta llmEventMeta,
) error {
	if a == nil || ctx == nil || runtime == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	now := time.Now().UTC()
	connector := telemetry.NormalizeMetricTextLabel(meta.Source)
	provider := telemetry.NormalizeGenAIProviderLabel(firstNonEmpty(meta.Provider, meta.Source))
	model := telemetry.NormalizeModelLabel(meta.Model)
	agentID := telemetry.NormalizeMetricIdentityLabel(meta.AgentID)
	agentName := telemetry.NormalizeMetricTextLabel(meta.AgentName)
	agentType := telemetry.NormalizeMetricTextLabel(meta.AgentType)
	rootAgentID := telemetry.NormalizeMetricIdentityLabel(firstNonEmpty(meta.RootAgentID, meta.AgentID))
	parentAgentID := telemetry.NormalizeMetricIdentityLabel(firstNonEmpty(meta.ParentAgentID, "none"))
	rootSessionID := telemetry.NormalizeMetricIdentityLabel(firstNonEmpty(meta.RootSessionID, "unknown"))
	lifecycleID := telemetry.NormalizeMetricIdentityLabel(firstNonEmpty(meta.LifecycleID, "unknown"))
	executionID := telemetry.NormalizeMetricIdentityLabel(firstNonEmpty(meta.ExecutionID, "unknown"))
	lifecycleEvent := telemetry.NormalizeMetricTextLabel(firstNonEmpty(meta.LifecycleEvent, "event"))
	lifecycleState := telemetry.NormalizeMetricTextLabel(firstNonEmpty(meta.LifecycleState, "observed"))
	phase := telemetry.NormalizeMetricTextLabel(firstNonEmpty(meta.Phase, "observed"))
	previousPhase := telemetry.NormalizeMetricTextLabel(firstNonEmpty(meta.PreviousPhase, "unknown"))
	depth := meta.AgentDepth
	if depth < 0 {
		depth = 0
	}

	build := func(
		family observability.EventName,
		buildRecord func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput) (observability.Record, error),
	) observabilityruntime.GeneratedMetricBatchItem {
		return observabilityruntime.GeneratedMetricBatchItem{
			Family: family,
			Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
				if snapshot.Generation() > math.MaxInt64 {
					return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
				}
				builder, err := observability.NewFamilyBuilder(
					observability.ClockFunc(func() time.Time { return now }),
					observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
				)
				if err != nil {
					return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
				}
				envelope := observability.FamilyEnvelopeInput{
					Source: observability.SourceConnector, Connector: meta.Source,
					Correlation: observability.Correlation{
						RunID: meta.RunID, RequestID: meta.RequestID, SessionID: meta.SessionID,
						TurnID: meta.TurnID, AgentID: meta.AgentID, PolicyID: meta.PolicyID,
						ToolInvocationID: meta.ToolID, ConnectorID: meta.Source,
					},
					Provenance: observability.FamilyProvenanceInput{
						Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
						ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
					},
				}
				if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
					envelope.Correlation.TraceID = spanContext.TraceID().String()
					envelope.Correlation.SpanID = spanContext.SpanID().String()
				}
				return buildRecord(builder, envelope)
			},
		}
	}

	items := []observabilityruntime.GeneratedMetricBatchItem{
		build(observability.EventName(observability.TelemetryInstrumentDefenseClawAgentLifecycleTransitions), func(
			builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAgentLifecycleTransitions(
				observability.MetricDefenseClawAgentLifecycleTransitionsInput{
					Envelope: envelope, Value: 1,
					DefenseClawConnectorSource:     observability.Present(connector),
					DefenseClawAgentDepth:          observability.Present(int64(depth)),
					DefenseClawAgentExecutionID:    observability.Present(executionID),
					DefenseClawAgentLifecycleEvent: observability.Present(lifecycleEvent),
					DefenseClawAgentLifecycleID:    observability.Present(lifecycleID),
					DefenseClawAgentLifecycleState: observability.Present(lifecycleState),
					DefenseClawAgentParentID:       observability.Present(parentAgentID),
					DefenseClawAgentRootID:         observability.Present(rootAgentID),
					DefenseClawSessionRootID:       observability.Present(rootSessionID),
					GenAIAgentID:                   observability.Present(agentID),
					GenAIAgentName:                 observability.Present(agentName),
					DefenseClawAgentType:           observability.Present(agentType),
					GenAIProviderName:              observability.Present(provider),
					GenAIRequestModel:              observability.Present(model),
				},
			)
		}),
		build(observability.EventName(observability.TelemetryInstrumentDefenseClawAgentLastSeen), func(
			builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAgentLastSeen(observability.MetricDefenseClawAgentLastSeenInput{
				Envelope: envelope, Value: float64(now.UnixNano()) / float64(time.Second),
				DefenseClawConnectorSource:  observability.Present(connector),
				DefenseClawAgentExecutionID: observability.Present(executionID),
				DefenseClawAgentLifecycleID: observability.Present(lifecycleID),
				DefenseClawAgentParentID:    observability.Present(parentAgentID),
				DefenseClawAgentRootID:      observability.Present(rootAgentID),
				DefenseClawSessionRootID:    observability.Present(rootSessionID),
				GenAIAgentID:                observability.Present(agentID),
				GenAIAgentName:              observability.Present(agentName),
				DefenseClawAgentType:        observability.Present(agentType),
			})
		}),
		build(observability.EventName(observability.TelemetryInstrumentDefenseClawAgentPhaseCurrent), func(
			builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAgentPhaseCurrent(observability.MetricDefenseClawAgentPhaseCurrentInput{
				Envelope: envelope, Value: int64(telemetry.AgentPhaseCode(phase)),
				DefenseClawConnectorSource:  observability.Present(connector),
				DefenseClawAgentExecutionID: observability.Present(executionID),
				DefenseClawAgentLifecycleID: observability.Present(lifecycleID),
				DefenseClawAgentRootID:      observability.Present(rootAgentID),
				GenAIAgentID:                observability.Present(agentID),
				GenAIAgentName:              observability.Present(agentName),
			})
		}),
	}
	if previousPhase != "unknown" && previousPhase != phase {
		items = append(items, build(
			observability.EventName(observability.TelemetryInstrumentDefenseClawAgentPhaseTransitions), func(
				builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			) (observability.Record, error) {
				return builder.BuildMetricDefenseClawAgentPhaseTransitions(
					observability.MetricDefenseClawAgentPhaseTransitionsInput{
						Envelope: envelope, Value: 1,
						DefenseClawConnectorSource:  observability.Present(connector),
						DefenseClawAgentExecutionID: observability.Present(executionID),
						DefenseClawAgentPhaseFrom:   observability.Present(previousPhase),
						DefenseClawAgentPhaseTo:     observability.Present(phase),
						DefenseClawAgentRootID:      observability.Present(rootAgentID),
						GenAIAgentID:                observability.Present(agentID),
						GenAIAgentName:              observability.Present(agentName),
					},
				)
			},
		))
	}
	if meta.ReportedCost && meta.ReportedCostUSD >= 0 &&
		!math.IsNaN(meta.ReportedCostUSD) && !math.IsInf(meta.ReportedCostUSD, 0) {
		items = append(items, build(
			observability.EventName(observability.TelemetryInstrumentDefenseClawAgentReportedCost), func(
				builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			) (observability.Record, error) {
				return builder.BuildMetricDefenseClawAgentReportedCost(
					observability.MetricDefenseClawAgentReportedCostInput{
						Envelope: envelope, Value: meta.ReportedCostUSD,
						DefenseClawConnectorSource:  observability.Present(connector),
						DefenseClawAgentExecutionID: observability.Present(executionID),
						DefenseClawAgentLifecycleID: observability.Present(lifecycleID),
						DefenseClawAgentRootID:      observability.Present(rootAgentID),
						GenAIAgentID:                observability.Present(agentID),
						GenAIAgentName:              observability.Present(agentName),
						GenAIProviderName:           observability.Present(provider),
						GenAIRequestModel:           observability.Present(model),
					},
				)
			},
		))
	}
	_, err := runtime.RecordGeneratedMetricBatch(ctx, items)
	return err
}

var _ hookLifecycleMetricV8Runtime = (*sidecarOwnedObservabilityV8Runtime)(nil)
