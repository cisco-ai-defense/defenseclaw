// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const gatewayEgressV8Producer = "gateway.egress"

type gatewayEgressV8Runtime interface {
	sidecarRuntimeEmitter
	RecordGeneratedMetric(
		context.Context,
		observability.EventName,
		observabilityruntime.GeneratedMetricBuilder,
	) (telemetry.V8MetricRecordResult, error)
}

// emitGatewayEgressV8 emits the generated log and the exact existing
// defenseclaw.egress.events metric. The boolean reports v8 ownership even when
// collection drops the signals or the runtime has already detached.
func emitGatewayEgressV8(
	ctx context.Context,
	p gatewaylog.EgressPayload,
	severity gatewaylog.Severity,
	runtime gatewayEgressV8Runtime,
	authoritative bool,
) bool {
	if !authoritative {
		return false
	}
	if runtime == nil || ctx == nil {
		return true
	}
	eventName := observability.TelemetryEventEgressAllowed
	outcome := observability.OutcomeAllowed
	if p.Decision == "block" {
		eventName = observability.TelemetryEventEgressBlocked
		outcome = observability.OutcomeBlocked
	}
	classification := observability.ClassificationContext{
		Bucket:    observability.BucketNetworkEgress,
		EventName: observability.EventName(eventName), RawSeverity: string(severity),
		MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: p.Decision == "block"},
		Enforced:       p.Decision == "block",
	}
	correlationEvent := gatewaylog.Event{}
	stampEventCorrelation(&correlationEvent, ctx)
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent, observability.ProducerKey(gatewaylog.EventEgress),
		classification, observability.SourceGateway, correlationEvent.Connector,
		observability.ProducerKey("egress"),
	)
	if err == nil {
		_, err = runtime.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, buildErr := aiDiscoveryV8Builder()
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			envelope := gatewayEgressV8Envelope(correlationEvent, snapshot, "policy")
			severityValue, logLevel := gatewayEgressV8Severity(severity)
			if p.Decision == "block" {
				return builder.BuildLogEgressBlocked(observability.LogEgressBlockedInput{
					Envelope: envelope, Severity: severityValue, LogLevel: logLevel, Outcome: outcome,
					GenAIConversationID:            optionalGatewayEgressText(correlationEvent.SessionID),
					GenAIAgentID:                   optionalGatewayEgressText(correlationEvent.AgentID),
					DefenseClawAgentRootID:         optionalGatewayEgressText(correlationEvent.RootAgentID),
					DefenseClawAgentParentID:       optionalGatewayEgressText(correlationEvent.ParentAgentID),
					DefenseClawSessionRootID:       optionalGatewayEgressText(correlationEvent.RootSessionID),
					DefenseClawAgentLifecycleID:    optionalGatewayEgressText(correlationEvent.AgentLifecycleID),
					DefenseClawAgentExecutionID:    optionalGatewayEgressText(correlationEvent.AgentExecutionID),
					UserID:                         optionalGatewayEgressText(correlationEvent.UserID),
					GenAIToolCallID:                optionalGatewayEgressText(correlationEvent.ToolID),
					DefenseClawNetworkTargetRef:    p.TargetHost,
					DefenseClawNetworkTargetPath:   optionalGatewayEgressText(p.TargetPath),
					DefenseClawNetworkDecision:     observability.Present(p.Decision),
					DefenseClawNetworkReason:       optionalGatewayEgressText(p.Reason),
					DefenseClawNetworkBranch:       optionalGatewayEgressToken(p.Branch),
					DefenseClawNetworkSource:       optionalGatewayEgressToken(p.Source),
					DefenseClawNetworkBodyShape:    optionalGatewayEgressToken(p.BodyShape),
					DefenseClawNetworkLooksLikeLLM: observability.Present(p.LooksLikeLLM),
					DefenseClawNetworkBlocked:      observability.Present(true),
					ServerAddress:                  optionalGatewayEgressText(p.TargetHost), MandatoryEnforcedOutcome: true,
				})
			}
			return builder.BuildLogEgressAllowed(observability.LogEgressAllowedInput{
				Envelope: envelope, Severity: severityValue, LogLevel: logLevel, Outcome: outcome,
				GenAIConversationID:            optionalGatewayEgressText(correlationEvent.SessionID),
				GenAIAgentID:                   optionalGatewayEgressText(correlationEvent.AgentID),
				DefenseClawAgentRootID:         optionalGatewayEgressText(correlationEvent.RootAgentID),
				DefenseClawAgentParentID:       optionalGatewayEgressText(correlationEvent.ParentAgentID),
				DefenseClawSessionRootID:       optionalGatewayEgressText(correlationEvent.RootSessionID),
				DefenseClawAgentLifecycleID:    optionalGatewayEgressText(correlationEvent.AgentLifecycleID),
				DefenseClawAgentExecutionID:    optionalGatewayEgressText(correlationEvent.AgentExecutionID),
				UserID:                         optionalGatewayEgressText(correlationEvent.UserID),
				GenAIToolCallID:                optionalGatewayEgressText(correlationEvent.ToolID),
				DefenseClawNetworkTargetRef:    p.TargetHost,
				DefenseClawNetworkTargetPath:   optionalGatewayEgressText(p.TargetPath),
				DefenseClawNetworkDecision:     observability.Present(p.Decision),
				DefenseClawNetworkReason:       optionalGatewayEgressText(p.Reason),
				DefenseClawNetworkBranch:       optionalGatewayEgressToken(p.Branch),
				DefenseClawNetworkSource:       optionalGatewayEgressToken(p.Source),
				DefenseClawNetworkBodyShape:    optionalGatewayEgressToken(p.BodyShape),
				DefenseClawNetworkLooksLikeLLM: observability.Present(p.LooksLikeLLM),
				DefenseClawNetworkBlocked:      observability.Present(false),
				ServerAddress:                  optionalGatewayEgressText(p.TargetHost),
			})
		})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "[guardrail] generated egress log failed")
	}
	_, metricErr := runtime.RecordGeneratedMetric(
		ctx, observability.EventName(observability.TelemetryInstrumentDefenseClawEgressEvents),
		func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, buildErr := aiDiscoveryV8Builder()
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMetricDefenseClawEgressEvents(observability.MetricDefenseClawEgressEventsInput{
				Envelope: gatewayEgressV8Envelope(correlationEvent, snapshot, "metrics"), Value: 1,
				DefenseClawMetricBranch:   observability.Present(p.Branch),
				DefenseClawMetricDecision: observability.Present(p.Decision),
				DefenseClawMetricSource:   observability.Present(p.Source),
			})
		},
	)
	if metricErr != nil {
		fmt.Fprintln(os.Stderr, "[guardrail] generated egress metric failed")
	}
	return true
}

func gatewayEgressV8Envelope(
	ev gatewaylog.Event,
	snapshot observabilityruntime.EmitContext,
	phase string,
) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Connector: ev.Connector,
		Action: string(gatewaylog.EventEgress), Phase: phase,
		Correlation: observability.Correlation{
			RunID: ev.RunID, RequestID: ev.RequestID, SessionID: ev.SessionID, TraceID: ev.TraceID,
			TurnID: ev.TurnID, AgentID: ev.AgentID, AgentInstanceID: ev.AgentInstanceID,
			SidecarInstanceID: ev.SidecarInstanceID, PolicyID: ev.PolicyID,
			ToolInvocationID: ev.ToolID, ConnectorID: ev.Connector,
		},
		Provenance: observability.FamilyProvenanceInput{
			Producer: gatewayEgressV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
}

func gatewayEgressV8Severity(
	severity gatewaylog.Severity,
) (observability.Optional[observability.Severity], observability.Optional[observability.LogLevel]) {
	normalized := observability.NormalizeSeverity(string(severity))
	if !normalized.Valid || !normalized.Present {
		return observability.Absent[observability.Severity](), observability.Absent[observability.LogLevel]()
	}
	logLevel := observability.Absent[observability.LogLevel]()
	if normalized.LogLevel != "" {
		logLevel = observability.Present(normalized.LogLevel)
	}
	return observability.Present(normalized.Severity), logLevel
}

func optionalGatewayEgressText(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalGatewayEgressToken(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}
