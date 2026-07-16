// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/google/uuid"
)

// networkEgressV8Event builds the legacy-compatible audit projection for the
// generated egress occurrence. The network_egress_events row remains the
// forensic source; this projection keeps the existing blocked-alert columns
// stable and gives allowed v8 occurrences the same queryable event-history
// shape without direct OTel or sink fanout.
func networkEgressV8Event(event NetworkEgressEvent, row NetworkEgressRow) Event {
	action := ActionNetworkEgressAllowed
	severity := event.effectiveSeverity()
	if event.Blocked {
		action = ActionNetworkEgressBlocked
	}
	details := fmt.Sprintf("url=%s method=%s decision=%s outcome=%s",
		truncateStr(row.URL, 200), event.HTTPMethod, event.DecisionCode, event.PolicyOutcome)
	result := Event{
		ID:                uuid.NewString(),
		Timestamp:         event.Timestamp.UTC(),
		Action:            string(action),
		Target:            event.Hostname,
		Actor:             "defenseclaw",
		Details:           details,
		Severity:          severity,
		RunID:             currentRunID(),
		SessionID:         event.SessionID,
		AgentID:           event.AgentID,
		SidecarInstanceID: ProcessAgentInstanceID(),
		Connector:         event.Connector,
		ToolID:            event.ToolID,
		Enforced:          event.Blocked,
	}
	stampAuditEventEnvelope(&result)
	return result
}

func (l *Logger) emitNetworkEgressV8(
	ctx context.Context,
	event NetworkEgressEvent,
	row NetworkEgressRow,
	binding runtimeV8Binding,
) (auditV8Disposition, error) {
	if binding.emitter == nil {
		return auditV8Persisted, fmt.Errorf("audit: network egress v8 runtime is unavailable")
	}
	if !validNetworkTargetRef(event.Hostname) {
		return auditV8Persisted, fmt.Errorf("audit: network egress target is not canonical")
	}
	auditEvent := networkEgressV8Event(event, row)
	eventName := observability.TelemetryEventEgressAllowed
	outcome := observability.OutcomeAllowed
	mandatory := false
	if event.Blocked {
		eventName = observability.TelemetryEventEgressBlocked
		outcome = observability.OutcomeBlocked
		mandatory = true
	}
	classification := observability.ClassificationContext{
		EventName: observability.EventName(eventName), RawSeverity: auditEvent.Severity,
		MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: event.Blocked},
		Enforced:       event.Blocked,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, observability.ProducerKey(auditEvent.Action), classification,
		observability.SourceGateway, auditEvent.Connector, observability.ProducerKey(auditEvent.Action),
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: classify network egress: %w", err)
	}
	correlation := controlPlaneV8Correlation(auditEvent)
	result, err := binding.emitter.EmitRuntimeV8(
		contextWithLegacyEventProjection(ctx, auditEvent), metadata,
		func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			if admission == router.AdmissionFloor {
				return buildRuntimeV8FloorRecord(
					auditEvent, snapshot, classification, observability.SourceGateway,
					"policy", outcome, correlation,
				)
			}
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("audit: network egress has no admitted path")
			}
			builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
				auditEvent, snapshot, observability.SourceGateway, "policy", correlation,
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			input := networkEgressFamilyInput(event, row, envelope, severity, logLevel, outcome)
			var record observability.Record
			if event.Blocked {
				record, buildErr = builder.BuildLogEgressBlocked(observability.LogEgressBlockedInput{
					Envelope: input.Envelope, Severity: input.Severity, LogLevel: input.LogLevel,
					Outcome: input.Outcome, GenAIConversationID: input.ConversationID,
					GenAIAgentID: input.AgentID, DefenseClawAgentRootID: input.RootAgentID,
					DefenseClawAgentParentID:    input.ParentAgentID,
					DefenseClawSessionRootID:    input.RootSessionID,
					DefenseClawAgentLifecycleID: input.AgentLifecycleID,
					DefenseClawAgentExecutionID: input.AgentExecutionID,
					UserID:                      input.UserID, GenAIToolCallID: input.ToolCallID,
					DefenseClawNetworkTargetRef:     input.TargetRef,
					DefenseClawNetworkTargetPath:    input.TargetPath,
					DefenseClawNetworkPolicyOutcome: input.PolicyOutcome,
					DefenseClawNetworkDecision:      input.Decision,
					DefenseClawNetworkDecisionCode:  input.DecisionCode,
					DefenseClawNetworkReason:        input.Reason,
					DefenseClawNetworkBlocked:       observability.Present(true),
					URLScheme:                       input.Scheme, ServerAddress: input.ServerAddress,
					ServerPort: input.ServerPort, MandatoryEnforcedOutcome: true,
				})
			} else {
				record, buildErr = builder.BuildLogEgressAllowed(observability.LogEgressAllowedInput{
					Envelope: input.Envelope, Severity: input.Severity, LogLevel: input.LogLevel,
					Outcome: input.Outcome, GenAIConversationID: input.ConversationID,
					GenAIAgentID: input.AgentID, DefenseClawAgentRootID: input.RootAgentID,
					DefenseClawAgentParentID:    input.ParentAgentID,
					DefenseClawSessionRootID:    input.RootSessionID,
					DefenseClawAgentLifecycleID: input.AgentLifecycleID,
					DefenseClawAgentExecutionID: input.AgentExecutionID,
					UserID:                      input.UserID, GenAIToolCallID: input.ToolCallID,
					DefenseClawNetworkTargetRef:     input.TargetRef,
					DefenseClawNetworkTargetPath:    input.TargetPath,
					DefenseClawNetworkPolicyOutcome: input.PolicyOutcome,
					DefenseClawNetworkDecision:      input.Decision,
					DefenseClawNetworkDecisionCode:  input.DecisionCode,
					DefenseClawNetworkReason:        input.Reason,
					DefenseClawNetworkBlocked:       observability.Present(false),
					URLScheme:                       input.Scheme, ServerAddress: input.ServerAddress,
					ServerPort: input.ServerPort,
				})
			}
			return verifyRuntimeV8Record(record, buildErr, auditEvent, mandatory)
		},
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit network egress: %w", err)
	}
	return runtimeV8Disposition(result, mandatory)
}

type networkEgressGeneratedInput struct {
	Envelope         observability.FamilyEnvelopeInput
	Severity         observability.Optional[observability.Severity]
	LogLevel         observability.Optional[observability.LogLevel]
	Outcome          observability.Outcome
	ConversationID   observability.Optional[string]
	AgentID          observability.Optional[string]
	RootAgentID      observability.Optional[string]
	ParentAgentID    observability.Optional[string]
	RootSessionID    observability.Optional[string]
	AgentLifecycleID observability.Optional[string]
	AgentExecutionID observability.Optional[string]
	UserID           observability.Optional[string]
	ToolCallID       observability.Optional[string]
	TargetRef        string
	TargetPath       observability.Optional[string]
	PolicyOutcome    observability.Optional[string]
	Decision         observability.Optional[string]
	DecisionCode     observability.Optional[string]
	Reason           observability.Optional[string]
	Scheme           observability.Optional[string]
	ServerAddress    observability.Optional[string]
	ServerPort       observability.Optional[int64]
}

func networkEgressFamilyInput(
	event NetworkEgressEvent,
	row NetworkEgressRow,
	envelope observability.FamilyEnvelopeInput,
	severity observability.Optional[observability.Severity],
	logLevel observability.Optional[observability.LogLevel],
	outcome observability.Outcome,
) networkEgressGeneratedInput {
	input := networkEgressGeneratedInput{
		Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
		ConversationID: optionalNetworkText(event.SessionID),
		AgentID:        optionalNetworkText(event.AgentID), RootAgentID: optionalNetworkText(event.RootAgentID),
		ParentAgentID: optionalNetworkText(event.ParentAgentID), RootSessionID: optionalNetworkText(event.RootSessionID),
		AgentLifecycleID: optionalNetworkText(event.AgentLifecycleID),
		AgentExecutionID: optionalNetworkText(event.AgentExecutionID),
		UserID:           optionalNetworkText(event.UserID), ToolCallID: optionalNetworkText(event.ToolID),
		TargetRef: event.Hostname, PolicyOutcome: optionalNetworkText(event.PolicyOutcome),
		DecisionCode:  optionalNetworkIdentifier(event.DecisionCode),
		Reason:        optionalNetworkText(event.Details),
		ServerAddress: optionalNetworkText(event.Hostname),
	}
	if event.Blocked {
		input.Decision = observability.Present("block")
	} else {
		input.Decision = observability.Present("allow")
	}
	if parsed, err := url.Parse(row.URL); err == nil {
		input.TargetPath = optionalNetworkText(parsed.EscapedPath())
		input.Scheme = optionalNetworkScheme(parsed.Scheme)
		if port := parsed.Port(); port != "" {
			if parsedPort, ok := parseNetworkPort(port); ok {
				input.ServerPort = observability.Present(parsedPort)
			}
		}
	}
	return input
}

func validNetworkTargetRef(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 8192 && utf8.ValidString(value)
}

func optionalNetworkText(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || len(value) > 65536 {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalNetworkIdentifier(value string) observability.Optional[string] {
	if !runtimeV8Identifier(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalNetworkScheme(value string) observability.Optional[string] {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http", "https":
		return observability.Present(strings.ToLower(strings.TrimSpace(value)))
	default:
		return observability.Absent[string]()
	}
}

func parseNetworkPort(value string) (int64, bool) {
	var port int64
	if _, err := fmt.Sscan(value, &port); err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}
