// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The Substrate records the leader relays to this replica (telemetryrelay):
// the actors' lifecycle as the controller reports it, the callout's egress
// decisions and the controller's counts. Before, they existed only as JSON
// lines in the controller's and the callout's pod logs, and no OTLP
// destination ever got log.sandbox.lifecycle, log.egress.* or the
// controller's metrics (GAP-0450, GAP-0453).

const substrateRelayV8Producer = "gateway.substrate.relay"

// recordSubstrateRelay records one batch this replica took from the leader.
func (a *APIServer) recordSubstrateRelay(ctx context.Context, b telemetryrelay.TakeResponse) {
	for _, r := range b.Records {
		switch r.Kind {
		case telemetryrelay.KindLifecycle:
			a.emitSubstrateLifecycleV8(ctx, r)
		case telemetryrelay.KindEgress:
			a.emitSubstrateEgressV8(ctx, r)
		case telemetryrelay.KindAskClosed:
			a.recordSubstrateAskClosed(ctx, r)
		case telemetryrelay.KindCount:
			a.recordSubstrateCount(r.Metric, r.Value)
		}
	}
	if v, ok := b.Gauges[telemetryrelay.MetricUnattestedTemplates]; ok {
		a.recordSubstrateUnattestedTemplates(v)
	}
	if b.Dropped > 0 {
		fmt.Fprintf(os.Stderr, "[substrate] telemetry relay: the leader dropped %d records it could not hand on in time\n", b.Dropped)
	}
}

// substrateLifecyclePhase maps a chainstate lifecycle event to the
// defenseclaw.sandbox.phase it enters and its trigger.
func substrateLifecyclePhase(event string) (phase, trigger string, ok bool) {
	switch event {
	case chainstate.LifecycleSuspended:
		return "suspended", "watch", true
	case chainstate.LifecycleResumed:
		return "ready", "watch", true
	case chainstate.LifecycleForked:
		// The child of a fork: a new actor made from its parent's snapshot.
		return "creating", "fork", true
	case chainstate.LifecycleReverted:
		return "reverting", "watch", true
	case chainstate.LifecycleCrashed:
		return "crashed", "watch", true
	case chainstate.LifecycleDeleted:
		return "deleted", "delete", true
	}
	return "", "", false
}

func substrateLifecycleOutcome(phase string) observability.Outcome {
	switch phase {
	case "ready", "deleted":
		return observability.OutcomeCompleted
	case "crashed", "unknown":
		return observability.OutcomeFailed
	}
	return observability.OutcomeAttempted
}

func substrateRelayText(v string) observability.Optional[string] {
	if v = strings.TrimSpace(v); v == "" {
		return observability.Absent[string]()
	}
	return observability.Present(v)
}

func substrateRelayRunMode(r telemetryrelay.Record) observability.Optional[string] {
	if r.RunMode == "interactive" || r.RunMode == "unattended" {
		return observability.Present(r.RunMode)
	}
	return observability.Absent[string]()
}

func substrateRelaySeverity(raw string) (observability.Optional[observability.Severity], observability.Optional[observability.LogLevel]) {
	n := observability.NormalizeSeverity(raw)
	if !n.Valid || !n.Present {
		return observability.Absent[observability.Severity](), observability.Absent[observability.LogLevel]()
	}
	level := observability.Absent[observability.LogLevel]()
	if n.LogLevel != "" {
		level = observability.Present(n.LogLevel)
	}
	return observability.Present(n.Severity), level
}

// emitSubstrateRelayLog emits one generated log under a registered audit
// action producer (sandbox-lifecycle, sandbox-egress), as the OpenShell
// sandbox records do.
func (a *APIServer) emitSubstrateRelayLog(ctx context.Context, r telemetryrelay.Record, producer audit.Action, bucket observability.Bucket, event string,
	severity string, enforced bool, phase string, build func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput) (observability.Record, error)) {
	runtime := a.observabilityV8RuntimeEmitter()
	if runtime == nil {
		return
	}
	connector := strings.ToLower(strings.TrimSpace(r.Connector))
	if !observability.IsStableToken(connector) {
		connector = ""
	}
	classification := observability.ClassificationContext{
		Bucket: bucket, EventName: observability.EventName(event), RawSeverity: severity,
		MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: enforced}, Enforced: enforced,
	}
	metadata, err := router.NewClassifiedLogMetadata(observability.ProducerAuditAction, observability.ProducerKey(producer),
		classification, observability.SourceGateway, connector, observability.ProducerKey(producer))
	if err == nil {
		_, err = runtime.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, err := aiDiscoveryV8Builder()
			if err != nil {
				return observability.Record{}, err
			}
			return build(builder, gatewayGeneratedEnvelope(ctx, snapshot, observability.SourceGateway, connector, substrateRelayV8Producer, string(producer), phase))
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] %s record failed: %v\n", event, err)
	}
}

// emitSubstrateLifecycleV8 is log.sandbox.lifecycle for an actor.
func (a *APIServer) emitSubstrateLifecycleV8(ctx context.Context, r telemetryrelay.Record) {
	phase, trigger, ok := substrateLifecyclePhase(r.Lifecycle)
	if !ok || r.Actor == "" {
		return
	}
	severity := "INFO"
	if phase == "crashed" {
		severity = "HIGH"
	}
	sev, level := substrateRelaySeverity(severity)
	outcome := substrateLifecycleOutcome(phase)
	a.emitSubstrateRelayLog(ctx, r, audit.ActionSandboxLifecycle, observability.BucketAgentLifecycle, observability.TelemetryEventSandboxLifecycle, severity, false, "lifecycle",
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildLogSandboxLifecycle(observability.LogSandboxLifecycleInput{
				Envelope: envelope, Severity: sev, LogLevel: level, Outcome: outcome,
				DefenseClawSandboxName:               r.Actor,
				DefenseClawSandboxRuntime:            observability.Present("substrate"),
				DefenseClawSandboxDriver:             substrateDriver(r.Driver),
				DefenseClawGuardrailProfileName:      hookV8OptionalIdentifier(r.Profile),
				DefenseClawSandboxPhase:              phase,
				DefenseClawSandboxLifecycleTrigger:   observability.Present(trigger),
				DefenseClawSandboxSubstrateAtespace:  substrateRelayText(r.Atespace),
				DefenseClawSandboxSubstrateActor:     substrateRelayText(r.Actor),
				DefenseClawSandboxSubstrateActorUid:  substrateRelayText(r.UID),
				DefenseClawSandboxSubstrateTemplate:  substrateRelayText(r.Template),
				DefenseClawSandboxSubstrateBatchID:   substrateRelayText(r.BatchID),
				DefenseClawSandboxSubstrateParentUid: substrateRelayText(r.ParentUID),
				DefenseClawSandboxSubstrateRunMode:   substrateRelayRunMode(r),
				AteActorUid:                          substrateRelayText(r.UID),
				UserID:                               hookV8OptionalIdentifier(r.UserID),
				DefenseClawUserIDKind:                v8UserIDKind(useridentity.KindForID(r.UserID)),
				DefenseClawUserName:                  v8UserName(r.UserName, hookV8OptionalIdentifier),
			})
		})
}

// emitSubstrateEgressV8 is log.egress.allowed or log.egress.blocked for a
// callout decision. defenseclaw.sandbox.substrate.registered is false when
// the leader could not tie it to a registration (GAP-0581).
func (a *APIServer) emitSubstrateEgressV8(ctx context.Context, r telemetryrelay.Record) {
	if r.Host == "" || (r.Decision != "allow" && r.Decision != "block") {
		return
	}
	blocked := r.Decision == "block"
	event, outcome, severity := observability.TelemetryEventEgressAllowed, observability.OutcomeAllowed, "INFO"
	if blocked {
		event, outcome, severity = observability.TelemetryEventEgressBlocked, observability.OutcomeBlocked, "MEDIUM"
	} else if r.Alert {
		severity = "LOW"
	}
	sev, level := substrateRelaySeverity(severity)
	code := substrateRelayText(r.Category)
	if v, ok := code.Get(); ok && !observability.IsStableToken(v) {
		code = observability.Absent[string]()
	}
	a.emitSubstrateRelayLog(ctx, r, audit.ActionSandboxEgress, observability.BucketNetworkEgress, event, severity, blocked, "policy",
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			if blocked {
				return builder.BuildLogEgressBlocked(observability.LogEgressBlockedInput{
					Envelope: envelope, Severity: sev, LogLevel: level, Outcome: outcome,
					DefenseClawNetworkTargetRef: r.Host, DefenseClawNetworkTargetPath: substrateRelayText(r.Path),
					DefenseClawNetworkDecision: observability.Present("block"), DefenseClawNetworkDecisionCode: code,
					DefenseClawNetworkReason: substrateRelayText(r.Reason), DefenseClawNetworkBlocked: observability.Present(true),
					DefenseClawNetworkBodyInspected: observability.Present(r.BodyInspected), DefenseClawNetworkBodyOverCap: observability.Present(r.BodyOverCap),
					ServerAddress: substrateRelayText(r.Host), DefenseClawSandboxName: substrateRelayText(r.Actor),
					DefenseClawSandboxRuntime: observability.Present("substrate"), DefenseClawGuardrailProfileName: hookV8OptionalIdentifier(r.Profile),
					DefenseClawSandboxSubstrateAtespace: substrateRelayText(r.Atespace), DefenseClawSandboxSubstrateActor: substrateRelayText(r.Actor),
					DefenseClawSandboxSubstrateActorUid: substrateRelayText(r.UID), AteActorUid: substrateRelayText(r.UID),
					DefenseClawSandboxSubstrateRegistered: observability.Present(!r.Unregistered),
					MandatoryEnforcedOutcome:              true,
				})
			}
			return builder.BuildLogEgressAllowed(observability.LogEgressAllowedInput{
				Envelope: envelope, Severity: sev, LogLevel: level, Outcome: outcome,
				DefenseClawNetworkTargetRef: r.Host, DefenseClawNetworkTargetPath: substrateRelayText(r.Path),
				DefenseClawNetworkDecision: observability.Present("allow"), DefenseClawNetworkDecisionCode: code,
				DefenseClawNetworkReason: substrateRelayText(r.Reason), DefenseClawNetworkBlocked: observability.Present(false),
				DefenseClawNetworkBodyInspected: observability.Present(r.BodyInspected), DefenseClawNetworkBodyOverCap: observability.Present(r.BodyOverCap),
				ServerAddress: substrateRelayText(r.Host), DefenseClawSandboxName: substrateRelayText(r.Actor),
				DefenseClawSandboxRuntime: observability.Present("substrate"), DefenseClawGuardrailProfileName: hookV8OptionalIdentifier(r.Profile),
				DefenseClawSandboxSubstrateAtespace: substrateRelayText(r.Atespace), DefenseClawSandboxSubstrateActor: substrateRelayText(r.Actor),
				DefenseClawSandboxSubstrateActorUid: substrateRelayText(r.UID), AteActorUid: substrateRelayText(r.UID),
				DefenseClawSandboxSubstrateRegistered: observability.Present(!r.Unregistered),
			})
		})
}

// emitSubstrateApprovalV8 is log.approval.requested for a new ask an actor's
// egress raised, or log.approval.resolved when a person answers it
// (GAP-0453). An ask that times out is closed by the leader and has no record
// here; one the leader closed because its actor crashed, was reverted or was
// deleted (by is automatic, state expired) is log.approval.resolved with the
// result cancelled (GAP-0677).
func (a *APIServer) emitSubstrateApprovalV8(ctx context.Context, ask asks.Ask, requested bool, by string) {
	runtime := a.observabilityV8RuntimeEmitter()
	if runtime == nil || ask.ID == "" {
		return
	}
	event := observability.TelemetryEventApprovalResolved
	producerKey := observability.ProducerKey(audit.ActionGatewayApprovalDenied)
	result, outcome, severity := "", observability.OutcomeAttempted, "INFO"
	facts := observability.MandatoryFacts{ApprovalResolution: true}
	switch {
	case requested:
		event, producerKey, facts = observability.TelemetryEventApprovalRequested, observability.ProducerKey(audit.ActionGatewayApprovalRequested), observability.MandatoryFacts{}
	case ask.State == asks.StateApproved:
		result, outcome, producerKey = audit.SandboxApprovalApproved, observability.OutcomeApproved, observability.ProducerKey(audit.ActionGatewayApprovalGranted)
	case ask.State == asks.StateDenied:
		result, outcome, severity = audit.SandboxApprovalDenied, observability.OutcomeDenied, "HIGH"
	case ask.State == asks.StateExpired && by == audit.SandboxApprovalByAutomatic:
		result, outcome, severity = audit.SandboxApprovalCancelled, observability.OutcomeCancelled, "MEDIUM"
	default:
		return
	}
	classification := observability.ClassificationContext{Bucket: observability.BucketComplianceActivity,
		EventName: observability.EventName(event), RawSeverity: severity, MandatoryFacts: facts}
	metadata, err := router.NewClassifiedLogMetadata(observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, "", producerKey)
	phase := "resolve"
	if requested {
		phase = "request"
	}
	if err == nil {
		_, err = runtime.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			envelope := gatewayGeneratedEnvelope(ctx, snapshot, observability.SourceGateway, "", substrateRelayV8Producer, string(producerKey), phase)
			if admission == router.AdmissionFloor && !requested {
				builder, err := observability.NewRecordBuilder(observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
					observability.TimeOrderedOccurrenceIDs)
				if err != nil {
					return observability.Record{}, err
				}
				return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
					ProducerKind: observability.ProducerAuditAction, ProducerKey: producerKey,
					ClassificationContext: classification, Source: observability.SourceGateway,
					Action: string(producerKey), Phase: phase, Outcome: outcome,
					Correlation: envelope.Correlation,
					Provenance: observability.Provenance{Producer: substrateRelayV8Producer, BinaryVersion: envelope.Provenance.BinaryVersion,
						RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
						ConfigGeneration:      envelope.Provenance.ConfigGeneration, ConfigDigest: envelope.Provenance.ConfigDigest},
				})
			}
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, err := aiDiscoveryV8Builder()
			if err != nil {
				return observability.Record{}, err
			}
			sev, level := substrateRelaySeverity(severity)
			kind := observability.Present(string(audit.SandboxApprovalNetworkRule))
			if requested {
				return builder.BuildLogApprovalRequested(observability.LogApprovalRequestedInput{
					Envelope: envelope, Severity: sev, LogLevel: level, Outcome: outcome,
					DefenseClawApprovalID: ask.ID, UserID: hookV8OptionalIdentifier(substrateOwnerSubject(ask.OwnerID)),
					DefenseClawUserIDKind:  v8UserIDKind(useridentity.KindForID(substrateOwnerSubject(ask.OwnerID))),
					ServerAddress:          substrateRelayText(ask.Host),
					DefenseClawSandboxName: substrateRelayText(ask.Actor), DefenseClawSandboxRuntime: observability.Present("substrate"),
					DefenseClawGuardrailProfileName:     hookV8OptionalIdentifier(ask.Profile),
					DefenseClawSandboxSubstrateAtespace: substrateRelayText(ask.Atespace), DefenseClawSandboxSubstrateActor: substrateRelayText(ask.Actor),
					DefenseClawSandboxSubstrateActorUid: substrateRelayText(ask.UID), DefenseClawSandboxApprovalKind: kind,
				})
			}
			scope := observability.Absent[string]()
			if result == audit.SandboxApprovalApproved {
				scope = observability.Present(string(audit.SandboxApprovalScopeSandbox))
				if ask.Always {
					scope = observability.Present(string(audit.SandboxApprovalScopeAlways))
				}
			}
			return builder.BuildLogApprovalResolved(observability.LogApprovalResolvedInput{
				Envelope: envelope, Severity: sev, LogLevel: level, Outcome: outcome,
				DefenseClawApprovalID: ask.ID, DefenseClawApprovalResult: result,
				DefenseClawApprovalActorType: observability.Present(by),
				UserID:                       hookV8OptionalIdentifier(substrateOwnerSubject(ask.OwnerID)),
				DefenseClawUserIDKind:        v8UserIDKind(useridentity.KindForID(substrateOwnerSubject(ask.OwnerID))),
				ServerAddress:                substrateRelayText(ask.Host),
				DefenseClawSandboxName:       substrateRelayText(ask.Actor), DefenseClawSandboxRuntime: observability.Present("substrate"),
				DefenseClawGuardrailProfileName:     hookV8OptionalIdentifier(ask.Profile),
				DefenseClawSandboxSubstrateAtespace: substrateRelayText(ask.Atespace), DefenseClawSandboxSubstrateActor: substrateRelayText(ask.Actor),
				DefenseClawSandboxSubstrateActorUid: substrateRelayText(ask.UID), DefenseClawSandboxApprovalKind: kind,
				DefenseClawSandboxApprovalScope: scope, MandatoryApprovalResolution: true,
			})
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] %s record failed: %v\n", event, err)
	}
}

// substrateOwnerSubject is the person's subject in an ask's owner key
// (issuer#subject): the user id the actor's hook records carry.
func substrateOwnerSubject(owner string) string {
	if i := strings.LastIndex(owner, "#"); i >= 0 {
		return owner[i+1:]
	}
	return owner
}
