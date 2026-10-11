// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

// emitCorrelationRelationshipsV8 publishes only relationships that have
// already committed to audit.db. The ledger remains authoritative if an
// optional destination is unavailable; callers deliberately do not roll back
// or discard the occurrence after this point.
func (a *APIServer) emitCorrelationRelationshipsV8(
	ctx context.Context,
	source observability.Source,
	connector string,
	semantic audit.SemanticEventID,
	logical audit.LogicalEventID,
	instance audit.ConnectorInstanceID,
	relationships []audit.CorrelationRelationship,
) error {
	if a == nil {
		return nil
	}
	// Secure Client keeps its agentless relationship rows (issue #1092).
	if ctx != nil && len(relationships) > 0 && !a.managedAIDOnly() {
		ctx = a.contextWithSessionAgentV8(ctx, connector)
	}
	return emitCorrelationRelationshipsV8WithEmitter(
		ctx, a.observabilityV8RuntimeEmitter(), source, connector,
		semantic, logical, instance, relationships,
	)
}

// contextWithSessionAgentV8 names the session's agent for an occurrence that
// reported its session but no agent: Codex's native OTLP logs carry only
// conversation.id. It takes the agent the canonical import of the same event
// is stamped with (enrichInboundWithHookLifecycleV8): the live hook snapshot,
// else the conversation's root agent. Without it, those occurrences'
// relationship rows did not join the session agent (GAP-0087).
func (a *APIServer) contextWithSessionAgentV8(ctx context.Context, connector string) context.Context {
	envelope := audit.EnvelopeFromContext(ctx)
	if envelope.AgentID != "" || envelope.SessionID == "" {
		return ctx
	}
	scope := nativeSessionAgentScopeV8(ctx, connector, envelope.SessionID)
	// Session IDs are supplied by agents and may overlap across users. Select
	// only a hook snapshot owned by the authenticated caller's agent identity.
	if scope != "" {
		identity := llmEventMeta{AgentIdentityID: scope}
		if snapshot, found := a.hookSessionStateSnapshotMatching(connector, envelope.SessionID, "", &identity); found && snapshot.meta.AgentID != "" {
			envelope.AgentID = snapshot.meta.AgentID
		}
	}
	if envelope.AgentID == "" {
		envelope.AgentID = agentNodeID(scope, connector, envelope.SessionID, "root")
	}
	return audit.ContextWithEnvelope(ctx, envelope)
}

func emitCorrelationRelationshipsV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source observability.Source,
	connector string,
	semantic audit.SemanticEventID,
	logical audit.LogicalEventID,
	instance audit.ConnectorInstanceID,
	relationships []audit.CorrelationRelationship,
) error {
	if !ManagedEnterpriseActive() {
		// A relationship is a change record: export it when it is created
		// or its status changes, not for each occurrence that only adds
		// evidence, which was almost half the exported bytes of a session
		// (GAP-0423). Secure Client keeps one record per occurrence (#1092).
		changed := relationships[:0:0]
		for _, relationship := range relationships {
			if !relationship.Unchanged {
				changed = append(changed, relationship)
			}
		}
		relationships = changed
	}
	if emitter == nil || len(relationships) == 0 {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("correlation relationship export requires context")
	}
	if source != observability.SourceConnector && source != observability.SourceOTelReceiver {
		return fmt.Errorf("correlation relationship export has invalid source")
	}
	itemFor := func(relationship audit.CorrelationRelationship) (observabilityruntime.LogBatchItem, error) {
		if relationship.RuleID == "" || relationship.RuleVersion == "" {
			return observabilityruntime.LogBatchItem{}, fmt.Errorf("correlation relationship export requires rule identity")
		}
		if relationship.EvidenceCount <= 0 {
			return observabilityruntime.LogBatchItem{}, fmt.Errorf("correlation relationship export requires durable evidence count")
		}
		classification := observability.ClassificationContext{
			Bucket: observability.BucketTelemetryIngest,
			EventName: observability.EventName(
				observability.TelemetryEventCorrelationRelationshipChanged,
			),
			RawSeverity: "INFO",
		}
		metadata, err := router.NewClassifiedLogMetadata(
			observability.ProducerAuditAction,
			observability.ProducerKey(audit.ActionOTelIngestLogs),
			classification,
			source,
			connector,
			observability.ProducerKey(observability.TelemetryEventCorrelationRelationshipChanged),
		)
		if err != nil {
			return observabilityruntime.LogBatchItem{}, err
		}
		return observabilityruntime.LogBatchItem{Context: ctx, Metadata: metadata, Builder: func(
			snapshot observabilityruntime.EmitContext,
			admission router.Admission,
		) (observability.Record, error) {
			if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, fmt.Errorf("correlation relationship record was not admitted")
			}
			builder, buildErr := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			observedAt := observability.Absent[time.Time]()
			if !relationship.LastSeenAt.IsZero() {
				observedAt = observability.Present(relationship.LastSeenAt.UTC())
			} else if !relationship.CreatedAt.IsZero() {
				observedAt = observability.Present(relationship.CreatedAt.UTC())
			}
			status := relationshipExportStatus(relationship.Status)
			envelope := audit.EnvelopeFromContext(ctx)
			correlation := observability.Correlation{
				SemanticEventID: string(semantic), LogicalEventID: string(logical),
				ConnectorInstanceID: string(instance), ConnectorID: connector,
				RunID: gatewaylog.ProcessRunID(), SidecarInstanceID: gatewaylog.SidecarInstanceID(),
				TraceID: envelope.TraceID, RequestID: envelope.RequestID,
				SessionID: envelope.SessionID, TurnID: envelope.TurnID,
				AgentID: envelope.AgentID, AgentInstanceID: envelope.AgentInstanceID,
				PolicyID: envelope.PolicyID, ToolInvocationID: envelope.ToolID,
			}
			return builder.BuildLogCorrelationRelationshipChanged(
				observability.LogCorrelationRelationshipChangedInput{
					Envelope: observability.FamilyEnvelopeInput{
						ObservedAt: observedAt, Source: source, Connector: connector,
						Action: observability.TelemetryEventCorrelationRelationshipChanged,
						Phase:  "graph", Correlation: correlation,
						Provenance: observability.FamilyProvenanceInput{
							Producer: "defenseclaw.correlation", BinaryVersion: version.Current().BinaryVersion,
							ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
						},
					},
					Severity:                                        observability.Present(observability.SeverityInfo),
					LogLevel:                                        observability.Present(observability.LogLevelInfo),
					Outcome:                                         observability.OutcomeApplied,
					DefenseClawSemanticEventID:                      observability.Present(string(semantic)),
					DefenseClawLogicalEventID:                       observability.Present(string(logical)),
					DefenseClawConnectorInstanceID:                  observability.Present(string(instance)),
					DefenseClawCorrelationRelationshipID:            relationship.RelationshipID,
					DefenseClawCorrelationRelationshipType:          string(relationship.Type),
					DefenseClawCorrelationRelationshipSourceKind:    string(relationship.FromKind),
					DefenseClawCorrelationRelationshipSourceID:      relationship.FromID,
					DefenseClawCorrelationRelationshipTargetKind:    string(relationship.ToKind),
					DefenseClawCorrelationRelationshipTargetID:      relationship.ToID,
					DefenseClawCorrelationRelationshipMethod:        string(relationship.Method),
					DefenseClawCorrelationRelationshipStatus:        status,
					DefenseClawCorrelationRelationshipRuleID:        relationship.RuleID,
					DefenseClawCorrelationRelationshipRuleVersion:   relationship.RuleVersion,
					DefenseClawCorrelationRelationshipConfidence:    float64(relationship.Confidence) / 100,
					DefenseClawCorrelationRelationshipEvidenceCount: relationship.EvidenceCount,
				},
			)
		}}, nil
	}
	// Outside Secure Client the rows of one occurrence commit together: one
	// write-ahead-log sync instead of one per relationship (GAP-0246).
	if batcher, ok := emitter.(sidecarRuntimeAtomicBatchEmitter); ok && !ManagedEnterpriseActive() &&
		len(relationships) > 1 && len(relationships) <= observabilityruntime.MaxLogBatchItems {
		items := make([]observabilityruntime.LogBatchItem, 0, len(relationships))
		for _, relationship := range relationships {
			item, err := itemFor(relationship)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		_, err := batcher.EmitAtomicBatch(ctx, items)
		return err
	}
	for _, relationship := range relationships {
		item, err := itemFor(relationship)
		if err != nil {
			return err
		}
		if _, err := emitter.Emit(item.Context, item.Metadata, item.Builder); err != nil {
			return err
		}
	}
	return nil
}

func relationshipExportStatus(status audit.CorrelationRelationshipStatus) string {
	if status == audit.CorrelationRelationshipCandidate {
		return "unresolved"
	}
	return string(status)
}
