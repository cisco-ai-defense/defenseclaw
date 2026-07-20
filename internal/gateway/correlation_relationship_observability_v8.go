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
	return emitCorrelationRelationshipsV8WithEmitter(
		ctx, a.observabilityV8RuntimeEmitter(), source, connector,
		semantic, logical, instance, relationships,
	)
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
	if emitter == nil || len(relationships) == 0 {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("correlation relationship export requires context")
	}
	if source != observability.SourceConnector && source != observability.SourceOTelReceiver {
		return fmt.Errorf("correlation relationship export has invalid source")
	}
	for _, relationship := range relationships {
		if relationship.RuleID == "" || relationship.RuleVersion == "" {
			return fmt.Errorf("correlation relationship export requires rule identity")
		}
		if relationship.EvidenceCount <= 0 {
			return fmt.Errorf("correlation relationship export requires durable evidence count")
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
			return err
		}
		_, err = emitter.Emit(ctx, metadata, func(
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
		})
		if err != nil {
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
