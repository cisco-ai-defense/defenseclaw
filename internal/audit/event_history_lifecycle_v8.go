// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const lifecycleProjectionProducer = "gateway.hook.lifecycle"

// LifecycleProjectionQuery identifies one exact hook agent. Recovery never
// performs fuzzy session or agent matching because doing so could attach an
// active execution cursor to the wrong agent after a gateway restart.
type LifecycleProjectionQuery struct {
	Connector string
	SessionID string
	AgentID   string
}

// LifecycleProjection is the content-free subset of a verified canonical v8
// lifecycle log that is safe to use for restart correlation. It deliberately
// excludes prompt/tool bodies, request/trace/span IDs, and provider handles.
type LifecycleProjection struct {
	RecordID          string
	RootAgentID       string
	ParentAgentID     string
	RootSessionID     string
	ParentSessionID   string
	LifecycleID       string
	ExecutionID       string
	Event             string
	State             string
	Phase             string
	LineageProvenance string
	Depth             int
	Sequence          int64
}

type storedLifecycleProjection struct {
	recordID             string
	timestamp            string
	timestampUnixNano    int64
	bucket               string
	eventName            string
	source               string
	signal               string
	bucketCatalogVersion int
	recordSchemaVersion  int
	redactionProfile     string
	connector            string
	sessionID            string
	agentID              string
	projected            string
	projectionHash       string
	payloadHMAC          string
	integrityAlgorithm   string
	integrityKeyID       string
}

type lifecycleProjectionEnvelope struct {
	SchemaVersion        int                            `json:"schema_version"`
	BucketCatalogVersion int                            `json:"bucket_catalog_version"`
	RecordID             string                         `json:"record_id"`
	Timestamp            time.Time                      `json:"timestamp"`
	Bucket               string                         `json:"bucket"`
	Signal               string                         `json:"signal"`
	EventName            string                         `json:"event_name"`
	Source               string                         `json:"source"`
	Connector            string                         `json:"connector"`
	Correlation          lifecycleProjectionCorrelation `json:"correlation"`
	Provenance           lifecycleProjectionProvenance  `json:"provenance"`
	Projection           lifecycleProjectionMetadata    `json:"projection"`
	Body                 json.RawMessage                `json:"body"`
}

type lifecycleProjectionCorrelation struct {
	SessionID   string `json:"session_id"`
	AgentID     string `json:"agent_id"`
	ConnectorID string `json:"connector_id"`
}

type lifecycleProjectionProvenance struct {
	Producer string `json:"producer"`
}

type lifecycleProjectionMetadata struct {
	RedactionProfile string `json:"redaction_profile"`
}

type lifecycleProjectionBody struct {
	SessionID         string `json:"gen_ai.conversation.id"`
	AgentID           string `json:"gen_ai.agent.id"`
	RootAgentID       string `json:"defenseclaw.agent.root.id"`
	ParentAgentID     string `json:"defenseclaw.agent.parent.id"`
	RootSessionID     string `json:"defenseclaw.session.root.id"`
	ParentSessionID   string `json:"defenseclaw.session.parent.id"`
	LifecycleID       string `json:"defenseclaw.agent.lifecycle.id"`
	ExecutionID       string `json:"defenseclaw.agent.execution.id"`
	Event             string `json:"defenseclaw.agent.lifecycle.event"`
	State             string `json:"defenseclaw.agent.lifecycle.state"`
	Phase             string `json:"defenseclaw.agent.phase"`
	LineageProvenance string `json:"defenseclaw.agent.lineage.provenance"`
	Depth             int64  `json:"defenseclaw.agent.depth"`
	Sequence          int64  `json:"defenseclaw.agent.sequence"`
}

// LatestLifecycleProjection returns the newest exact canonical lifecycle row
// only when its projection hash and HMAC both verify under this generation's
// writer. Invalid, transformed, ambiguous, or inconsistent rows are treated as
// unavailable rather than falling back to an older execution cursor.
func (writer *EventHistoryWriter) LatestLifecycleProjection(
	ctx context.Context,
	query LifecycleProjectionQuery,
) (LifecycleProjection, bool, error) {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return LifecycleProjection{}, false, fmt.Errorf("audit: v8 lifecycle history is not initialized")
	}
	if ctx == nil {
		return LifecycleProjection{}, false, fmt.Errorf("audit: v8 lifecycle history context is required")
	}
	if !validLifecycleProjectionQuery(query) {
		return LifecycleProjection{}, false, nil
	}
	release, err := writer.store.acquireReady()
	if err != nil {
		return LifecycleProjection{}, false, err
	}
	defer release()

	rows, err := writer.store.db.QueryContext(ctx, `
		SELECT id, COALESCE(CAST(timestamp AS TEXT),''), COALESCE(retention_timestamp_unix_nano,0),
		       COALESCE(bucket,''), COALESCE(event_name,''), COALESCE(source,''), COALESCE(signal,''),
		       COALESCE(bucket_catalog_version,0), COALESCE(record_schema_version,0),
		       COALESCE(redaction_profile,''), COALESCE(connector,''),
		       COALESCE(session_id,''), COALESCE(agent_id,''),
		       COALESCE(projected_record_json,''), COALESCE(projection_hash,''),
		       COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''), COALESCE(integrity_key_id,'')
		FROM audit_events
		WHERE connector = ? AND session_id = ? AND agent_id = ?
		  AND signal = 'logs'
		  AND event_name IN ('session_start','session_end','subagent_start','subagent_stop',
		                     'turn_start','turn_end','tool_start','tool_end','compact_start','compact_end','event')
		ORDER BY retention_timestamp_unix_nano DESC, rowid DESC
		LIMIT 2`, query.Connector, query.SessionID, query.AgentID)
	if err != nil {
		return LifecycleProjection{}, false, fmt.Errorf("audit: read v8 lifecycle history: %w", err)
	}
	defer rows.Close()

	candidates := make([]storedLifecycleProjection, 0, 2)
	for rows.Next() {
		var row storedLifecycleProjection
		if err := rows.Scan(
			&row.recordID, &row.timestamp, &row.timestampUnixNano, &row.bucket, &row.eventName, &row.source, &row.signal,
			&row.bucketCatalogVersion, &row.recordSchemaVersion, &row.redactionProfile, &row.connector,
			&row.sessionID, &row.agentID, &row.projected, &row.projectionHash, &row.payloadHMAC,
			&row.integrityAlgorithm, &row.integrityKeyID,
		); err != nil {
			return LifecycleProjection{}, false, fmt.Errorf("audit: scan v8 lifecycle history")
		}
		candidates = append(candidates, row)
	}
	if err := rows.Err(); err != nil {
		return LifecycleProjection{}, false, fmt.Errorf("audit: iterate v8 lifecycle history: %w", err)
	}
	if len(candidates) == 0 {
		return LifecycleProjection{}, false, nil
	}
	if candidates[0].timestampUnixNano <= 0 ||
		(len(candidates) > 1 && candidates[0].timestampUnixNano == candidates[1].timestampUnixNano) {
		return LifecycleProjection{}, false, nil
	}

	row := candidates[0]
	verification, err := writer.verifyStoredProjection(
		ctx, row.recordID, []byte(row.projected), row.projectionHash,
		row.payloadHMAC, row.integrityAlgorithm, row.integrityKeyID,
	)
	if err != nil {
		return LifecycleProjection{}, false, err
	}
	if verification.Status != EventHistoryVerified || !verification.ProjectionHashValid ||
		!verification.IntegrityVerified {
		return LifecycleProjection{}, false, nil
	}
	projection, valid := decodeLifecycleProjection(row, query)
	return projection, valid, nil
}

func validLifecycleProjectionQuery(query LifecycleProjectionQuery) bool {
	return observability.IsStableToken(query.Connector) &&
		validLifecycleProjectionID(query.SessionID, true) && validLifecycleProjectionID(query.AgentID, true)
}

func validLifecycleProjectionID(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if !utf8.ValidString(value) || len(value) > observability.MaxCorrelationIDBytes {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func decodeLifecycleProjection(
	row storedLifecycleProjection,
	query LifecycleProjectionQuery,
) (LifecycleProjection, bool) {
	if row.recordSchemaVersion != observability.CurrentRecordSchemaVersion ||
		row.bucketCatalogVersion != observability.CurrentBucketCatalogVersion ||
		row.source != string(observability.SourceConnector) || row.signal != string(observability.SignalLogs) ||
		row.connector != query.Connector || row.sessionID != query.SessionID || row.agentID != query.AgentID ||
		row.redactionProfile == string(observabilityredaction.ProfileLegacyV7) ||
		!validLifecycleBucketEvent(row.bucket, row.eventName) {
		return LifecycleProjection{}, false
	}
	var envelope lifecycleProjectionEnvelope
	decoder := json.NewDecoder(strings.NewReader(row.projected))
	if err := decoder.Decode(&envelope); err != nil {
		return LifecycleProjection{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return LifecycleProjection{}, false
	}
	if envelope.SchemaVersion != row.recordSchemaVersion ||
		envelope.BucketCatalogVersion != row.bucketCatalogVersion || envelope.RecordID != row.recordID ||
		envelope.Bucket != row.bucket || envelope.Signal != row.signal || envelope.EventName != row.eventName ||
		envelope.Source != row.source || envelope.Connector != query.Connector ||
		envelope.Correlation.SessionID != query.SessionID || envelope.Correlation.AgentID != query.AgentID ||
		envelope.Correlation.ConnectorID != query.Connector ||
		envelope.Provenance.Producer != lifecycleProjectionProducer ||
		envelope.Projection.RedactionProfile != row.redactionProfile || len(envelope.Body) == 0 {
		return LifecycleProjection{}, false
	}
	storedTimestamp, err := time.Parse(time.RFC3339Nano, row.timestamp)
	if err != nil || envelope.Timestamp.IsZero() || !envelope.Timestamp.Equal(storedTimestamp) ||
		storedTimestamp.UnixNano() != row.timestampUnixNano {
		return LifecycleProjection{}, false
	}
	var body lifecycleProjectionBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil ||
		body.SessionID != query.SessionID || body.AgentID != query.AgentID || body.Event != row.eventName ||
		!validLifecycleProjectionBody(body) {
		return LifecycleProjection{}, false
	}
	return LifecycleProjection{
		RecordID: row.recordID, RootAgentID: body.RootAgentID, ParentAgentID: body.ParentAgentID,
		RootSessionID: body.RootSessionID, ParentSessionID: body.ParentSessionID,
		LifecycleID: body.LifecycleID, ExecutionID: body.ExecutionID,
		Event: body.Event, State: body.State, Phase: body.Phase,
		LineageProvenance: body.LineageProvenance, Depth: int(body.Depth), Sequence: body.Sequence,
	}, true
}

func validLifecycleBucketEvent(bucket, event string) bool {
	if event == "tool_start" || event == "tool_end" {
		return bucket == string(observability.BucketToolActivity)
	}
	return bucket == string(observability.BucketAgentLifecycle)
}

func validLifecycleProjectionBody(body lifecycleProjectionBody) bool {
	for _, value := range []string{
		body.SessionID, body.AgentID, body.RootAgentID, body.RootSessionID,
		body.LifecycleID, body.ExecutionID,
	} {
		if !validLifecycleProjectionID(value, true) {
			return false
		}
	}
	for _, value := range []string{body.ParentAgentID, body.ParentSessionID} {
		if !validLifecycleProjectionID(value, false) {
			return false
		}
	}
	if body.Depth < 0 || body.Depth > 64 || body.Sequence <= 0 ||
		!validLifecycleState(body.State) || !validLifecyclePhase(body.Phase) ||
		(body.LineageProvenance != "" && body.LineageProvenance != "reported" && body.LineageProvenance != "inferred") {
		return false
	}
	if body.Depth == 0 {
		return body.RootAgentID == body.AgentID && body.ParentAgentID == "" &&
			body.RootSessionID == body.SessionID && body.ParentSessionID == ""
	}
	return body.RootAgentID != body.AgentID && body.ParentAgentID != "" && body.ParentAgentID != body.AgentID
}

func validLifecycleState(state string) bool {
	switch state {
	case "active", "observed", "completed", "failed", "interrupted", "cancelled", "canceled":
		return true
	default:
		return false
	}
}

func validLifecyclePhase(phase string) bool {
	switch phase {
	case "session", "planning", "model", "responding", "approval", "tool", "waiting",
		"maintenance", "completed", "failed", "interrupted", "observed":
		return true
	default:
		return false
	}
}
