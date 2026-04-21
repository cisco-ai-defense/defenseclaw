// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// JudgeStore persists LLM judge bodies to SQLite with full v7 correlation.
type JudgeStore struct {
	store *audit.Store
}

// NewJudgeStore wraps the audit store for judge_responses inserts.
func NewJudgeStore(s *audit.Store) *JudgeStore {
	if s == nil {
		return nil
	}
	return &JudgeStore{store: s}
}

// PersistJudgeEvent writes a retained judge body when RawResponse is non-empty
// (same guard as audit.InsertJudgeResponse). Context supplies correlation + identity.
func (j *JudgeStore) PersistJudgeEvent(ctx context.Context, dir gatewaylog.Direction, p gatewaylog.JudgePayload, toolName, toolID, policyID, destinationApp string) error {
	if j == nil || j.store == nil || p.RawResponse == "" {
		return nil
	}
	prov := version.Current()
	ident := AgentIdentityFromContext(ctx)
	body := p.RawResponse
	h := sha256.Sum256([]byte(body))
	row := audit.JudgeResponse{
		Kind:       p.Kind,
		Direction:  string(dir),
		Model:      p.Model,
		Action:     p.Action,
		Severity:   string(p.Severity),
		LatencyMs:  p.LatencyMs,
		ParseError: p.ParseError,
		Raw:        body,
		RequestID:  RequestIDFromContext(ctx),
		TraceID:    TraceIDFromContext(ctx),
		RunID:      os.Getenv("DEFENSECLAW_RUN_ID"),
		SessionID:  SessionIDFromContext(ctx),
		InputHash:  "sha256:" + hex.EncodeToString(h[:]),
		// InspectedModel is the upstream traffic model when known; judge model is p.Model.
		InspectedModel:    p.Model,
		SchemaVersion:     prov.SchemaVersion,
		ContentHash:       prov.ContentHash,
		Generation:        prov.Generation,
		BinaryVersion:     prov.BinaryVersion,
		AgentID:           ident.AgentID,
		AgentInstanceID:   ident.AgentInstanceID,
		SidecarInstanceID: ident.SidecarInstanceID,
		PolicyID:          policyID,
		DestinationApp:    destinationApp,
		ToolName:          toolName,
		ToolID:            toolID,
	}
	return j.store.InsertJudgeResponse(row)
}
