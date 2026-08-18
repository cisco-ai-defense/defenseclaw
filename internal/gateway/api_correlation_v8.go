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

package gateway

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const correlationQueryMaxLimit = 500

var correlationQueryParameters = map[string]struct{}{
	"record_id": {}, "semantic_event_id": {}, "logical_event_id": {},
	"session_id": {}, "turn_id": {}, "agent_id": {}, "lifecycle_id": {},
	"execution_id": {}, "model_request_id": {}, "model_response_id": {},
	"tool_invocation_id": {}, "trace_id": {}, "span_id": {},
	"connector_instance_id": {}, "limit": {}, "after_time": {}, "after_id": {},
}

func (a *APIServer) handleCorrelationGraphV8(w http.ResponseWriter, r *http.Request) {
	a.handleCorrelationReadV8(w, r, func(repo *audit.CorrelationRepository, query audit.CorrelationGraphQuery) (any, error) {
		return repo.QueryGraph(r.Context(), query)
	})
}

func (a *APIServer) handleCorrelationExplainV8(w http.ResponseWriter, r *http.Request) {
	a.handleCorrelationReadV8(w, r, func(repo *audit.CorrelationRepository, query audit.CorrelationGraphQuery) (any, error) {
		return repo.Explain(r.Context(), query)
	})
}

func (a *APIServer) handleCorrelationTimelineV8(w http.ResponseWriter, r *http.Request) {
	a.handleCorrelationReadV8(w, r, func(repo *audit.CorrelationRepository, query audit.CorrelationGraphQuery) (any, error) {
		return repo.QueryTimeline(r.Context(), query)
	})
}

func (a *APIServer) handleCorrelationConflictsV8(w http.ResponseWriter, r *http.Request) {
	a.handleCorrelationReadV8(w, r, func(repo *audit.CorrelationRepository, query audit.CorrelationGraphQuery) (any, error) {
		return repo.QueryConflicts(r.Context(), audit.CorrelationConflictsQuery{
			Anchor: query.Anchor,
			Page:   query.Page,
		})
	})
}

type correlationQueryOperation func(
	*audit.CorrelationRepository,
	audit.CorrelationGraphQuery,
) (any, error)

func (a *APIServer) handleCorrelationReadV8(
	w http.ResponseWriter,
	r *http.Request,
	operation correlationQueryOperation,
) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if a == nil || a.store == nil || !a.store.Ready() {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "correlation ledger is not available"})
		return
	}
	query, err := parseCorrelationQuery(r.URL.Query())
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	repo, err := a.store.CorrelationRepository()
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "correlation ledger is not available"})
		return
	}
	result, err := operation(repo, query)
	if err != nil {
		// Parser-level validation catches all caller-controlled shape errors.
		// Repository errors can contain SQL or local filesystem details, so do
		// not reflect them through this authenticated API.
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "correlation query failed"})
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

func parseCorrelationQuery(values url.Values) (audit.CorrelationGraphQuery, error) {
	var query audit.CorrelationGraphQuery
	for key, entries := range values {
		if _, ok := correlationQueryParameters[key]; !ok {
			return query, fmt.Errorf("unsupported query parameter %q", key)
		}
		if len(entries) != 1 {
			return query, fmt.Errorf("query parameter %q must be specified once", key)
		}
		if strings.TrimSpace(entries[0]) != entries[0] {
			return query, fmt.Errorf("query parameter %q contains surrounding whitespace", key)
		}
	}
	query.Anchor = audit.CorrelationAnchor{
		ConnectorInstanceID: audit.ConnectorInstanceID(values.Get("connector_instance_id")),
		RecordID:            values.Get("record_id"),
		SemanticEventID:     audit.SemanticEventID(values.Get("semantic_event_id")),
		LogicalEventID:      audit.LogicalEventID(values.Get("logical_event_id")),
		SessionID:           values.Get("session_id"),
		TurnID:              values.Get("turn_id"),
		AgentID:             values.Get("agent_id"),
		LifecycleID:         values.Get("lifecycle_id"),
		ExecutionID:         values.Get("execution_id"),
		ModelRequestID:      values.Get("model_request_id"),
		ModelResponseID:     values.Get("model_response_id"),
		ToolInvocationID:    values.Get("tool_invocation_id"),
		TraceID:             values.Get("trace_id"),
		SpanID:              values.Get("span_id"),
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > correlationQueryMaxLimit {
			return query, fmt.Errorf("limit must be between 1 and %d", correlationQueryMaxLimit)
		}
		query.Page.Limit = limit
	}
	afterTime, afterID := values.Get("after_time"), values.Get("after_id")
	if (afterTime == "") != (afterID == "") {
		return query, fmt.Errorf("after_time and after_id must be provided together")
	}
	if afterTime != "" {
		parsed, err := time.Parse(time.RFC3339Nano, afterTime)
		if err != nil {
			return query, fmt.Errorf("after_time must be RFC3339Nano")
		}
		query.Page.AfterTime = parsed.UTC()
		query.Page.AfterID = afterID
	}
	if err := validateCorrelationQueryShape(query.Anchor); err != nil {
		return query, err
	}
	return query, nil
}

func validateCorrelationQueryShape(anchor audit.CorrelationAnchor) error {
	anchors := []string{
		anchor.RecordID, string(anchor.SemanticEventID), string(anchor.LogicalEventID),
		anchor.SessionID, anchor.TurnID, anchor.AgentID, anchor.LifecycleID,
		anchor.ExecutionID, anchor.ModelRequestID, anchor.ModelResponseID,
		anchor.ToolInvocationID, anchor.TraceID,
	}
	count := 0
	for _, value := range anchors {
		if value != "" {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("exactly one correlation anchor is required")
	}
	if anchor.SpanID != "" && anchor.TraceID == "" {
		return fmt.Errorf("span_id requires trace_id")
	}
	for field, value := range map[string]string{
		"connector_instance_id": string(anchor.ConnectorInstanceID),
		"semantic_event_id":     string(anchor.SemanticEventID),
		"logical_event_id":      string(anchor.LogicalEventID),
	} {
		if value != "" && !validCorrelationUUIDv7(value) {
			return fmt.Errorf("%s must be a canonical UUIDv7", field)
		}
	}
	if anchor.TraceID != "" && !validCorrelationHexID(anchor.TraceID, 16) {
		return fmt.Errorf("trace_id must be 32 lowercase hexadecimal characters")
	}
	if anchor.SpanID != "" && !validCorrelationHexID(anchor.SpanID, 8) {
		return fmt.Errorf("span_id must be 16 lowercase hexadecimal characters")
	}
	for field, value := range map[string]string{
		"record_id": anchor.RecordID, "session_id": anchor.SessionID, "turn_id": anchor.TurnID,
		"agent_id": anchor.AgentID, "lifecycle_id": anchor.LifecycleID, "execution_id": anchor.ExecutionID,
		"model_request_id": anchor.ModelRequestID, "model_response_id": anchor.ModelResponseID,
		"tool_invocation_id": anchor.ToolInvocationID,
	} {
		if len(value) > 512 {
			return fmt.Errorf("%s exceeds 512 bytes", field)
		}
	}
	return nil
}

func validCorrelationHexID(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}
