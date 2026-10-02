// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// HookToolInvocationQuery selects the v8 event-history record the gateway
// writes when a connector hook reports a tool call it is about to run
// (tool.invocation.requested).
type HookToolInvocationQuery struct {
	// Connector is the connector the record must come from.
	Connector string
	// ToolCallID is the agent's tool call id (gen_ai.tool.call.id). It is an
	// identifier, which every built-in redaction profile keeps, unlike the
	// tool arguments.
	ToolCallID string
	// Since is the earliest record time accepted.
	Since time.Time
	// UserID, when set, is the OS user id the hook must have reported
	// (user.id).
	UserID string
}

// HookToolInvocationEvidence is what the event history holds for a query.
type HookToolInvocationEvidence struct {
	// Matched reports a record that meets every condition of the query.
	Matched bool
	// Mismatches describe records with the query's tool call id that fail
	// another condition.
	Mismatches []string
}

const (
	hookToolInvocationClockSkew = 2 * time.Second
	hookToolInvocationScanLimit = 10000
)

// FindHookToolInvocation searches the audit database at dbPath for the
// record the query selects. The database is opened read-only and
// query-only, with no migration or journal pragma, so a diagnostic never
// becomes a second writer beside the running gateway.
func FindHookToolInvocation(ctx context.Context, dbPath string, query HookToolInvocationQuery) (HookToolInvocationEvidence, error) {
	var evidence HookToolInvocationEvidence
	if strings.TrimSpace(query.Connector) == "" || strings.TrimSpace(query.ToolCallID) == "" || query.Since.IsZero() {
		return evidence, errors.New("audit: a hook tool invocation query needs a connector, a tool call id and a start time")
	}
	db, err := openAuditReadOnly(dbPath)
	if err != nil {
		return evidence, err
	}
	defer db.Close()
	since := query.Since.UTC()
	// Timestamps are stored as RFC 3339 with a variable-length fraction, so
	// the indexed bound is whole seconds, one second early; the exact bound
	// is applied to the parsed time below.
	lower := since.Add(-hookToolInvocationClockSkew - time.Second).Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	rows, err := db.QueryContext(ctx, `SELECT timestamp, connector, tool_id, projected_record_json
		FROM audit_events WHERE event_name = ? AND timestamp >= ? ORDER BY timestamp LIMIT ?`,
		observability.TelemetryEventToolInvocationRequested, lower, hookToolInvocationScanLimit)
	if err != nil {
		return evidence, fmt.Errorf("audit: read event history %s: %w", dbPath, err)
	}
	defer rows.Close()
	for rows.Next() {
		var stamp, connector, toolID, projected sql.NullString
		if err := rows.Scan(&stamp, &connector, &toolID, &projected); err != nil {
			return evidence, fmt.Errorf("audit: read event history %s: %w", dbPath, err)
		}
		record := decodeHookToolInvocation(projected.String)
		if toolID.String != query.ToolCallID && record.Correlation.ToolInvocationID != query.ToolCallID &&
			record.Body.ToolCallID != query.ToolCallID {
			continue
		}
		recordConnector := strings.TrimSpace(connector.String)
		if recordConnector == "" {
			recordConnector = strings.TrimSpace(record.Connector)
		}
		when, parseErr := time.Parse(time.RFC3339Nano, stamp.String)
		switch {
		case !strings.EqualFold(recordConnector, query.Connector):
			evidence.Mismatches = append(evidence.Mismatches, fmt.Sprintf("a tool call record for connector %q", recordConnector))
		case parseErr != nil || when.Before(since.Add(-hookToolInvocationClockSkew)):
			evidence.Mismatches = append(evidence.Mismatches, fmt.Sprintf("a tool call record from %s, before the check started", stamp.String))
		case query.UserID != "" && strings.TrimSpace(record.Body.UserID) != query.UserID:
			evidence.Mismatches = append(evidence.Mismatches, fmt.Sprintf("a tool call record for user %q", record.Body.UserID))
		default:
			evidence.Matched = true
			return evidence, nil
		}
	}
	if err := rows.Err(); err != nil {
		return evidence, fmt.Errorf("audit: read event history %s: %w", dbPath, err)
	}
	return evidence, nil
}

type hookToolInvocationRecord struct {
	Connector   string `json:"connector"`
	Correlation struct {
		ToolInvocationID string `json:"tool_invocation_id"`
	} `json:"correlation"`
	Body struct {
		ToolCallID string `json:"gen_ai.tool.call.id"`
		UserID     string `json:"user.id"`
	} `json:"body"`
}

func decodeHookToolInvocation(projected string) hookToolInvocationRecord {
	var record hookToolInvocationRecord
	_ = json.Unmarshal([]byte(projected), &record)
	return record
}

// openAuditReadOnly opens an existing audit database read-only.
func openAuditReadOnly(dbPath string) (*sql.DB, error) {
	clean := filepath.Clean(strings.TrimSpace(dbPath))
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("audit: database path %q is not absolute", dbPath)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("audit: %s is not a regular file", clean)
	}
	uriPath := filepath.ToSlash(clean)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath // a Windows drive path: file:///C:/...
	}
	dsn := (&url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s read-only: %w", clean, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
