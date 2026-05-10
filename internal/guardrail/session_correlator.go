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

package guardrail

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// SessionFindingReader is the minimum surface SessionCorrelator needs
// from the audit store. Defined here so the correlator can be
// exercised in tests with a fake store.
type SessionFindingReader interface {
	ListRecentFindingsInSession(sessionID, agentInstanceID string, limit int) ([]SessionFindingRow, error)
}

// SessionFindingRow mirrors the projection returned by the audit
// store's ListRecentFindingsInSession but lives in this package to
// avoid a guardrail <- audit import (audit already imports guardrail
// via scan_persist for the CorrelationFindingRow type).
type SessionFindingRow struct {
	ID                  string
	RuleID              sql.NullString
	Category            sql.NullString
	Severity            string
	DataAxis            sql.NullString
	ToolCapabilityClass sql.NullString
	ContentFingerprint  sql.NullString
	ExternalEndpoint    sql.NullString
	TurnID              sql.NullInt64
	Timestamp           string
}

// SessionCorrelator satisfies scanner.Correlator. Runs the pattern
// library against a session's recent findings and writes back CORR-*
// synthetic findings when any pattern fires.
type SessionCorrelator struct {
	reader        SessionFindingReader
	patterns      []CorrelationPattern
	windowLimit   int
	firedPerSess  sync.Map // map[sessKey]map[patternID]struct{} to avoid firing the same pattern repeatedly in a session
}

// NewSessionCorrelator builds a correlator from a reader and a
// pre-loaded pattern set. The reader is how it reaches into persisted
// findings; the patterns are typically parsed from
// defaults/correlation-patterns.yaml at boot.
func NewSessionCorrelator(reader SessionFindingReader, patterns []CorrelationPattern) *SessionCorrelator {
	limit := 0
	for _, p := range patterns {
		if p.WindowEvents > limit {
			limit = p.WindowEvents
		}
	}
	if limit <= 0 {
		limit = 50
	}
	return &SessionCorrelator{
		reader:      reader,
		patterns:    patterns,
		windowLimit: limit,
	}
}

// RunForSession implements scanner.Correlator. Non-fatal: any error
// reading findings, evaluating patterns, or persisting the synthetic
// finding is returned to the caller (EmitScanResult logs and ignores).
func (c *SessionCorrelator) RunForSession(
	ctx context.Context,
	sessionID, agentInstanceID string,
	pers scanner.ScanPersistence,
	target string,
	meta scanner.ScanFindingMeta,
) error {
	_ = ctx
	if c == nil || c.reader == nil || len(c.patterns) == 0 {
		return nil
	}
	if sessionID == "" || agentInstanceID == "" {
		return nil
	}

	rows, err := c.reader.ListRecentFindingsInSession(sessionID, agentInstanceID, c.windowLimit)
	if err != nil {
		return fmt.Errorf("correlator: read session window: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}

	window := make([]CorrelationFinding, 0, len(rows))
	for _, r := range rows {
		window = append(window, rowToCorrelationFinding(r))
	}

	matches := Evaluate(c.patterns, window)
	if len(matches) == 0 {
		return nil
	}

	sessKey := sessionID + "|" + agentInstanceID
	firedAny, _ := c.firedPerSess.LoadOrStore(sessKey, &sync.Map{})
	fired := firedAny.(*sync.Map)

	var synthetic []scanner.Finding
	for _, m := range matches {
		if _, already := fired.LoadOrStore(m.Pattern.ID, struct{}{}); already {
			continue
		}
		synthetic = append(synthetic, syntheticFindingFromMatch(m, meta))
	}
	if len(synthetic) == 0 {
		return nil
	}

	scanID := "corr-" + uuid.New().String()
	if err := pers.InsertScanSummary(scanner.ScanSummaryParams{
		ScanID:          scanID,
		Scanner:         "correlator",
		Target:          target,
		Timestamp:       time.Now().UTC(),
		FindingCount:    len(synthetic),
		MaxSeverity:     "CRITICAL",
		Verdict:         "block",
		SessionID:       sessionID,
		AgentInstanceID: agentInstanceID,
		RunID:           meta.RunID,
		RequestID:       meta.RequestID,
		TraceID:         meta.TraceID,
	}); err != nil {
		return fmt.Errorf("correlator: insert synthetic scan summary: %w", err)
	}
	corrMeta := meta
	corrMeta.Timestamp = time.Now().UTC()
	if err := pers.InsertScanFindings(scanID, target, synthetic, corrMeta); err != nil {
		return fmt.Errorf("correlator: insert synthetic findings: %w", err)
	}
	return nil
}

func rowToCorrelationFinding(r SessionFindingRow) CorrelationFinding {
	f := CorrelationFinding{
		ID:       r.ID,
		Severity: r.Severity,
	}
	if r.RuleID.Valid {
		f.RuleID = r.RuleID.String
	}
	if r.Category.Valid {
		f.Category = r.Category.String
	}
	if r.DataAxis.Valid && r.DataAxis.String != "" {
		for _, a := range strings.Split(strings.Trim(r.DataAxis.String, "[]\""), ",") {
			a = strings.TrimSpace(strings.Trim(a, `"`))
			if a != "" {
				f.DataAxis = append(f.DataAxis, DataAxis(a))
			}
		}
	}
	if r.ToolCapabilityClass.Valid {
		f.ToolCapabilityClass = ToolCapabilityClass(r.ToolCapabilityClass.String)
	}
	if r.ContentFingerprint.Valid {
		f.ContentFingerprint = r.ContentFingerprint.String
	}
	if r.ExternalEndpoint.Valid {
		f.ExternalEndpoint = r.ExternalEndpoint.String
	}
	if r.TurnID.Valid {
		f.TurnID = int(r.TurnID.Int64)
	}
	return f
}

func syntheticFindingFromMatch(m CorrelationMatch, _ scanner.ScanFindingMeta) scanner.Finding {
	contribIDs := make([]string, 0, len(m.Contributing))
	for _, f := range m.Contributing {
		contribIDs = append(contribIDs, f.ID)
	}
	desc := fmt.Sprintf("Correlation pattern %s matched on %d contributing findings: %s",
		m.Pattern.ID, len(m.Contributing), strings.Join(contribIDs, ", "))
	if m.Pattern.Description != "" {
		desc = m.Pattern.Description + "\n\n" + desc
	}
	return scanner.Finding{
		ID:          "corr-" + m.Pattern.ID + "-" + uuid.New().String()[:8],
		Severity:    scanner.Severity(m.Pattern.SeverityOnMatch),
		Title:       "Correlation: " + m.Pattern.ID,
		Description: desc,
		Scanner:     "correlator",
		RuleID:      m.SyntheticFindingRuleID(),
		Category:    "correlation",
		Tags:        []string{"correlation", m.Pattern.ID},
	}
}
