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
	ListRecentFindingsInSession(
		sessionID, agentInstanceID, agentID string,
		limit int,
	) ([]SessionFindingRow, error)
	ListFiredCorrelationRuleIDsInSession(
		sessionID, agentInstanceID, agentID string,
		candidateRuleIDs []string,
	) ([]string, error)
}

// SessionFindingRow mirrors the projection returned by the audit
// store's ListRecentFindingsInSession but lives in this package to
// avoid a guardrail <- audit import (audit already imports guardrail
// via scan_persist for the CorrelationFindingRow type).
type SessionFindingRow struct {
	ID                  string
	AgentID             string
	AgentInstanceID     string
	Scanner             string
	RuleID              sql.NullString
	Category            sql.NullString
	Severity            string
	Tags                []string
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
	reader      SessionFindingReader
	patterns    []CorrelationPattern
	windowLimit int
	// Partition locks close the in-process check-then-persist race without
	// retaining attacker-controlled session keys. The persisted CORR-* ledger
	// remains the durable once-per-session authority after a lock is released.
	partitionLocks [sessionCorrelatorPartitionLockStripes]sync.Mutex
}

const sessionCorrelatorPartitionLockStripes = 64

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
	partition, ok := newCorrelationAgentPartition(sessionID, agentInstanceID, meta.AgentID)
	if !ok {
		return nil
	}

	rows, err := c.reader.ListRecentFindingsInSession(
		partition.sessionID, partition.agentInstanceID, partition.agentID, c.windowLimit,
	)
	if err != nil {
		return fmt.Errorf("correlator: read session window: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}

	// Rows arrive newest-first. Walk oldest-first while deduplicating so an
	// exact later replay cannot replace the original primitive and reorder an
	// otherwise valid ingress -> sensitive-access -> egress sequence. Reverse
	// the result back to the evaluator's newest-first contract afterward.
	oldestFirst := make([]CorrelationFinding, 0, len(rows))
	seenPrimitive := make(map[string]struct{}, len(rows))
	for index := len(rows) - 1; index >= 0; index-- {
		r := rows[index]
		if !partition.includes(r) || !correlationInputEligible(r) {
			continue
		}
		if key, deduplicate := correlationPrimitiveKey(r); deduplicate {
			if _, seen := seenPrimitive[key]; seen {
				continue
			}
			seenPrimitive[key] = struct{}{}
		}
		oldestFirst = append(oldestFirst, rowToCorrelationFinding(r))
	}
	if len(oldestFirst) == 0 {
		return nil
	}
	window := make([]CorrelationFinding, len(oldestFirst))
	for index := range oldestFirst {
		window[len(oldestFirst)-1-index] = oldestFirst[index]
	}

	matches := Evaluate(c.patterns, window)
	if len(matches) == 0 {
		return nil
	}

	// Serialize the durable-ledger read and synthetic write for this partition
	// inside one process. A fixed stripe table bounds memory independently of
	// client-controlled session cardinality; collisions only serialize work.
	partitionLock := &c.partitionLocks[correlationPartitionLockIndex(partition.key())]
	partitionLock.Lock()
	defer partitionLock.Unlock()

	// Query persisted CORR-* identities for currently matched patterns as the
	// durable once-per-session ledger. These rows never enter the contributor
	// window, and an evicted/previous partition needs no retained in-memory key.
	candidateRuleIDs := make([]string, 0, len(matches))
	candidateSet := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		key := strings.ToLower(strings.TrimSpace(match.SyntheticFindingRuleID()))
		if _, exists := candidateSet[key]; !exists {
			candidateSet[key] = struct{}{}
			candidateRuleIDs = append(candidateRuleIDs, match.SyntheticFindingRuleID())
		}
	}
	persistedRuleIDs, err := c.reader.ListFiredCorrelationRuleIDsInSession(
		partition.sessionID, partition.agentInstanceID, partition.agentID, candidateRuleIDs,
	)
	if err != nil {
		return fmt.Errorf("correlator: read persisted firing ledger: %w", err)
	}
	persisted := make(map[string]struct{}, len(persistedRuleIDs))
	for _, ruleID := range persistedRuleIDs {
		persisted[strings.ToLower(strings.TrimSpace(ruleID))] = struct{}{}
	}

	var synthetic []scanner.Finding
	scheduled := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		key := strings.ToLower(strings.TrimSpace(m.SyntheticFindingRuleID()))
		if _, already := persisted[key]; already {
			continue
		}
		if _, already := scheduled[key]; already {
			continue
		}
		scheduled[key] = struct{}{}
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
		SessionID:       partition.sessionID,
		AgentInstanceID: partition.agentInstanceID,
		AgentID:         partition.agentID,
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

// correlationAgentPartition is the identity boundary for a synthetic attack
// chain. AgentInstanceID is the primary execution identity when present, but
// Codex can report one session-scoped instance for multiple logical subagents.
// Therefore an available AgentID is also required to match inside that
// instance. If an instance is absent, AgentID is the conservative fallback.
// Rows with missing identity only correlate with rows missing the same tier;
// they are never folded into a known agent's chain. With neither identity the
// correlator stays disabled rather than constructing a cross-agent session
// chain from ambiguous evidence.
type correlationAgentPartition struct {
	sessionID       string
	agentInstanceID string
	agentID         string
}

func newCorrelationAgentPartition(sessionID, agentInstanceID, agentID string) (correlationAgentPartition, bool) {
	partition := correlationAgentPartition{
		sessionID:       strings.TrimSpace(sessionID),
		agentInstanceID: strings.TrimSpace(agentInstanceID),
		agentID:         strings.TrimSpace(agentID),
	}
	return partition, partition.sessionID != "" &&
		(partition.agentInstanceID != "" || partition.agentID != "")
}

func (p correlationAgentPartition) key() string {
	return p.sessionID + "\x00" + p.agentInstanceID + "\x00" + p.agentID
}

func correlationPartitionLockIndex(key string) int {
	// FNV-1a is sufficient for lock striping: collisions affect scheduling,
	// never identity or authorization, and the table size is fixed.
	const (
		fnvOffset32 = uint32(2166136261)
		fnvPrime32  = uint32(16777619)
	)
	hash := fnvOffset32
	for index := 0; index < len(key); index++ {
		hash ^= uint32(key[index])
		hash *= fnvPrime32
	}
	return int(hash % uint32(sessionCorrelatorPartitionLockStripes))
}

func (p correlationAgentPartition) includes(row SessionFindingRow) bool {
	rowInstanceID := strings.TrimSpace(row.AgentInstanceID)
	rowAgentID := strings.TrimSpace(row.AgentID)
	if p.agentInstanceID != "" {
		if rowInstanceID != p.agentInstanceID {
			return false
		}
		if p.agentID != "" {
			return rowAgentID == p.agentID
		}
		return rowAgentID == ""
	}
	return rowInstanceID == "" && p.agentID != "" && rowAgentID == p.agentID
}

func correlationInputEligible(row SessionFindingRow) bool {
	if strings.EqualFold(strings.TrimSpace(row.Scanner), "correlator") {
		return false
	}
	for _, tag := range row.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), scanner.FindingTagDetectionOnly) {
			return false
		}
	}
	return true
}

// correlationPrimitiveKey collapses repeat observations of the same concrete
// primitive. A non-empty fingerprint is required: findings without a value
// identity may be distinct events and therefore remain separate. Rule and
// category stay in the key so two independent detectors can still establish a
// real multi-step chain even when they refer to the same value.
func correlationPrimitiveKey(row SessionFindingRow) (string, bool) {
	if !row.ContentFingerprint.Valid {
		return "", false
	}
	fingerprint := strings.ToLower(strings.TrimSpace(row.ContentFingerprint.String))
	if fingerprint == "" {
		return "", false
	}
	ruleID := ""
	if row.RuleID.Valid {
		ruleID = strings.ToLower(strings.TrimSpace(row.RuleID.String))
	}
	category := ""
	if row.Category.Valid {
		category = strings.ToLower(strings.TrimSpace(row.Category.String))
	}
	return ruleID + "\x00" + category + "\x00" + fingerprint, true
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
