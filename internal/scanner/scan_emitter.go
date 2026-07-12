// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

// scanResultJSON retains the source-backed result for the local forensic
// store. Canonical v8 producers build immutable records from the same source;
// the central pipeline then applies each destination's redaction profile.
// Transforming this copy here would make the default-unredacted profile and
// destination-specific projections impossible.
func scanResultJSON(r *ScanResult) ([]byte, error) {
	if r == nil {
		return []byte(`{}`), nil
	}
	return json.MarshalIndent(r, "", "  ")
}

// ScanPersistence persists scan summary + per-finding rows. Implemented by
// *audit.Store (see audit/scan_persist.go).
type ScanPersistence interface {
	InsertScanSummary(ScanSummaryParams) error
	InsertScanFindings(scanID, target string, findings []Finding, meta ScanFindingMeta) error
}

// Correlator runs after findings are persisted to detect multi-step
// attack flows (lethal trifecta, escalation chains, destructive
// flows) by reading a session's recent findings and matching them
// against declared patterns. Nil means "don't run correlation".
type Correlator interface {
	RunForSession(ctx context.Context, sessionID, agentInstanceID string, pers ScanPersistence, target string, meta ScanFindingMeta) error
}

// defaultCorrelator holds the package-level correlator installed at
// sidecar boot. Accessed only via SetCorrelator / the read in
// EmitScanResult, so a plain pointer with a mutex is plenty — this
// is not a hot path.
var defaultCorrelator Correlator

// SetCorrelator installs the correlator that EmitScanResult will run
// after every successful InsertScanFindings. Pass nil to disable.
// Intended to be called once at sidecar boot from the gateway wiring
// layer so the scanner package stays free of guardrail imports.
func SetCorrelator(c Correlator) { defaultCorrelator = c }

// findingEnricher is the hook that maps a finding's rule_id + tags
// to the lethal-trifecta data axes. Nil when the sidecar hasn't
// wired up guardrail.AxesForRuleID yet — see cli/correlator_wire.go.
var findingEnricher func(*Finding) []string

// SetFindingEnricher installs the axis-labeling hook that runs on
// every finding emitted through EmitScanResult. The hook is called
// only when Finding.DataAxis is empty, so scanner-specific code that
// already sets axes (e.g. clawshield tagging by content hash) wins.
func SetFindingEnricher(f func(*Finding) []string) { findingEnricher = f }

// capabilityEnricher maps a finding's rule_id to its
// tool_capability_class (read_fs / write_fs / exec_shell /
// network_fetch / send_message). Nil until the guardrail wiring layer
// installs guardrail.CapabilityForRuleID — see cli/correlator_wire.go.
// Returning "" means "no capability", leaving the field untouched.
var capabilityEnricher func(*Finding) string

// SetCapabilityEnricher installs the capability-labeling hook that
// runs on every finding emitted through EmitScanResult. Like the axis
// enricher it only runs when Finding.ToolCapabilityClass is empty, so
// surfaces that already classified the capability from a real tool
// name (e.g. proxy tool-call inspection via ClassifyToolName) win.
func SetCapabilityEnricher(f func(*Finding) string) { capabilityEnricher = f }

// ScanSummaryParams is the v7 scan_results row payload.
type ScanSummaryParams struct {
	ScanID            string
	Scanner           string
	Target            string
	Timestamp         time.Time
	DurationMs        int64
	FindingCount      int
	MaxSeverity       string
	RawJSON           string
	RunID             string
	Verdict           string
	ExitCode          int
	ScanError         string
	SchemaVersion     int
	ContentHash       string
	Generation        uint64
	BinaryVersion     string
	AgentID           string
	AgentName         string
	AgentInstanceID   string
	SidecarInstanceID string
	SessionID         string
	RequestID         string
	TraceID           string
	// EvaluationID joins this scan to the upstream runtime
	// evaluation (hook handler, /api/v1/inspect/*, proxy guardrail,
	// mid-stream, tool-call-inspect). Empty for classic scanner
	// invocations.
	EvaluationID string
}

// ScanFindingMeta stamps correlation + provenance on scan_findings rows.
type ScanFindingMeta struct {
	Timestamp         time.Time
	RunID             string
	RequestID         string
	SessionID         string
	TraceID           string
	AgentID           string
	AgentName         string
	AgentInstanceID   string
	SidecarInstanceID string
	SchemaVersion     int
	ContentHash       string
	Generation        uint64
	BinaryVersion     string
	// EvaluationID matches ScanSummaryParams.EvaluationID; copied
	// onto every scan_findings row so SIEM queries can pivot on it
	// without joining to scan_results.
	EvaluationID string
}

// EmitScanResult owns only scan identity, enrichment, forensic persistence,
// and correlator invocation. Canonical logs and metrics are emitted by the
// audit logger after this call, so this package never receives a gateway JSONL
// writer or telemetry provider and cannot create a duplicate signal path.
func EmitScanResult(
	ctx context.Context,
	pers ScanPersistence,
	result *ScanResult,
	agent AgentIdentity,
) (scanID string, err error) {
	if result == nil {
		return "", fmt.Errorf("scanner: EmitScanResult: nil result")
	}
	scanID = strings.TrimSpace(result.ScanID)
	if scanID == "" {
		scanID = uuid.New().String()
	} else if _, parseErr := uuid.Parse(scanID); parseErr != nil {
		return "", fmt.Errorf("scanner: EmitScanResult: invalid scan ID")
	}
	// Publish the effective identifier on the in-memory result as well as every
	// persisted/emitted projection. Canonical callers need the exact allocated
	// join key after this single allocation boundary.
	result.ScanID = scanID

	for i := range result.Findings {
		result.Findings[i].FindingOccurrenceID = uuid.NewString()
		result.Findings[i].RuleID = EnsureRuleID(&result.Findings[i], result.Scanner)
		// Auto-populate DataAxis labels when the finding creator left
		// them blank. The enricher (installed by the guardrail wiring
		// layer at boot) maps the finding's RuleID, Tags, and Category
		// to one or more of the three lethal-trifecta axes. Keeping
		// this at the emission boundary avoids touching every regex
		// rule site; the enricher is a one-import hook.
		if len(result.Findings[i].DataAxis) == 0 && findingEnricher != nil {
			if axes := findingEnricher(&result.Findings[i]); len(axes) > 0 {
				result.Findings[i].DataAxis = axes
			}
		}
		// Auto-populate ToolCapabilityClass the same way: derive it
		// from the rule_id for content-matched findings that didn't
		// already get a class from a real tool name upstream. Without
		// this the DESTRUCTIVE-FLOW correlator pattern (which keys on
		// exec_shell) can never fire on regex/plugin detections.
		if result.Findings[i].ToolCapabilityClass == "" && capabilityEnricher != nil {
			if cap := capabilityEnricher(&result.Findings[i]); cap != "" {
				result.Findings[i].ToolCapabilityClass = cap
			}
		}
	}

	verdict := VerdictForResult(result)

	prov := version.Current()
	meta := ScanFindingMeta{
		Timestamp:         result.Timestamp,
		RunID:             agent.RunID,
		RequestID:         agent.RequestID,
		SessionID:         agent.SessionID,
		TraceID:           agent.TraceID,
		AgentID:           agent.AgentID,
		AgentName:         agent.AgentName,
		AgentInstanceID:   agent.AgentInstanceID,
		SidecarInstanceID: agent.SidecarInstanceID,
		SchemaVersion:     prov.SchemaVersion,
		ContentHash:       prov.ContentHash,
		Generation:        prov.Generation,
		BinaryVersion:     prov.BinaryVersion,
		EvaluationID:      agent.EvaluationID,
	}

	if pers != nil {
		raw, jerr := scanResultJSON(result)
		if jerr != nil {
			raw = []byte(`{}`)
		}
		sum := ScanSummaryParams{
			ScanID:            scanID,
			Scanner:           result.Scanner,
			Target:            result.Target,
			Timestamp:         result.Timestamp,
			DurationMs:        result.Duration.Milliseconds(),
			FindingCount:      len(result.Findings),
			MaxSeverity:       string(result.MaxSeverity()),
			RawJSON:           string(raw),
			RunID:             agent.RunID,
			RequestID:         agent.RequestID,
			SessionID:         agent.SessionID,
			TraceID:           agent.TraceID,
			Verdict:           verdict,
			ExitCode:          result.ExitCode,
			ScanError:         result.ScanError,
			SchemaVersion:     prov.SchemaVersion,
			ContentHash:       prov.ContentHash,
			Generation:        prov.Generation,
			BinaryVersion:     prov.BinaryVersion,
			AgentID:           agent.AgentID,
			AgentName:         agent.AgentName,
			AgentInstanceID:   agent.AgentInstanceID,
			SidecarInstanceID: agent.SidecarInstanceID,
			EvaluationID:      agent.EvaluationID,
		}
		if err := pers.InsertScanSummary(sum); err != nil {
			return scanID, err
		}
		if err := pers.InsertScanFindings(scanID, result.Target, result.Findings, meta); err != nil {
			return scanID, err
		}

		// Correlator runs once per scan, after findings are persisted.
		// Match failures are non-fatal — a correlator hiccup shouldn't
		// drop the scan itself. Only runs when session correlation
		// IDs are present; out-of-session scans (CLI audits, batch
		// jobs) skip correlation entirely.
		if c := defaultCorrelator; c != nil && meta.SessionID != "" && meta.AgentInstanceID != "" {
			_ = c.RunForSession(ctx, meta.SessionID, meta.AgentInstanceID, pers, result.Target, meta)
		}
	}

	return scanID, nil
}
