// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// ScanPersistence persists scan summary + per-finding rows. Implemented by
// *audit.Store (see audit/scan_persist.go).
type ScanPersistence interface {
	InsertScanSummary(ScanSummaryParams) error
	InsertScanFindings(scanID, target string, findings []Finding, meta ScanFindingMeta) error
}

// ScanTelemetry records per-finding metrics. Implemented by *telemetry.Provider.
type ScanTelemetry interface {
	RecordScanFindingByRule(ctx context.Context, scannerName, ruleID, severity, connector string)
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

// EmitScanResult fans out one EventScan + N EventScanFinding events (when w
// is non-nil), persists scan_results + scan_findings (when pers is non-nil),
// and records per-finding metrics (when tel is non-nil). Returns the
// correlation scan_id (UUID v4).
func EmitScanResult(
	ctx context.Context,
	w *gatewaylog.Writer,
	pers ScanPersistence,
	tel ScanTelemetry,
	result *ScanResult,
	agent AgentIdentity,
) (scanID string, err error) {
	if result == nil {
		return "", fmt.Errorf("scanner: EmitScanResult: nil result")
	}
	scanID = uuid.New().String()

	for i := range result.Findings {
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
	}

	targetType := result.EffectiveTargetType()
	verdict := VerdictForResult(result)
	counts := severityCounts(result)
	maxSev := toGatewaySeverity(result.MaxSeverity())

	// Normalize to v7 gateway-event schema enums. The raw Scanner /
	// TargetType / Verdict values can be full scanner names ("skill-scanner"),
	// classification bucket names ("code", "inventory"), or upper-case
	// verdicts from external scanners. Writing the raw values tripped
	// SCHEMA_VIOLATION drops on gateway.jsonl; persistence + telemetry
	// keep the original values for backwards compatibility.
	scannerEnum := NormalizeScannerEnum(result.Scanner)
	targetTypeEnum := NormalizeTargetTypeEnum(targetType)
	verdictEnum := NormalizeVerdictEnum(verdict)

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
		raw, jerr := result.JSON()
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

	if w != nil {
		w.Emit(gatewaylog.Event{
			Timestamp:         time.Now().UTC(),
			EventType:         gatewaylog.EventScan,
			Severity:          maxSev,
			RunID:             meta.RunID,
			RequestID:         meta.RequestID,
			SessionID:         meta.SessionID,
			TraceID:           meta.TraceID,
			AgentID:           agent.AgentID,
			AgentName:         agent.AgentName,
			AgentInstanceID:   agent.AgentInstanceID,
			SidecarInstanceID: agent.SidecarInstanceID,
			Scan: &gatewaylog.ScanPayload{
				ScanID:       scanID,
				Scanner:      scannerEnum,
				Target:       result.Target,
				TargetType:   targetTypeEnum,
				Verdict:      verdictEnum,
				DurationMs:   result.Duration.Milliseconds(),
				SeverityMax:  maxSev,
				Counts:       counts,
				TotalCount:   len(result.Findings),
				ExitCode:     result.ExitCode,
				Error:        result.ScanError,
				EvaluationID: agent.EvaluationID,
			},
		})
		for i := range result.Findings {
			f := &result.Findings[i]
			ln := 0
			if f.LineNumber != nil {
				ln = *f.LineNumber
			}
			w.Emit(gatewaylog.Event{
				Timestamp:         time.Now().UTC(),
				EventType:         gatewaylog.EventScanFinding,
				Severity:          toGatewaySeverity(f.Severity),
				RunID:             meta.RunID,
				RequestID:         meta.RequestID,
				SessionID:         meta.SessionID,
				TraceID:           meta.TraceID,
				AgentID:           agent.AgentID,
				AgentName:         agent.AgentName,
				AgentInstanceID:   agent.AgentInstanceID,
				SidecarInstanceID: agent.SidecarInstanceID,
				ScanFinding: &gatewaylog.ScanFindingPayload{
					ScanID:       scanID,
					Scanner:      scannerEnum,
					Target:       result.Target,
					FindingID:    f.ID,
					RuleID:       f.RuleID,
					Category:     f.Category,
					Title:        f.Title,
					Description:  f.Description,
					Severity:     toGatewaySeverity(f.Severity),
					Location:     f.Location,
					LineNumber:   ln,
					Remediation:  f.Remediation,
					Tags:         f.Tags,
					Confidence:   f.Confidence,
					EvaluationID: agent.EvaluationID,
				},
			})
		}
	}

	if tel != nil {
		for i := range result.Findings {
			f := &result.Findings[i]
			tel.RecordScanFindingByRule(ctx, result.Scanner, f.RuleID, string(f.Severity), agent.Connector)
		}
	}

	return scanID, nil
}

func severityCounts(r *ScanResult) map[string]int {
	out := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}
	for i := range r.Findings {
		out[string(r.Findings[i].Severity)]++
	}
	return out
}

func toGatewaySeverity(s Severity) gatewaylog.Severity {
	switch s {
	case SeverityCritical:
		return gatewaylog.SeverityCritical
	case SeverityHigh:
		return gatewaylog.SeverityHigh
	case SeverityMedium:
		return gatewaylog.SeverityMedium
	case SeverityLow:
		return gatewaylog.SeverityLow
	default:
		return gatewaylog.SeverityInfo
	}
}
