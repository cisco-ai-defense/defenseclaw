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
	RecordScanFindingByRule(ctx context.Context, scannerName, ruleID, severity string)
}

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
		}
		if err := pers.InsertScanSummary(sum); err != nil {
			return scanID, err
		}
		if err := pers.InsertScanFindings(scanID, result.Target, result.Findings, meta); err != nil {
			return scanID, err
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
				ScanID:      scanID,
				Scanner:     scannerEnum,
				Target:      result.Target,
				TargetType:  targetTypeEnum,
				Verdict:     verdictEnum,
				DurationMs:  result.Duration.Milliseconds(),
				SeverityMax: maxSev,
				Counts:      counts,
				TotalCount:  len(result.Findings),
				ExitCode:    result.ExitCode,
				Error:       result.ScanError,
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
					ScanID:      scanID,
					Scanner:     scannerEnum,
					Target:      result.Target,
					FindingID:   f.ID,
					RuleID:      f.RuleID,
					Category:    f.Category,
					Title:       f.Title,
					Description: f.Description,
					Severity:    toGatewaySeverity(f.Severity),
					Location:    f.Location,
					LineNumber:  ln,
					Remediation: f.Remediation,
					Tags:        f.Tags,
				},
			})
		}
	}

	if tel != nil {
		for i := range result.Findings {
			f := &result.Findings[i]
			tel.RecordScanFindingByRule(ctx, result.Scanner, f.RuleID, string(f.Severity))
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
