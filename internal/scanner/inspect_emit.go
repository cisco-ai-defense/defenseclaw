// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// InspectFinding is the scanner-package-neutral input shape that
// EmitInspectFindings adapts into a scanner.Finding for fan-out
// through the existing EmitScanResult pipeline (scan_results +
// scan_findings + EventScan + EventScanFinding +
// defenseclaw_scan_findings_by_rule_total + correlator).
//
// Callers in the gateway package (hook handlers, /api/v1/inspect/*,
// proxy guardrail, mid-stream, tool-call-inspect, watcher rescan,
// AID lane, asset policy) populate it from their own
// detector-specific structures (gateway.RuleFinding, AID
// classifications, config.AssetPolicyDecision, etc.) and pass
// already-redacted strings — EmitInspectFindings does not redact.
type InspectFinding struct {
	// RuleID is the stable detection rule identifier. Empty means
	// "let EnsureRuleID synthesize from scanner+category+title".
	RuleID string
	// Title is a short human-readable label. May be displayed
	// in TUI / dashboards.
	Title string
	// Description is the long form. Caller must redact before
	// passing in; EmitInspectFindings will not redact again.
	Description string
	// Severity is the canonical CRITICAL|HIGH|MEDIUM|LOW|INFO.
	Severity Severity
	// Category groups findings when RuleID is absent.
	Category string
	// Tags are free-form labels picked up by the correlator's
	// data-axis enricher (e.g. ["secret", "ingress_untrusted"]).
	Tags []string
	// Confidence is the detector's self-reported certainty in
	// [0,1]. Zero means "not computed" and is omitted on the wire.
	Confidence float64
	// Evidence is the matched literal (already redacted by the
	// caller via redaction.ForSinkEvidence). EmitInspectFindings
	// turns it into ContentFingerprint = sha256(evidence)[:8] so
	// correlator can match the same value across turns without
	// persisting the cleartext.
	Evidence string
	// Location is the file/tool/source location. Caller must
	// redact path/line if applicable.
	Location string
	// LineNumber is the 1-based source line; nil when not
	// meaningful.
	LineNumber *int
	// Remediation is human-readable fix guidance. Caller must
	// redact.
	Remediation string
	// ToolCapabilityClass labels what kind of tool this finding
	// attached to (read_fs / write_fs / exec_shell / network_fetch
	// / send_message). Optional.
	ToolCapabilityClass string
	// ExternalEndpoint is the host/URL for any network-touching
	// finding. Optional.
	ExternalEndpoint string
}

// InspectFindingSource describes a single runtime evaluation that
// produced N>=0 findings. Callers fill this in once per evaluation
// (one hook turn, one /api/v1/inspect/* call, one proxy guardrail
// invocation, one mid-stream check, one tool-call-inspect, one
// watcher rescan) and hand it to EmitInspectFindings.
type InspectFindingSource struct {
	// Scanner is one of the runtime-finding enum values defined
	// in NormalizeScannerEnum: hook-rules | inline-codeguard |
	// ai-defense | asset-policy | tool-call-inspect | inspect-http
	// | guardrail-llm | mid-stream | rescan. Classic file scans
	// should keep using EmitScanResult directly with skill / mcp /
	// plugin / aibom / codeguard.
	Scanner string
	// Target is the surface the evaluation ran against. For hooks
	// it's connector:hookEvent (e.g. "claudecode:PreToolUse"); for
	// inspect-http it's the endpoint name; for proxy guardrail
	// it's the model + direction; for tool-call-inspect it's the
	// tool name.
	Target string
	// TargetType is one of the enum values defined in
	// NormalizeTargetTypeEnum (file / skill / mcp / plugin /
	// aibom / tool_call / prompt / completion / tool_response /
	// inspect). Empty falls back to "inspect".
	TargetType string
	// Verdict is the evaluation's final action (clean / warn /
	// block / alert / allow / confirm). Normalized through
	// NormalizeVerdictEnum.
	Verdict string
	// DurationMs is the evaluation latency. Optional.
	DurationMs int64
	// EvaluationID is the join key linking this evaluation to
	// the audit row that triggered it. Empty causes
	// EmitInspectFindings to generate a fresh UUID.
	EvaluationID string
	// Timestamp is the evaluation time. Zero defaults to now.
	Timestamp time.Time
	// Findings is the list of per-rule findings produced. May be
	// empty — empty-finding evaluations still emit the
	// EventScan summary so SIEM sees the evaluation happened.
	Findings []InspectFinding
	// ScanError is populated when the evaluation itself failed
	// (timeout, panic, AID HTTP error). Surfaced on the EventScan
	// payload so dashboards can alert on detector-side outages.
	ScanError string
}

// EmitInspectFindings fans the source into the existing scanner
// emission pipeline: EmitScanResult writes scan_results +
// scan_findings, emits EventScan + N×EventScanFinding, records
// defenseclaw_scan_findings_by_rule_total, and (when session +
// agent_instance_id are populated) runs the lethal-trifecta
// correlator. Returns the evaluation_id (newly generated when the
// caller passed empty) and the underlying scan_id for the caller
// to stamp on its audit row.
//
// The function is intentionally tolerant: a nil writer / nil
// persistence / nil telemetry each disable that surface. The only
// hard requirement is a non-empty Scanner value (so the writer's
// schema gate doesn't drop the event).
func EmitInspectFindings(
	ctx context.Context,
	w *gatewaylog.Writer,
	pers ScanPersistence,
	tel ScanTelemetry,
	src InspectFindingSource,
	agent AgentIdentity,
) (evaluationID, scanID string, err error) {
	evaluationID = strings.TrimSpace(src.EvaluationID)
	if evaluationID == "" {
		evaluationID = uuid.New().String()
	}
	// Propagate evaluation_id onto the AgentIdentity so
	// EmitScanResult stamps it on every emitted payload + DB row
	// without each caller having to set it themselves.
	agent.EvaluationID = evaluationID

	if strings.TrimSpace(src.Scanner) == "" {
		// Defensive — keep the writer's schema gate happy; the
		// runtime-finding emitters should always set this.
		src.Scanner = "guardrail-llm"
	}
	targetType := strings.TrimSpace(src.TargetType)
	if targetType == "" {
		targetType = "inspect"
	}
	ts := src.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	result := &ScanResult{
		Scanner:    src.Scanner,
		Target:     src.Target,
		Timestamp:  ts,
		Duration:   time.Duration(src.DurationMs) * time.Millisecond,
		TargetType: targetType,
		Verdict:    src.Verdict,
		ScanError:  src.ScanError,
	}
	if len(src.Findings) > 0 {
		result.Findings = make([]Finding, 0, len(src.Findings))
		for _, in := range src.Findings {
			result.Findings = append(result.Findings, adaptInspectFinding(in, src.Scanner))
		}
	}

	scanID, err = EmitScanResult(ctx, w, pers, tel, result, agent)
	return evaluationID, scanID, err
}

// adaptInspectFinding maps the gateway-package-neutral
// InspectFinding into the existing scanner.Finding shape that
// EmitScanResult understands. Caller is responsible for redaction.
func adaptInspectFinding(in InspectFinding, scannerName string) Finding {
	severity := in.Severity
	if severity == "" {
		severity = SeverityInfo
	}

	// Synthesize a stable per-finding ID from rule_id + a fresh
	// uuid so multiple matches of the same rule in the same
	// evaluation each get distinct DB rows.
	id := strings.TrimSpace(in.RuleID)
	if id == "" {
		id = "finding"
	}
	id = id + ":" + uuid.New().String()

	f := Finding{
		ID:                  id,
		Severity:            severity,
		Title:               in.Title,
		Description:         in.Description,
		Location:            in.Location,
		Remediation:         in.Remediation,
		Scanner:             scannerName,
		Tags:                in.Tags,
		RuleID:              in.RuleID,
		Category:            in.Category,
		LineNumber:          in.LineNumber,
		Confidence:          clampConfidence(in.Confidence),
		ToolCapabilityClass: in.ToolCapabilityClass,
		ExternalEndpoint:    in.ExternalEndpoint,
	}
	if strings.TrimSpace(in.Evidence) != "" {
		f.ContentFingerprint = evidenceFingerprint(in.Evidence)
	}
	return f
}

// clampConfidence pins the detector's reported score into the
// JSON-Schema-declared [0,1] range. Values outside the range are
// silently corrected rather than dropped so a buggy detector
// can't cause schema-gate event loss.
func clampConfidence(c float64) float64 {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	default:
		return c
	}
}

// evidenceFingerprint returns the first 8 hex chars of
// sha256(evidence) — the same fingerprint shape the correlator
// already reads via ScanFinding.ContentFingerprint. Caller must
// redact the evidence string before passing it in; we hash
// whatever they hand us.
func evidenceFingerprint(evidence string) string {
	sum := sha256.Sum256([]byte(evidence))
	return hex.EncodeToString(sum[:])[:8]
}

// TopRuleIDs returns up to n distinct rule_ids from the source
// findings, preserving order. Callers use this to populate
// VerdictPayload.RuleIDs and to append ` rule_ids=` to audit
// detail strings without redacting each call site.
func TopRuleIDs(findings []InspectFinding, n int) []string {
	if n <= 0 {
		return nil
	}
	seen := make(map[string]struct{}, n)
	out := make([]string, 0, n)
	for i := range findings {
		id := strings.TrimSpace(findings[i].RuleID)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= n {
			break
		}
	}
	return out
}
