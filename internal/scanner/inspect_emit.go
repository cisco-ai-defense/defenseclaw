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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
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
// source-backed strings. Redaction is deliberately deferred to the canonical
// v8 destination projection.
type InspectFinding struct {
	// RuleID is the stable detection rule identifier. Empty means
	// "let EnsureRuleID synthesize from scanner+category+title".
	RuleID string
	// Title is a short human-readable label. May be displayed
	// in TUI / dashboards.
	Title string
	// Description is the source-supplied long form. It remains unredacted until
	// the canonical v8 destination projection.
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
	// Evidence is a bounded matched excerpt, not the complete prompt, response,
	// tool payload, or file. EmitInspectFindings retains it as the canonical
	// evidence summary and also derives ContentFingerprint = sha256(evidence)[:8]
	// so the correlator can match the same value across turns.
	Evidence string
	// Location is the file/tool/source location. The v8 field classification
	// causes path redaction to be applied independently per destination.
	Location string
	// LineNumber is the 1-based source line; nil when not
	// meaningful.
	LineNumber *int
	// Remediation is source- or rule-catalog-supplied human-readable guidance.
	// The adapter never asks a model to invent it.
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
	// ScanID is an optional caller-minted UUID used when the enclosing trace
	// must carry the durable scan join before this function persists findings.
	// Empty preserves the normal EmitScanResult allocation behavior.
	ScanID string
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

// BuildInspectScanResult converts one runtime inspection into the canonical
// scanner result consumed by the v8 audit logger. Keeping this adaptation
// independent from delivery lets live gateway producers use one generated v8
// pipeline without reconstructing findings or losing caller-provided
// evaluation and scan identifiers.
func BuildInspectScanResult(src InspectFindingSource) (evaluationID string, result *ScanResult) {
	evaluationID = strings.TrimSpace(src.EvaluationID)
	if evaluationID == "" {
		evaluationID = uuid.New().String()
	}

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

	result = &ScanResult{
		ScanID:     src.ScanID,
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
	return evaluationID, result
}

// adaptInspectFinding maps the gateway-package-neutral InspectFinding into the
// existing scanner.Finding shape that EmitScanResult understands. It bounds
// source evidence but intentionally does not redact it; v8 routing owns that.
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
		f.EvidenceSummary = boundedInspectEvidenceSummary(in.Evidence)
		f.ContentFingerprint = evidenceFingerprint(in.Evidence)
	}
	return f
}

const maxInspectEvidenceSummaryBytes = 4096

func boundedInspectEvidenceSummary(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "\uFFFD"))
	if len(value) <= maxInspectEvidenceSummaryBytes {
		return value
	}
	cut := maxInspectEvidenceSummaryBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut]
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

// evidenceFingerprint returns the first 8 hex chars of sha256(evidence) — the
// same fingerprint shape the correlator already reads via
// ScanFinding.ContentFingerprint. It hashes the source excerpt before any
// destination projection so correlation remains stable across redaction
// profiles.
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
