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

package scanner

import (
	"encoding/json"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingTagDetectionOnly is the persisted provenance marker for a finding
// that is useful as low-level detection telemetry but must not contribute to
// enforcement or multi-step correlation. Observe mode is intentionally
// independent: an enforcement-eligible finding observed without blocking does
// not carry this tag.
const FindingTagDetectionOnly = "detection-only"

var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

type Finding struct {
	ID string `json:"id"`
	// FindingOccurrenceID is minted at the emission boundary for one observed
	// occurrence. ID and RuleID retain their detector/rule compatibility
	// meanings; neither is reused as the canonical occurrence identity.
	FindingOccurrenceID string   `json:"finding_occurrence_id,omitempty"`
	Severity            Severity `json:"severity"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	// EvidenceSummary is a bounded, source-backed matched excerpt or
	// deterministic summary used by the canonical observability record. It is
	// intentionally excluded from the legacy scanner JSON shape: v8 route
	// projection, not a second scanner wire contract, owns its redaction.
	EvidenceSummary string   `json:"-"`
	Location        string   `json:"location"`
	Remediation     string   `json:"remediation"`
	Scanner         string   `json:"scanner"`
	Tags            []string `json:"tags"`
	// RuleID is the stable detection id (from upstream JSON or synthesized).
	RuleID string `json:"rule_id,omitempty"`
	// Category groups findings for synthesis when RuleID is absent.
	Category string `json:"category,omitempty"`
	// LineNumber is 1-based when applicable; nil means unknown / N/A.
	LineNumber *int `json:"line_number,omitempty"`
	// Confidence is the detector's self-reported certainty in [0,1].
	// Populated by regex/judge/AID detectors; 0 (omitted) for binary
	// match-or-miss scanners.
	Confidence float64 `json:"confidence,omitempty"`

	// --- Multi-step correlation fields (see internal/guardrail/correlator.go) ---

	// DataAxis labels the finding with one or more of the three lethal-
	// trifecta axes: ingress_untrusted, sensitive_access, egress_external.
	// The correlator intersects axes across a session's recent findings
	// to detect attack flows without hardcoding rule-id lists.
	DataAxis []string `json:"data_axis,omitempty"`

	// ToolCapabilityClass categorizes the tool call this finding attaches to
	// (read_fs, write_fs, exec_shell, network_fetch, send_message). Empty
	// for non-tool-call surfaces. Lets correlator patterns reason about
	// capability sequences across arbitrary MCP servers.
	ToolCapabilityClass string `json:"tool_capability_class,omitempty"`

	// ContentFingerprint is the first 8 lowercase hex characters of the
	// installation-keyed hash-v1 evidence HMAC. The audit Logger replaces any
	// producer value at its persistence boundary so the correlator can match the
	// same value across sensitive_access and egress_external findings without an
	// offline-enumerable cleartext hash.
	ContentFingerprint string `json:"content_fingerprint,omitempty"`

	// ExternalEndpoint is the host/URL for any network-touching finding.
	// Lets patterns distinguish an allowlisted API call from an
	// attacker-controlled webhook.
	ExternalEndpoint string `json:"external_endpoint,omitempty"`

	// TurnID is a monotonic counter within a session. Cleaner than
	// timestamps for sequence-based pattern matching (immune to clock
	// skew) and makes TUI session replays trivial.
	TurnID *int `json:"turn_id,omitempty"`

	// DecisionPath is a structured audit trail of why this finding
	// landed at its current severity — which regex matched, which
	// judge category fired, whether `sensitive_context` override ran,
	// whether rubric reconciliation adjusted the verdict. Freeform
	// JSON; the correlator and the TUI both read it for explanations.
	DecisionPath json.RawMessage `json:"decision_path,omitempty"`

	// codeGuardProvenance is minted only while the in-process CodeGuard
	// scanner evaluates a code-owned rule. It is deliberately private and is
	// therefore neither accepted from nor emitted to scanner JSON. Callers may
	// use CodeGuardBuiltinMatch to decide whether a finding carries that
	// provenance; a decoded or manually assembled Finding always fails closed.
	codeGuardProvenance codeGuardFindingProvenance
}

type codeGuardFindingProvenance struct {
	builtinRuleID string
}

// CodeGuardBuiltinMatch reports whether this finding was produced by an exact
// match of a code-owned builtin CodeGuard rule. Rule IDs and scanner names are
// public metadata and are intentionally insufficient on their own.
func (f Finding) CodeGuardBuiltinMatch(ruleID string) bool {
	builtinRuleID := f.codeGuardProvenance.builtinRuleID
	return builtinRuleID != "" &&
		ruleID == builtinRuleID &&
		f.ID == builtinRuleID &&
		f.RuleID == builtinRuleID &&
		f.Scanner == "codeguard"
}

type ScanResult struct {
	// ScanID is an optional caller-minted correlation key. It is never
	// serialized into scanner-owned raw evidence; EmitScanResult validates and
	// reuses it so an enclosing trace can carry the same ID before persistence.
	ScanID     string        `json:"-"`
	Scanner    string        `json:"scanner"`
	Target     string        `json:"target"`
	Timestamp  time.Time     `json:"timestamp"`
	Findings   []Finding     `json:"findings"`
	Duration   time.Duration `json:"duration"`
	TargetType string        `json:"target_type,omitempty"`
	Verdict    string        `json:"verdict,omitempty"`
	ExitCode   int           `json:"exit_code,omitempty"`
	ScanError  string        `json:"error,omitempty"`
}

// EffectiveTargetType returns TargetType when set, otherwise InferTargetType(Scanner).
func (r *ScanResult) EffectiveTargetType() string {
	if r == nil {
		return ""
	}
	if strings.TrimSpace(r.TargetType) != "" {
		return r.TargetType
	}
	return InferTargetType(r.Scanner)
}

func (r *ScanResult) HasSeverity(s Severity) bool {
	for i := range r.Findings {
		if r.Findings[i].Severity == s {
			return true
		}
	}
	return false
}

func (r *ScanResult) MaxSeverity() Severity {
	if len(r.Findings) == 0 {
		return SeverityInfo
	}
	max := r.Findings[0].Severity
	for i := 1; i < len(r.Findings); i++ {
		if severityRank[r.Findings[i].Severity] > severityRank[max] {
			max = r.Findings[i].Severity
		}
	}
	return max
}

func (r *ScanResult) CountBySeverity(s Severity) int {
	count := 0
	for i := range r.Findings {
		if r.Findings[i].Severity == s {
			count++
		}
	}
	return count
}

func (r *ScanResult) IsClean() bool {
	return len(r.Findings) == 0
}

func CompareSeverity(a, b Severity) int {
	return severityRank[a] - severityRank[b]
}

func (r *ScanResult) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
