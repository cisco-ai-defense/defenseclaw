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

package policy

// AdmissionInput is the structured input passed to the OPA admission policy.
type AdmissionInput struct {
	TargetType string           `json:"target_type"`
	TargetName string           `json:"target_name"`
	Path       string           `json:"path"`
	BlockList  []ListEntry      `json:"block_list"`
	AllowList  []ListEntry      `json:"allow_list"`
	ScanResult *ScanResultInput `json:"scan_result,omitempty"`
}

// ListEntry represents one entry in the block or allow list.
type ListEntry struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
}

// ScanResultInput is the scan result subset needed by OPA.
type ScanResultInput struct {
	MaxSeverity   string         `json:"max_severity"`
	TotalFindings int            `json:"total_findings"`
	ScannerName   string         `json:"scanner_name,omitempty"`
	Findings      []FindingInput `json:"findings,omitempty"`
}

// FindingInput is a single finding passed to OPA for fine-grained policy decisions.
type FindingInput struct {
	Severity string `json:"severity"`
	Scanner  string `json:"scanner"`
	Title    string `json:"title"`
}

// AdmissionOutput is the structured output from the OPA admission policy.
type AdmissionOutput struct {
	Verdict       string `json:"verdict"`
	Reason        string `json:"reason"`
	FileAction    string `json:"file_action"`
	InstallAction string `json:"install_action"`
	RuntimeAction string `json:"runtime_action"`
}

// GuardrailScanResult is a scanner's verdict passed into the guardrail policy.
type GuardrailScanResult struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Findings []string `json:"findings"`
	Reason   string   `json:"reason"`
	IsSafe   *bool    `json:"is_safe,omitempty"`
}

// GuardrailInput is sent by the Python guardrail to evaluate via OPA.
type GuardrailInput struct {
	Direction     string               `json:"direction"`
	Model         string               `json:"model"`
	Mode          string               `json:"mode"`
	ScannerMode   string               `json:"scanner_mode"`
	LocalResult   *GuardrailScanResult `json:"local_result"`
	CiscoResult   *GuardrailScanResult `json:"cisco_result"`
	ContentLength int                  `json:"content_length"`

	// PolicyTier is the operator-selected guardrail mode handle
	// ("default" | "strict" | "permissive"). Rego resolves
	// data.guardrail.taint.<tier> from this value to pick
	// escalation knobs without round-tripping through config files.
	// Optional — empty falls back to "default" inside Rego.
	PolicyTier string `json:"policy_tier,omitempty"`

	// TaintContext is the per-evaluation overlay built by the
	// session TaintTracker (Go) and consumed by the guardrail Rego
	// policy. Omitted when no tracker is wired (legacy / tests),
	// in which case Rego skips the taint escalation branches.
	TaintContext *GuardrailTaintContext `json:"taint_context,omitempty"`
}

// GuardrailTaintContext mirrors gateway.TaintContext on the policy
// boundary. Kept as a structurally identical, package-local type to
// avoid an import cycle (internal/gateway already imports
// internal/policy via policy.Engine.EvaluateGuardrail). The gateway
// builds a TaintContext via TaintTracker.BuildTaintContext and
// converts to this view immediately before the OPA call.
type GuardrailTaintContext struct {
	HasStrongConsumer       bool     `json:"has_strong_consumer"`
	HasWeakConsumer         bool     `json:"has_weak_consumer"`
	HasTaintSourceInSession bool     `json:"has_taint_source_in_session"`
	TaintedFilesReferenced  []string `json:"tainted_files_referenced"`
	SourceFindings          []string `json:"source_findings"`
	MaxConsumerConfidence   float64  `json:"max_consumer_confidence"`
	NetworkDestExcluded     bool     `json:"network_dest_excluded"`
	EventsSinceSource       int      `json:"events_since_source"`
}

// GuardrailOutput is the OPA-determined verdict returned to the Python guardrail.
type GuardrailOutput struct {
	Action           string                    `json:"action"`
	Severity         string                    `json:"severity"`
	Reason           string                    `json:"reason"`
	ScannerSources   []string                  `json:"scanner_sources"`
	TaintEscalation  *GuardrailTaintEscalation `json:"taint_escalation,omitempty"`
}

// GuardrailTaintEscalation is the structured telemetry block emitted
// by guardrail.rego when taint context bumped severity. Nil when no
// escalation occurred, so callers can treat presence as "this verdict
// was influenced by session taint".
type GuardrailTaintEscalation struct {
	Path                  string   `json:"path"`
	Tier                  string   `json:"tier"`
	Steps                 int      `json:"steps"`
	BaseSeverityRank      int      `json:"base_severity_rank"`
	EffectiveSeverityRank int      `json:"effective_severity_rank"`
	TaintedFiles          []string `json:"tainted_files,omitempty"`
	Sources               []string `json:"sources,omitempty"`
	EventsSinceSource     int      `json:"events_since_source"`
	NetworkDestExcluded   bool     `json:"network_dest_excluded"`
}

// FirewallInput is the structured input passed to the OPA firewall policy.
type FirewallInput struct {
	TargetType  string `json:"target_type"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
}

// FirewallOutput is the structured output from the OPA firewall policy.
type FirewallOutput struct {
	Action   string `json:"action"`
	RuleName string `json:"rule_name"`
}

// SandboxInput is the structured input passed to the OPA sandbox policy.
type SandboxInput struct {
	SkillName            string   `json:"skill_name"`
	RequestedEndpoints   []string `json:"requested_endpoints"`
	RequestedPermissions []string `json:"requested_permissions"`
}

// SandboxOutput is the structured output from the OPA sandbox policy.
type SandboxOutput struct {
	AllowedEndpoints  []string `json:"allowed_endpoints"`
	DeniedEndpoints   []string `json:"denied_endpoints"`
	DeniedFromRequest []string `json:"denied_from_request"`
	Permissions       []string `json:"permissions"`
	AllowedSkills     []string `json:"allowed_skills"`
}

// AuditInput is the structured input passed to the OPA audit policy.
type AuditInput struct {
	EventType     string   `json:"event_type"`
	Severity      string   `json:"severity"`
	AgeDays       int      `json:"age_days"`
	ExportTargets []string `json:"export_targets"`
}

// AuditOutput is the structured output from the OPA audit policy.
type AuditOutput struct {
	Retain       bool     `json:"retain"`
	RetainReason string   `json:"retain_reason"`
	ExportTo     []string `json:"export_to"`
}

// SkillActionsInput is the structured input passed to the OPA skill_actions policy.
type SkillActionsInput struct {
	Severity   string `json:"severity"`
	TargetType string `json:"target_type,omitempty"`
}

// SkillActionsOutput is the structured output from the OPA skill_actions policy.
type SkillActionsOutput struct {
	RuntimeAction string `json:"runtime_action"`
	FileAction    string `json:"file_action"`
	InstallAction string `json:"install_action"`
	ShouldBlock   bool   `json:"should_block"`
}
