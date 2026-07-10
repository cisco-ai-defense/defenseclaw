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

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	guardrailActionAllow   = "allow"
	guardrailActionAlert   = "alert"
	guardrailActionConfirm = "confirm"
	guardrailActionBlock   = "block"
)

const (
	severityNone = iota
	severityLow
	severityMedium
	severityHigh
	severityCritical
)

// SeverityCriteria is the single source of truth for what each severity
// level means across the runtime guardrails. Regex rules, LLM judges,
// the correlator, and human reviewers all reference this rubric so that
// "CRITICAL" means the same thing in every layer.
//
// The line between CRITICAL and HIGH is drawn at: CRITICAL requires the
// harm to be proven by the content alone (no plausible benign reading,
// no further attacker action needed). HIGH covers strong adversarial
// intent or sensitive data that still requires context/action to cause
// actual harm.
var SeverityCriteria = map[string]string{
	"CRITICAL": "Direct unambiguous harm provable from the content alone. " +
		"Examples: plaintext credentials, completed jailbreak output, " +
		"SSN/passport/password disclosed, reverse shell, destructive shell command.",
	"HIGH": "Clear adversarial intent OR high-impact sensitive data that still " +
		"requires context or a follow-up action to cause harm. " +
		"Examples: /etc/passwd request, phone number in completion, " +
		"multi-word injection phrase, SSH key path reference.",
	"MEDIUM": "Suspicious but ambiguous; benign readings are plausible. Alert, do not block. " +
		"Examples: single 9-digit number that may or may not be an SSN, " +
		"single-category injection signal without corroboration.",
	"LOW": "Weak indicator; content is commonly legitimate. " +
		"Examples: email in user prompt (self-disclosure), IP address mention.",
	"NONE": "No concern.",
}

// SeverityOrder is the canonical ordering of severity labels, from
// weakest to strongest. Consumers that need to iterate in rank order
// (e.g. when rendering the rubric in a judge prompt) should use this
// slice rather than hard-coding a literal.
var SeverityOrder = []string{"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// SignalStrengthToSeverity maps the structured-reasoning output used by
// the LLM judges (see Step 3 / llm_judge.go system prompts) to a
// severity label. The judges answer two booleans per finding:
//
//	unambiguous  — is the malicious intent obvious from the content alone?
//	high_impact  — would the worst-case outcome cause hard-to-reverse damage?
//
// The mapping is deterministic: any drift between a judge's claimed
// severity and the value returned here is a reconciliation error and
// should be logged on the finding's decision_path (see Step 5 schema).
//
//	unambiguous  high_impact  ->  severity
//	     T            T            CRITICAL   (strong_signal)
//	     T            F            HIGH       (signal)
//	     F            T            MEDIUM     (needs_review)
//	     F            F            LOW        (weak_signal)
func SignalStrengthToSeverity(unambiguous, highImpact bool) string {
	switch {
	case unambiguous && highImpact:
		return "CRITICAL"
	case unambiguous && !highImpact:
		return "HIGH"
	case !unambiguous && highImpact:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func guardrailRuntimeAction(cfg *config.Config, severity string, confirmable bool) string {
	if cfg == nil {
		return guardrailRuntimeActionForGuardrail(nil, severity, confirmable)
	}
	return guardrailRuntimeActionForGuardrail(&cfg.Guardrail, severity, confirmable)
}

func guardrailRuntimeActionForGuardrail(gc *config.GuardrailConfig, severity string, confirmable bool) string {
	return guardrailRuntimeActionForGuardrailConnector(gc, "", severity, confirmable)
}

// guardrailRuntimeActionForConnector mirrors guardrailRuntimeAction but
// resolves the block/alert threshold from the request connector's effective
// rule pack (guardrail.connectors[X].rule_pack_dir, falling back to the
// global pack). This gives each connector its own enforcement posture —
// strict on one agent, permissive on another — matching single-connector
// behavior where the pack IS the posture. An empty connector resolves to the
// global pack, so existing single-connector callers are unaffected.
func guardrailRuntimeActionForConnector(cfg *config.Config, connector, severity string, confirmable bool) string {
	if cfg == nil {
		return guardrailRuntimeActionForGuardrailConnector(nil, connector, severity, confirmable)
	}
	rank := guardrailSeverityRank(severity)
	if rank <= severityNone {
		return guardrailActionAllow
	}

	blockThreshold, alertThreshold := guardrailThresholdsForConfigConnector(cfg, connector)
	if rank >= blockThreshold {
		return guardrailActionBlock
	}
	if hiltEnabledForConfig(cfg, connector) && confirmable && rank >= hiltMinRankForConfig(cfg, connector) {
		return guardrailActionConfirm
	}
	if rank >= alertThreshold {
		return guardrailActionAlert
	}
	return guardrailActionAllow
}

func guardrailRuntimeActionForGuardrailConnector(gc *config.GuardrailConfig, connector, severity string, confirmable bool) string {
	rank := guardrailSeverityRank(severity)
	if rank <= severityNone {
		return guardrailActionAllow
	}

	blockThreshold, alertThreshold := guardrailThresholdsForConnector(gc, connector)
	if rank >= blockThreshold {
		return guardrailActionBlock
	}
	if hiltEnabled(gc, connector) && confirmable && rank >= hiltMinRank(gc, connector) {
		return guardrailActionConfirm
	}
	if rank >= alertThreshold {
		return guardrailActionAlert
	}
	return guardrailActionAllow
}

func guardrailThresholds(gc *config.GuardrailConfig) (blockThreshold int, alertThreshold int) {
	return guardrailThresholdsForConnector(gc, "")
}

func guardrailThresholdsForConnector(gc *config.GuardrailConfig, connector string) (blockThreshold int, alertThreshold int) {
	switch guardrailProfileForConnector(gc, connector) {
	case "strict":
		return severityMedium, severityLow
	case "permissive":
		return severityCritical, severityHigh
	default:
		return severityCritical, severityMedium
	}
}

func guardrailThresholdsForConfigConnector(cfg *config.Config, connector string) (blockThreshold int, alertThreshold int) {
	switch guardrailProfileForConfigConnector(cfg, connector) {
	case "strict":
		return severityMedium, severityLow
	case "permissive":
		return severityCritical, severityHigh
	default:
		return severityCritical, severityMedium
	}
}

func guardrailProfile(gc *config.GuardrailConfig) string {
	return guardrailProfileForConnector(gc, "")
}

// guardrailProfileForConnector resolves the posture profile from the
// connector's effective rule pack (per-connector override > global pack).
// connector="" yields the global pack, preserving single-connector behavior.
func guardrailProfileForConnector(gc *config.GuardrailConfig, connector string) string {
	if gc == nil {
		return "default"
	}
	dir := strings.ToLower(strings.TrimSpace(gc.EffectiveRulePackDir(connector)))
	return guardrailProfileForDir(dir)
}

func guardrailProfileForConfigConnector(cfg *config.Config, connector string) string {
	if cfg == nil {
		return "default"
	}
	dir := strings.ToLower(strings.TrimSpace(cfg.EffectiveRulePackDirForConnector(connector)))
	return guardrailProfileForDir(dir)
}

func guardrailProfileForDir(dir string) string {
	if dir == "" {
		return "default"
	}
	base := strings.ToLower(filepath.Base(filepath.Clean(dir)))
	switch base {
	case "strict", "permissive", "default", "balanced":
		if base == "balanced" {
			return "default"
		}
		return base
	default:
		return "default"
	}
}

// hiltEnabled reports whether human-in-the-loop confirmation is active for
// the request's connector. It resolves through EffectiveHILT so a
// per-connector override (guardrail.connectors[X].hilt) takes precedence over
// the global HILT block; an empty connector resolves to the global HILT, so
// single-connector callers are unaffected.
func hiltEnabled(gc *config.GuardrailConfig, connector string) bool {
	return gc != nil && gc.EffectiveHILT(connector).Enabled
}

func hiltEnabledForConfig(cfg *config.Config, connector string) bool {
	return cfg != nil && cfg.EffectiveHILTForConnector(connector).Enabled
}

// hiltMinRank returns the minimum severity rank that triggers a HILT confirm
// for the request's connector, resolved via EffectiveHILT (per-connector
// override → global). Defaults to HIGH when unset.
func hiltMinRank(gc *config.GuardrailConfig, connector string) int {
	if gc == nil {
		return severityHigh
	}
	rank := guardrailSeverityRank(gc.EffectiveHILT(connector).MinSeverity)
	if rank <= severityNone {
		return severityHigh
	}
	return rank
}

func hiltMinRankForConfig(cfg *config.Config, connector string) int {
	if cfg == nil {
		return severityHigh
	}
	rank := guardrailSeverityRank(cfg.EffectiveHILTForConnector(connector).MinSeverity)
	if rank <= severityNone {
		return severityHigh
	}
	return rank
}

func guardrailSeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return severityCritical
	case "HIGH":
		return severityHigh
	case "MEDIUM":
		return severityMedium
	case "LOW":
		return severityLow
	default:
		return severityNone
	}
}

func normalizedGuardrailAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny":
		return guardrailActionBlock
	case "confirm", "ask":
		return guardrailActionConfirm
	case "alert", "warn", "warning":
		return guardrailActionAlert
	default:
		return guardrailActionAllow
	}
}

// isPromptDirection reports whether the supplied direction string identifies
// the user → LLM prompt surface. Comparison is case-insensitive and ignores
// surrounding whitespace.
func isPromptDirection(direction string) bool {
	return strings.EqualFold(strings.TrimSpace(direction), "prompt")
}

// promptSurfaceClampReason is the canonical operator-facing explanation appended
// to a verdict's reason when the prompt-surface UX contract demotes a non-allow
// action to alert. Connector hooks today (Claude Code PreToolUse, OpenClaw
// before_tool_call) only expose a native modal at the tool-call surface, so
// blocking or asking for human approval on the raw user prompt has no usable UI
// — the runtime falls back to chat-message HITL that is impossible for users to
// answer correctly. The cleaner contract is: prompts are scanned and reported
// (audit/observability), and enforcement happens when the LLM actually attempts
// the dangerous action via a tool call.
const promptSurfaceClampReason = "demoted to alert (prompt surface has no modal; enforcement deferred to tool-call gate)"

// clampPromptDirectionAction enforces the prompt-surface UX contract on an
// action string: any block/confirm decision becomes alert, allow/alert are
// returned unchanged. The boolean reports whether a demotion occurred so the
// caller can append a reason or emit a "would-have-blocked" telemetry record.
//
// This helper accepts the raw action string (rather than mutating a verdict
// struct) so it composes cleanly with both ScanVerdict (proxy + inspector
// surfaces) and ToolInspectVerdict (inspect-hook surfaces) without tying the
// two type hierarchies together.
func clampPromptDirectionAction(direction, action string) (string, bool) {
	if !isPromptDirection(direction) {
		return action, false
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case guardrailActionBlock, guardrailActionConfirm:
		return guardrailActionAlert, true
	}
	return action, false
}
