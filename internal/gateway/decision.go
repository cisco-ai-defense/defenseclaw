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

// One threshold model (config.yaml guardrail.block_at / alert_at at the
// global, connector and profile scopes, else the selected rule pack's
// posture) decides every guardrail surface: hook prompts, completions, tool
// responses and messages, tool calls, the proxy and its OPA policy. The
// levels are resolved by resolveThresholds (thresholds.go).

// guardrailActionForConnector maps a severity to an action for the
// connector of cfg, which may be a profile-derived configuration. An empty
// connector resolves the global levels.
func guardrailActionForConnector(cfg *config.Config, connector, severity string, confirmable bool) string {
	blockThreshold, alertThreshold := guardrailThresholdRanks(resolveThresholds(cfg, connector))
	return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold,
		confirmable && hiltEnabledForConfig(cfg, connector), hiltMinRankForConfig(cfg, connector))
}

// guardrailActionForGuardrailConnector is guardrailActionForConnector for a
// caller that holds only the guardrail block (the proxy and the router).
func guardrailActionForGuardrailConnector(gc *config.GuardrailConfig, connector, severity string, confirmable bool) string {
	blockThreshold, alertThreshold := guardrailThresholdRanks(resolveGuardrailThresholds(gc, connector))
	return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold,
		confirmable && hiltEnabled(gc, connector), hiltMinRank(gc, connector))
}

func guardrailActionForConnectorFindings(
	cfg *config.Config,
	connector string,
	findings []RuleFinding,
	confirmable bool,
) string {
	return guardrailActionForFindings(findings, func(severity string) string {
		return guardrailActionForConnector(cfg, connector, severity, confirmable)
	})
}

// guardrailContentAction is guardrailActionForConnector for a content
// surface (prompt, completion, tool response, message). Under the Secure
// Client integration content keeps the rule pack's posture levels, as it
// did before the one threshold model, so that deployment's decisions and
// records do not change.
func guardrailContentAction(cfg *config.Config, connector, severity string, confirmable bool) string {
	if cfg != nil && cfg.SecureClientIntegration() {
		blockThreshold, alertThreshold := guardrailThresholdRanks(resolvePackThresholds(cfg, connector))
		return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold,
			confirmable && hiltEnabledForConfig(cfg, connector), hiltMinRankForConfig(cfg, connector))
	}
	return guardrailActionForConnector(cfg, connector, severity, confirmable)
}

func guardrailContentActionForFindings(cfg *config.Config, connector string, findings []RuleFinding, confirmable bool) string {
	return guardrailActionForFindings(findings, func(severity string) string {
		return guardrailContentAction(cfg, connector, severity, confirmable)
	})
}

// guardrailContentActionForGuardrail is guardrailContentAction for a caller
// that holds only the guardrail block; the Secure Client posture comes from
// the process-wide managed flag.
func guardrailContentActionForGuardrail(gc *config.GuardrailConfig, severity string) string {
	if ManagedEnterpriseActive() {
		posture := "default"
		if gc != nil {
			ref := gc.EffectiveRulePackRef("")
			posture = packPosture(ref, ref.Dir)
		}
		blockThreshold, alertThreshold := guardrailProfileThresholds(posture)
		return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold, false, 0)
	}
	return guardrailActionForGuardrailConnector(gc, "", severity, false)
}

// guardrailActionForGuardrailFindings maps the guardrail proxy's findings
// for the request's connector.
func guardrailActionForGuardrailFindings(
	gc *config.GuardrailConfig,
	connector string,
	findings []RuleFinding,
	confirmable bool,
) string {
	return guardrailActionForFindings(findings, func(severity string) string {
		return guardrailActionForGuardrailConnector(gc, connector, severity, confirmable)
	})
}

// guardrailActionForFindings maps enforceable findings with actionFor and
// caps alert-only findings at an alert.
func guardrailActionForFindings(findings []RuleFinding, actionFor func(severity string) string) string {
	action := guardrailActionAllow
	if enforceable := enforceableRuleFindings(findings); len(enforceable) > 0 {
		action = actionFor(HighestSeverity(enforceable))
	}
	if alerts := alertOnlyRuleFindings(findings); len(alerts) > 0 {
		candidate := actionFor(HighestSeverity(alerts))
		if candidate == guardrailActionBlock || candidate == guardrailActionConfirm {
			candidate = guardrailActionAlert
		}
		action = strongerGuardrailAction(action, candidate)
	}
	return action
}

func strongerGuardrailAction(left, right string) string {
	rank := func(action string) int {
		switch action {
		case guardrailActionBlock:
			return 3
		case guardrailActionConfirm:
			return 2
		case guardrailActionAlert:
			return 1
		default:
			return 0
		}
	}
	if rank(right) > rank(left) {
		return right
	}
	return left
}

// guardrailActionForRank maps a severity rank to an action: block at or above
// the block threshold, then ask a human (when confirm is armed) at or above
// hiltMin, then alert at or above the alert threshold.
func guardrailActionForRank(rank, blockThreshold, alertThreshold int, confirm bool, hiltMin int) string {
	switch {
	case rank <= severityNone:
		return guardrailActionAllow
	case rank >= blockThreshold:
		return guardrailActionBlock
	case confirm && rank >= hiltMin:
		return guardrailActionConfirm
	case rank >= alertThreshold:
		return guardrailActionAlert
	default:
		return guardrailActionAllow
	}
}

// guardrailProfileThresholds maps a rule-pack posture to its block and alert
// severity ranks: strict blocks MEDIUM+ and alerts LOW+, permissive blocks
// CRITICAL and alerts HIGH+, default blocks CRITICAL and alerts MEDIUM+.
func guardrailProfileThresholds(profile string) (blockThreshold int, alertThreshold int) {
	switch profile {
	case "strict":
		return severityMedium, severityLow
	case "permissive":
		return severityCritical, severityHigh
	default:
		return severityCritical, severityMedium
	}
}

// guardrailProfileForDir is the posture of a rule-pack folder without a
// manifest posture: its base name (strict, permissive), else default. Only
// the three built-in packs rely on it.
func guardrailProfileForDir(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return "default"
	}
	base := strings.ToLower(filepath.Base(filepath.Clean(dir)))
	switch base {
	case "strict", "permissive":
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
