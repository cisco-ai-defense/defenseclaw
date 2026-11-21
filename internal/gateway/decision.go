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
	"context"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
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
	return guardrailActionForProfileUnknown(findings, cfg != nil && cfg.SecureClientIntegration(),
		func() bool { return cfg.HookPolicyTierForConnector(connector) == config.HookPolicyTierStrict },
		func() string { return cascadeUnknownForConfig(cfg, connector) },
		func(severity string) string {
			return guardrailActionForConnector(cfg, connector, severity, confirmable)
		})
}

// profileMeetActionForFindings evaluates each member's own findings under its
// own thresholds, HILT and mode on this request path. Untagged findings come
// from shared scanners (such as CodeGuard) and apply to every member. The
// strictest resulting action is the meet's verdict; an observing member can
// contribute an alert but never a confirmation or block.
func profileMeetActionForFindings(
	ctx context.Context, cfg *config.Config, connector string, findings []RuleFinding,
	confirmable, content bool,
) string {
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil || resolved.set == nil {
		return singleProfileActionForFindings(cfg, connector, findings, confirmable, content)
	}
	meet := resolved.evaluationMeet()
	if meet == nil {
		return singleProfileActionForFindings(cfg, connector, findings, confirmable, content)
	}
	action := guardrailActionAllow
	for _, member := range meet.members {
		memberCfg := resolved.set.profileConfig(member)
		var own []RuleFinding
		for _, finding := range findings {
			if finding.profile == "" || finding.profile == member {
				own = append(own, finding)
			}
		}
		candidate := singleProfileActionForFindings(memberCfg, connector, own, confirmable, content)
		if !configBlocksOn(memberCfg, connector, requestProfilePath(ctx)) &&
			(candidate == guardrailActionBlock || candidate == guardrailActionConfirm) {
			candidate = guardrailActionAlert
		}
		action = strongerGuardrailAction(action, candidate)
	}
	return action
}

func singleProfileActionForFindings(cfg *config.Config, connector string, findings []RuleFinding, confirmable, content bool) string {
	action := legacySingleProfileActionForFindings(cfg, connector, findings, confirmable, content)
	decideDual("single", connector, action, func() decide.Input {
		return decideInputForConfig(cfg, connector, findings, confirmable, content, true)
	})
	return action
}

func legacySingleProfileActionForFindings(cfg *config.Config, connector string, findings []RuleFinding, confirmable, content bool) string {
	if managedClosesOnUnverifiedPath(cfg, findings) {
		return guardrailActionBlock
	}
	if content {
		return guardrailContentActionForFindings(cfg, connector, findings, confirmable)
	}
	return guardrailActionForConnectorFindings(cfg, connector, findings, confirmable)
}

// managedClosesOnUnverifiedPath reports a managed deployment (any enterprise
// profile with local rules) that holds an enforceable TOOL-PATH-UNVERIFIED
// finding: a check the file system would not answer fails closed there, as in
// the strict tier, whatever threshold its rule pack gives the finding. The
// OSS default and permissive tiers keep the finding as a visible alert.
func managedClosesOnUnverifiedPath(cfg *config.Config, findings []RuleFinding) bool {
	if cfg == nil || cfg.EnterpriseProfile() == "" {
		return false
	}
	for _, finding := range enforceableRuleFindings(findings) {
		if finding.RuleID == windowsPathUnverifiedRuleID {
			return true
		}
	}
	return false
}

func profileMeetActionForSeverity(ctx context.Context, cfg *config.Config, connector, severity string, confirmable, content bool) string {
	return profileMeetActionForFindings(ctx, cfg, connector, []RuleFinding{{Severity: severity}}, confirmable, content)
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
	action := guardrailActionForFindings(findings, func(severity string) string {
		return guardrailContentAction(cfg, connector, severity, confirmable)
	})
	decideDual("content", connector, action, func() decide.Input {
		return decideInputForConfig(cfg, connector, findings, confirmable, true, false)
	})
	return action
}

// guardrailContentActionForGuardrail is guardrailContentAction for a caller
// that holds only the guardrail block, with the connector's levels (spec
// 2.2); the Secure Client posture comes from the process-wide managed flag.
func guardrailContentActionForGuardrail(gc *config.GuardrailConfig, connector, severity string) string {
	if ManagedEnterpriseActive() {
		posture := "default"
		if gc != nil {
			ref := gc.EffectiveRulePackRef("")
			posture = guardrailPackPosture(gc, ref)
		}
		blockThreshold, alertThreshold := guardrailProfileThresholds(posture)
		return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold, false, 0)
	}
	return guardrailActionForGuardrailConnector(gc, connector, severity, false)
}

// guardrailContentActionForGeneration is guardrailContentActionForGuardrail
// with generation g's configuration and levels: a scan that pinned g decides
// with g, whatever was published or set meanwhile (GAP-0927, GAP-0928).
func guardrailContentActionForGeneration(g *Generation, connector, severity string) string {
	cfg := g.Config
	if ManagedEnterpriseActive() {
		ref := cfg.Guardrail.EffectiveRulePackRef("")
		blockThreshold, alertThreshold := guardrailProfileThresholds(packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)))
		return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold, false, 0)
	}
	blockThreshold, alertThreshold := guardrailThresholdRanks(ResolveThresholds(g, connector, ""))
	return guardrailActionForRank(guardrailSeverityRank(severity), blockThreshold, alertThreshold,
		false, hiltMinRank(&cfg.Guardrail, connector))
}

// guardrailActionForGuardrailFindings maps the guardrail proxy's findings
// for the request's connector.
func guardrailActionForGuardrailFindings(
	gc *config.GuardrailConfig,
	connector string,
	findings []RuleFinding,
	confirmable bool,
) string {
	// ManagedEnterpriseActive is the Secure Client posture: the sidecar sets
	// it from cfg.ManagedAIDOnly() (sidecar.go). A managed standalone install
	// leaves it false, so its proxy limit findings map by the pack like the
	// hook routes (TestBoundedProxyPathMapsByThePack).
	strict := func() bool {
		return gc != nil && guardrailPackPosture(gc, gc.EffectiveRulePackRef(connector)) == config.HookPolicyTierStrict
	}
	action := guardrailActionForProfileUnknown(findings, ManagedEnterpriseActive(), strict,
		func() string { return cascadeUnknownForGuardrail(gc, connector, strict) },
		func(severity string) string {
			return guardrailActionForGuardrailConnector(gc, connector, severity, confirmable)
		})
	decideDual("guardrail", connector, action, func() decide.Input {
		return decideInputForGuardrail(gc, connector, findings, confirmable)
	})
	return action
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
// manifest posture: its base name (strict, permissive), else default. Shipped
// packs carry manifests; this preserves the legacy directory fallback.
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

// strictPackPosture reports whether the rule pack of connector in cfg has the
// strict posture, read as the thresholds read it (packPostureFor).
func strictPackPosture(cfg *config.Config, connector string) bool {
	if cfg == nil {
		return false
	}
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	return packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)) == config.HookPolicyTierStrict
}

// The one decision function (DET111 D4, internal/guardrail/decide). The
// gateway resolves what the config says (levels, tier, deployment, the
// cascade unknown tier) and hands decide.Decide the findings with their
// proofs; the tier table of the pack says what each proof is worth.

// decideFinding is f as decide.Decide reads it. The severity is read as
// HighestSeverity reads it (exact labels), so a finding the levels never
// ranked stays unranked.
func decideFinding(f RuleFinding) decide.Finding {
	out := decide.Finding{RuleID: f.RuleID, Severity: decide.Severity(severityRank[f.Severity]), Proof: f.Proof}
	switch f.enforcement {
	case findingEnforcementDetectionOnly:
		out.Ceiling = decide.CeilingRecord
	case findingEnforcementAlertOnly:
		out.Ceiling = decide.CeilingAlert
	}
	if out.Proof.IsZero() {
		out.Proof = legacyFindingProof(f)
	}
	return out
}

func decideFindings(findings []RuleFinding) []decide.Finding {
	out := make([]decide.Finding, len(findings))
	for i, f := range findings {
		out[i] = decideFinding(f)
	}
	return out
}

// legacyFindingProof is the proof of a finding whose reader set none, from
// the private marks the 1.0.10 readers put on it: a call the evaluation
// failed on, the evaluation-limit finding the profile maps by tier, an
// opened path the file system would not answer for, a DefenseClaw state
// write, a shell command on a protected file. Any other finding maps by its
// severity alone.
func legacyFindingProof(f RuleFinding) decide.Proof {
	id := canonicalTrustedRuleID(f.RuleID)
	switch {
	case f.evaluationFault:
		return decide.Proof{Kind: decide.KindUnread, Certainty: decide.CertBound, Cap: "evaluation_fault", Source: "gateway:evaluation_fault"}
	case profileMappedLimitFinding(f):
		return decide.Proof{Kind: decide.KindTruncated, Certainty: decide.CertBound, Cap: "evaluation_limit", Source: "gateway:" + id}
	case f.RuleID == windowsPathUnverifiedRuleID:
		return decide.Proof{Kind: decide.KindRead, Target: decide.TargetOther, Certainty: decide.CertMaybe, Reach: decide.ReachFS, Source: "gateway:" + id}
	case selfProtectionRules[id]:
		return decide.Proof{Kind: decide.KindWrite, Target: decide.TargetState, Certainty: decide.CertKnown, Source: "gateway:" + id}
	case f.shellProtectedFile:
		return decide.Proof{Kind: decide.KindWrite, Target: shellProtectedFileTarget(id), Certainty: decide.CertKnown, Source: "gateway:" + id}
	}
	return decide.Proof{}
}

// shellProtectedFileTarget is the protected class of a shell protected-file
// rule (shellProtectedFileRules).
func shellProtectedFileTarget(canonicalID string) decide.TargetClass {
	switch canonicalID {
	case "PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND":
		return decide.TargetAuthorizedKeys
	case "PATH-SSH-DIR":
		return decide.TargetCredential
	default:
		return decide.TargetAutostart
	}
}

func decideSeverityOfRank(rank int) decide.Severity {
	return decide.Severity(min(max(rank, 0), 255))
}

// decideLevels are the levels guardrailActionForRank maps by.
func decideLevels(blockThreshold, alertThreshold int, confirm bool, hiltMin int) decide.Levels {
	return decide.Levels{
		Block: decideSeverityOfRank(blockThreshold), Alert: decideSeverityOfRank(alertThreshold),
		Confirm: confirm, ConfirmAt: decideSeverityOfRank(hiltMin),
	}
}

func connectorLevels(cfg *config.Config, connector string, confirmable bool) decide.Levels {
	blockThreshold, alertThreshold := guardrailThresholdRanks(resolveThresholds(cfg, connector))
	return decideLevels(blockThreshold, alertThreshold,
		confirmable && hiltEnabledForConfig(cfg, connector), hiltMinRankForConfig(cfg, connector))
}

func contentLevels(cfg *config.Config, connector string, confirmable bool) decide.Levels {
	if cfg != nil && cfg.SecureClientIntegration() {
		blockThreshold, alertThreshold := guardrailThresholdRanks(resolvePackThresholds(cfg, connector))
		return decideLevels(blockThreshold, alertThreshold,
			confirmable && hiltEnabledForConfig(cfg, connector), hiltMinRankForConfig(cfg, connector))
	}
	return connectorLevels(cfg, connector, confirmable)
}

func guardrailConnectorLevels(gc *config.GuardrailConfig, connector string, confirmable bool) decide.Levels {
	blockThreshold, alertThreshold := guardrailThresholdRanks(resolveGuardrailThresholds(gc, connector))
	return decideLevels(blockThreshold, alertThreshold, confirmable && hiltEnabled(gc, connector), hiltMinRank(gc, connector))
}

func decideTierOf(name string) decide.Tier {
	tier, _ := decide.ParseTier(name)
	return tier
}

func decideAction(a decide.Action) string {
	switch a {
	case decide.Block:
		return guardrailActionBlock
	case decide.Confirm:
		return guardrailActionConfirm
	case decide.Alert:
		return guardrailActionAlert
	default:
		return guardrailActionAllow
	}
}

// decideInputForConfig is the decide.Input of a hook or inspect call of
// connector under cfg. content selects the content surface (prompt,
// completion, tool response, message); managed is false for a content
// caller that never had the managed unverified-path close.
func decideInputForConfig(cfg *config.Config, connector string, findings []RuleFinding, confirmable, content, managed bool) decide.Input {
	secureClient := cfg != nil && cfg.SecureClientIntegration()
	in := decide.Input{
		Findings:     decideFindings(findings),
		SecureClient: secureClient,
		Tier:         func() decide.Tier { return decideTierOf(cfg.HookPolicyTierForConnector(connector)) },
		PackTier: func() decide.Tier {
			if cfg == nil {
				// No config: the limit finding maps by the levels.
				return decide.TierStrict
			}
			ref := cfg.EffectiveRulePackRefForConnector(connector)
			return decideTierOf(packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)))
		},
		Unknown: func() (decide.Action, bool) {
			if cfg == nil || secureClient {
				return decide.Allow, false
			}
			if u := cfg.ResolveCascade(connector).Unknown; u != "" && u != config.CascadeUnknownPack {
				return decide.ParseAction(u), true
			}
			return decide.Allow, false
		},
	}
	if managed && cfg != nil && cfg.EnterpriseProfile() != "" {
		in.Deployment = decide.Managed
	}
	if content {
		in.Surface = decide.SurfaceContent
		in.Levels = contentLevels(cfg, connector, confirmable)
	} else {
		in.Levels = connectorLevels(cfg, connector, confirmable)
	}
	return in
}

// decideInputForGuardrail is the decide.Input of a guardrail proxy call:
// the pack posture is both the tier and the pack tier, and the Secure
// Client posture is the process-wide managed flag (ManagedEnterpriseActive).
func decideInputForGuardrail(gc *config.GuardrailConfig, connector string, findings []RuleFinding, confirmable bool) decide.Input {
	tier := func() decide.Tier {
		if gc == nil {
			return decide.TierDefault
		}
		return decideTierOf(guardrailPackPosture(gc, gc.EffectiveRulePackRef(connector)))
	}
	return decide.Input{
		Findings:     decideFindings(findings),
		SecureClient: ManagedEnterpriseActive(),
		Levels:       guardrailConnectorLevels(gc, connector, confirmable),
		Tier:         tier,
		Unknown: func() (decide.Action, bool) {
			if u := gc.CascadeUnknown(connector); u != config.CascadeUnknownPack {
				return decide.ParseAction(u), true
			}
			return decide.Allow, false
		},
	}
}

// decideDualHook, set only by tests (DET111_S1_DUAL), sees every decision
// the legacy path made beside the decide.Decide answer for the same call.
var decideDualHook func(route, connector, legacy string, in decide.Input, got decide.Output)

func decideDual(route, connector, legacy string, input func() decide.Input) {
	if decideDualHook == nil {
		return
	}
	in := input()
	decideDualHook(route, connector, legacy, in, decide.Decide(in))
}
