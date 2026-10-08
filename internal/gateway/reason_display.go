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
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

const builtInMatchReasonPrefix = "matched: "

// trustedBuiltInMatchReason reports whether reason consists exclusively of
// exact rule ID/title pairs from the compiled-in catalog. The equality check
// is deliberately stricter than a character allow-list: scanner-provided
// titles can contain matched literals that merely look like harmless metadata.
func trustedBuiltInMatchReason(reason string) bool {
	body, ok := strings.CutPrefix(reason, builtInMatchReasonPrefix)
	if !ok || body == "" {
		return false
	}
	labels := splitMatchLabels(body)
	if len(labels) == 0 || len(labels) > 5 {
		return false
	}
	for _, label := range labels {
		if !trustedBuiltInFindingLabel(label) {
			return false
		}
	}
	return true
}

// matchLabelStart opens every "<rule-id>:<title>" label of a matched reason.
var matchLabelStart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:`)

// splitMatchLabels splits the body of a "matched: " reason into its labels.
// Labels are joined with ", ", and a rule title may hold ", " too ("P0 marker,
// off by default (high)"), so a piece that does not open with a rule ID and a
// colon continues the label before it. A title that happens to look like a
// label start splits early; its label then matches no known rule and the
// message keeps the bare rule ID.
func splitMatchLabels(body string) []string {
	var labels []string
	for _, piece := range strings.Split(body, ", ") {
		if n := len(labels); n > 0 && !matchLabelStart.MatchString(piece) {
			labels[n-1] += ", " + piece
			continue
		}
		labels = append(labels, piece)
	}
	return labels
}

func trustedBuiltInFindingLabel(label string) bool {
	for _, category := range defaultRuleCategories {
		for _, rule := range category.Rules {
			base := rule.ID + ":" + rule.Title
			if label == base || label == base+obfuscatedFindingLabelSuffix {
				return true
			}
		}
	}
	// A built-in CodeGuard rule on a file write (GAP-2029).
	for _, rule := range scanner.BuiltinRulesMeta() {
		if label == rule.ID+":"+strings.TrimSpace(rule.Title) {
			return true
		}
	}
	return false
}

// agentDisplayReason keeps exact, ship-authored catalog metadata readable on
// agent surfaces under the default compatibility policy while retaining the
// existing scrub for every free-form or scanner-authored reason. Explicit
// managed policies remain authoritative in both directions.
func agentDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy != redaction.SinkPolicyDefault {
		return redaction.ReasonForSink(reason, policy)
	}
	if trustedBuiltInMatchReason(reason) || trustedCodeGuardHookReason(reason) {
		return reason
	}
	return redaction.ReasonForAgent(reason)
}

// notificationDisplayReason applies the same narrow catalog carve-out to OS
// notifications only under the default compatibility policy. An explicit
// managed-enterprise redact directive remains authoritative. An LLM judge
// verdict (alone or after a rule match) is worded the way the agent reads it
// ("LLM judge: personal data or credentials"), not as raw judge labels with
// redaction tokens (GAP-1981).
func notificationDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy == redaction.SinkPolicyDefault && (trustedBuiltInMatchReason(reason) || trustedCodeGuardHookReason(reason)) {
		return reason
	}
	if policy == redaction.SinkPolicyDefault && !managedEnterpriseActive.Load() {
		if subject := agentAssetPolicySubject(reason); subject != "" {
			return subject
		}
		if subject := agentJudgeSubject(reason); subject != "" {
			return subject
		}
		if subject := agentRuleAndJudgeSubject(reason); subject != "" {
			return subject
		}
	}
	return redaction.ReasonForSink(reason, policy)
}

// defaultSinkDisplayReason applies the catalog carve-out to compatibility
// response bodies only when no managed override is active.
func defaultSinkDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy == redaction.SinkPolicyDefault && (trustedBuiltInMatchReason(reason) || trustedCodeGuardHookReason(reason)) {
		return reason
	}
	return redaction.ReasonForSink(reason, policy)
}

// standaloneEnterpriseActive records whether the running deployment is the
// standalone enterprise profile, where the organization's policy decides.
// Wired next to managedEnterpriseActive by NewSidecar and the config reload.
var standaloneEnterpriseActive atomic.Bool

func setStandaloneEnterpriseActive(v bool) { standaloneEnterpriseActive.Store(v) }

// agentRuleIDPattern is the shape of a rule ID an agent message may name.
var agentRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// agentBlockNoRetry ends every policy block the agent receives. An agent that
// got only the rule name sometimes rewrote the blocked command to get the
// same result; the sentence tells it the block is final.
const agentBlockNoRetry = "Do not retry it in another form."

// agentReviewAction is the action agentVerdictReason words for a
// confirmation the connector cannot ask for: the gateway answers it with an
// alert, so the call runs.
const agentReviewAction = "review"

// agentVerdictReason words a block or a confirmation of a local policy rule
// for the agent's user. The bare "matched: <rule-id>:<title>" reason, with a
// custom rule's title replaced by a "<redacted len=N sha=...>" token, read
// like a broken hook, and users (and the model) went looking in their own
// agent settings. The message says DefenseClaw made the decision under the
// organization's policy (standalone enterprise) or DefenseClaw policy
// (per-user), names the rules by ID (a compiled-in or rule-pack rule keeps
// its title), and a block tells the agent not to retry the action in another
// form. The audit record keeps the full source reason. A confirmation the
// connector cannot ask for (agentReviewAction) says DefenseClaw flagged the
// action for review.
//
// Other actions and any other reason (a configured block message, a
// foreign-hook or AI Defense verdict) keep displayReason. Secure Client
// keeps its pinned wording: a managed deployment, an explicit managed
// redaction directive, or the managed agent-reason carve-out (which hands
// the agent the raw reason) leave displayReason unchanged.
func agentVerdictReason(action, sourceReason, displayReason string, policy redaction.SinkPolicy) string {
	if action != "block" && action != "confirm" && action != agentReviewAction {
		return displayReason
	}
	if managedEnterpriseActive.Load() || policy != redaction.SinkPolicyDefault {
		return displayReason
	}
	subject := agentBlockListSubject(sourceReason)
	if subject == "" {
		subject = agentAssetPolicySubject(sourceReason)
	}
	if subject == "" {
		subject = agentJudgeSubject(sourceReason)
	}
	if subject == "" {
		subject = agentRuleAndJudgeSubject(sourceReason)
	}
	if action == "block" && subject != "" {
		return agentBlockSentence(subject)
	}
	if displayReason == sourceReason && !trustedBuiltInMatchReason(sourceReason) {
		return displayReason
	}
	rules := agentMatchedRules(sourceReason)
	if rules == "" {
		return displayReason
	}
	standalone := standaloneEnterpriseActive.Load()
	switch {
	case action == "block":
		return agentBlockSentence(rules)
	case action == agentReviewAction && standalone:
		return "DefenseClaw flagged this action for review under your organization's policy (" + rules + ")."
	case action == agentReviewAction:
		return "DefenseClaw policy flagged this action for review (" + rules + ")."
	default:
		return agentConfirmSentence(rules)
	}
}

// agentBlockSentence is the block an agent and its user read for subject
// (the deciding rules, a judge verdict or a block-list entry; "" when none
// can be named). Host hooks (agentVerdictReason) and sandbox hooks
// (sandboxVerdictReason) share it, so one rule reads the same wherever the
// connector runs (GAP-1885).
func agentBlockSentence(subject string) string {
	detail := ""
	if subject != "" {
		detail = " (" + subject + ")"
	}
	if standaloneEnterpriseActive.Load() {
		return "DefenseClaw blocked this action under your organization's policy" + detail + ". " +
			agentBlockNoRetry + " Contact your administrator if you need it allowed."
	}
	return "DefenseClaw policy blocked this action" + detail + ". " + agentBlockNoRetry
}

// agentConfirmSentence is agentBlockSentence for a confirmation.
func agentConfirmSentence(subject string) string {
	detail := ""
	if subject != "" {
		detail = " (" + subject + ")"
	}
	if standaloneEnterpriseActive.Load() {
		return "DefenseClaw needs your confirmation for this action under your organization's policy" + detail + "."
	}
	return "DefenseClaw policy needs your confirmation for this action" + detail + "."
}

// agentObservedReason names the rules of a finding DefenseClaw lets through
// (observe mode, or an alert) the way agentVerdictReason names them in a
// block: "rule R1: Title". The observe notice used to show a rule pack's
// title as a "<redacted len=N sha=...>" token while the action-mode block
// printed it (GAP-1187). The gates are agentVerdictReason's: a managed
// deployment or an explicit redaction directive keeps displayReason, and so
// does any reason that is not a plain local rule match.
func agentObservedReason(action, sourceReason, displayReason string, policy redaction.SinkPolicy) string {
	if action == "block" || action == "confirm" || action == agentReviewAction {
		return displayReason
	}
	if managedEnterpriseActive.Load() || policy != redaction.SinkPolicyDefault {
		return displayReason
	}
	if displayReason == sourceReason && !trustedBuiltInMatchReason(sourceReason) {
		return displayReason
	}
	if rules := agentMatchedRules(sourceReason); rules != "" {
		return rules
	}
	return displayReason
}

// agentBlockListReasonPattern matches the two ship-authored block-list
// reasons (inspect.go): `tool "<name>" is on the static block list` and
// `mcp server "<name>" is blocked`. The name is the tool or server the agent
// itself called; any other text fails the match and stays redacted.
var agentBlockListReasonPattern = regexp.MustCompile(
	`^(tool|mcp server) "([A-Za-z0-9][A-Za-z0-9._:@/-]{0,127})" (?:is on the static block list|is blocked)$`)

// agentJudgeKinds words the LLM judge reasons (llm_judge.go) for the agent.
// The judge's own text can quote the prompt, so only its kind is named.
var agentJudgeKinds = []struct{ prefix, words string }{
	{"judge-pii: ", "personal data or credentials"},
	{"judge-exfil: ", "possible data exfiltration"},
	{"judge-injection: ", "prompt injection"},
	{"judge-tool-injection: ", "tool-call injection"},
}

// agentJudgeSubject words a reason that starts with an LLM judge verdict
// ("LLM judge: personal data or credentials, possible data exfiltration"),
// or returns "" for any other reason. The redacted judge text read like a
// broken hook ("judge-pii: Password: <redacted len=22 sha=...>") (GAP-1564).
func agentJudgeSubject(reason string) string {
	if !strings.HasPrefix(reason, "judge-") {
		return ""
	}
	var kinds []string
	for _, part := range strings.Split(reason, "; ") {
		for _, kind := range agentJudgeKinds {
			if strings.HasPrefix(part, kind.prefix) && !slices.Contains(kinds, kind.words) {
				kinds = append(kinds, kind.words)
			}
		}
	}
	if len(kinds) == 0 {
		return ""
	}
	return "LLM judge: " + strings.Join(kinds, ", ")
}

// agentRuleAndJudgeSubject words a local rule match that the LLM judge also
// flagged ("matched: R:Title; judge-pii: ...") as "rule R: Title; LLM judge:
// personal data or credentials", or returns "" when either half is not one
// agentMatchedRules or agentJudgeSubject words. The mixed reason fell back to
// the redacted text with its raw labels (GAP-1824).
func agentRuleAndJudgeSubject(reason string) string {
	local, judge, found := strings.Cut(reason, "; judge-")
	if !found {
		return ""
	}
	rules := agentMatchedRules(local)
	judgeSubject := agentJudgeSubject("judge-" + judge)
	if rules == "" || judgeSubject == "" {
		return ""
	}
	return rules + "; " + judgeSubject
}

// agentBlockListSubject words a block-list reason for the agent ("tool Write
// is on the block list"), or returns "" for any other reason. The redacted
// reason read like a broken hook ("hook error: <redacted ...>") (GAP-1099).
func agentBlockListSubject(reason string) string {
	m := agentBlockListReasonPattern.FindStringSubmatch(reason)
	if m == nil {
		return ""
	}
	if m[1] == "tool" {
		return "tool " + m[2] + " is on the block list"
	}
	return "MCP server " + m[2] + " is on the block list"
}

// agentAssetPolicyKinds words the asset types of an asset-policy reason.
var agentAssetPolicyKinds = map[string]string{"mcp": "MCP server", "skill": "skill", "plugin": "plugin"}

// agentAssetPolicyKeys are the fields assetPolicyResponseReason emits.
var agentAssetPolicyKeys = []string{
	"reason_code", "source", "asset_type", "asset_name", "connector",
	"registry_status", "registry_configured", "surface",
}

// agentAssetPolicyValuePattern is the shape of a value an asset-policy reason
// may show the agent: the asset name the agent itself asked for, or an enum.
var agentAssetPolicyValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)

// agentAssetPolicySubject words an asset-policy block reason
// (assetPolicyResponseReason: "ASSET-POLICY reason_code=... asset_name=...")
// for the agent ("MCP server github is not in the approved registry"), or
// returns "" for any other reason. The redacted key=value reason read like a
// broken hook and hid the server name (GAP-2423). Every field must be a known
// key with a plain value; anything else stays redacted.
func agentAssetPolicySubject(reason string) string {
	fields := strings.Split(reason, " ")
	if len(fields) < 2 || fields[0] != "ASSET-POLICY" {
		return ""
	}
	values := make(map[string]string, len(fields)-1)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok || !slices.Contains(agentAssetPolicyKeys, key) || !agentAssetPolicyValuePattern.MatchString(value) {
			return ""
		}
		values[key] = value
	}
	kind, name := agentAssetPolicyKinds[values["asset_type"]], values["asset_name"]
	if kind == "" || name == "" {
		return ""
	}
	switch values["reason_code"] {
	case "not-in-approved-registry":
		return kind + " " + name + " is not in the approved registry"
	case "registry-required-but-empty":
		return kind + " " + name + " needs an approved registry, and none is configured"
	case "default-deny":
		return kind + " " + name + " is denied by the default asset policy"
	case "admin-deny":
		return kind + " " + name + " is denied by asset policy"
	case "runtime-disable":
		// A disabled or quarantined asset: say so in words, not with the
		// registry fields of the record (GAP-0362).
		if values["asset_type"] == "skill" {
			return "skill " + name + " is disabled by security policy; `defenseclaw skill info " + name + "` shows why"
		}
		return kind + " " + name + " is disabled by security policy"
	}
	return ""
}

// agentOrderedRulePrefix starts the note an ordered tool-call chain match
// appends to a reason (agent_hook_chain.go).
const agentOrderedRulePrefix = "matched ordered safety rule: "

// The notes a human-approval fallback appends to a confirm it turns into a
// block (inspect.go). The rule that asked for the confirmation still
// decided.
const (
	approvalUnsupportedNote      = "human approval unsupported on this connector surface; failing closed"
	approvalNativeOpenClawNote   = "human approval requires native OpenClaw approval; failing closed"
	obfuscatedFindingLabelSuffix = " (obfuscated)"
)

// activeRulePackLabel reports whether id and title are a rule of a loaded
// rule pack (the global generation or a connector's). That title is the
// pack author's static text, which the agent may show, unlike a scanner's
// title, which can carry matched text.
func activeRulePackLabel(id, title string) bool {
	id = strings.ToUpper(strings.TrimSpace(id))
	title = strings.TrimSpace(strings.TrimSuffix(title, obfuscatedFindingLabelSuffix))
	if id == "" || title == "" {
		return false
	}
	ruleCategoriesMu.RLock()
	defer ruleCategoriesMu.RUnlock()
	if allRuleGeneration != nil {
		if _, ok := allRuleGeneration.ruleIdentityTitles[id][title]; ok {
			return true
		}
	}
	for _, generation := range connectorRuleGenerations {
		if generation == nil {
			continue
		}
		if _, ok := generation.ruleIdentityTitles[id][title]; ok {
			return true
		}
	}
	return false
}

// agentMatchedRules names the rules of a "matched: <rule-id>:<title>, ..."
// reason, and of any ordered-chain note appended to it: "rule ID" or
// "rules ID1, ID2". A title from the compiled-in catalog or from a loaded
// rule pack is kept ("rule ID: Title"); any other title (a scanner's, which
// can carry matched text) is left to the audit record. It returns "" for any
// other reason, and for a reason that also carries another verdict's text
// (an AI Defense or judge reason merged after the local match): naming only
// the local rule would drop the reason that decided.
func agentMatchedRules(reason string) string {
	for _, note := range []string{approvalUnsupportedNote, approvalNativeOpenClawNote} {
		reason = strings.ReplaceAll(reason, "; "+note, "")
	}
	var items []string
	seen := make(map[string]bool)
	add := func(id, item string) {
		if len(items) == 5 || seen[id] || !agentRuleIDPattern.MatchString(id) {
			return
		}
		seen[id] = true
		items = append(items, item)
	}
	for i, part := range strings.Split(reason, "; ") {
		switch {
		case i == 0 && strings.HasPrefix(part, builtInMatchReasonPrefix):
			for _, label := range splitMatchLabels(strings.TrimPrefix(part, builtInMatchReasonPrefix)) {
				id, title, found := strings.Cut(label, ":")
				if !found {
					continue
				}
				item := id
				if trustedBuiltInFindingLabel(label) || activeRulePackLabel(id, title) {
					item = id + ": " + title
				}
				add(id, item)
			}
		case strings.HasPrefix(part, agentOrderedRulePrefix):
			for _, id := range strings.Split(strings.TrimPrefix(part, agentOrderedRulePrefix), ", ") {
				add(id, id)
			}
		default:
			return ""
		}
	}
	switch len(items) {
	case 0:
		return ""
	case 1:
		return "rule " + items[0]
	}
	return "rules " + strings.Join(items, ", ")
}

// agentConfirmUnavailableReason words the block the standalone enterprise
// profile makes of a confirmation the agent cannot ask for
// (confirmWithoutAskAgent), so the user learns that the rule wanted their
// approval instead of reading an ordinary block. It names the rules where
// agentVerdictReason would, and keeps the display reason otherwise.
func agentConfirmUnavailableReason(agent, sourceReason, displayReason string, policy redaction.SinkPolicy) string {
	detail := displayReason
	if agentVerdictReason("confirm", sourceReason, displayReason, policy) != displayReason {
		detail = agentMatchedRules(sourceReason)
	}
	if detail != "" {
		detail = " (" + detail + ")"
	}
	return "DefenseClaw blocked this action: your organization's policy needs your confirmation for it" + detail +
		", and " + agent + " cannot ask for it. Contact your administrator if you need it allowed."
}
