// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0747StateRule is the rule of a proven write to DefenseClaw state.
const gap0747StateRule = "tamper.detector_state_write"

// gap0747SSHKeysRule and gap0747CompoundLimitRule are the other rules a row
// that still blocks in the default pack names (GAP-1563): the SSH authorized
// keys mutation and the evaluation limit of a call the analysis did not read.
const (
	gap0747SSHKeysRule       = "persistence.ssh_authorized_keys_command"
	gap0747CompoundLimitRule = "ACTION-COMPOUND-LIMIT"
)

// gap0747DefaultTierCheck judges the verdict of findings in a pack that is
// not strict (default, permissive, managed default). want is the old
// every-tier expectation "this call is a proven DefenseClaw state write that
// blocks". GAP-0747 owner tiering 2026-11-15T15:20Z: such a write is a HIGH
// alert outside strict and managed-strict (rows that still block for another
// rule keep blocking, and strict rows live in gap_fu12_rules_tiers_test.go).
// It returns "" when the verdict is the expected one, else what was wrong. A
// state write (want true) needs the state rule present, no other rule
// blocking, and the action alert (not allow, not block).
// gap0747Blocked keeps the block of a row that blocks for another rule.
func gap0747DefaultTierCheck(findings []RuleFinding, want bool) string {
	verdict := buildVerdict(findings, "tool_call")
	if !want {
		if verdict.Action == "block" {
			return "blocked, want no block"
		}
		return ""
	}
	state, rest := gap0747SplitState(findings)
	if state == nil {
		return "no " + gap0747StateRule + " finding, want the state write (action " + verdict.Action + ")"
	}
	if other := buildVerdict(rest, "tool_call"); other.Action == "block" {
		return "another rule blocks (" + strings.Join(findingIDs(rest), ",") + "), want the state write alone"
	}
	if verdict.Action != "alert" {
		return "action " + verdict.Action + ", want alert (HIGH state write outside strict)"
	}
	if !strings.EqualFold(state.Severity, "HIGH") {
		return "state write severity " + state.Severity + ", want HIGH"
	}
	return ""
}

// gap0747BlockedForRule judges a row that blocks in the default pack for a
// rule of its own, not as the HIGH state write alert (GAP-1563): the action
// must be block and every named rule id must be among the findings. It
// returns "" when it does, else what was wrong; no rule id means no oracle,
// so it is a failure.
func gap0747BlockedForRule(findings []RuleFinding, ruleIDs ...string) string {
	if len(ruleIDs) == 0 {
		return "no rule id named for the block"
	}
	ids := findingIDs(findings)
	if action := buildVerdict(findings, "tool_call").Action; action != "block" {
		return "action " + action + ", want block for " + strings.Join(ruleIDs, "+") + " (findings " + strings.Join(ids, ",") + ")"
	}
	for _, id := range ruleIDs {
		// "!id": the block must not name that rule.
		if absent, ok := strings.CutPrefix(id, "!"); ok {
			if slices.Contains(ids, absent) {
				return "block names " + absent + " (findings " + strings.Join(ids, ",") + ")"
			}
			continue
		}
		if !slices.Contains(ids, id) {
			return "block without the " + id + " finding (findings " + strings.Join(ids, ",") + ")"
		}
	}
	return ""
}

// gap0747SplitState splits findings into the state write finding (nil when
// there is none) and the other findings.
func gap0747SplitState(findings []RuleFinding) (*RuleFinding, []RuleFinding) {
	var rest []RuleFinding
	var state *RuleFinding
	for i := range findings {
		// A link-held state write (GAP-1568) carries the keys hold's own
		// verdict, not the state write's tier: it stays with the rest.
		if findings[i].RuleID == gap0747StateRule && !findings[i].linkHeld {
			state = &findings[i]
			continue
		}
		rest = append(rest, findings[i])
	}
	return state, rest
}

// gap0747StateProven reports whether findings hold a state write finding the
// trusted ActionFacts owner proved: it mirrors the proof of
// provenActiveStateMutation without its block-only action gate (the tier).
func gap0747StateProven(findings []RuleFinding) bool {
	for _, finding := range findings {
		if finding.RuleID == gap0747StateRule && finding.contributesToEnforcement() &&
			finding.proof.authorizes(finding.RuleID) &&
			(finding.proof.kind == findingProofActionFactsSemantic ||
				finding.proof.kind == findingProofActionFactsSubgraph ||
				finding.proof.kind == findingProofActiveStateMutation) {
			return true
		}
	}
	return false
}

// gap0747StateWriteAction is the verdict of a proven DefenseClaw state write
// in tier (GAP-0747 owner tiering 2026-11-15T15:20Z): a HIGH alert in the
// default and permissive tiers (and a managed install on the default pack),
// a block in strict and managed-strict.
func gap0747StateWriteAction(tier bounded.Tier) bounded.Action {
	if tier == bounded.TierStrict {
		return bounded.Block
	}
	return bounded.Alert
}

// gap0747BodyAction is the action of a hook or file-tool response body.
func gap0747BodyAction(body string) string {
	const key = `"action":"`
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// gap0747BodyBlocked is the blocked verdict of a hook response body for a row
// whose old expectation is want (true: a proven DefenseClaw state write that
// blocked in every tier). Outside strict (strict false) such a write is a
// HIGH alert that names the state rule and does not block (GAP-0747 owner
// tiering 2026-11-15T15:20Z), so that body counts as the expected verdict;
// in strict the body must still block.
func gap0747BodyBlocked(body string, want, strict bool) bool {
	return gap0747ActionBlocked(gap0747BodyAction(body), body, want, strict)
}

// gap0747ActionBlocked is gap0747BodyBlocked for a verdict that has the action
// and a text that names the rules (the findings or the whole response).
func gap0747ActionBlocked(action, text string, want, strict bool) bool {
	blocked := action == "block"
	if want && !strict && !blocked && strings.Contains(text, gap0747StateRule) {
		return true
	}
	return blocked
}

// gap0747Blocked is the blocked verdict of findings for a row whose old
// expectation is want (true: a proven DefenseClaw state write, which blocked
// in every tier). In a pack that is not strict the write is a HIGH alert
// (GAP-0747 owner tiering 2026-11-15T15:20Z), so a row that wants a block and
// gets exactly that alert counts as the expected verdict; any other
// difference keeps the old comparison and fails.
func gap0747Blocked(findings []RuleFinding, want bool) bool {
	if want {
		// A row that blocks for a rule of its own keeps the block it had in
		// every tier; the state write alone must be the HIGH alert.
		state, rest := gap0747SplitState(findings)
		if buildVerdict(findings, "tool_call").Action == "block" &&
			(state == nil || buildVerdict(rest, "tool_call").Action == "block") {
			return true
		}
	}
	if gap0747DefaultTierCheck(findings, want) == "" {
		return want
	}
	return !want
}

// gap0747OtherTamperFinding reports whether findings (rule id, colon, text)
// name a tamper or persistence rule other than the state write and the agent
// hook config write (a HIGH alert outside strict too), which still blocks the
// call for its own rule in every tier (tamper.agent_hook_config_disable, the
// removal of a registered DefenseClaw hook file, does).
func gap0747OtherTamperFinding(findings []string) bool {
	for _, f := range findings {
		id := f
		if i := strings.IndexByte(f, ':'); i >= 0 {
			id = f[:i]
		}
		switch id {
		case gap0747StateRule, agentHookConfigWriteRuleID:
			continue
		}
		if strings.HasPrefix(id, "tamper.") || strings.HasPrefix(id, "persistence.") {
			return true
		}
	}
	return false
}

// gap0747StateVerdict maps the action of a hook response body to the old
// every-tier vocabulary of a test that rotates file-tool shapes: a proven
// DefenseClaw state write is a HIGH alert outside strict (GAP-0747 owner
// tiering 2026-11-15T15:20Z) and counts as "block" there when the body names
// the state rule; in strict the action must itself be a block. Any other
// action is returned unchanged.
func gap0747StateVerdict(action, body string, strict bool) string {
	if !strict && action == "alert" && strings.Contains(body, gap0747StateRule) {
		return "block"
	}
	return action
}

// gap0747WantAction is the action of a proven DefenseClaw state write in a
// file-tool or hook cell: a block in strict, a HIGH alert elsewhere.
func gap0747WantAction(strict bool) string {
	if strict {
		return "block"
	}
	return "alert"
}

// gap0747FileToolBlocked is the blocked verdict of a file-tool response body
// for a write of a protected settings file in the pack (empty is the
// default). Outside strict such a proven state write is a HIGH alert that
// names the state rule (GAP-0747 owner tiering 2026-11-15T15:20Z); in strict
// the body must carry the block prefix.
func gap0747FileToolBlocked(body, pack string) bool {
	if strings.HasPrefix(body, fileToolBlockPrefix) {
		return true
	}
	return pack != "strict" && gap0747BodyAction(body) == "alert" && strings.Contains(body, gap0747StateRule)
}

// gap0747TierWantAction is the action name of a proven DefenseClaw state
// write in a bounded tier: "block" in strict, "alert" elsewhere.
func gap0747TierWantAction(tier bounded.Tier) string {
	return gap0747WantAction(tier == bounded.TierStrict)
}

// gap0747HookBlocked is the blocked verdict of a hook response body in the
// pack (empty is the default): a block in strict, and outside strict a HIGH
// alert that names the state rule for a proven DefenseClaw state write
// (GAP-0747 owner tiering 2026-11-15T15:20Z). Any other body is not blocked.
func gap0747HookBlocked(got, pack string) bool {
	if strings.HasPrefix(got, `{"action":"block"`) {
		return true
	}
	return pack != "strict" && strings.HasPrefix(got, `{"action":"alert"`) && strings.Contains(got, gap0747StateRule)
}

// gap0747HookBlockedAnyMode is gap0747HookBlocked for a test that runs the
// default pack in observe and action mode: a proven DefenseClaw state write
// is a HIGH alert in action mode and an allow that carries the state finding
// in observe mode (GAP-0747 owner tiering 2026-11-15T15:20Z).
func gap0747HookBlockedAnyMode(got string) bool {
	return gap0747HookBlocked(got, "") ||
		strings.HasPrefix(got, `{"action":"allow"`) && strings.Contains(got, gap0747StateRule)
}

// gap0747HookAnswer is the part of a hook response the tier oracle reads.
type gap0747HookAnswer struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Findings []string `json:"findings"`
	RuleIDs  []string `json:"rule_ids"`
}

// gap0747HookBodyCheck judges a hook response body of the default pack (the
// managed hook peer included) against want: "allow"; "block" (a block for a
// rule of the row's own); or "alert", a proven DefenseClaw state write that
// is the only blocking-class rule, so the answer is the HIGH alert that names
// the state rule (GAP-0747 owner tiering 2026-11-15T15:20Z). want may end in
// "+rule.id" (repeatable): the answer must carry those finding ids too. It
// returns "" when the answer is the expected one, else what was wrong.
func gap0747HookBodyCheck(body, want string) string {
	kinds := strings.Split(want, "+")
	var answer gap0747HookAnswer
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		return "answer is not JSON: " + err.Error() + " " + body
	}
	ids := make([]string, 0, len(answer.Findings))
	for _, f := range answer.Findings {
		id, _, _ := strings.Cut(f, ":")
		ids = append(ids, id)
	}
	if answer.Action != kinds[0] {
		return "action " + answer.Action + ", want " + kinds[0] + " (findings " + strings.Join(ids, ",") + ")"
	}
	for _, id := range kinds[1:] {
		// "!id": the answer must not name that rule.
		if absent, ok := strings.CutPrefix(id, "!"); ok {
			if slices.Contains(ids, absent) {
				return "answer names " + absent + " (findings " + strings.Join(ids, ",") + ")"
			}
			continue
		}
		if !slices.Contains(ids, id) {
			return "no " + id + " finding (findings " + strings.Join(ids, ",") + ")"
		}
	}
	switch kinds[0] {
	case "alert":
		if !slices.Contains(ids, gap0747StateRule) {
			return "alert without the " + gap0747StateRule + " finding (findings " + strings.Join(ids, ",") + ")"
		}
		if !strings.EqualFold(answer.Severity, "HIGH") {
			return "state write severity " + answer.Severity + ", want HIGH"
		}
		if gap0747OtherTamperFinding(answer.Findings) {
			return "another tamper rule fires beside the state write (findings " + strings.Join(ids, ",") + ")"
		}
	}
	return ""
}
