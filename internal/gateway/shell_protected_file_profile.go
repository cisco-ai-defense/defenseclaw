// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// shellProtectedFileRules is the class of rules that decide whether a shell
// command writes, appends, copies, moves, renames, links, extracts or
// otherwise materializes content into one of the protected files of the user:
// the SSH authorized-keys and control files (hookpaths), shell startup
// profiles and active Git hooks (rel-1-0-6:GAP-0675).
//
// Every rule pack rates such a finding at least as an alert, so no pack
// allows it silently (the permissive pack used to allow a shell startup file
// write without a trace). Whether the finding blocks stays what the rule
// pack's thresholds and the proof of the finding say: a protected file or
// link that a command names directly, through a value it sets or through a
// link stays blocked in every profile. No finding of the class is lowered:
// every reading that tried to tell an unproven target from a named one in
// the gateway opened a protected write (a link the command makes, an
// extraction), so the balanced warning for the unproven remainder is a
// detection and proof task (#1189), not a profile rule.
var shellProtectedFileRules = map[string]bool{
	"PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND": true,
	"PATH-SSH-DIR":                    true,
	"PERSISTENCE.SHELL_PROFILE_WRITE": true,
	"PERSISTENCE.GIT_HOOK_WRITE":      true,
}

// shellProtectedFileRule reports a rule of the shell-command protected-file
// class.
func shellProtectedFileRule(ruleID string) bool {
	return shellProtectedFileRules[canonicalTrustedRuleID(ruleID)]
}

// trustedShellCommandInput reports an action that runs a shell command now:
// the command text or argv of a shell or execution tool. A native write or
// edit tool, the apply_patch tool and a stored command payload are not shell
// commands here; they keep their enforcement in every profile. A shell call
// that names apply_patch (a word, an echo, a patch it runs) is still a shell
// command: its protected-file findings get the floor like any other, so the
// word cannot switch the floor off for a separate write in the same call.
func trustedShellCommandInput(input actionfacts.Input) bool {
	if actionfacts.ApplyPatchTool(input.Tool) {
		return false
	}
	return input.Command != "" || len(input.Argv) > 0 ||
		actionfacts.IsImmediateShellExecutionTool(input.Tool)
}

// markShellProtectedFileFindings records, on the findings of one trusted
// action, which belong to the shell-command protected-file class. It only
// labels them; profileClassFloor decides what the label does. The label is
// set afresh at every level of a nested dispatch (a statement, a child or a
// twin of the call): the outermost call, which runs last, decides.
func markShellProtectedFileFindings(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	class := trustedShellCommandInput(request.Input)
	for index := range findings {
		findings[index].shellProtectedFile = class && shellProtectedFileRule(findings[index].RuleID)
	}
	return findings
}

// selfProtectionRules are the rules that protect DefenseClaw itself: a
// write, append, delete or metadata change of its state, configuration,
// hooks, policies, receipts and registries (tamper.detector_state_write and
// the active-state owners that report it). An enforcing finding of these
// rules blocks in every profile, permissive included, per-user and managed
// (rel-1-0-6:GAP-0675 review 1 M3a).
var selfProtectionRules = map[string]bool{
	"TAMPER.DETECTOR_STATE_WRITE": true,
}

// profileClassFloor is the one place a rule pack is kept from allowing what
// the profiles must never allow silently (rel-1-0-6:GAP-0675). It returns the
// least action the findings get whatever the thresholds say:
//   - a self-protection finding that could block: block, in every profile;
//   - a shell-command protected-file finding that could block: at least an
//     alert, so the permissive profile shows the finding and records it
//     instead of allowing the command without a trace.
//
// A finding that could not block (detection-only, alert-only, allowed) sets no
// floor. The Secure Client integration is unchanged: Cisco AI Defense decides
// there.
func profileClassFloor(findings []RuleFinding, secureClient bool) string {
	floor := guardrailActionAllow
	if secureClient {
		return floor
	}
	for _, finding := range findings {
		if !finding.contributesToEnforcement() {
			continue
		}
		if selfProtectionRules[canonicalTrustedRuleID(finding.RuleID)] {
			floor = guardrailActionBlock
		} else if finding.shellProtectedFile {
			floor = strongerGuardrailAction(floor, guardrailActionAlert)
		}
	}
	return floor
}
