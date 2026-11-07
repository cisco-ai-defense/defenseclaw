// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"

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
	namesState, namesStateKnown := false, false
	for index := range findings {
		findings[index].shellProtectedFile = class && shellProtectedFileRule(findings[index].RuleID)
		findings[index].namesState = false
		if canonicalTrustedRuleID(findings[index].RuleID) != evaluationLimitRuleID {
			continue
		}
		if !namesStateKnown {
			command, _ := trustedBashCommandInput(request.Input)
			namesState, namesStateKnown = textNamesStateFolder(command), true
		}
		findings[index].namesState = namesState
	}
	return findings
}

// textNamesStateFolder reports a command text that names the DefenseClaw
// state folder (".defenseclaw") as a path component: after a path separator
// ("~/.defenseclaw", "$HOME/.defenseclaw/config.yaml", a backslash form on
// Windows), before one (".defenseclaw/config.yaml") or joined to a home root
// ("Join-Path $HOME .defenseclaw"), also with quotes, escapes or backticks in
// the name or in any case. A word that only contains the name (an unrelated
// ".defenseclaw-backup" file, a printed ".defenseclaw") is not the folder. It
// is the text test of a call no reader could analyse; a name built from
// variables or patterns, or a bare relative name beside no home root, is not
// seen (a documented limit of the default and permissive profiles; strict
// blocks the call).
func textNamesStateFolder(command string) bool {
	if !strings.Contains(strings.ToLower(command), "defense") {
		return false
	}
	// A backslash is an escape in one reading and a path separator in the
	// other ("%USERPROFILE%\.defenseclaw").
	for _, backslash := range []string{"", "/"} {
		text := stateQuoteStripper.Replace(strings.ReplaceAll(command, "\\", backslash))
		if stateFolderComponent(strings.ToLower(text)) {
			return true
		}
	}
	return false
}

var stateQuoteStripper = strings.NewReplacer("'", "", "\"", "", "`", "")

// stateHomeRoots are the spellings of the user home that a call joins to the
// state folder name as a separate word.
var stateHomeRoots = []string{"~", "$home", "${home}", "$env:home", "$env:userprofile", "$userprofile",
	"%userprofile%", "%home%", "%homepath%", "$env:homepath"}

// stateFolderComponent reports text that has ".defenseclaw" as a whole path
// component: neither side continues the name, and a separator or a home root
// is beside it.
func stateFolderComponent(text string) bool {
	const name = ".defenseclaw"
	for from := 0; ; {
		at := strings.Index(text[from:], name)
		if at < 0 {
			return false
		}
		at += from
		end := at + len(name)
		from = end
		var before, after byte
		if at > 0 {
			before = text[at-1]
		}
		if end < len(text) {
			after = text[end]
		}
		if stateNameByte(before) || stateNameByte(after) {
			continue
		}
		if before == '/' || after == '/' || stateJoinedToHomeRoot(text[:at]) {
			return true
		}
	}
}

// stateNameByte reports a byte that continues a file name.
func stateNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// stateJoinedToHomeRoot reports a prefix whose last word is a home root.
func stateJoinedToHomeRoot(prefix string) bool {
	word := strings.TrimRight(prefix, " \t\r\n,")
	if cut := strings.LastIndexAny(word, " \t\r\n,(;|&"); cut >= 0 {
		word = word[cut+1:]
	}
	return slices.Contains(stateHomeRoots, word)
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

// evaluationLimitRuleID is the finding of a call the reader could not
// analyse within its bounds (statement budget, an earlier statement it could
// not parse). It carries no target: it says that no path was proven.
const evaluationLimitRuleID = "ACTION-COMPOUND-LIMIT"

// withoutEnforcingEvaluationLimit returns the findings without the
// evaluation-limit finding that could block, and whether there was one. A
// call such a finding blocks has no proven target (one whose text names the
// DefenseClaw state folder keeps its block, namesState); every other finding
// (a named or known protected path, a resolved link, self-protection) is
// kept and decides on its own (rel-1-0-6:GAP-0675 round 10).
func withoutEnforcingEvaluationLimit(findings []RuleFinding) ([]RuleFinding, bool) {
	isLimit := func(finding RuleFinding) bool {
		return finding.contributesToEnforcement() && !finding.namesState &&
			canonicalTrustedRuleID(finding.RuleID) == evaluationLimitRuleID
	}
	if !slices.ContainsFunc(findings, isLimit) {
		return findings, false
	}
	return slices.DeleteFunc(slices.Clone(findings), isLimit), true
}

// guardrailActionForProfile maps findings to the action of the profile: the
// class floor (profileClassFloor) over the thresholds. A verdict whose only
// basis is the evaluation limit is an alert outside the strict profile (the
// call runs, the agent shows the limit, the audit row records
// decision=alert, and the LLM judge decides where it is configured); the
// strict profile, managed strict included, keeps the block. A proven
// finding beside the limit decides, whatever the profile. The Secure Client
// integration is unchanged. strict is read only when a limit finding is
// present.
func guardrailActionForProfile(
	findings []RuleFinding, secureClient bool, strict func() bool, actionFor func(severity string) string,
) string {
	if !secureClient {
		if rest, limited := withoutEnforcingEvaluationLimit(findings); limited && !strict() {
			return strongerGuardrailAction(guardrailActionAlert, strongerGuardrailAction(
				profileClassFloor(rest, false), guardrailActionForFindings(rest, actionFor)))
		}
	}
	return strongerGuardrailAction(profileClassFloor(findings, secureClient),
		guardrailActionForFindings(findings, actionFor))
}
