// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// shellProtectedFileRules is the class of rules that decide whether a shell
// command writes, appends, copies, moves, renames, links, extracts or
// otherwise materializes content into one of the protected files of the user:
// the SSH authorized-keys and control files (hookpaths), shell startup
// profiles and active Git hooks. Owner decision 2026-11-06
// (rel-1-0-6:GAP-0675, detections round #1189): in the default (balanced)
// and permissive profiles, per-user and managed, such a finding on a shell
// command is a visible alert and never blocks; the strict profile, managed
// strict included, blocks it as before.
//
// DefenseClaw self-protection is not in this class and keeps blocking in
// every profile: its state, configuration, plugins and bridges
// (tamper.detector_state_write and the active-state owners), turning its
// hooks off or changing the hook settings of an agent, rule-pack tamper, agent
// instruction files (COG-*), native write and edit tools, MCP and skill
// admission and the fail modes.
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
// edit tool, an apply_patch envelope (also one a shell call runs or feeds:
// mayRunApplyPatch) and a stored command payload are not shell commands
// here; they keep their enforcement in every profile.
func trustedShellCommandInput(input actionfacts.Input) bool {
	if actionfacts.ApplyPatchTool(input.Tool) || mayRunApplyPatch(input) {
		return false
	}
	return input.Command != "" || len(input.Argv) > 0 ||
		actionfacts.IsImmediateShellExecutionTool(input.Tool)
}

// mayRunApplyPatch reports a call whose text, argv or arguments name
// apply_patch or carry a patch envelope. It over-matches on purpose: a false
// answer only keeps the enforcement the call had before GAP-0675.
func mayRunApplyPatch(input actionfacts.Input) bool {
	names := func(text string) bool {
		lower := strings.ToLower(text)
		return strings.Contains(lower, "apply_patch") || strings.Contains(lower, "applypatch") ||
			strings.Contains(lower, "apply-patch") || strings.Contains(lower, "*** begin patch")
	}
	return names(input.Command) || names(string(input.Args)) || slices.ContainsFunc(input.Argv, names)
}

// markShellProtectedFileFindings records, on the findings of one trusted
// action, which belong to the shell-command protected-file class. It only
// labels them; the profile decides what they do (profileClassFindings).
// The label is set afresh at every level of a nested dispatch (a statement,
// a child or a twin of the call): the outermost call, which runs last, has
// the whole command and decides.
//
// A call that may reach the DefenseClaw state is self-protection, not the
// class: the protected-write owners also report a write that reaches the
// state through a link, and such a finding keeps its block in every profile
// (rel-1-0-6:GAP-0675 review 1 M3a). The check over-matches on purpose and
// runs only when a finding of the class is present. A native write or edit
// tool is not in the class either.
func markShellProtectedFileFindings(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return shellProtectedFileRule(f.RuleID) }) {
		for index := range findings {
			findings[index].shellProtectedFile = false
		}
		return findings
	}
	class := trustedShellCommandInput(request.Input) && !shellCommandMayReachState(request)
	for index := range findings {
		findings[index].shellProtectedFile = class && shellProtectedFileRule(findings[index].RuleID)
	}
	return findings
}

// shellCommandMayReachState reports a shell call that may write the
// DefenseClaw state: its text, argv or arguments may name the state folder
// however the shell spells it (mayNameStateFolder), the state target
// scan places a target in the active state (it follows the links on disk),
// or the hook client resolved a write target below the state folder of the
// active home. Each answer over-matches: a false answer only keeps the
// block the call had before GAP-0675.
func shellCommandMayReachState(request trustedActionRequest) bool {
	input := request.Input
	if mayNameStateFolder(input.Command) || mayNameStateFolder(string(input.Args)) ||
		slices.ContainsFunc(input.Argv, mayNameStateFolder) {
		return true
	}
	if home := strings.TrimSpace(input.ActiveHome); home != "" {
		state := strings.ToLower(filepath.ToSlash(filepath.Join(home, ".defenseclaw")))
		for _, target := range request.ResolvedWriteTargets {
			if lower := strings.ToLower(filepath.ToSlash(target)); lower == state || strings.HasPrefix(lower, state+"/") {
				return true
			}
		}
	}
	command, ok := trustedBashCommandInput(input)
	if !ok || request.SkipLocalFilesystemResolution {
		return false
	}
	return request.targetMemo.ActionStateTargetMention(command, input.CWD, input.ActiveHome) ||
		commandWordLinksIntoState(command, input.CWD, input.ActiveHome)
}

// mayNameStateFolder reports a text that may name the .defenseclaw state
// folder with quotes, escapes or backticks in the name, in any case or split
// across variables (d=.Defense; e=Claw): it holds "defense" once those are
// removed. hookpaths.MayNameState also matches "claw", which every OpenClaw
// path holds; that would keep the class enforcing for an ordinary OpenClaw
// user in the default profile.
func mayNameStateFolder(text string) bool {
	return strings.Contains(strings.ToLower(strings.NewReplacer("'", "", "\"", "", "\\", "", "`", "").Replace(text)), "defense")
}

// commandWordLinksIntoState reports a word of command that names an existing
// link whose target is the DefenseClaw state folder of home or below it:
// a command can make its own link to such a link and write through it after
// a cd the readers cannot place. One readlink per word, on at most
// stateLinkWordsMax words; it over-matches (a read through the link counts).
func commandWordLinksIntoState(command, cwd, home string) bool {
	home = strings.TrimSpace(home)
	if home == "" {
		return false
	}
	state := filepath.Clean(filepath.Join(home, ".defenseclaw"))
	inState := func(target string) bool {
		target = filepath.Clean(target)
		return strings.EqualFold(target, state) ||
			strings.HasPrefix(strings.ToLower(target), strings.ToLower(state)+string(filepath.Separator))
	}
	words := strings.FieldsFunc(command, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ';' || r == '&' || r == '|' ||
			r == '(' || r == ')' || r == '"' || r == '\'' || r == '<' || r == '>' || r == '='
	})
	for index, word := range words {
		if index == stateLinkWordsMax {
			return false
		}
		if rest, ok := strings.CutPrefix(word, "~/"); ok {
			word = filepath.Join(home, rest)
		}
		if !filepath.IsAbs(word) {
			if cwd == "" {
				continue
			}
			word = filepath.Join(cwd, word)
		}
		target, err := os.Readlink(word)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(word), target)
		}
		if inState(target) {
			return true
		}
	}
	return false
}

// stateLinkWordsMax bounds the words commandWordLinksIntoState reads.
const stateLinkWordsMax = 256

// selfProtectionRules are the rules that protect DefenseClaw itself: a
// write, append, delete or metadata change of its state, configuration,
// hooks, policies, receipts and registries (tamper.detector_state_write and
// the active-state owners that report it). An enforcing finding of these
// rules blocks in every profile, permissive included, per-user and managed
// (rel-1-0-6:GAP-0675 review 1 M3a).
var selfProtectionRules = map[string]bool{
	"TAMPER.DETECTOR_STATE_WRITE": true,
}

// profileClassFindings is the one place a rule-pack posture decides the
// shell-command protected-file class and DefenseClaw self-protection
// (rel-1-0-6:GAP-0675). It returns the findings to map with the thresholds
// and the least action the request gets whatever the thresholds say:
//   - a self-protection finding that could block: block, in every profile;
//   - a class finding that could block: outside the strict posture it is
//     capped at an alert, so the command runs, the agent shows the alert with
//     the rule id and the audit row records decision=alert; in every posture
//     it is at least an alert, so the permissive profile never allows it
//     silently; the strict posture keeps it as it is (it blocks).
//
// A finding that could not block (detection-only, alert-only, allowed) stays
// as it was. The Secure Client integration is unchanged: Cisco AI Defense
// decides there. posture is read only when a class finding is present.
func profileClassFindings(findings []RuleFinding, secureClient bool, posture func() string) ([]RuleFinding, string) {
	floor := guardrailActionAllow
	if secureClient {
		return findings, floor
	}
	class := false
	for _, finding := range findings {
		if !finding.contributesToEnforcement() {
			continue
		}
		if selfProtectionRules[canonicalTrustedRuleID(finding.RuleID)] {
			floor = guardrailActionBlock
		} else if finding.shellProtectedFile {
			class = true
			floor = strongerGuardrailAction(floor, guardrailActionAlert)
		}
	}
	if !class || posture() == config.HookPolicyTierStrict {
		return findings, floor
	}
	capped := slices.Clone(findings)
	for index := range capped {
		if capped[index].shellProtectedFile && capped[index].contributesToEnforcement() {
			capped[index].enforcement = findingEnforcementAlertOnly
		}
	}
	return capped, floor
}

// rulePackPostureForConnector is the posture of the rule pack of connector
// in cfg, as its thresholds read it (resolveThresholds).
func rulePackPostureForConnector(cfg *config.Config, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if cfg != nil {
			ref = cfg.EffectiveRulePackRefForConnector(connector)
		}
		if cfg == nil {
			return config.HookPolicyTierDefault
		}
		return packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref))
	}
}

// guardrailRulePackPosture is rulePackPostureForConnector for a caller that
// holds only the guardrail block (resolveGuardrailThresholds).
func guardrailRulePackPosture(gc *config.GuardrailConfig, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if gc != nil {
			ref = gc.EffectiveRulePackRef(connector)
		}
		if gc == nil {
			return config.HookPolicyTierDefault
		}
		return packPosture(ref, guardrailRulePackDir(gc, ref))
	}
}
