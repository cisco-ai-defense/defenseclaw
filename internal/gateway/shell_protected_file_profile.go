// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"

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
// edit tool, an apply_patch envelope and a stored command payload are not
// shell commands here.
func trustedShellCommandInput(input actionfacts.Input) bool {
	if actionfacts.ApplyPatchTool(input.Tool) {
		return false
	}
	return input.Command != "" || len(input.Argv) > 0 ||
		actionfacts.IsImmediateShellExecutionTool(input.Tool)
}

// markShellProtectedFileFindings records, on the findings of one trusted
// action, which belong to the shell-command protected-file class. It only
// labels them; the profile decides what they do
// (shellProtectedFileFindingsForPosture).
func markShellProtectedFileFindings(input actionfacts.Input, findings []RuleFinding) []RuleFinding {
	if len(findings) == 0 || !trustedShellCommandInput(input) {
		return findings
	}
	for index := range findings {
		if shellProtectedFileRule(findings[index].RuleID) {
			findings[index].shellProtectedFile = true
		}
	}
	return findings
}

// shellProtectedFileFindingsForPosture is the one place a rule-pack posture
// decides the shell-command protected-file class (GAP-0675): outside the
// strict posture each such finding that could block is capped at an alert,
// so the command runs, the agent shows the alert with the rule id and the
// audit row records decision=alert. The strict posture keeps them as they
// are. The Secure Client integration is unchanged: Cisco AI Defense decides
// there. posture is read only when a finding of the class is present.
func shellProtectedFileFindingsForPosture(findings []RuleFinding, secureClient bool, posture func() string) []RuleFinding {
	if secureClient || !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.shellProtectedFile }) ||
		posture() == config.HookPolicyTierStrict {
		return findings
	}
	capped := slices.Clone(findings)
	for index := range capped {
		if capped[index].shellProtectedFile && capped[index].contributesToEnforcement() {
			capped[index].enforcement = findingEnforcementAlertOnly
		}
	}
	return capped
}

// unnamedPackClassPosture, when set, is the posture the class is decided
// with for a configuration that names no rule pack. It is empty in the
// product, where such a configuration has the default posture. The gateway
// package tests set it to strict once, before any test runs (init in
// shell_protected_file_profile_test.go): the classifier tests written before
// GAP-0675 build such configurations and keep asserting that the class
// blocks in strict, while the TestGAP0675 tests name their rule pack and
// check the default, permissive and strict postures.
var unnamedPackClassPosture string

// rulePackPostureForConnector is the posture of the rule pack of connector
// in cfg, as its thresholds read it (resolveThresholds).
func rulePackPostureForConnector(cfg *config.Config, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if cfg != nil {
			ref = cfg.EffectiveRulePackRefForConnector(connector)
		}
		if ref == (config.RulePackRef{}) && unnamedPackClassPosture != "" {
			return unnamedPackClassPosture
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
		if ref == (config.RulePackRef{}) && unnamedPackClassPosture != "" {
			return unnamedPackClassPosture
		}
		if gc == nil {
			return config.HookPolicyTierDefault
		}
		return packPosture(ref, guardrailRulePackDir(gc, ref))
	}
}
