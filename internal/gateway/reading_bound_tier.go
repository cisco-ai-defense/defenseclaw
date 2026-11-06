// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A call the readers did not finish, because it is past a reading bound
// (its nested shell bodies weigh more than shellparse.MaxNestedBodyBytes,
// GAP-0677) or because the hook client stopped at a recovered parse
// (shell-parse-bound, GAP-0534), is graded by its text. When the text may
// name a protected target (hookpaths.BoundCallMayNameProtected: the
// DefenseClaw state, a protected file or folder, or the home folder
// directly or through a known value) it keeps the over-limit block
// (ACTION-COMPOUND-LIMIT) in every tier. Otherwise the bound is a limit of
// the readers, not a finding about the call: the strict tier blocks it,
// and the default and permissive tiers, per-user and managed, show it as
// an alert and let the call run (owner steer for 1.0.9: the default tier
// does not block an ordinary command, and a protective rule that would
// block it moves to strict). A command nested past
// shellparse.MaxNestingDepth still blocks in every tier (GAP-2537). A call
// whose nested bodies weigh more than shellparse.MaxNestedBodyProofBytes,
// but not past the reading bound, is read in full; past that weight the
// readers do not prove its protected targets, so one whose text may name a
// protected target keeps the over-limit block.

// trustedReadingBoundMayNameProtected reports whether the text of input
// may name a protected target (hookpaths.BoundCallMayNameProtected, or a
// link to one): its command, argv, top-level command argument and tool
// arguments.
func trustedReadingBoundMayNameProtected(request trustedActionRequest) bool {
	input, clientTargets := request.Input, request.ResolvedWriteTargets
	text := input.Command + "\n" + strings.Join(input.Argv, "\n") + "\n" + string(input.Args)
	if command, present, valid := trustedTopLevelCommandField(input.Args); valid && present {
		// The decoded value: in the JSON text a word ends at a quote or a
		// brace that is not part of it.
		text += "\n" + command
	}
	if hookpaths.BoundCallMayNameProtected(text, input.CWD, input.ActiveHome) {
		return true
	}
	// A word that reaches a protected file through a link of the project
	// (hookpaths.BoundCallReachesProtectedLink): the hook client looked the
	// words up as the user and sent the decision, which a gateway behind
	// ProtectHome cannot repeat; a per-user gateway looks them up itself.
	if clientTargets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision {
		return true
	}
	// Behind ProtectHome, a map that says only "incomplete", with no
	// directory, is the hook client giving up on a payload over its size
	// bound: nobody could look the words up, so the call is not shown to
	// reach nothing.
	if request.ProtectedHomeHook && clientTargets[hookpaths.TruncatedKey] == "1" && clientTargets[hookpaths.CWDKey] == "" {
		return true
	}
	return hookpaths.BoundCallReachesProtectedLink(text, input.CWD, input.ActiveHome)
}

// readingBoundUnreadFindings is the over-limit finding of a call past a
// reading bound whose text names no protected target, marked for the
// policy tier (readingBoundFindingsForTier).
func readingBoundUnreadFindings(enforcementCapable bool) []RuleFinding {
	findings := trustedActionLimitFindings(enforcementCapable)
	for index := range findings {
		findings[index].readingBoundUnread = true
	}
	return findings
}

// withReadingBoundUnreadFinding adds readingBoundUnreadFindings to the
// findings of a call the readers did read, unless an over-limit finding is
// already there.
func withReadingBoundUnreadFinding(findings []RuleFinding) []RuleFinding {
	if slices.ContainsFunc(findings, func(finding RuleFinding) bool { return finding.RuleID == "ACTION-COMPOUND-LIMIT" }) {
		return findings
	}
	return append(findings, readingBoundUnreadFindings(true)...)
}

// readingBoundFindingsForTier is the one place the hook policy tier decides
// a readingBoundUnread finding: outside the strict tier each one that could
// block is capped at an alert, so the call runs and the agent shows the
// alert. The strict tier keeps the block. The Secure Client integration is
// unchanged: Cisco AI Defense decides there.
func readingBoundFindingsForTier(cfg *config.Config, connector string, findings []RuleFinding) []RuleFinding {
	if !slices.ContainsFunc(findings, func(finding RuleFinding) bool { return finding.readingBoundUnread }) ||
		cfg != nil && cfg.SecureClientIntegration() ||
		cfg.HookPolicyTierForConnector(connector) == config.HookPolicyTierStrict {
		return findings
	}
	capped := slices.Clone(findings)
	for index := range capped {
		if capped[index].readingBoundUnread && capped[index].contributesToEnforcement() {
			capped[index].enforcement = findingEnforcementAlertOnly
		}
	}
	return capped
}
