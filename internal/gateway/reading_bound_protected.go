// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A call the readers did not finish, because it is past a reading bound
// (nested past shellparse.MaxNestingDepth, GAP-2537, or with nested shell
// bodies that weigh more than shellparse.MaxNestedBodyBytes, GAP-0677) or
// because the hook client stopped at a recovered parse (shell-parse-bound,
// GAP-0534), gets only the evaluation-limit finding (ACTION-COMPOUND-LIMIT),
// which guardrailActionForProfile shows as an alert outside the strict
// profile and blocks in strict, whatever its text may name: the bound is a
// limit of the readers, not a finding about the call (owner rule for 1.0.9:
// an evaluation-limit-only call alerts outside strict, rel-1-0-6:GAP-0675).
// A call whose nested bodies weigh more than
// shellparse.MaxNestedBodyProofBytes, but not past the reading bound, is
// read in full, and a target a reader proves decides on its own in every
// profile; past that weight the readers do not prove its protected targets,
// so one whose text may name a protected target also gets the
// evaluation-limit finding.

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
