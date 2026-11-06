// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A call the readers did not finish, because it is past a reading bound
// (its nested shell bodies weigh more than shellparse.MaxNestedBodyBytes,
// GAP-0677) or because the hook client stopped at a recovered parse
// (shell-parse-bound, GAP-0534), is graded by its text. When the text may
// name a protected target (hookpaths.BoundCallMayNameProtected: the
// DefenseClaw state, a protected file or folder, or the home folder
// directly or through a known value) its over-limit finding
// (ACTION-COMPOUND-LIMIT) keeps the block in every profile
// (limitKeepsBlock). Any other such call gets the plain evaluation-limit
// finding, which guardrailActionForProfile shows as an alert outside the
// strict profile: the bound is a limit of the readers, not a finding about
// the call (owner steer for 1.0.9: the default profile does not block an
// ordinary command). A command nested past shellparse.MaxNestingDepth takes
// the plain over-limit path (GAP-2537). A call whose nested bodies weigh
// more than shellparse.MaxNestedBodyProofBytes, but not past the reading
// bound, is read in full; past that weight the readers do not prove its
// protected targets, so one whose text may name a protected target keeps
// the over-limit block.

// trustedReadingBoundMayNameProtected reports whether the text of input
// may name a protected target (hookpaths.BoundCallMayNameProtected): its
// command, argv, top-level command argument and tool arguments.
func trustedReadingBoundMayNameProtected(input actionfacts.Input) bool {
	text := input.Command + "\n" + strings.Join(input.Argv, "\n") + "\n" + string(input.Args)
	if command, present, valid := trustedTopLevelCommandField(input.Args); valid && present {
		// The decoded value: in the JSON text a word ends at a quote or a
		// brace that is not part of it.
		text += "\n" + command
	}
	return hookpaths.BoundCallMayNameProtected(text, input.CWD, input.ActiveHome)
}

// readingBoundProtectedFindings is the over-limit verdict of a call past a
// reading bound whose text may name a protected target: the readers did not
// prove its target, so it blocks in every profile (limitKeepsBlock).
func readingBoundProtectedFindings(enforcementCapable bool) []RuleFinding {
	findings := trustedActionLimitFindings(enforcementCapable)
	for index := range findings {
		findings[index].limitKeepsBlock = true
	}
	return findings
}
