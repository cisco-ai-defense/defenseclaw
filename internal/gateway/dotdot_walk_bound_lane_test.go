// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// dotDotWalkBoundParts is the walk bound of a write operand with a ..
// component (hookpaths maxDotDotWalkParts): an operand of more path
// components is past it and TRUNCATED, cap paths (rel-1-0-10:GAP-1007).
const dotDotWalkBoundParts = 256

// The property test of the bound rule (TestBoundRuleEveryLaneCap) covers the
// .. walk bound in the five tiers (rel-1-0-10:GAP-1061). The generated
// operand is absolute and has size path components: the root, size-3
// folders that do not exist, the .. and the file. At the bound the walk runs
// and stops at the first missing folder, so the lexical reading stands and
// nothing is truncated; one component past it the target is unknown.
func init() {
	walk := func(size int) string {
		return "printf done > /" + strings.Repeat("dcwalk/", size-3) + "../out.txt"
	}
	registerBoundedLane(boundedLaneCap{lane: "dotdot write walk", cap: bounded.Paths, limit: dotDotWalkBoundParts,
		gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
			if shape.nested || shape.multi {
				return boundedLaneCall{}, false
			}
			return boundedShellLane(walk, walk)(size, shape)
		},
		seen: boundedShellSeenCall,
		// In a managed install the protected-home hook reports the write
		// past the bound as an operand it could not place, and the keys
		// proof blocks it decisively (persistence.ssh_authorized_keys_command)
		// without the judge: the 1.0.10 managed fail-closed verdict for a
		// truncated write that may reach the keys file. A bound is a MAYBE,
		// and a MAYBE keeps its 1.0.10 verdict (DET111 ruling 2026-11-22),
		// so the block stands (rel-1-0-10:GAP-1203). Managed strict blocks
		// at the floor too.
		decisive: map[string]string{"managed/" + boundedJudgeOpenShape: "rel-1-0-10:GAP-1203 managed keys fail-closed"}})
}
