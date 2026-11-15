// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-0663 (lane s7-tmin2): the caps of the inline hand-off and
// archive-member readers of s7/tamper-min are registered with the cross-lane
// bound test (TestBoundRuleEveryLaneCap). A prefix chain of wrappers or
// runners longer than actionfacts.InlineChainRounds rounds, and shell bodies
// nested deeper than hookpaths.InlineMaxShellDepth, are TRUNCATED: at least
// the unknown tier of the pack, never the silent allow they were.
//
// A call is cut at its first bound, and runner chains (xargs) and nested
// shell bodies pass the shared sender reader first: one past
// actionfacts.MaxSenderDepth the call is TRUNCATED (cap depth), whatever the
// hand-off reader reads (rel-1-0-10:GAP-0827). So the xargs and shell-body
// rows are registered at that bound, where the call is cut. The hand-off and
// archive readers still read on to their own bounds, so a write they prove
// deeper keeps its block (a proven finding decides). A wrapper chain (nohup)
// is no nesting for the sender reader and stays at the hand-off bound.
//
// The generators build the chain in front of a benign call (an inline
// python that prints, a project extraction), so the answer at the cap is an
// allow and past it the evaluation-limit finding with the cap named.
const (
	tminChainBody    = `python3 -c pass notes.txt`
	tminChainArchive = `tar -xf /tmp/tmin.tar -C ~/proj notes/a.txt`
)

// tminNestedShells wraps core in size sh -c bodies, each double quoted with
// its quotes escaped, so the text grows by half a doubling per level and not
// by the fourfold of single-quote escaping.
func tminNestedShells(core string, size int) string {
	command := core
	for range size {
		command = `sh -c "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(command) + `"`
	}
	return command
}

func tminChainFill(prefix, core string) func(int) string {
	return func(size int) string { return strings.Repeat(prefix, size) + core }
}

func tminChainMulti(prefix, core string) func(int) string {
	return func(size int) string {
		return strings.Repeat(prefix, size) + core + "; " + boundedListOperands(actionfacts.MaxOperandsPerCall+size)
	}
}

func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "s7/tamper-min xargs chain", cap: bounded.Depth, limit: actionfacts.MaxSenderDepth,
			gen:  boundedShellLane(tminChainFill("xargs ", tminChainBody), tminChainMulti("xargs ", tminChainBody)),
			seen: boundedShellSeenCall},
		boundedLaneCap{lane: "s7/tamper-min wrapper chain", cap: bounded.Depth, limit: actionfacts.InlineChainRounds * 8,
			gen:  boundedShellLane(tminChainFill("nohup ", tminChainBody), tminChainMulti("nohup ", tminChainBody)),
			seen: boundedShellSeenCall},
		boundedLaneCap{lane: "s7/tamper-min shell bodies", cap: bounded.Depth, limit: actionfacts.MaxSenderDepth,
			gen: boundedShellLane(func(size int) string { return tminNestedShells(tminChainBody, size) },
				func(size int) string {
					return tminNestedShells(tminChainBody, size) + "; " + boundedListOperands(actionfacts.MaxOperandsPerCall+size)
				}),
			seen: boundedShellSeenCall},
		boundedLaneCap{lane: "s7/tamper-min archive shell bodies", cap: bounded.Depth, limit: actionfacts.MaxSenderDepth,
			gen: boundedShellLane(func(size int) string { return tminNestedShells(tminChainArchive, size) },
				func(size int) string {
					return tminNestedShells(tminChainArchive, size) + "; " + boundedListOperands(actionfacts.MaxOperandsPerCall+size)
				}),
			seen: boundedShellSeenCall},
	)
}
