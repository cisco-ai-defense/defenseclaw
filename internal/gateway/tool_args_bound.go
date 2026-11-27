// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// Arguments of an MCP or app tool call past the bounds of the shared argument
// reading (actionfacts.ArgsLimitIssue: a string over 64 KiB, over 256 KiB in
// all, a key over 4 KiB, more than 512 members, deeper than 16) give the
// structured rules no facts, so padding a blocked command with a large value
// made a laptop PreToolUse a silent allow (substrate-1:GAP-1096). The call is
// now judged as the substrate MCP callout judges it (GAP-1094): every rule
// reading of the call also reads its bounded projections
// (substrateMCPArgsProjections: the read keys first, heads and tails of long
// strings cut at word boundaries), and the call gets the unknown tier of the
// pack (ACTION-COMPOUND-LIMIT: an alert in the default pack, a block in the
// strict pack or under guardrail.cascade.unknown block). A large benign call
// is never a silent allow and, at defaults, never a block. Projections go to
// the rules alone; the LLM judge and AID read the whole arguments as before.
// A shell or native file-tool call keeps its own bounds
// (nonShellToolApplies: posixParseTruncation, the over-limit write readings).

type toolArgsProjectedKey struct{}

// withToolArgsProjected marks the readings of a caller that judges the
// bounded projections of over-bound arguments and floors them itself
// (substrateMCPVerdict, substrateMCPBoundedVerdict), so they are not judged
// twice.
func withToolArgsProjected(ctx context.Context) context.Context {
	return context.WithValue(ctx, toolArgsProjectedKey{}, true)
}

func toolArgsProjected(ctx context.Context) bool {
	projected, _ := ctx.Value(toolArgsProjectedKey{}).(bool)
	return projected
}

// overBoundToolArgsFindings adds to findings, the rule readings of an MCP or
// app tool call, the findings of its bounded projections when its arguments
// pass a bound of the shared reading, and the unknown-tier finding of that
// bound. A call inside the bounds keeps findings as they are.
func overBoundToolArgsFindings(ctx context.Context, action trustedActionRequest, findings []RuleFinding, mcpServer string, secureClient bool) []RuleFinding {
	if len(action.Input.Args) == 0 || toolArgsProjected(ctx) {
		return findings
	}
	// The bound first: a call inside it costs one scan of its bytes.
	issue := actionfacts.ArgsLimitIssue(action.Input.Args)
	if issue == "" || !nonShellToolApplies(action, mcpServer) {
		return findings
	}
	for _, projection := range substrateMCPArgsProjections(action.Input.Args) {
		twin := action
		twin.Input.Args = projection
		twin.LegacyText = string(projection)
		twin.guestMemo, twin.conflictSource = nil, nil
		findings = withOverLimitTwinFindings(findings, trustedToolCallFindingsOf(ctx, twin, mcpServer, secureClient))
	}
	set := bounded.Of(bounded.Bytes)
	if issue == actionfacts.IssueDepthLimit {
		set = bounded.Of(bounded.Depth)
	}
	return withUnknownFinding(findings, boundedTruncatedFinding(set, action.EnforcementCapable))
}
