// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// unknownKeyWriteTwinRequests are the requests of a native file-write call
// that carries a key outside the tool's reviewed schema: such a call stays
// partial and names no path, so no rule saw the file it writes. Each target
// the call names (the reviewed key, or any other key holding a rooted path;
// actionfacts.UnknownKeyWriteTargetCalls) is judged as the reviewed call
// that writes that one file (rel-1-0-6:GAP-0729 review 6).
func unknownKeyWriteTwinRequests(request trustedActionRequest, facts actionfacts.Facts) []trustedActionRequest {
	var twins []trustedActionRequest
	for _, args := range actionfacts.UnknownKeyWriteTargetCalls(request.Input, facts) {
		twin := request
		twin.Input.Args = args
		twin.LegacyText = string(args)
		twin.conflictSource = nil
		twin.record, twin.recordTelemetry = nil, nil
		twins = append(twins, twin)
	}
	return twins
}

// withUnknownKeyStateWrites adds the proven mutation of DefenseClaw's own
// state that a twin found. Only that finding counts: the call's other keys
// are not files the harness writes, so no other rule's match on them is a
// block of this call.
func withUnknownKeyStateWrites(findings, twin []RuleFinding) []RuleFinding {
	return withTwinProvenBlocks(findings, slices.DeleteFunc(twin, func(f RuleFinding) bool {
		return f.RuleID != "tamper.detector_state_write"
	}))
}

// dispatchUnknownKeyWriteTwins judges each twin of the call.
func dispatchUnknownKeyWriteTwins(parent context.Context, findings []RuleFinding, twins []trustedActionRequest) []RuleFinding {
	for _, twin := range twins {
		findings = withUnknownKeyStateWrites(findings, dispatchTrustedAction(parent, twin))
	}
	return findings
}
