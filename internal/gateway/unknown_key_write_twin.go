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
// that can reach DefenseClaw's state or the machine policy files it
// publishes (the reviewed key, or any other key naming such a path;
// actionfacts.UnknownKeyProtectedStateCalls) is judged as the reviewed call
// that writes that one file. A call whose targets are ordinary files has no
// twin (rel-1-0-6:GAP-0729).
func unknownKeyWriteTwinRequests(request trustedActionRequest, facts actionfacts.Facts) []trustedActionRequest {
	var twins []trustedActionRequest
	for _, args := range actionfacts.UnknownKeyProtectedStateCalls(request.Input, facts) {
		twin := request
		twin.Input.Args = args
		twin.LegacyText = string(args)
		twin.conflictSource = nil
		twin.record, twin.recordTelemetry = nil, nil
		twins = append(twins, twin)
	}
	return twins
}

// dispatchUnknownKeyWriteTwins judges each twin of the call until one proves
// a write of the state. Only that finding counts: the call's other keys are
// not files the harness writes, so no other rule's match on them is a block
// of this call.
func dispatchUnknownKeyWriteTwins(parent context.Context, findings []RuleFinding, twins []trustedActionRequest) []RuleFinding {
	for _, twin := range twins {
		proven := slices.DeleteFunc(dispatchTrustedAction(parent, twin), func(f RuleFinding) bool {
			return f.RuleID != "tamper.detector_state_write"
		})
		findings = withTwinProvenBlocks(findings, proven)
		if slices.ContainsFunc(proven, RuleFinding.contributesToEnforcement) {
			break
		}
	}
	return findings
}
