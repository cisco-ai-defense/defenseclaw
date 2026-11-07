// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// unknownKeyTwinRequests are the requests for the readings of a file-tool
// call with argument keys outside its reviewed schema
// (actionfacts.UnknownKeyTwins): the call without those
// keys, and the same tool aimed at each path-shaped value they hold. Each
// reading is judged by every lane, so an extra key never hides the file a
// call names from a path rule, the state-write block or the credential and
// key rules (gas-ux-r1 GAP-0076). Only what a reading proves counts
// (withOverLimitTwinFindings): a reading never removes a finding of the
// call. A string under a key that names no place is text to every rule but
// the one that protects DefenseClaw's own state (selfProtectionOnly,
// rel-1-0-6:GAP-0729).
func unknownKeyTwinRequests(request trustedActionRequest, facts actionfacts.Facts) ([]unknownKeyTwinRequest, bool) {
	twins, overflow := actionfacts.UnknownKeyTwins(request.Input, facts)
	if len(twins) == 0 {
		return nil, overflow
	}
	out := make([]unknownKeyTwinRequest, 0, len(twins))
	for _, reading := range twins {
		twin := request
		twin.Input.Args = reading.Args
		twin.LegacyText = string(reading.Args)
		twin.conflictSource = nil
		twin.record, twin.recordTelemetry = nil, nil
		out = append(out, unknownKeyTwinRequest{request: twin, selfProtectionOnly: reading.SelfProtectionOnly})
	}
	return out, overflow
}

// unknownKeyTwinRequest is one reading of a file-tool call with extra keys.
type unknownKeyTwinRequest struct {
	request            trustedActionRequest
	selfProtectionOnly bool
}

// findings judges the reading and returns what counts for the call.
func (twin unknownKeyTwinRequest) findings(parent context.Context) []RuleFinding {
	found := dispatchTrustedAction(parent, twin.request)
	if twin.selfProtectionOnly {
		found = selfProtectionFindings(found)
	}
	return found
}

// selfProtectionFindings keeps the findings that protect DefenseClaw's own
// state (tamper.detector_state_write): the one class that blocks in every
// profile for a string in any key of a file-tool call.
func selfProtectionFindings(findings []RuleFinding) []RuleFinding {
	return slices.DeleteFunc(slices.Clone(findings), func(f RuleFinding) bool {
		return f.RuleID != "tamper.detector_state_write"
	})
}
