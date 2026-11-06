// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

// unknownKeyFileToolOverflowTitle is the reason of the conservative block of
// a file-write tool call whose unknown argument keys hold more possible
// targets than are judged.
const unknownKeyFileToolOverflowTitle = "File-write tool call names too many possible files in arguments outside its reviewed schema to verify; remove the extra arguments"

// unknownKeyTwinRequests are the requests for the readings of a file-tool
// call whose parse is partial only because of argument keys outside its
// reviewed schema (actionfacts.UnknownKeyTwins): the call without those
// keys, and the same tool aimed at each path-shaped value they hold. Each
// reading is judged by every lane, so an extra key never hides the file a
// call names from a path rule, the state-write block or the credential and
// key rules (gas-ux-r1 GAP-0076). Only what a reading proves counts
// (withOverLimitTwinFindings): a reading never removes a finding of the
// call.
func unknownKeyTwinRequests(request trustedActionRequest, facts actionfacts.Facts) []trustedActionRequest {
	twins, _ := actionfacts.UnknownKeyTwins(request.Input, facts)
	if len(twins) == 0 {
		return nil
	}
	out := make([]trustedActionRequest, 0, len(twins))
	for _, reading := range twins {
		twin := request
		twin.Input.Args = reading.Args
		twin.LegacyText = string(reading.Args)
		twin.conflictSource = nil
		twin.record, twin.recordTelemetry = nil, nil
		out = append(out, twin)
	}
	return out
}
