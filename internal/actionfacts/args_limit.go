// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "encoding/json"

// Bounds of the generic tool-argument reading (extractArgsAtSchema), for a
// caller that projects arguments to fit them.
const (
	MaxArgsJSONBytes = maxArgsJSONBytes
	MaxJSONDepth     = maxJSONDepth
	MaxJSONMembers   = maxJSONMembers
	MaxJSONKeyBytes  = maxScalarBytes
)

// ArgsLimitIssue is the bound the generic argument reading stops at for raw:
// IssueInputLimit (over MaxArgsJSONBytes, a string over MaxCommandBytes, a
// key over MaxJSONKeyBytes, more than MaxJSONMembers members) or
// IssueDepthLimit (deeper than MaxJSONDepth), else "". Arguments past a bound
// give the structured readers no facts at all, so a caller can judge a
// bounded projection of them as well (substrate-1:GAP-1094). It reads only;
// the analysis is unchanged.
func ArgsLimitIssue(raw json.RawMessage) IssueCode {
	if len(raw) > maxArgsJSONBytes {
		return IssueInputLimit
	}
	switch issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue {
	case IssueInputLimit, IssueDepthLimit:
		return issue
	}
	return ""
}
