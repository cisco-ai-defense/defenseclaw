// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
)

// Bounds of the generic tool-argument reading (extractArgsAtSchema), for a
// caller that projects arguments to fit them.
const (
	MaxJSONDepth           = maxJSONDepth
	MaxArgsProjectionDepth = maxArgsProjectionDepth
	MaxArgsJSONBytes       = maxArgsJSONBytes
	MaxJSONMembers         = maxJSONMembers
)

// ArgsLimitIssue is the bound the generic argument reading stops at for raw:
// IssueInputLimit (over 256 KiB, a string over MaxCommandBytes, a key over
// 4 KiB, more than MaxJSONMembers members) or IssueDepthLimit (deeper than
// MaxJSONDepth), else "". Arguments past a bound give the structured readers
// no facts at all, so a caller can judge a bounded projection of them as
// well (substrate-1:GAP-1094). It reads only; the analysis is unchanged.
//
// Most calls are far inside the bounds: a scan of the bytes that allocates
// nothing proves that (argsInsideLimits) and skips the decode. The hook
// routes ask this of every MCP and app tool call (substrate-1:GAP-1096).
func ArgsLimitIssue(raw json.RawMessage) IssueCode {
	if len(raw) > maxArgsJSONBytes {
		return IssueInputLimit
	}
	if argsInsideLimits(raw) {
		return ""
	}
	return argsLimitIssueDecoded(raw)
}

// argsLimitIssueDecoded is ArgsLimitIssue by the reading's own decode.
func argsLimitIssueDecoded(raw json.RawMessage) IssueCode {
	switch issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue {
	case IssueInputLimit, IssueDepthLimit:
		return issue
	}
	return ""
}

// argsInsideLimits reports raw that no bound of validateJSONWithStringLimit
// can stop, in one pass over the bytes with no allocation: no string, key or
// value, that may decode longer than maxScalarBytes (an escape never decodes
// longer than it is written, a byte of 0x80 or more may decode to the three
// bytes of U+FFFD), at most maxJSONMembers commas and openings (every member
// but the first of a container follows a comma, so they bound the members),
// no nesting deeper than maxJSONDepth and no unterminated string. False only
// means the decode must decide.
func argsInsideLimits(raw []byte) bool {
	depth, items, run := 0, 0, 0
	inString, escaped := false, false
	for _, c := range raw {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
				continue
			}
			if c >= 0x80 {
				run += 3
			} else {
				run++
			}
			if run > maxScalarBytes {
				return false
			}
			continue
		}
		switch c {
		case '"':
			inString, run = true, 0
		case '{', '[':
			depth++
			items++
			if depth > maxJSONDepth {
				return false
			}
		case '}', ']':
			depth--
		case ',':
			items++
		}
		if items > maxJSONMembers {
			return false
		}
	}
	return !inString
}

// ReadArgumentField returns the canonical field read for an argument
// key at any reader-permitted envelope depth. It uses the same
// strings.ToLower mapping as the shared reader; callers
// must not use Unicode simple folding to group aliases.
func ReadArgumentField(key string) (string, bool) {
	return canonicalInputFieldName(key)
}

// ReadArgumentKeyRank is how directly the structured argument reading reads
// an argument key: 0 for a key it reads as spelled (canonicalInputFieldName's
// command, cmd, script, path, file_path, url, ... and the closed file-tool
// keys), 1 for another spelling of one of those (it folds case), 2 for a key
// it does not read. A caller that projects arguments to fit the reading's
// bounds keeps the read keys first, so padding members cannot push them out
// of the projection (substrate-1:GAP-1094).
func ReadArgumentKeyRank(key string) int {
	if closedFileToolArgumentKeys[key] {
		return 0
	}
	if _, ok := canonicalInputFieldName(key); ok {
		if strings.ToLower(key) == key {
			return 0
		}
		return 1
	}
	return 2
}
