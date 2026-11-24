// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// Arguments past the bounds of the tool-argument reading (a string over
// 64 KiB, over 256 KiB in all, a key over 4 KiB, more than 512 members,
// deeper than 16: actionfacts.ArgsLimitIssue) give the structured rules no
// facts, so padding a denied command with a large value made a bridged
// tools/call (and the methods judged like one, and the callout route) an
// allow; the bridge carries up to mcp_bridge.message_max_bytes, 1 MiB by
// default (substrate-1:GAP-1094). The shared reading is unchanged (the hook
// path has the same bound); the substrate verdict judges bounded projections
// of such arguments as well and keeps the strictest verdict, then floors an
// allow at the unknown tier of the pack, as the hook routes floor a
// truncated reading: an alert with the evaluation-limit finding in the
// default pack, a block where the pack or guardrail.cascade.unknown says so.
// A large call is never a silent allow, and never weaker than the same call
// without the padding where the padding sits beside the command.

const (
	// substrateMCPWindowMembers is the most top-level members one projection
	// keeps; an object with more is judged in windows of this many.
	substrateMCPWindowMembers = actionfacts.MaxJSONMembers * 3 / 4
	// substrateMCPMaxWindows bounds the projections of one call (two each:
	// heads and tails of long strings); the floor covers what they leave out.
	substrateMCPMaxWindows = 4
	// substrateMCPKeyMax is the longest key a projection keeps whole.
	substrateMCPKeyMax = 1 << 10
)

// substrateMCPStringLimits are the longest strings a projection keeps, the
// largest first that fits the reading's bounds.
var substrateMCPStringLimits = []int{actionfacts.MaxCommandBytes, 16 << 10, 4 << 10, 1 << 10, 256, 64}

// substrateMCPBoundedVerdict is the verdict of a call whose full reading
// gave full, with judge the verdict of one reading of its arguments.
func (a *APIServer) substrateMCPBoundedVerdict(ctx context.Context, reg registry.Registration, connectorName string,
	args json.RawMessage, full SubstrateCalloutVerdict, judge func(json.RawMessage) SubstrateCalloutVerdict) SubstrateCalloutVerdict {
	issue := actionfacts.ArgsLimitIssue(args)
	if issue == "" {
		return full
	}
	out := full
	for _, p := range substrateMCPArgsProjections(args) {
		if out.Verdict == "deny" {
			break
		}
		out = substrateMCPStricter(out, judge(p))
	}
	if out.Verdict != "allow" {
		return out
	}
	set := bounded.Of(bounded.Bytes)
	if issue == actionfacts.IssueDepthLimit {
		set = bounded.Of(bounded.Depth)
	}
	out.Source, out.Reason = "tool_rules", boundedTruncatedTitle+" ("+set.Reason()+")"
	out.Findings = append(slices.Clip(out.Findings), evaluationLimitRuleID)
	switch bounded.Unknown(a.boundedTier(ctx, connectorName)) {
	case bounded.Block:
		out.Verdict, out.Severity = "deny", "HIGH"
	case bounded.Confirm:
		out.Verdict, out.Severity = "ask", "MEDIUM"
		if reg.Unattended {
			out.Verdict = "deny" // D12: unattended asks deny by default
		}
	default:
		out.Severity = "MEDIUM"
	}
	return out
}

// substrateMCPStricter is the stricter of two verdicts (deny, ask, allow;
// the first on a tie).
func substrateMCPStricter(a, b SubstrateCalloutVerdict) SubstrateCalloutVerdict {
	rank := func(v SubstrateCalloutVerdict) int {
		switch v.Verdict {
		case "deny":
			return 2
		case "ask":
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// substrateMCPArgsProjections are readings of over-bound arguments that fit
// the bounds: for each window of top-level members (scalars first, then by
// key), one with the head and one with the tail of every long string, cut
// at a word boundary so a cut never makes a word the call did not carry.
func substrateMCPArgsProjections(raw json.RawMessage) []json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	windows := [][]string{nil}
	if obj, ok := v.(map[string]any); ok && len(obj) > substrateMCPWindowMembers {
		keys := substrateMCPKeyOrder(obj)
		windows = nil
		for i := 0; i < len(keys) && len(windows) < substrateMCPMaxWindows; i += substrateMCPWindowMembers {
			windows = append(windows, keys[i:min(i+substrateMCPWindowMembers, len(keys))])
		}
	}
	var out []json.RawMessage
	for _, window := range windows {
		for _, tail := range []bool{false, true} {
			for _, limit := range substrateMCPStringLimits {
				p := substrateMCPProjector{tail: tail, strMax: limit}
				enc, err := substrateMCPEncode(p.value(v, 0, window))
				if err == nil && actionfacts.ArgsLimitIssue(enc) == "" {
					out = append(out, enc)
					break
				}
			}
		}
	}
	return out
}

// substrateMCPKeyOrder is obj's keys with the scalar members first, so a
// small field beside large or deep ones keeps its place in a window.
func substrateMCPKeyOrder(obj map[string]any) []string {
	keys := slices.Sorted(maps.Keys(obj))
	slices.SortStableFunc(keys, func(x, y string) int {
		return substrateMCPContainer(obj[x]) - substrateMCPContainer(obj[y])
	})
	return keys
}

func substrateMCPContainer(v any) int {
	switch v.(type) {
	case map[string]any, []any:
		return 1
	}
	return 0
}

type substrateMCPProjector struct {
	tail    bool
	strMax  int
	members int
}

// value is v within the reading's bounds; only, when set, is the keys a
// top-level object keeps.
func (p *substrateMCPProjector) value(v any, depth int, only []string) any {
	switch x := v.(type) {
	case string:
		return substrateMCPCut(x, p.strMax, p.tail)
	case map[string]any:
		if depth >= actionfacts.MaxJSONDepth {
			return nil
		}
		keys := only
		if keys == nil {
			keys = substrateMCPKeyOrder(x)
		}
		out := make(map[string]any, len(keys))
		for _, k := range keys {
			if p.members >= actionfacts.MaxJSONMembers {
				break
			}
			ck := k
			if len(ck) > substrateMCPKeyMax {
				ck = substrateMCPCut(ck, substrateMCPKeyMax, false)
			}
			if _, dup := out[ck]; dup {
				continue
			}
			p.members++
			out[ck] = p.value(x[k], depth+1, nil)
		}
		return out
	case []any:
		if depth >= actionfacts.MaxJSONDepth {
			return nil
		}
		out := make([]any, 0, min(len(x), actionfacts.MaxJSONMembers))
		for _, e := range x {
			if p.members >= actionfacts.MaxJSONMembers {
				break
			}
			p.members++
			out = append(out, p.value(e, depth+1, nil))
		}
		return out
	}
	return v
}

// substrateMCPCut is the first (or, with tail, the last) n bytes of s, less
// the word the cut splits when the kept part has a space before it.
func substrateMCPCut(s string, n int, tail bool) string {
	if len(s) <= n {
		return s
	}
	if !tail {
		i := n
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		head := s[:i]
		last, _ := utf8.DecodeLastRuneInString(head)
		if r, _ := utf8.DecodeRuneInString(s[i:]); !unicode.IsSpace(r) && !unicode.IsSpace(last) {
			if j := strings.LastIndexFunc(head, unicode.IsSpace); j >= 0 {
				head = head[:j]
			}
		}
		return head
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	rest := s[i:]
	first, _ := utf8.DecodeRuneInString(rest)
	if r, _ := utf8.DecodeLastRuneInString(s[:i]); !unicode.IsSpace(r) && !unicode.IsSpace(first) {
		if j := strings.IndexFunc(rest, unicode.IsSpace); j >= 0 {
			rest = rest[j:]
		}
	}
	return rest
}
