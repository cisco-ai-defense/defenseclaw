// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
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
// without the padding where the padding sits beside the command. The
// projections go to the rules alone; the LLM judge and AID read the call's
// own reading (RV-0841b F6).

const (
	// substrateMCPWindowMembers is the most top-level members one projection
	// keeps; an object with more is judged in windows of this many, the keys
	// the rules read first (substrateMCPKeyOrder).
	substrateMCPWindowMembers = actionfacts.MaxJSONMembers * 3 / 4
	// substrateMCPMaxWindows bounds the windows of one reading (two
	// projections each: heads and tails of long strings); the floor covers
	// what they leave out.
	substrateMCPMaxWindows = 4
	// substrateMCPMaxProjections is the most projections one reading adds.
	substrateMCPMaxProjections = 2 * substrateMCPMaxWindows
	// substrateMCPReadingsPerArgs is the most judged readings one argument
	// reading costs: itself and its projections. A bridged call with more
	// readings shares this budget per argument reading (substrateMCPReading).
	substrateMCPReadingsPerArgs = 1 + substrateMCPMaxProjections
	// substrateMCPKeyMax is the longest key a projection keeps whole.
	substrateMCPKeyMax = 1 << 10
	// substrateMCPTailRoom is what a tail cut keeps free for the placeholder
	// word it puts where the cut dropped one (substrateMCPCut).
	substrateMCPTailRoom = len("x ")
)

// substrateMCPStringLimits are the longest strings a projection keeps, the
// largest first that fits the reading's bounds.
var substrateMCPStringLimits = []int{actionfacts.MaxCommandBytes, 16 << 10, 4 << 10, 1 << 10, 256, 64}

// substrateMCPReading is how the bridge has one of a call's readings judged
// when the call has more than one (substrateMCPBridge.judge): rulesOnly
// keeps the reading off the LLM judge and AID, which read the call's whole
// params, and left is the projections the call may still add, shared by its
// readings. The callout route sets neither: one reading, judged in full.
type substrateMCPReading struct {
	rulesOnly bool
	left      *int
}

type substrateMCPReadingKey struct{}

func withSubstrateMCPReading(ctx context.Context, r substrateMCPReading) context.Context {
	return context.WithValue(ctx, substrateMCPReadingKey{}, r)
}

func substrateMCPReadingOf(ctx context.Context) substrateMCPReading {
	r, _ := ctx.Value(substrateMCPReadingKey{}).(substrateMCPReading)
	return r
}

// substrateMCPBoundedVerdict is the verdict of a call whose full reading
// gave full, with judge the rule verdict of one projection of its arguments.
func (a *APIServer) substrateMCPBoundedVerdict(ctx context.Context, reg registry.Registration, connectorName string,
	args json.RawMessage, full SubstrateCalloutVerdict, judge func(json.RawMessage) SubstrateCalloutVerdict) SubstrateCalloutVerdict {
	issue := actionfacts.ArgsLimitIssue(args)
	if issue == "" {
		return full
	}
	out := full
	rd := substrateMCPReadingOf(ctx)
	var projections []json.RawMessage
	switch {
	case out.Verdict == "deny":
	case rd.left == nil:
		projections = substrateMCPArgsProjections(args) // the callout route: one reading
	default:
		projections = substrateMCPProjectionsUpTo(args, min(substrateMCPMaxProjections, *rd.left))
	}
	for _, p := range projections {
		if rd.left != nil {
			*rd.left--
		}
		if out = substrateMCPStricter(out, judge(p)); out.Verdict == "deny" {
			break
		}
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
// the bounds (at most substrateMCPMaxProjections).
func substrateMCPArgsProjections(raw json.RawMessage) []json.RawMessage {
	return substrateMCPProjectionsUpTo(raw, substrateMCPMaxProjections)
}

// substrateMCPProjectionsUpTo is at most limit projections of raw: for each
// window of top-level members (substrateMCPKeyOrder), one with the head and
// one with the tail of every long string (the tail one only when it
// differs), cut at a word boundary so a cut never makes a word the call did
// not carry.
func substrateMCPProjectionsUpTo(raw json.RawMessage, limit int) []json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if limit <= 0 || dec.Decode(&v) != nil {
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
		var head json.RawMessage
		for _, tail := range []bool{false, true} {
			if len(out) >= limit {
				return out
			}
			for _, strMax := range substrateMCPStringLimits {
				p := substrateMCPProjector{tail: tail, strMax: strMax}
				enc, err := substrateMCPEncode(p.value(v, 0, window))
				if err != nil || actionfacts.ArgsLimitIssue(enc) != "" {
					continue
				}
				if !tail {
					head = enc
					out = append(out, enc)
				} else if !bytes.Equal(enc, head) {
					out = append(out, enc)
				}
				break
			}
		}
	}
	return out
}

// substrateMCPKeyOrder is obj's keys in projection order: the keys the
// structured reading reads first (as spelled, then other spellings:
// actionfacts.ReadArgumentKeyRank), then the other scalar members, then the
// other containers, each by key. Padding members, whatever their names,
// never push a command or path out of the first window (RV-0841b F3).
func substrateMCPKeyOrder(obj map[string]any) []string {
	type ranked struct {
		key  string
		rank int
	}
	rs := make([]ranked, 0, len(obj))
	for k, v := range obj {
		r := actionfacts.ReadArgumentKeyRank(k)
		if r == 2 {
			r += substrateMCPContainer(v)
		}
		rs = append(rs, ranked{k, r})
	}
	slices.SortFunc(rs, func(x, y ranked) int {
		if c := cmp.Compare(x.rank, y.rank); c != 0 {
			return c
		}
		return strings.Compare(x.key, y.key)
	})
	keys := make([]string, len(rs))
	for i, r := range rs {
		keys[i] = r.key
	}
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

// substrateMCPWordBreak ends a shell word: a space or an operator.
func substrateMCPWordBreak(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(";&|()<>`", r)
}

// substrateMCPCut is the first (or, with tail, the last) n bytes of s at a
// word boundary. The head drops the word the cut splits when the kept part
// has a space before it. The tail (n less substrateMCPTailRoom) puts the
// placeholder word x where the word the cut splits or ends was, and before
// a first word that followed another word, so what follows keeps its place:
// "AAAA ; rm" keeps "x ; rm" (a command after a separator, RV-0841b F2) and
// "AAAA rm" keeps "x rm" (rm stays an argument). A cut never makes a word
// the call did not carry, nor puts one in command position.
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
	n = max(n-substrateMCPTailRoom, 0)
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	before, rest := s[:i], s[i:]
	last, _ := utf8.DecodeLastRuneInString(before)
	first, _ := utf8.DecodeRuneInString(rest)
	switch {
	case !substrateMCPWordBreak(last) && !substrateMCPWordBreak(first):
		// The cut splits a word: the placeholder stands for it.
		j := strings.IndexFunc(rest, substrateMCPWordBreak)
		if j < 0 {
			return rest
		}
		return "x" + rest[j:]
	case !substrateMCPWordBreak(last):
		// A word ends at the cut.
		return "x" + rest
	}
	// The cut is between words: the first kept word follows a separator
	// (or nothing) and is a command, or follows a word and is not.
	k := strings.LastIndexFunc(before, func(r rune) bool { return r != ' ' && r != '\t' })
	if k < 0 || strings.ContainsRune(";&|(`\n", rune(before[k])) {
		return rest
	}
	return "x " + rest
}
