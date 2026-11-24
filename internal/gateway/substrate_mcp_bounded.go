// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"reflect"
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
// A large call is never a silent allow. The bridge reads each distinct value
// of a recognized field within its fixed budget; excess members or values
// receive the unknown-tier finding. Projections go to the rules alone. The
// LLM judge and AID read whole params when no earlier argument reading has
// already denied (RV-0841b F6, RV-0841c F2).

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
	// One field may have many spellings, but only eight other distinct
	// values are read. Each may need a head and tail projection.
	substrateMCPMaxAlternateValues = 8
	substrateMCPMaxFieldMembers    = 8
	// Full reading, eight base projections, and two per alternate value:
	// at most 25 rule readings per argument reading. The bridge shares this
	// budget across its readings (substrateMCPReading).
	substrateMCPReadingsPerArgs = 1 + substrateMCPMaxProjections + 2*substrateMCPMaxAlternateValues
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

// substrateMCPBoundedVerdict judges bounded projections and, on the bridge,
// each distinct value hidden by a conflicting read-key alias. A deny returns
// early. Any reading left uncovered is floored at the configured unknown tier.
func (a *APIServer) substrateMCPBoundedVerdict(ctx context.Context, reg registry.Registration, connectorName string,
	args json.RawMessage, full SubstrateCalloutVerdict, judge func(json.RawMessage) SubstrateCalloutVerdict) SubstrateCalloutVerdict {
	issue := actionfacts.ArgsLimitIssue(args)
	rd := substrateMCPReadingOf(ctx)
	out := full
	base := args
	var alternates []json.RawMessage
	overflow := false
	changed := false
	if rd.left != nil && out.Verdict != "deny" {
		base, alternates, changed, overflow = substrateMCPReadFieldVariants(args)
	}
	// Keep small calls with no conflicting values on their original path.
	if issue == "" && !overflow && len(alternates) == 0 {
		return out
	}
	read := func(raw json.RawMessage) {
		if out.Verdict == "deny" {
			return
		}
		if rd.left != nil {
			if *rd.left <= 0 {
				overflow = true
				return
			}
			*rd.left--
		}
		out = substrateMCPStricter(out, judge(raw))
	}
	if issue == "" {
		if changed && len(alternates) > 0 {
			read(base) // the shared reader could not read the original conflict
		}
	} else if out.Verdict != "deny" {
		var projections []json.RawMessage
		if rd.left == nil {
			projections = substrateMCPArgsProjections(base) // callout route
		} else {
			projections = substrateMCPProjectionsUpTo(base, min(substrateMCPMaxProjections, *rd.left))
		}
		if len(projections) == 0 {
			overflow = true
		}
		for _, p := range projections {
			read(p)
		}
	}
	for _, alt := range alternates {
		if out.Verdict == "deny" {
			break
		}
		if actionfacts.ArgsLimitIssue(alt) == "" {
			read(alt)
			continue
		}
		limit := 2 // one value's head and tail, with no unrelated members
		if rd.left != nil {
			limit = min(limit, *rd.left)
		}
		projections := substrateMCPProjectionsUpTo(alt, limit)
		if len(projections) == 0 {
			overflow = true
		}
		for _, p := range projections {
			read(p)
		}
	}
	if out.Verdict != "allow" || (issue == "" && !overflow) {
		return out
	}
	set := bounded.Of(bounded.Bytes)
	switch {
	case overflow:
		set = bounded.Of(bounded.Items)
	case issue == actionfacts.IssueDepthLimit:
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

// substrateMCPReadFieldVariants is bridge-only. It keeps one spelling of
// each field in the base reading, and one isolated reading per other value.
// Sorting makes the representative stable; grouping uses exactly the shared
// reader's canonicalization. Isolated readings cannot inherit ambiguity from
// other fields. The caller floors over-budget input at the unknown tier.
func substrateMCPReadFieldVariants(raw json.RawMessage) (json.RawMessage, []json.RawMessage, bool, bool) {
	if len(raw) == 0 {
		return raw, nil, false, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return raw, nil, false, true
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return raw, nil, false, false
	}
	seen := make(map[string]bool)
	collision := false
	for key := range obj {
		if field, known := actionfacts.ReadArgumentField(key); known {
			if seen[field] {
				collision = true
				break
			}
			seen[field] = true
		}
	}
	if !collision {
		return raw, nil, false, false
	}
	type fieldValues struct {
		members int
		values  []any
	}
	fields := make(map[string]*fieldValues)
	base := make(map[string]any, len(obj))
	var alternates []json.RawMessage
	changed, overflow := false, false
	for _, key := range substrateMCPKeyOrder(obj) {
		value := obj[key]
		field, known := actionfacts.ReadArgumentField(key)
		if !known {
			base[key] = value
			continue
		}
		group := fields[field]
		if group == nil {
			fields[field] = &fieldValues{members: 1, values: []any{value}}
			base[key] = value
			continue
		}
		changed = true
		group.members++
		if group.members > substrateMCPMaxFieldMembers {
			overflow = true
		}
		distinct := true
		for _, prior := range group.values {
			if reflect.DeepEqual(prior, value) {
				distinct = false
				break
			}
		}
		if !distinct {
			continue
		}
		if len(alternates) >= substrateMCPMaxAlternateValues {
			overflow = true
			continue
		}
		group.values = append(group.values, value)
		alt, err := substrateMCPEncode(map[string]any{key: value})
		if err != nil {
			overflow = true
			continue
		}
		alternates = append(alternates, alt)
	}
	if !changed {
		return raw, nil, false, overflow
	}
	enc, err := substrateMCPEncode(base)
	if err != nil {
		return raw, alternates, false, true
	}
	return enc, alternates, true, overflow
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
