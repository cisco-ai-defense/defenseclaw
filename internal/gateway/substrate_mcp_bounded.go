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
// default (substrate-1:GAP-1094). The shared reading is unchanged; the hook
// routes judge the same projections (overBoundToolArgsFindings, GAP-1096),
// and the substrate verdict judges bounded projections
// of such arguments as well and keeps the strictest verdict, then floors an
// allow at the unknown tier of the pack, as the hook routes floor a
// truncated reading: an alert with the evaluation-limit finding in the
// default pack, a block where the pack or guardrail.cascade.unknown says so.
// A large call is never a silent allow. The bridge reads each distinct value
// of a recognized field within its fixed budget; excess members or values
// receive the unknown-tier finding. An exhausted byte budget refuses the
// unresolved call. Projections go to the rules alone. The
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
	// One call may spend at most this many bytes on additional rules
	// readings. The original argument and params readings remain reserved.
	substrateMCPExtraBytesPerCall = 160 << 10
	// Conflicting aliases spend less of that reserve: if a long value
	// exhausts it, the bridge refuses the unresolved call.
	substrateMCPVariantBytesPerArgs = 96 << 10
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
	rulesOnly  bool
	left       *int
	extraBytes *int
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
// early. Item and input limits use the configured unknown tier; a spent
// bridge byte budget refuses an unresolved alias.
func (a *APIServer) substrateMCPBoundedVerdict(ctx context.Context, reg registry.Registration, connectorName string,
	args json.RawMessage, full SubstrateCalloutVerdict, judge func(json.RawMessage) SubstrateCalloutVerdict) SubstrateCalloutVerdict {
	issue := actionfacts.ArgsLimitIssue(args)
	rd := substrateMCPReadingOf(ctx)
	out := full
	base := args
	var alternates []json.RawMessage
	overflow := false
	byteExhausted := false
	depthLimit := false
	changed := false
	if rd.left != nil && out.Verdict != "deny" {
		limit := int(^uint(0) >> 1)
		if rd.extraBytes != nil {
			limit = min(*rd.extraBytes, substrateMCPVariantBytesPerArgs)
		}
		base, alternates, changed, overflow, byteExhausted, depthLimit = substrateMCPReadFieldVariantsUpTo(args, limit)
		if depthLimit && issue == "" {
			issue = actionfacts.IssueDepthLimit
		}
	}
	// Keep small calls with no conflicting values on their original path.
	if issue == "" && !overflow && len(alternates) == 0 {
		return out
	}
	read := func(raw json.RawMessage) {
		if out.Verdict == "deny" {
			return
		}
		if rd.left != nil && *rd.left <= 0 {
			overflow = true
			return
		}
		if rd.extraBytes != nil {
			if len(raw) > *rd.extraBytes {
				overflow = true
				byteExhausted = true
				return
			}
			*rd.extraBytes -= len(raw)
		}
		if rd.left != nil {
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
	if out.Verdict == "deny" || (issue == "" && !overflow && !byteExhausted) {
		return out
	}
	set := bounded.Of(bounded.Bytes)
	switch {
	case issue == actionfacts.IssueDepthLimit:
		set = bounded.Of(bounded.Depth)
	case overflow:
		set = bounded.Of(bounded.Items)
	}
	floor := out
	floor.Source, floor.Reason = "tool_rules", boundedTruncatedTitle+" ("+set.Reason()+")"
	floor.Findings = append(slices.Clip(floor.Findings), evaluationLimitRuleID)
	switch bounded.Unknown(a.boundedTier(ctx, connectorName)) {
	case bounded.Block:
		floor.Verdict, floor.Severity = "deny", "HIGH"
	case bounded.Confirm:
		floor.Verdict, floor.Severity = "ask", "MEDIUM"
		if reg.Unattended {
			floor.Verdict = "deny" // D12: unattended asks deny by default
		}
	default:
		floor.Severity = "MEDIUM"
	}
	if byteExhausted {
		floor.Verdict, floor.Severity = "deny", "HIGH"
		floor.Reason += "; byte budget exhausted"
	}
	if out.Verdict == "ask" && floor.Verdict != "deny" {
		out.Findings = append(slices.Clip(out.Findings), evaluationLimitRuleID)
		return out
	}
	return floor
}

// substrateMCPReadFieldVariantsUpTo is bridge-only. It walks exactly the
// object envelopes and projection depth the shared reader walks. Each
// candidate keeps one value of every conflicting resolved field, including
// conflicts between a parent object and a nested envelope. Values in other
// fields stay in place, so every candidate is a complete rules reading.
func substrateMCPReadFieldVariantsUpTo(raw json.RawMessage, byteLimit int) (json.RawMessage, []json.RawMessage, bool, bool, bool, bool) {
	if len(raw) == 0 {
		return raw, nil, false, false, false, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return raw, nil, false, true, false, false
	}
	root, ok := v.(map[string]any)
	if !ok {
		return raw, nil, false, false, false, false
	}

	first := make(map[string]substrateMCPVariantEntry)
	byPath := make(map[string]substrateMCPVariantEntry)
	counts := make(map[string]int)
	values := make(map[string][]any)
	entries := make(map[string][]substrateMCPVariantEntry)
	var alternates []substrateMCPVariantEntry
	changed, overflow, depthLimit := false, false, false
	var walk func(map[string]any, []string, int)
	walk = func(obj map[string]any, parent []string, depth int) {
		for _, key := range substrateMCPKeyOrder(obj) {
			value := obj[key]
			field, known := actionfacts.ReadArgumentField(key)
			if !known {
				continue
			}
			if depth < actionfacts.MaxArgsProjectionDepth && (field == "nested" || field == "args") {
				if s, isString := value.(string); isString {
					trimmed := strings.TrimSpace(s)
					if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') &&
						actionfacts.ArgsLimitIssue(json.RawMessage(trimmed)) == "" {
						nestedDec := json.NewDecoder(strings.NewReader(trimmed))
						nestedDec.UseNumber()
						var nested any
						if nestedDec.Decode(&nested) == nil {
							switch x := nested.(type) {
							case map[string]any:
								value = substrateMCPVariantString{object: x}
							case []any:
								value = substrateMCPVariantArrayString{elements: x}
							}
							obj[key] = value
						}
					}
				}
			}
			path := append(slices.Clone(parent), key)
			group := substrateMCPVariantGroup(field, value, parent)
			entry := substrateMCPVariantEntry{group: group, path: path}
			byPath[substrateMCPVariantPath(path)] = entry
			if len(entries[group]) < substrateMCPMaxFieldMembers {
				entries[group] = append(entries[group], entry)
			}
			counts[group]++
			if counts[group] > substrateMCPMaxFieldMembers {
				overflow = true
			}
			if _, exists := first[group]; !exists {
				first[group] = entry
				values[group] = []any{value}
			} else {
				changed = true
				distinct := true
				for _, prior := range values[group] {
					if reflect.DeepEqual(prior, value) {
						distinct = false
						break
					}
				}
				if distinct {
					if len(alternates) >= substrateMCPMaxAlternateValues {
						overflow = true
					} else {
						values[group] = append(values[group], value)
						alternates = append(alternates, entry)
					}
				}
			}
			if field != "nested" && field != "args" {
				continue
			}
			if depth >= actionfacts.MaxArgsProjectionDepth {
				// The shared reader reports IssueDepthLimit for this envelope.
				// Carry it to the unknown-tier floor before forwarding.
				depthLimit, overflow = true, true
				continue
			}
			switch x := value.(type) {
			case map[string]any:
				walk(x, path, depth+1)
			case substrateMCPVariantString:
				walk(x.object, path, depth+1)
			}
		}
	}
	walk(root, nil, 0)
	if !changed {
		return raw, nil, false, overflow, false, depthLimit
	}

	selected := make(map[string][]string, len(first))
	for group, entry := range first {
		selected[group] = entry.path
	}
	makeReading := func(entry *substrateMCPVariantEntry) (json.RawMessage, error) {
		choice := make(map[string][]string, len(selected))
		for group, path := range selected {
			choice[group] = path
		}
		if entry != nil {
			choice[entry.group] = entry.path
			// A variant inside an alternate envelope must keep that
			// envelope rather than the baseline envelope.
			for i := 1; i < len(entry.path); i++ {
				if ancestor, exists := byPath[substrateMCPVariantPath(entry.path[:i])]; exists {
					choice[ancestor.group] = ancestor.path
				}
			}
		}
		// Keep another resolved field's value from the selected envelope
		// when its baseline value belonged to an envelope now removed.
		groups := make([]string, 0, len(choice))
		for group := range choice {
			groups = append(groups, group)
		}
		slices.SortFunc(groups, func(a, b string) int {
			if c := cmp.Compare(len(first[a].path), len(first[b].path)); c != 0 {
				return c
			}
			return strings.Compare(a, b)
		})
		for _, group := range groups {
			if substrateMCPVariantCompatible(choice[group], choice, byPath) {
				continue
			}
			for _, candidate := range entries[group] {
				if substrateMCPVariantCompatible(candidate.path, choice, byPath) {
					choice[group] = candidate.path
					break
				}
			}
		}
		return substrateMCPEncode(substrateMCPVariantCopy(root, nil, choice, len(raw) > 64<<10))
	}
	base, err := makeReading(nil)
	if err != nil {
		return raw, nil, false, true, false, depthLimit
	}
	out := make([]json.RawMessage, 0, len(alternates))
	remaining := byteLimit - len(base)
	byteExhausted := false
	if remaining < 0 {
		overflow = true
		byteExhausted = true
	}
	for i := range alternates {
		if remaining <= 0 {
			overflow = true
			byteExhausted = true
			break
		}
		alt, err := makeReading(&alternates[i])
		if err != nil {
			overflow = true
			continue
		}
		duplicate := bytes.Equal(alt, base)
		for _, prior := range out {
			if bytes.Equal(alt, prior) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(alt) > remaining {
			overflow = true
			byteExhausted = true
			break
		}
		remaining -= len(alt)
		out = append(out, alt)
	}
	return base, out, true, overflow, byteExhausted, depthLimit
}

type substrateMCPVariantEntry struct {
	group string
	path  []string
}

// A nested JSON string remains a string in each candidate. The reader also
// accepts object envelopes; changing the shape would be an inaccurate read.
type substrateMCPVariantString struct {
	object map[string]any
}

type substrateMCPVariantArrayString struct {
	elements []any
}

func substrateMCPVariantCompatible(path []string, choice map[string][]string, byPath map[string]substrateMCPVariantEntry) bool {
	for i := 1; i < len(path); i++ {
		if ancestor, exists := byPath[substrateMCPVariantPath(path[:i])]; exists &&
			!slices.Equal(choice[ancestor.group], ancestor.path) {
			return false
		}
	}
	return true
}

func substrateMCPVariantPath(path []string) string {
	return strings.Join(path, "\x00")
}

func substrateMCPVariantGroup(field string, value any, parent []string) string {
	if field == "nested" {
		switch value.(type) {
		case map[string]any, substrateMCPVariantString:
			return "nested\x00" + substrateMCPVariantPath(parent)
		case []any, substrateMCPVariantArrayString:
			return "argv"
		case string:
			return "command"
		}
	}
	if field == "args" {
		switch value.(type) {
		case map[string]any, substrateMCPVariantString:
			return "args\x00" + substrateMCPVariantPath(parent)
		case []any, substrateMCPVariantArrayString:
			return "argv"
		case string:
			return "command"
		}
	}
	return field
}

func substrateMCPVariantCopy(v any, parent []string, selected map[string][]string, focus bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, value := range x {
			field, known := actionfacts.ReadArgumentField(key)
			if !known && focus {
				continue
			}
			path := append(slices.Clone(parent), key)
			if known {
				group := substrateMCPVariantGroup(field, value, parent)
				if !slices.Equal(path, selected[group]) {
					continue
				}
			}
			if (field == "nested" || field == "args") && len(parent) < actionfacts.MaxArgsProjectionDepth {
				out[key] = substrateMCPVariantCopy(value, path, selected, focus)
			} else {
				out[key] = value
			}
		}
		return out
	case substrateMCPVariantString:
		nested := substrateMCPVariantCopy(x.object, parent, selected, focus)
		enc, _ := substrateMCPEncode(nested)
		return string(enc)
	case substrateMCPVariantArrayString:
		enc, _ := substrateMCPEncode(x.elements)
		return string(enc)
	default:
		return v
	}
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
	out, _ := substrateMCPProjectionsRead(raw, limit, false)
	return out
}

// substrateMCPProjectionsRead is substrateMCPProjectionsUpTo, and whether
// the projections leave unread a part of raw the structured reading reads
// (substrate-1:GAP-1096): a command, argv, cwd, path, source, destination,
// target, url or method value, at the top level or in an input, parameters
// or request envelope, that a projection cuts or drops a part of, a member
// of such an object it drops that the reading reads (a payload field too:
// the reading keeps that it is there), or a window it does not judge. A cut
// payload field keeps what the reading keeps of it, its kind and that it is
// not empty; members, containers and strings the reading does not read lose
// nothing. False only when every part the rules read was judged whole.
//
// With readOnly the projections keep only the members the structured
// reading reads (substrateMCPReadKey, at the top level and in envelopes):
// the hook routes judge the whole call as well, so a projection there only
// has to give the structured reading its facts, and dropping the rest keeps
// a padded call to one small extra reading (substrate-1:GAP-1096).
func substrateMCPProjectionsRead(raw json.RawMessage, limit int, readOnly bool) ([]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if limit <= 0 || dec.Decode(&v) != nil {
		return nil, true
	}
	windows := [][]string{nil}
	var dropped []string // top-level keys past the last window
	obj, isObj := v.(map[string]any)
	if isObj && readOnly {
		kept := make(map[string]any, len(obj))
		for k, e := range obj {
			if substrateMCPReadKey(k) {
				kept[k] = e
			}
		}
		obj, v = kept, kept
	}
	if isObj && len(obj) > substrateMCPWindowMembers {
		keys := substrateMCPKeyOrder(obj)
		windows = nil
		i := 0
		for ; i < len(keys) && len(windows) < substrateMCPMaxWindows; i += substrateMCPWindowMembers {
			windows = append(windows, keys[i:min(i+substrateMCPWindowMembers, len(keys))])
		}
		if i < len(keys) {
			dropped = keys[i:]
		}
	}
	unread := false
	keysUnread := func(keys []string) {
		for _, k := range keys {
			if !unread && substrateMCPReadKey(k) {
				unread = true
			}
		}
	}
	keysUnread(dropped)
	var out []json.RawMessage
	for w, window := range windows {
		var head json.RawMessage
		judged := false
		for _, tail := range []bool{false, true} {
			if len(out) >= limit {
				break
			}
			for _, strMax := range substrateMCPStringLimits {
				p := substrateMCPProjector{tail: tail, strMax: strMax, readOnly: readOnly}
				enc, err := substrateMCPEncode(p.value(v, 0, window))
				if err != nil || actionfacts.ArgsLimitIssue(enc) != "" {
					continue
				}
				if !tail {
					head = enc
					out = append(out, enc)
					judged = true
					unread = unread || p.lost
				} else if !bytes.Equal(enc, head) {
					out = append(out, enc)
				}
				break
			}
		}
		if !judged {
			// No projection of this window fits, or the limit stops first.
			if !isObj || window == nil {
				return out, true
			}
			keysUnread(window)
		}
		if len(out) >= limit {
			for _, rest := range windows[w+1:] {
				keysUnread(rest)
			}
			return out, unread
		}
	}
	return out, unread
}

// substrateMCPReadKey reports a key the structured reading reads where it
// reads keys (actionfacts.ReadArgumentField): losing such a member, a
// payload field too, changes what the reading sees.
func substrateMCPReadKey(key string) bool {
	_, known := actionfacts.ReadArgumentField(key)
	return known
}

// substrateMCPReadsAKey reports an object with a key the reading reads.
func substrateMCPReadsAKey(obj map[string]any) bool {
	for k := range obj {
		if substrateMCPReadKey(k) {
			return true
		}
	}
	return false
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

func substrateMCPPayloadField(field string) bool {
	switch field {
	case "body", "data", "payload", "content", "headers":
		return true
	}
	return false
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
	// lost is set when the projection cuts or drops a part the structured
	// reading reads (substrateMCPProjectionsRead).
	lost bool
	// readOnly drops the members of an envelope the reading does not read.
	readOnly bool
}

// value is v within the reading's bounds; only, when set, is the keys a
// top-level object keeps.
func (p *substrateMCPProjector) value(v any, depth int, only []string) any {
	_, obj := v.(map[string]any)
	return p.valueRead(v, depth, only, !obj, obj)
}

// valueRead is value. read reports v is (inside) the value of a field the
// structured reading reads whole (a command, argv, path or url value), and
// envelope an object whose keys it reads (the top level and an input,
// parameters or request object: actionfacts extractJSONObject); it reads
// nothing else, so cutting or dropping anything else loses nothing.
func (p *substrateMCPProjector) valueRead(v any, depth int, only []string, read, envelope bool) any {
	switch x := v.(type) {
	case string:
		if read && len(x) > p.strMax {
			p.lost = true
		}
		return substrateMCPCut(x, p.strMax, p.tail)
	case map[string]any:
		if depth >= actionfacts.MaxJSONDepth {
			p.lost = p.lost || read && len(x) > 0 || envelope && substrateMCPReadsAKey(x)
			return nil
		}
		keys := only
		if keys == nil {
			keys = substrateMCPKeyOrder(x)
		}
		out := make(map[string]any, len(keys))
		for i, k := range keys {
			if p.readOnly && envelope && !read && !substrateMCPReadKey(k) {
				continue
			}
			if p.members >= actionfacts.MaxJSONMembers {
				for _, rest := range keys[i:] {
					p.lost = p.lost || read || envelope && substrateMCPReadKey(rest)
				}
				break
			}
			ck := k
			if len(ck) > substrateMCPKeyMax {
				ck = substrateMCPCut(ck, substrateMCPKeyMax, false)
			}
			if _, dup := out[ck]; dup {
				p.lost = p.lost || read || envelope && substrateMCPReadKey(k)
				continue
			}
			p.members++
			field, known := actionfacts.ReadArgumentField(k)
			if known && substrateMCPPayloadField(field) {
				if text, ok := x[k].(string); ok && len(text) > 64 {
					// The shared reader retains only payload kind and
					// non-emptiness. The full reading still sees every
					// payload byte; a projection need not copy 64 KiB of it.
					out[ck] = substrateMCPCut(text, 64, false)
					continue
				}
			}
			childRead, childEnvelope := read, false
			if !read && envelope && known && !substrateMCPPayloadField(field) {
				_, obj := x[k].(map[string]any)
				if field == "nested" && obj {
					childEnvelope = true
				} else {
					childRead = true
				}
			}
			out[ck] = p.valueRead(x[k], depth+1, nil, childRead, childEnvelope)
		}
		return out
	case []any:
		if depth >= actionfacts.MaxJSONDepth {
			p.lost = p.lost || read && len(x) > 0
			return nil
		}
		out := make([]any, 0, min(len(x), actionfacts.MaxJSONMembers))
		for _, e := range x {
			if p.members >= actionfacts.MaxJSONMembers {
				p.lost = p.lost || read
				break
			}
			p.members++
			out = append(out, p.valueRead(e, depth+1, nil, read, false))
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
