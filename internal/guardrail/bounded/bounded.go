// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package bounded is the one bound rule of the guardrail readers: a walk,
// extraction or parse that hits a cap (items, depth, paths, effects, bytes,
// locations, nodes, time) reports it, and a truncated input is never judged
// below the unknown tier of the active pack nor below the verdict of the part
// read before the cap (rel-1-0-10:GAP-0301, GAP-0290, GAP-0296, GAP-0284,
// GAP-0285, GAP-0258).
//
// A reader keeps one Truncated per call (never copied, never shared between
// goroutines: go vet's copylocks check flags a copy), counts with Counters
// bound to it, keeps judging what it read, and returns the CapSet of the caps
// it hit (Truncated.Set). The caller turns that CapSet into the verdict floor
// with Floor. Nothing here allocates on the hot path.
package bounded

import (
	"math"
	"testing"
	"time"
)

// Cap is the kind of bound a reader hit.
type Cap uint8

// The cap kinds. Each reader names the kind its bound measures.
const (
	// Items counts entries of a list, map, statement sequence or operands.
	Items Cap = iota + 1
	// Depth counts nesting levels.
	Depth
	// Paths counts path targets.
	Paths
	// Effects counts read, write, exec or network effects.
	Effects
	// Bytes counts the size of a string, body or text.
	Bytes
	// Locations counts the locations a frame names (ACP).
	Locations
	// Nodes counts values of any kind walked (JSON or syntax tree nodes).
	Nodes
	// Time is a work budget (counted in work units, see Counter) or a
	// wall-clock deadline (Truncated.Before).
	Time
	capEnd
)

// CapSet holds one bit per cap kind: a new kind past bit 15 must not compile
// (it would shift to nothing and record no hit).
var _ [16 - capEnd]struct{}

var capNames = [capEnd]string{"", "items", "depth", "paths", "effects", "bytes", "locations", "nodes", "time"}

// String is the cap's audit name ("paths").
func (c Cap) String() string {
	if c == 0 || c >= capEnd {
		return "unknown"
	}
	return capNames[c]
}

// Caps lists every cap kind, for tables and tests.
func Caps() []Cap {
	return []Cap{Items, Depth, Paths, Effects, Bytes, Locations, Nodes, Time}
}

// CapSet is the set of caps a reading hit: a plain value a reader returns in
// its result. The zero value hit none.
type CapSet struct{ bits uint16 }

// Of is the CapSet of the given caps. A cap with no kind (0 or out of range)
// counts as Items: a reader that names no kind is still truncated.
func Of(caps ...Cap) CapSet {
	var s CapSet
	for _, c := range caps {
		s = s.with(c)
	}
	return s
}

func (s CapSet) with(c Cap) CapSet {
	if c == 0 || c >= capEnd {
		c = Items
	}
	s.bits |= 1 << c
	return s
}

// Union is the caps of s and o.
func (s CapSet) Union(o CapSet) CapSet { return CapSet{s.bits | o.bits} }

// Any reports that some cap was hit.
func (s CapSet) Any() bool { return s.bits != 0 }

// Has reports that cap c was hit.
func (s CapSet) Has(c Cap) bool { return c != 0 && c < capEnd && s.bits&(1<<c) != 0 }

// ReasonCode is the audit reason code of every truncated input.
const ReasonCode = "bounded_truncated"

// Reason is the audit reason of s: "bounded_truncated cap=paths,depth" (cap
// kinds in their declared order), or "" when no cap was hit. It allocates;
// call it only for a truncated input.
func (s CapSet) Reason() string {
	if !s.Any() {
		return ""
	}
	buf := make([]byte, 0, len(ReasonCode)+32)
	buf = append(buf, ReasonCode...)
	buf = append(buf, " cap="...)
	first := true
	for c := Items; c < capEnd; c++ {
		if s.Has(c) {
			if !first {
				buf = append(buf, ',')
			}
			buf = append(buf, capNames[c]...)
			first = false
		}
	}
	return string(buf)
}

// noCopy makes go vet (copylocks) flag a copy of the struct holding it.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Truncated records the caps one reading hit. Keep one per call, pass it by
// pointer, and do not share it between goroutines: a copy loses the hits
// made through it (go vet flags copies). The zero value hit none.
type Truncated struct {
	_   noCopy
	set CapSet
}

// Hit records that cap c cut the reading short.
func (t *Truncated) Hit(c Cap) { t.set = t.set.with(c) }

// Within reports n <= max; past max it records cap c. A reader calls it with
// the count it is about to reach and stops reading that branch when it is
// false:
//
//	if !t.Within(bounded.Depth, depth, maxDepth) { return }
func (t *Truncated) Within(c Cap, n, max int) bool {
	if n <= max {
		return true
	}
	t.Hit(c)
	return false
}

// Before reports that now is before deadline; at or after it records Time.
// A zero deadline is a reader that never set one: it records Time too, so a
// forgotten deadline shows as a truncated input instead of a cap that never
// trips. A reader with no time bound does not call Before.
func (t *Truncated) Before(now, deadline time.Time) bool {
	if !deadline.IsZero() && now.Before(deadline) {
		return true
	}
	t.Hit(Time)
	return false
}

// Merge adds the caps of a nested reading.
func (t *Truncated) Merge(s CapSet) { t.set = t.set.Union(s) }

// Any reports that some cap was hit.
func (t *Truncated) Any() bool { return t.set.Any() }

// Set is the caps hit so far, the value a reader returns. Pass the reader's
// Counters: their hits are included even when a Counter was bound to another
// Truncated by mistake, or never bound (a zero Counter). Under go test such a
// Counter panics here instead, so the mistake is found where it is made.
func (t *Truncated) Set(counters ...*Counter) CapSet {
	set := t.set
	for _, k := range counters {
		if k == nil {
			continue
		}
		if k.t != t {
			if misboundPanics {
				panic("bounded: a Counter passed to Truncated.Set is bound to another Truncated (or none); make it with NewCounter(&thisTruncated, ...)")
			}
			if k.t != nil {
				set = set.Union(k.t.set)
			}
		}
		set = set.Union(k.own)
	}
	return set
}

// misboundPanics makes Set panic on a misbound Counter in test binaries; a
// production gateway merges its hits instead.
var misboundPanics = testing.Testing()

// Counter counts one cap kind across a walk and records its hit in the
// Truncated it was made for. Like Truncated it is used by pointer and never
// copied (a copy restarts the count, so the cap would never trip):
//
//	paths := bounded.NewCounter(&trunc, bounded.Paths, maxPaths)
//	if !paths.Take() { break }
//
// A Time cap counted in work units (one per node, statement or effect the
// reader visits) trips on the same input on every host; prefer it to a
// wall-clock deadline.
type Counter struct {
	_      noCopy
	t      *Truncated
	own    CapSet // the hits of a Counter with no Truncated (a zero Counter)
	n, max int
	cap    Cap
}

// NewCounter is a counter of cap c that allows max takes and records its hit
// in t. Assign it once (a field of the reader, or a local) and use it there.
func NewCounter(t *Truncated, c Cap, max int) Counter {
	return Counter{t: t, max: max, cap: c}
}

// Take counts one item. It is false once the count is past max, and then
// records the cap.
func (k *Counter) Take() bool { return k.TakeN(1) }

// TakeN counts n items (the bytes of a string, for example). A negative n is
// a reader error, never a refund: it records the cap and is false. The count
// saturates instead of wrapping. A zero Counter (not made by NewCounter) has
// a max of 0, so its first take records the cap (as items) and is false; the
// hit reaches the result through Truncated.Set(counters...).
func (k *Counter) TakeN(n int) bool {
	switch {
	case n < 0:
		k.n = math.MaxInt
	case n > math.MaxInt-k.n:
		k.n = math.MaxInt
	default:
		k.n += n
	}
	if k.n <= k.max {
		return true
	}
	if k.t != nil {
		k.t.Hit(k.cap)
	} else {
		k.own = k.own.with(k.cap)
	}
	return false
}

// Action is a guardrail verdict, ordered from the weakest to the strictest.
type Action uint8

const (
	Allow Action = iota
	Alert
	Confirm
	Block
)

var actionNames = [...]string{"allow", "alert", "confirm", "block"}

// String is the gateway's action name.
func (a Action) String() string {
	if int(a) < len(actionNames) {
		return actionNames[a]
	}
	return "block"
}

// ParseAction reads a gateway action name, in any case and with surrounding
// ASCII white space. "ask" is Confirm. An empty name is Allow. Any other name is Block
// and known false: a verdict the floor cannot read is never lowered.
func ParseAction(s string) (a Action, known bool) {
	start, end := 0, len(s)
	for start < end && asciiSpace(s[start]) {
		start++
	}
	for end > start && asciiSpace(s[end-1]) {
		end--
	}
	s = s[start:end]
	if s == "" {
		return Allow, true
	}
	if equalFoldASCII(s, "ask") {
		return Confirm, true
	}
	for i, name := range actionNames {
		if equalFoldASCII(s, name) {
			return Action(i), true
		}
	}
	return Block, false
}

func asciiSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func equalFoldASCII(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// Stricter is the stricter of a and b.
func Stricter(a, b Action) Action {
	if b > a {
		return b
	}
	return a
}

// Tier is the policy tier of the active rule pack. A managed install is
// judged by its pack like any other install: a managed install that runs the
// default pack is in the default tier (rel-1-0-6:GAP-0675).
type Tier uint8

const (
	TierDefault Tier = iota
	TierPermissive
	TierStrict
	// TierConfirm is the tier guardrail.cascade.unknown: confirm selects: an
	// unknown case asks where the connector can (its confirm mapping applies
	// where it cannot). No pack posture maps to it.
	TierConfirm
)

// TierOf is the tier of a pack posture as the config resolves it
// (config.HookPolicyTier*: "default", "permissive", "strict"). Any other
// value is the default tier.
func TierOf(posture string) Tier {
	switch posture {
	case "strict":
		return TierStrict
	case "permissive":
		return TierPermissive
	}
	return TierDefault
}

// Unknown is the verdict of the unknown tier: block in the strict pack;
// alert in the default and permissive packs, which never block an unknown
// case (where the connector can ask, its own confirm mapping applies).
func Unknown(tier Tier) Action {
	switch tier {
	case TierStrict:
		return Block
	case TierConfirm:
		return Confirm
	}
	return Alert
}

// Floor is the verdict of an input read up to a cap: base (the verdict of
// what was read before the cap) when no cap was hit, else the stricter of
// base and the unknown tier.
func Floor(base Action, s CapSet, tier Tier) Action {
	if !s.Any() {
		return base
	}
	return Stricter(base, Unknown(tier))
}
