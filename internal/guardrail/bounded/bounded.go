// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package bounded is the one bound rule of the guardrail readers: a walk,
// extraction or parse that hits a cap (items, depth, paths, effects, bytes,
// locations, nodes, time) reports Truncated, and a truncated input is never
// judged below the unknown tier of the active policy nor below the verdict
// of the part read before the cap (rel-1-0-10:GAP-0301, GAP-0290, GAP-0296,
// GAP-0284, GAP-0285, GAP-0258).
//
// Everything here is a small value type with no allocation, because it runs
// on the hook hot path. A reader keeps one Truncated per call, marks each cap
// it hits, and keeps judging what it read; the caller turns the result into
// the verdict floor with Floor.
package bounded

import "time"

// Cap is the kind of bound a reader hit.
type Cap uint8

// The cap kinds. Each reader names the kind its bound measures.
const (
	// Items counts entries of a list, map or statement sequence.
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
	// Time is a work or wall-clock budget.
	Time
	capEnd
)

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

// Truncated is the set of caps a reader hit. The zero value hit none.
type Truncated struct{ caps uint16 }

// Hit records that cap c cut the reading short.
func (t *Truncated) Hit(c Cap) {
	if c == 0 || c >= capEnd {
		c = Items // a reader that names no kind is still truncated
	}
	t.caps |= 1 << c
}

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
// A zero deadline never expires.
func (t *Truncated) Before(now, deadline time.Time) bool {
	if deadline.IsZero() || now.Before(deadline) {
		return true
	}
	t.Hit(Time)
	return false
}

// Merge adds the caps of o (a nested reader's result).
func (t *Truncated) Merge(o Truncated) { t.caps |= o.caps }

// Any reports that some cap was hit.
func (t Truncated) Any() bool { return t.caps != 0 }

// Has reports that cap c was hit.
func (t Truncated) Has(c Cap) bool { return c != 0 && c < capEnd && t.caps&(1<<c) != 0 }

// Of returns a Truncated with the given caps hit.
func Of(caps ...Cap) Truncated {
	var t Truncated
	for _, c := range caps {
		t.Hit(c)
	}
	return t
}

// ReasonCode is the audit reason code of every truncated input.
const ReasonCode = "bounded_truncated"

// Reason is the audit reason of t: "bounded_truncated cap=paths,depth" (cap
// kinds in their declared order), or "" when no cap was hit. It allocates;
// call it only for a truncated input.
func (t Truncated) Reason() string {
	if !t.Any() {
		return ""
	}
	buf := make([]byte, 0, len(ReasonCode)+32)
	buf = append(buf, ReasonCode...)
	buf = append(buf, " cap="...)
	first := true
	for c := Items; c < capEnd; c++ {
		if t.Has(c) {
			if !first {
				buf = append(buf, ',')
			}
			buf = append(buf, capNames[c]...)
			first = false
		}
	}
	return string(buf)
}

// Counter counts one cap kind across a walk:
//
//	paths := bounded.NewCounter(bounded.Paths, maxPaths)
//	if !paths.Take(&trunc) { break }
type Counter struct {
	n, max int
	cap    Cap
}

// NewCounter is a counter of cap c that allows max takes.
func NewCounter(c Cap, max int) Counter { return Counter{max: max, cap: c} }

// Take counts one item. It is false once the count is past max, and then
// records the cap in t.
func (k *Counter) Take(t *Truncated) bool { return k.TakeN(1, t) }

// TakeN counts n items (bytes of a string, for example).
func (k *Counter) TakeN(n int, t *Truncated) bool {
	k.n += n
	return t.Within(k.cap, k.n, k.max)
}

// Count is the number taken so far.
func (k Counter) Count() int { return k.n }

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

// ParseAction reads a gateway action name; an unknown name is Allow.
func ParseAction(s string) Action {
	for i, name := range actionNames {
		if s == name {
			return Action(i)
		}
	}
	return Allow
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
	if tier == TierStrict {
		return Block
	}
	return Alert
}

// Floor is the verdict of an input read up to a cap: base (the verdict of
// what was read before the cap) when no cap was hit, else the stricter of
// base and the unknown tier.
func Floor(base Action, t Truncated, tier Tier) Action {
	if !t.Any() {
		return base
	}
	return Stricter(base, Unknown(tier))
}
