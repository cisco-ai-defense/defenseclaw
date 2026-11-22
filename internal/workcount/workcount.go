// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package workcount counts the costly steps of a hook call: full parses of
// a large command, request argument decodes, whole-text lower-cased copies,
// memo key builds and file lookups. Each counter is one atomic add where the
// work is done. Cost tests assert bounds on these counts for one call, never
// on wall-clock time, so a bound holds on any machine and under any load
// (rel-1-0-10:GAP-0299).
package workcount

import "sync/atomic"

// Kind names one counted step.
type Kind int

const (
	// LargeParse is a full shell parse of a command of 64 KiB or more.
	LargeParse Kind = iota
	// WalkKey is a memo key string or link stack the walk of a write target
	// built through the target memo.
	WalkKey
	// MemoWalk is a walk of a write target through the target memo.
	MemoWalk
	// ArgsDecode is a JSON decode of tool arguments of 64 KiB or more.
	ArgsDecode
	// TextLower is a lower-cased copy of a text of 64 KiB or more.
	TextLower
	// WordLookup is a file system lookup (lstat or stat) made while
	// resolving a word of a command as a write target.
	WordLookup
	// RegexRun is a rule regex run over a text of 64 KiB or more.
	RegexRun
	kinds
)

// Large is the size from which a parse, a decode or a lower-cased copy is
// counted: the size from which the parse cache keeps a command.
const Large = 64 << 10

var counts [kinds]atomic.Int64

// Add counts one step of kind.
func Add(kind Kind) { counts[kind].Add(1) }

// AddLarge counts one step of kind on a text of n bytes when n is Large or
// more.
func AddLarge(kind Kind, n int) {
	if n >= Large {
		counts[kind].Add(1)
	}
}

// Read returns the steps of kind counted since the process started.
func Read(kind Kind) int64 { return counts[kind].Load() }

// Snapshot is the counts at one moment; Since gives the steps after it.
type Snapshot [kinds]int64

// Take reads every counter.
func Take() Snapshot {
	var snap Snapshot
	for kind := range snap {
		snap[kind] = counts[kind].Load()
	}
	return snap
}

// Since returns the steps of kind counted after snap was taken.
func (snap Snapshot) Since(kind Kind) int64 { return counts[kind].Load() - snap[kind] }
