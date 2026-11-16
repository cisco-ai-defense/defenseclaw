// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package rxprefilter

import (
	"regexp"
	"regexp/syntax"
	"sync"
	"unicode"
)

// WindowMinText is the shortest text whose matches are searched in windows:
// under it the automaton over the whole text is a few milliseconds.
const WindowMinText = 64 << 10

// A detection regex such as a card number, a phone number or an IBAN is made
// of digits, letters and a few separators. Go runs its automaton over every
// byte of a benign 900 KB text to find that it matches nowhere (about 35 ms
// per rule per call, and a hook call scans with several such rules). No
// match of such a regex can hold a byte outside the set of bytes the
// expression names, so a match lies wholly inside one maximal run of those
// bytes, and the run is all the regex needs to read. Searching the runs one
// by one, each with the byte on either side of it so that the word-boundary
// assertions see their real neighbours, finds the matches the whole-text
// search finds, in the same order and at the same offsets (GAP-1040).
//
// The plan is made only for an expression that reads no more than the run:
// its bytes are all ASCII, it has no anchor, no any-character and no negated
// class, and it never matches the empty string. Any other expression is
// searched over the whole text as before.

// windowPlan is what the search of an expression in runs relies on.
type windowPlan struct {
	ok       bool
	alphabet [4]uint64 // bit b is set when a match may hold byte b
	minLen   int       // bytes of the shortest match
}

var windowPlans sync.Map // *regexp.Regexp -> windowPlan

func windowPlanFor(re *regexp.Regexp) windowPlan {
	if cached, ok := windowPlans.Load(re); ok {
		return cached.(windowPlan)
	}
	plan := windowPlan{}
	if parsed, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		parsed = parsed.Simplify()
		var alphabet [4]uint64
		if collectAlphabet(parsed, &alphabet) {
			if n := shortestMatch(parsed); n > 0 {
				plan = windowPlan{ok: true, alphabet: alphabet, minLen: n}
			}
		}
	}
	windowPlans.Store(re, plan)
	return plan
}

func addAlphabetByte(alphabet *[4]uint64, r rune) bool {
	if r < 0 || r >= 0x80 {
		return false
	}
	alphabet[r>>6] |= 1 << (uint(r) & 63)
	return true
}

// collectAlphabet adds to alphabet the bytes a match of re may hold and
// reports false when re may read something other than ASCII bytes of that set
// (an any-character, a class that is not ASCII, an anchor).
func collectAlphabet(re *syntax.Regexp, alphabet *[4]uint64) bool {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if !addAlphabetByte(alphabet, r) {
				return false
			}
			if re.Flags&syntax.FoldCase != 0 {
				// (?i) also matches the other members of the fold orbit
				// (the Kelvin sign for k); one that is not ASCII is a byte
				// the run does not hold.
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					if !addAlphabetByte(alphabet, f) {
						return false
					}
				}
			}
		}
		return true
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if !addAlphabetByte(alphabet, r) {
					return false
				}
			}
		}
		return true
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return collectAlphabet(re.Sub[0], alphabet)
	case syntax.OpConcat, syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !collectAlphabet(sub, alphabet) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// shortestMatch is the fewest bytes a match of re holds (every byte of a match
// is ASCII once collectAlphabet accepted re).
func shortestMatch(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return shortestMatch(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * shortestMatch(re.Sub[0])
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			total += shortestMatch(sub)
		}
		return total
	case syntax.OpAlternate:
		shortest := -1
		for _, sub := range re.Sub {
			if n := shortestMatch(sub); shortest < 0 || n < shortest {
				shortest = n
			}
		}
		return max(shortest, 0)
	default:
		return 0
	}
}

// runKey names the runs of one text: the same bytes and the same shortest
// match give the same runs.
type runKey struct {
	alphabet [4]uint64
	minLen   int
}

// runSet is the runs of a text for one runKey; plain is set when the runs
// cover so much of the text that searching them saves nothing.
type runSet struct {
	spans [][2]int
	plain bool
}

// runsFor returns the runs a search of re reads, ok false when re is searched
// over the whole text.
func (t *Text) runsFor(re *regexp.Regexp) ([][2]int, bool) {
	plan := windowPlanFor(re)
	if !plan.ok {
		return nil, false
	}
	key := runKey{plan.alphabet, plan.minLen}
	t.runMu.Lock()
	defer t.runMu.Unlock()
	set, found := t.runs[key]
	if !found {
		set = findRuns(t.text, key)
		if t.runs == nil {
			t.runs = map[runKey]runSet{}
		}
		t.runs[key] = set
	}
	return set.spans, !set.plain
}

func findRuns(text string, key runKey) runSet {
	var set runSet
	covered := 0
	start := -1
	in := func(b byte) bool { return b < 0x80 && key.alphabet[b>>6]&(1<<(b&63)) != 0 }
	for i := 0; i <= len(text); i++ {
		if i < len(text) && in(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= key.minLen {
			set.spans = append(set.spans, [2]int{start, i})
			covered += i - start
		}
		start = -1
	}
	set.plain = covered*2 > len(text)
	return set
}

// context widens a run by the byte before and after it, so an assertion at
// the run edge sees the same neighbour as in the whole text. Neither byte is
// in the alphabet, so no match starts or ends on it.
func context(text string, span [2]int) (lo, hi int) {
	lo, hi = span[0], span[1]
	if lo > 0 {
		lo--
	}
	if hi < len(text) {
		hi++
	}
	return lo, hi
}

// FindStringIndex is re.FindStringIndex on the text.
func (t *Text) FindStringIndex(re *regexp.Regexp) []int {
	if t == nil || re == nil {
		return nil
	}
	if len(t.text) >= WindowMinText {
		if spans, ok := t.runsFor(re); ok {
			for _, span := range spans {
				lo, hi := context(t.text, span)
				if loc := re.FindStringIndex(t.text[lo:hi]); loc != nil {
					return []int{lo + loc[0], lo + loc[1]}
				}
			}
			return nil
		}
	}
	return re.FindStringIndex(t.text)
}

// FindAllStringIndex is re.FindAllStringIndex(text, -1) on the text.
func (t *Text) FindAllStringIndex(re *regexp.Regexp) [][]int {
	if t == nil || re == nil {
		return nil
	}
	if len(t.text) >= WindowMinText {
		if spans, ok := t.runsFor(re); ok {
			var out [][]int
			for _, span := range spans {
				lo, hi := context(t.text, span)
				for _, loc := range re.FindAllStringIndex(t.text[lo:hi], -1) {
					out = append(out, []int{lo + loc[0], lo + loc[1]})
				}
			}
			return out
		}
	}
	return re.FindAllStringIndex(t.text, -1)
}
