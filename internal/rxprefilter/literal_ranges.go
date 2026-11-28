// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package rxprefilter

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// A rule such as the credential-named assignment (SEC-SECRET-ASSIGN) is
// case-insensitive and reads spaces and punctuation, so neither the literal
// check (MayMatch) nor the search in runs (windows.go) spares it a text
// that names one of its keywords anywhere: Go's automaton then reads the
// whole text. A streamed reply is checked every 500 bytes of text, so one
// keyword early in a long reply made each check read the whole reply again
// (GAP-1697).
//
// Every match of such an expression holds one of the literals of a required
// clause, and starts at most reach runes before that literal (the parts of
// the expression in front of it are bounded). So the leftmost match starts
// in one of the ranges [hit-reach, hit] of the clause's literal hits, and
// the search reads only those ranges: from each range's start, it runs the
// expression anchored behind a lazy skip of at most reach runes, which finds
// the leftmost start in the range and, at that start, the match the
// whole-text search prefers. The rune before the range is read too, so the
// assertions (\b, ^ in multi-line mode) see their real neighbour, and the
// rest of the text after the range is there, so a match may be as long as it
// is in the whole text: no window cuts a match. The matches, their order and
// their offsets are those of the whole-text search.
//
// The search is used only for a valid UTF-8 text (so the rune steps back
// from a hit are the ones the automaton reads forward) whose case fold keeps
// every rune's width (so a hit in the fold is at the same offset in the
// text), and only when the ranges are a small part of the text. Any other
// text, and any expression without such a clause, is searched whole, as
// before.

// MaxLiteralReach bounds the reach of a clause the search uses: a farther
// literal gives ranges too wide to save anything.
const MaxLiteralReach = 256

// literalPlan is the search of one expression in the ranges of a clause.
type literalPlan struct {
	ok     bool
	clause clause
	reach  int // runes from a match start to the start of its literal, at most
	// fromStart is the anchored search from the start of the text, behind
	// the lazy skip; afterRune the one that reads one rune of context
	// first.
	fromStart *regexp.Regexp
	afterRune *regexp.Regexp
}

var literalPlans sync.Map // *regexp.Regexp -> *literalPlan

func literalPlanFor(re *regexp.Regexp) *literalPlan {
	if cached, ok := literalPlans.Load(re); ok {
		return cached.(*literalPlan)
	}
	plan := &literalPlan{}
	if parsed, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		parsed = parsed.Simplify()
		if !neverMatches(parsed) {
			if best, ok := bestReachClause(requiredReach(parsed)); ok && best.reach >= 0 && best.reach <= MaxLiteralReach {
				skip := `(?s:.{0,` + strconv.Itoa(best.reach) + `}?)`
				fromStart, err1 := regexp.Compile(`\A` + skip + `(` + re.String() + `)`)
				afterRune, err2 := regexp.Compile(`\A(?s:.)` + skip + `(` + re.String() + `)`)
				if err1 == nil && err2 == nil {
					plan = &literalPlan{ok: true, clause: best.clause, reach: best.reach, fromStart: fromStart, afterRune: afterRune}
				}
			}
		}
	}
	actual, _ := literalPlans.LoadOrStore(re, plan)
	return actual.(*literalPlan)
}

// reachClause is a clause every match satisfies with a literal that starts
// at most reach runes after the match start; reach -1 means no bound.
type reachClause struct {
	clause clause
	reach  int
}

// requiredReach is required with the reach of each clause.
func requiredReach(re *syntax.Regexp) []reachClause {
	switch re.Op {
	case syntax.OpLiteral:
		if l, ok := newLiteral(re.Rune, re.Flags&syntax.FoldCase != 0); ok {
			return []reachClause{{clause{l}, 0}}
		}
		return nil
	case syntax.OpCapture, syntax.OpPlus:
		// The first repetition of a plus starts where the plus does.
		return requiredReach(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredReach(re.Sub[0])
		}
		return nil
	case syntax.OpAlternate:
		var joined reachClause
		for _, sub := range re.Sub {
			best, ok := bestReachClause(requiredReach(sub))
			if !ok {
				return nil
			}
			joined.clause = append(joined.clause, best.clause...)
			if len(joined.clause) > maxClause {
				return nil
			}
			if best.reach < 0 || joined.reach < 0 {
				joined.reach = -1
			} else {
				joined.reach = max(joined.reach, best.reach)
			}
		}
		return []reachClause{joined}
	case syntax.OpConcat:
		var out []reachClause
		offset := 0 // runes before the current part, at most; -1 no bound
		var run []rune
		runFold, runOffset := false, 0
		flush := func() {
			if len(run) > 0 {
				if l, ok := newLiteral(run, runFold); ok {
					out = append(out, reachClause{clause{l}, runOffset})
				}
			}
			run = nil
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				fold := sub.Flags&syntax.FoldCase != 0
				if len(run) > 0 && fold != runFold {
					flush()
				}
				if len(run) == 0 {
					runOffset = offset
				}
				run, runFold = append(run, sub.Rune...), fold
				offset = addReach(offset, len(sub.Rune))
				continue
			}
			flush()
			for _, c := range requiredReach(sub) {
				out = append(out, reachClause{c.clause, addReach(offset, c.reach)})
			}
			offset = addReach(offset, maxRunes(sub))
		}
		flush()
		return out
	default:
		return nil
	}
}

// addReach adds two bounds; -1 is no bound.
func addReach(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return a + b
}

// bestReachClause is the most selective clause with a bound reach (the
// shortest literal longest, then the fewest literals, then the nearest),
// or the most selective clause when none is bound, so an alternation of
// unbounded branches joins as unbounded.
func bestReachClause(clauses []reachClause) (reachClause, bool) {
	best, found := reachClause{}, false
	better := func(c reachClause) bool {
		if !found {
			return true
		}
		if (c.reach >= 0) != (best.reach >= 0) {
			return c.reach >= 0
		}
		if a, b := clauseScore(c.clause), clauseScore(best.clause); a != b {
			return a > b
		}
		if len(c.clause) != len(best.clause) {
			return len(c.clause) < len(best.clause)
		}
		return c.reach >= 0 && c.reach < best.reach
	}
	for _, c := range clauses {
		if len(c.clause) > 0 && clauseScore(c.clause) > 0 && better(c) {
			best, found = c, true
		}
	}
	return best, found
}

// maxRunes is the most runes a match of re holds, -1 when unbounded.
func maxRunes(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpNoMatch:
		return 0
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture:
		return maxRunes(re.Sub[0])
	case syntax.OpQuest:
		return maxRunes(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		if maxRunes(re.Sub[0]) == 0 {
			return 0
		}
		return -1
	case syntax.OpRepeat:
		n := maxRunes(re.Sub[0])
		if n < 0 || (re.Max < 0 && n > 0) {
			return -1
		}
		if re.Max < 0 {
			return 0
		}
		return re.Max * n
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			total = addReach(total, maxRunes(sub))
		}
		return total
	case syntax.OpAlternate:
		longest := 0
		for _, sub := range re.Sub {
			n := maxRunes(sub)
			if n < 0 {
				return -1
			}
			longest = max(longest, n)
		}
		return longest
	default:
		return -1
	}
}

// literalHitCost is the work of one range beyond its reach, in bytes: the
// literal and the rest of a match the anchored search reads.
const literalHitCost = 96

// hits returns the start offsets of every hit of plan's clause in the text,
// in order, and ok false when the text is not searched in ranges (not valid
// UTF-8, a case fold that changes a rune's width, or ranges that cover so
// much of the text that the search saves nothing).
func (t *Text) hits(plan *literalPlan) ([]int, bool) {
	t.hitMu.Lock()
	defer t.hitMu.Unlock()
	if cached, found := t.hitSets[plan]; found {
		return cached.offsets, cached.ok
	}
	set := t.findHits(plan)
	if t.hitSets == nil {
		t.hitSets = map[*literalPlan]hitSet{}
	}
	t.hitSets[plan] = set
	return set.offsets, set.ok
}

type hitSet struct {
	offsets []int
	ok      bool
}

func (t *Text) findHits(plan *literalPlan) hitSet {
	if !t.validUTF8() {
		return hitSet{}
	}
	folded, aligned := "", true
	for _, l := range plan.clause {
		if l.fold {
			folded, aligned = t.foldAligned()
			break
		}
	}
	if !aligned {
		return hitSet{}
	}
	limit := len(t.text) / (2 * (plan.reach + literalHitCost))
	seen := map[int]bool{}
	var offsets []int
	for _, l := range plan.clause {
		haystack := t.text
		if l.fold {
			haystack = folded
		}
		for from := 0; from < len(haystack); {
			i := strings.Index(haystack[from:], l.text)
			if i < 0 {
				break
			}
			at := from + i
			if !seen[at] {
				seen[at] = true
				offsets = append(offsets, at)
				if len(offsets) > limit {
					return hitSet{}
				}
			}
			_, width := utf8.DecodeRuneInString(haystack[at:])
			from = at + width
		}
	}
	slices.Sort(offsets)
	return hitSet{offsets: offsets, ok: true}
}

// rangeStart is the offset reach runes before at, not before floor.
func rangeStart(text string, at, reach, floor int) int {
	lo := at
	for i := 0; i < reach && lo > floor; i++ {
		_, width := utf8.DecodeLastRuneInString(text[:lo])
		lo -= width
	}
	return max(lo, floor)
}

// findFrom is the leftmost match of the plan's expression that starts at or
// after from, searched in the ranges of the hits at or after from; found
// false when there is none.
func (plan *literalPlan) findFrom(text string, offsets []int, from int) ([]int, bool) {
	for _, at := range offsets {
		if at < from {
			continue
		}
		lo := rangeStart(text, at, plan.reach, from)
		var loc []int
		if lo == 0 {
			loc = plan.fromStart.FindStringSubmatchIndex(text)
		} else {
			_, width := utf8.DecodeLastRuneInString(text[:lo])
			base := lo - width
			if loc = plan.afterRune.FindStringSubmatchIndex(text[base:]); loc != nil {
				loc = []int{0, 0, base + loc[2], base + loc[3]}
			}
		}
		if loc != nil {
			return []int{loc[2], loc[3]}, true
		}
	}
	return nil, false
}

// literalFind is FindStringIndex in the ranges of the hits; ok false when
// the expression or the text is searched whole.
func (t *Text) literalFind(re *regexp.Regexp) (loc []int, ok bool) {
	plan := literalPlanFor(re)
	if !plan.ok {
		return nil, false
	}
	offsets, ok := t.hits(plan)
	if !ok {
		return nil, false
	}
	loc, _ = plan.findFrom(t.text, offsets, 0)
	return loc, true
}

// literalFindAll is FindAllStringIndex(text, -1) in the ranges of the hits.
// No match is empty (each holds a literal), so the next search starts where
// the last match ends, as the whole-text search does.
func (t *Text) literalFindAll(re *regexp.Regexp) (out [][]int, ok bool) {
	plan := literalPlanFor(re)
	if !plan.ok {
		return nil, false
	}
	offsets, ok := t.hits(plan)
	if !ok {
		return nil, false
	}
	for from := 0; ; {
		loc, found := plan.findFrom(t.text, offsets, from)
		if !found {
			return out, true
		}
		out = append(out, loc)
		from = loc[1]
	}
}

// validUTF8 reports whether the text is valid UTF-8, computed once.
func (t *Text) validUTF8() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.validDone {
		t.valid, t.validDone = utf8.ValidString(t.text), true
	}
	return t.valid
}

// foldAligned returns the text's fold (foldCanonical) and whether every rune
// of it has the width of the rune it folds, so an offset in the fold is the
// same offset in the text.
func (t *Text) foldAligned() (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.alignDone {
		aligned := true
		for _, r := range t.text {
			if r >= utf8.RuneSelf && utf8.RuneLen(foldCanonicalRune(r)) != utf8.RuneLen(r) {
				aligned = false
				break
			}
		}
		t.aligned, t.alignDone = aligned, true
	}
	if !t.done {
		if t.memo != nil {
			// A text of a memo folds only what is new since the last one
			// (memo.go): the fold of each mid-stream check is not redone.
			t.folded, t.done = t.memo.fold.Apply(t.text, foldCanonical, SplitBeforeASCII), true
		} else {
			t.folded, t.done = foldCanonical(t.text), true
		}
	}
	return t.folded, t.aligned
}
