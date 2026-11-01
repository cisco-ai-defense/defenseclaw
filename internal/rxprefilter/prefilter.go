// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package rxprefilter skips a regular expression over a text that cannot
// hold a match of it.
//
// Go's regexp has no literal prefilter for case-insensitive alternations, so
// each detection regex runs its full automaton over the whole input. A
// 950 KB benign Bash heredoc spent about 10 s in the gateway's rule scan
// and was denied on Windows as a gateway no-answer (GAP-2279). From the
// parsed expression this package derives literals every match must contain
// (a conjunction of clauses, each a set of alternatives) and reports false
// only when the text misses a clause. An expression it cannot reason about
// always runs, so callers' matches, offsets and validators are unchanged.
package rxprefilter

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// MinText is the shortest text worth the check: below it the regex is
// cheaper than the containment tests.
const MinText = 4096

const (
	// maxClause bounds the alternatives of one clause.
	maxClause = 64
	// maxClauses bounds the clauses of one expression.
	maxClauses = 8
)

// literal is one required literal; fold marks a case-insensitive one, kept
// in foldCanonical form.
type literal struct {
	text string
	fold bool
}

// clause holds when the text contains one of its literals.
type clause []literal

// anchors is the clauses of one expression: every match satisfies all of
// them. ok false means none is known and the expression always runs.
type anchors struct {
	clauses []clause
	ok      bool
	fold    bool
}

var cache sync.Map // *regexp.Regexp -> anchors

func anchorsFor(re *regexp.Regexp) anchors {
	if cached, ok := cache.Load(re); ok {
		return cached.(anchors)
	}
	set := anchors{}
	if parsed, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		if clauses := required(parsed.Simplify()); len(clauses) > 0 {
			set = anchors{clauses: clauses, ok: true}
			for _, c := range clauses {
				for _, l := range c {
					set.fold = set.fold || l.fold
				}
			}
		}
	}
	cache.Store(re, set)
	return set
}

// required returns clauses every match of re satisfies (nil: none known).
func required(re *syntax.Regexp) []clause {
	switch re.Op {
	case syntax.OpLiteral:
		if l, ok := newLiteral(re.Rune, re.Flags&syntax.FoldCase != 0); ok {
			return []clause{{l}}
		}
		return nil
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil
	case syntax.OpAlternate:
		// A match is a match of one branch, so one clause of each branch
		// (its most selective) joined is required.
		var joined clause
		for _, sub := range re.Sub {
			best := bestClause(required(sub))
			if best == nil {
				return nil
			}
			joined = append(joined, best...)
			if len(joined) > maxClause {
				return nil
			}
		}
		return []clause{joined}
	case syntax.OpConcat:
		// Every part of a concatenation is required: all their clauses hold.
		var out []clause
		var run []rune
		runFold := false
		flush := func() {
			if len(run) > 0 {
				if l, ok := newLiteral(run, runFold); ok {
					out = append(out, clause{l})
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
				run, runFold = append(run, sub.Rune...), fold
				continue
			}
			flush()
			out = append(out, required(sub)...)
		}
		flush()
		return strongest(out)
	default:
		return nil
	}
}

// bestClause is the clause whose shortest literal is longest.
func bestClause(clauses []clause) clause {
	var best clause
	bestScore := 0
	for _, c := range clauses {
		if score := clauseScore(c); score > bestScore || (score == bestScore && len(c) < len(best)) {
			best, bestScore = c, score
		}
	}
	return best
}

// strongest keeps at most maxClauses clauses, the most selective first.
func strongest(clauses []clause) []clause {
	if len(clauses) <= maxClauses {
		return clauses
	}
	rest := append([]clause(nil), clauses...)
	out := make([]clause, 0, maxClauses)
	for len(out) < maxClauses {
		best := 0
		for i := range rest {
			if clauseScore(rest[i]) > clauseScore(rest[best]) {
				best = i
			}
		}
		out = append(out, rest[best])
		rest = append(rest[:best], rest[best+1:]...)
	}
	return out
}

func clauseScore(c clause) int {
	score := -1
	for _, l := range c {
		if n := utf8.RuneCountInString(l.text); score < 0 || n < score {
			score = n
		}
	}
	return score
}

func newLiteral(runes []rune, fold bool) (literal, bool) {
	if len(runes) == 0 {
		return literal{}, false
	}
	var b strings.Builder
	for _, r := range runes {
		if r == utf8.RuneError || r < 0 || r > unicode.MaxRune {
			// Invalid input bytes match U+FFFD in the regex but not as bytes.
			return literal{}, false
		}
		if fold {
			r = foldCanonicalRune(r)
		}
		b.WriteRune(r)
	}
	return literal{text: b.String(), fold: fold}, true
}

// foldCanonicalRune maps r to the smallest rune of its simple case-fold
// orbit, the equivalence (?i) matching uses (k, K and the Kelvin sign all
// map to K; s, S and the long s to S).
func foldCanonicalRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < least {
			least = f
		}
	}
	return least
}

func foldCanonical(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		b.WriteRune(foldCanonicalRune(r))
	}
	return b.String()
}

// Text is one text checked against many expressions; its fold form is made
// once, when first needed.
type Text struct {
	text   string
	folded string
	done   bool
}

// NewText returns the check state for text.
func NewText(text string) *Text {
	return &Text{text: text}
}

// String is the text.
func (t *Text) String() string { return t.text }

// MayMatch reports false only when re cannot match the text. Texts shorter
// than MinText always report true.
func (t *Text) MayMatch(re *regexp.Regexp) bool {
	if t == nil || re == nil || len(t.text) < MinText {
		return true
	}
	return t.holds(re)
}

func (t *Text) holds(re *regexp.Regexp) bool {
	set := anchorsFor(re)
	if !set.ok {
		return true
	}
	if set.fold && !t.done {
		t.folded, t.done = foldCanonical(t.text), true
	}
	for _, c := range set.clauses {
		found := false
		for _, l := range c {
			haystack := t.text
			if l.fold {
				haystack = t.folded
			}
			if strings.Contains(haystack, l.text) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// MayMatch is Text.MayMatch for one expression.
func MayMatch(re *regexp.Regexp, text string) bool {
	return NewText(text).MayMatch(re)
}

// RequiredLiteralsIn reports whether text, of any length, satisfies every
// clause derived for re (true when none is known). Tests use it to check that
// each match of re holds the literals the check relies on.
func RequiredLiteralsIn(re *regexp.Regexp, text string) bool {
	return NewText(text).holds(re)
}

// HasRequiredLiterals reports whether a clause is known for re.
func HasRequiredLiterals(re *regexp.Regexp) bool {
	return anchorsFor(re).ok
}
