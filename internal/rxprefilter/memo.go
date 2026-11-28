// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package rxprefilter

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// A stream guard checks the text of a reply every few hundred bytes, and
// every check reads the whole text so far, so a reply of n bytes costs
// O(n^2) (rel-1-0-10:GAP-0515). The texts of one stream mostly extend the
// one before, and what a check computes from a text does not change for
// the part that did not change. The memos here keep those answers between
// the checks of one text "role" (the reply, its normalized form, ...) and
// compute only what the new part can change, so every answer equals the one
// the whole text gives; none is a window. Each memo compares the new text
// with the last one (commonPrefixLen) and goes back to the last point
// before the first changed byte, so a text that is not an extension (a lane
// grew before the last one) is exact too, only slower.

// commonPrefixLen is the length of the longest common prefix of a and b.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i+4096 <= n && a[i:i+4096] == b[i:i+4096] {
		i += 4096
	}
	for i+64 <= n && a[i:i+64] == b[i:i+64] {
		i += 64
	}
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// SplitMemo is f over the texts of one role, for an f that splits: f(s) ==
// f(s[:c]) + f(s[c:]) whenever split(s, c). It keeps f of the prefix up to
// the last split point and computes f of the rest.
type SplitMemo struct {
	mu     sync.Mutex
	text   string
	prefix string
	cuts   []splitCut
}

type splitCut struct {
	at, prefixLen int // f(text[:at]) == prefix[:prefixLen]
}

// Apply is f(s). split(s, c) is only asked for 0 < c < len(s); it must
// read no more than s[c-1] and s[c].
func (m *SplitMemo) Apply(s string, f func(string) string, split func(s string, c int) bool) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	// A cut stays when s has the same bytes up to and including the one
	// after it: it is still a split point of s, with the same prefix.
	keep := len(m.cuts)
	if keep > 0 {
		if last := m.cuts[keep-1].at; last >= len(s) || s[:last+1] != m.text[:last+1] {
			common := commonPrefixLen(s, m.text)
			for keep > 0 && m.cuts[keep-1].at >= common {
				keep--
			}
		}
	}
	m.cuts = m.cuts[:keep]
	prefix, at := "", 0
	if keep > 0 {
		at = m.cuts[keep-1].at
		prefix = m.prefix[:m.cuts[keep-1].prefixLen]
	}
	next := at
	for c := len(s) - 1; c > at; c-- {
		if split(s, c) {
			next = c
			break
		}
	}
	if next > at {
		prefix += f(s[at:next])
		at = next
		m.cuts = append(m.cuts, splitCut{at: at, prefixLen: len(prefix)})
	}
	m.text, m.prefix = s, prefix
	if at == 0 {
		return f(s)
	}
	if tail := f(s[at:]); tail != "" {
		return prefix + tail
	}
	return prefix
}

// SplitBeforeASCII is a split point of every function that maps one rune at
// a time (a fold, a case map): s[c] is ASCII, so the decoding of s from its
// start reaches c whatever came before, and the runes after c are the runes
// of s[c:].
func SplitBeforeASCII(s string, c int) bool { return s[c] < utf8.RuneSelf }

// Presence answers strings.Contains(hay, literal) for the hay texts of one
// role, keeping the first index of every literal asked.
type Presence struct {
	mu   sync.Mutex
	gen  uint64
	cur  string
	lits map[string]presenceEntry
}

type presenceEntry struct {
	gen uint64
	at  int // first index of the literal in the hay of gen; -1: none
}

// PresenceView is a Presence for one hay.
type PresenceView struct {
	p      *Presence
	hay    string
	gen    uint64
	common int // common prefix of hay and the hay of gen-1
}

// View returns the view of p for hay; it is the hay every later view is
// compared with.
func (p *Presence) View(hay string) *PresenceView {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gen++
	common := commonPrefixLen(hay, p.cur)
	p.cur = hay
	return &PresenceView{p: p, hay: hay, gen: p.gen, common: common}
}

// Contains is strings.Contains(v's hay, literal).
func (v *PresenceView) Contains(literal string) bool {
	p := v.p
	p.mu.Lock()
	e, known := p.lits[literal]
	p.mu.Unlock()
	if known && e.gen == v.gen {
		return e.at >= 0
	}
	var at int
	switch {
	case known && e.gen == v.gen-1 && e.at >= 0 && e.at+len(literal) <= v.common:
		// The first occurrence is in the part that did not change.
		at = e.at
	case known && e.gen == v.gen-1:
		// No occurrence lies wholly in the part that did not change (the
		// first one, if any, did not): a new one overlaps the rest.
		from := max(0, v.common-len(literal)+1)
		at = strings.Index(v.hay[from:], literal)
		if at >= 0 {
			at += from
		}
	default:
		at = strings.Index(v.hay, literal)
	}
	p.mu.Lock()
	if p.lits == nil {
		p.lits = make(map[string]presenceEntry)
	}
	if cur, ok := p.lits[literal]; !ok || cur.gen <= v.gen {
		p.lits[literal] = presenceEntry{gen: v.gen, at: at}
	}
	p.mu.Unlock()
	return at >= 0
}

// Memo is what the checks of one role's texts keep: the required-literal
// answers of the text and of its fold form, and the matches of every
// expression searched in runs (windows.go). NewTextMemo is the Text of one
// text of the role.
type Memo struct {
	mu     sync.Mutex
	gen    uint64
	cur    string
	raw    Presence
	folded Presence
	fold   SplitMemo
	chains map[*regexp.Regexp]*runChain
}

// NewTextMemo is NewText for a text of m's role: its answers come from m
// and equal those of NewText(text).
func NewTextMemo(text string, m *Memo) *Text {
	if m == nil {
		return NewText(text)
	}
	m.mu.Lock()
	m.gen++
	common := commonPrefixLen(text, m.cur)
	m.cur = text
	gen := m.gen
	m.mu.Unlock()
	return &Text{text: text, memo: m, memoGen: gen, memoCommon: common}
}

// contains is strings.Contains of the text (fold false) or of its fold
// form (fold true), from the memo.
func (t *Text) contains(literal string, fold bool) bool {
	t.mu.Lock()
	if fold {
		if t.foldedView == nil {
			folded := t.memo.fold.Apply(t.text, foldCanonical, SplitBeforeASCII)
			t.foldedView = t.memo.folded.View(folded)
		}
	} else if t.rawView == nil {
		t.rawView = t.memo.raw.View(t.text)
	}
	view := t.rawView
	if fold {
		view = t.foldedView
	}
	t.mu.Unlock()
	return view.Contains(literal)
}

// memoPlan is what the memo's search of an expression in runs relies on:
// the runes a match may hold (ASCII by bitmap, the others by range: the
// windows.go plan with the runes beyond ASCII too, so a case-folded k or s,
// a line class such as [^\r\n] or a class of tag characters also splits),
// and the fewest runes of a match. As in windows.go, the expression has no
// anchor and never matches the empty string, so a match lies in one
// maximal run of those runes and reads only the run and the rune on each
// side of it: \b and \B look at one rune on each side, and neither side
// rune is in the set, so no match holds it.
type memoPlan struct {
	ok     bool
	ascii  [4]uint64
	ranges []rune // lo, hi pairs beyond ASCII
	minLen int
}

func (p *memoPlan) in(r rune) bool {
	if r < utf8.RuneSelf {
		return r >= 0 && p.ascii[r>>6]&(1<<(uint(r)&63)) != 0
	}
	for i := 0; i+1 < len(p.ranges); i += 2 {
		if p.ranges[i] <= r && r <= p.ranges[i+1] {
			return true
		}
	}
	return false
}

func (p *memoPlan) add(lo, hi rune) {
	for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
		p.ascii[r>>6] |= 1 << (uint(r) & 63)
	}
	if hi >= utf8.RuneSelf {
		p.ranges = append(p.ranges, max(lo, utf8.RuneSelf), hi)
	}
}

var memoPlans sync.Map // *regexp.Regexp -> *memoPlan

func memoPlanFor(re *regexp.Regexp) *memoPlan {
	if cached, ok := memoPlans.Load(re); ok {
		return cached.(*memoPlan)
	}
	plan := &memoPlan{}
	if parsed, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		parsed = parsed.Simplify()
		if n, ok := plan.collect(parsed); ok && n > 0 {
			plan.ok, plan.minLen = true, n
		}
	}
	if !plan.ok {
		plan = &memoPlan{}
	}
	memoPlans.Store(re, plan)
	return plan
}

// collect adds the runes a match of re may hold to the plan and returns
// the fewest runes of a match; false for an anchor.
func (p *memoPlan) collect(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			p.add(r, r)
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					p.add(f, f)
				}
			}
		}
		return len(re.Rune), true
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			p.add(re.Rune[i], re.Rune[i+1])
		}
		return 1, true
	case syntax.OpAnyCharNotNL:
		p.add(0, '\n'-1)
		p.add('\n'+1, unicode.MaxRune)
		return 1, true
	case syntax.OpAnyChar:
		p.add(0, unicode.MaxRune)
		return 1, true
	case syntax.OpCapture, syntax.OpPlus:
		return p.collect(re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		_, ok := p.collect(re.Sub[0])
		return 0, ok
	case syntax.OpRepeat:
		n, ok := p.collect(re.Sub[0])
		return n * re.Min, ok
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			n, ok := p.collect(sub)
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	case syntax.OpAlternate:
		shortest := -1
		for _, sub := range re.Sub {
			n, ok := p.collect(sub)
			if !ok {
				return 0, false
			}
			if shortest < 0 || n < shortest {
				shortest = n
			}
		}
		return max(shortest, 0), true
	}
	return 0, false
}

// runChain is the matches of one expression in the texts of a role, by run:
// the matches of every run that ended before done, read from text.
type runChain struct {
	mu   sync.Mutex
	gen  uint64
	text string
	done int
	locs []runMatch
	// vol is the matches of the text of gen after the settled part, read
	// again with every text.
	vol []runMatch
}

type runMatch struct {
	start, end int
	readTo     int // the match was read from text[..readTo): the run and the rune after it
}

// memoMatches is re.FindAllStringIndex(t.text, -1) by run, from the memo,
// or with firstOnly its first match only (re.FindStringIndex), without the
// list of every match; ok false when re is not searched in runs.
func (t *Text) memoMatches(re *regexp.Regexp, firstOnly bool) ([][]int, bool) {
	plan := memoPlanFor(re)
	if !plan.ok {
		return nil, false
	}
	m := t.memo
	m.mu.Lock()
	c := m.chains[re]
	if c == nil {
		if m.chains == nil {
			m.chains = make(map[*regexp.Regexp]*runChain)
		}
		c = &runChain{}
		m.chains[re] = c
	}
	m.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.gen == t.memoGen:
	case c.gen > t.memoGen:
		// A later text of the role moved the chain on: read this one alone.
		var fresh runChain
		fresh.move(t.text, re, plan, 0)
		return fresh.answer(firstOnly), true
	default:
		common := t.memoCommon
		if c.gen != t.memoGen-1 {
			common = commonPrefixLen(t.text, c.text)
		}
		c.move(t.text, re, plan, common)
		c.gen = t.memoGen
	}
	return c.answer(firstOnly), true
}

// answer is the chain's matches in its text, in order, in new slices: all
// of them, or the first one only.
func (c *runChain) answer(firstOnly bool) [][]int {
	n := len(c.locs) + len(c.vol)
	if n == 0 {
		return nil
	}
	if firstOnly {
		first := c.vol
		if len(c.locs) > 0 {
			first = c.locs
		}
		return [][]int{{first[0].start, first[0].end}}
	}
	out := make([][]int, 0, n)
	for _, l := range c.locs {
		out = append(out, []int{l.start, l.end})
	}
	for _, l := range c.vol {
		out = append(out, []int{l.start, l.end})
	}
	return out
}

// memoMargin is how far past a rune the decoding of an invalid byte may
// look: a position is settled only when the text has memoMargin more bytes.
const memoMargin = utf8.UTFMax - 1

// move moves the chain to text, whose first common bytes are those of the
// chain's text: locs and vol are then all the matches in text, in order. The
// runes are decoded from done, a rune start of the decoding from the start
// of the text (the one the regexp engine uses), so they stay on it. What
// the chain keeps is settled: it reads only bytes memoMargin before the end
// of the text it was read from, so its decoding does not change when bytes
// are added after them; the rest is read again each time.
func (c *runChain) move(text string, re *regexp.Regexp, plan *memoPlan, common int) {
	if c.done+memoMargin > common {
		keep := len(c.locs)
		for keep > 0 && c.locs[keep-1].readTo+memoMargin > common {
			keep--
		}
		c.locs = c.locs[:keep]
		c.done = 0
		if keep > 0 {
			c.done = c.locs[keep-1].readTo
		}
	}
	c.text = text
	limit := len(text) - memoMargin
	var volatile []runMatch
	pos := c.done
	for {
		for pos < len(text) {
			if pos <= limit {
				c.done = pos
			}
			r, w := utf8.DecodeRuneInString(text[pos:])
			if plan.in(r) {
				break
			}
			pos += w
		}
		if pos == len(text) {
			if pos <= limit {
				c.done = pos
			}
			break
		}
		start, end := pos, pos
		for end < len(text) {
			r, w := utf8.DecodeRuneInString(text[end:])
			if !plan.in(r) {
				break
			}
			end += w
		}
		var found []runMatch
		if end-start >= plan.minLen {
			found = runMatchesOf(text, re, start, end)
		}
		if end == len(text) {
			// The run may grow: it is read again with the next text.
			volatile = append(volatile, found...)
			break
		}
		_, w := utf8.DecodeRuneInString(text[end:])
		if end+w <= limit {
			c.locs = append(c.locs, found...)
			c.done = end + w
		} else {
			volatile = append(volatile, found...)
		}
		pos = end + w
	}
	c.vol = volatile
}

// runMatchesOf is the matches of re in the run text[start:end], read with
// the rune before and after it.
func runMatchesOf(text string, re *regexp.Regexp, start, end int) []runMatch {
	lo, hi := start, end
	if lo > 0 {
		_, w := utf8.DecodeLastRuneInString(text[:lo])
		lo -= w
	}
	if hi < len(text) {
		_, w := utf8.DecodeRuneInString(text[hi:])
		hi += w
	}
	found := re.FindAllStringIndex(text[lo:hi], -1)
	if len(found) == 0 {
		return nil
	}
	out := make([]runMatch, 0, len(found))
	for _, loc := range found {
		out = append(out, runMatch{start: lo + loc[0], end: lo + loc[1], readTo: hi})
	}
	return out
}
