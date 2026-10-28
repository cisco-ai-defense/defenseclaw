// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// A rule regex only runs on text that contains one of the literals every
// match of it must contain (its anchors). Go's regexp has no literal
// prefilter for case-insensitive alternations, so each rule of a pack ran
// its full automaton over the whole text: a 950 KB benign Bash heredoc
// took about 10 s of rule scanning on a build box and was denied as a
// gateway no-answer on Windows (GAP-2279). The anchors are derived from the
// parsed regex and only skip a regex that cannot match, so findings,
// evidence and validators are unchanged.

// ruleAnchor is one required literal; fold marks a case-insensitive one,
// stored in ruleFoldCanonical form.
type ruleAnchor struct {
	text string
	fold bool
}

// ruleAnchorSet is the anchors of one regex: every match contains at least
// one of them. ok false means no such set is known and the regex always runs.
type ruleAnchorSet struct {
	anchors []ruleAnchor
	ok      bool
	fold    bool // some anchor is case-insensitive
}

const (
	// ruleAnchorMaxSet bounds an alternation's anchor set.
	ruleAnchorMaxSet = 64
	// rulePrefilterMinText is the shortest text worth the prefilter: below
	// it the regex is cheaper than the checks.
	rulePrefilterMinText = 4096
)

var ruleAnchorCache sync.Map // *regexp.Regexp -> ruleAnchorSet

func ruleAnchorsFor(re *regexp.Regexp) ruleAnchorSet {
	if cached, ok := ruleAnchorCache.Load(re); ok {
		return cached.(ruleAnchorSet)
	}
	set := ruleAnchorSet{}
	if parsed, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		if anchors, ok := requiredRuleAnchors(parsed.Simplify()); ok && len(anchors) > 0 {
			set = ruleAnchorSet{anchors: anchors, ok: true}
			for _, anchor := range anchors {
				set.fold = set.fold || anchor.fold
			}
		}
	}
	ruleAnchorCache.Store(re, set)
	return set
}

// requiredRuleAnchors returns a set of literals one of which every match of
// re contains, and false when it cannot name one.
func requiredRuleAnchors(re *syntax.Regexp) ([]ruleAnchor, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return literalRuleAnchor(re.Rune, re.Flags&syntax.FoldCase != 0)
	case syntax.OpCapture:
		return requiredRuleAnchors(re.Sub[0])
	case syntax.OpPlus:
		return requiredRuleAnchors(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredRuleAnchors(re.Sub[0])
		}
		return nil, false
	case syntax.OpAlternate:
		var out []ruleAnchor
		for _, sub := range re.Sub {
			anchors, ok := requiredRuleAnchors(sub)
			if !ok {
				return nil, false
			}
			out = append(out, anchors...)
			if len(out) > ruleAnchorMaxSet {
				return nil, false
			}
		}
		return out, true
	case syntax.OpConcat:
		var best []ruleAnchor
		bestScore := 0
		consider := func(anchors []ruleAnchor, ok bool) {
			if !ok || len(anchors) == 0 {
				return
			}
			score := ruleAnchorScore(anchors)
			if score > bestScore || (score == bestScore && len(anchors) < len(best)) {
				best, bestScore = anchors, score
			}
		}
		// Adjacent literals of the same case mode form one longer anchor.
		var run []rune
		runFold := false
		flush := func() {
			if len(run) > 0 {
				consider(literalRuleAnchor(run, runFold))
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
			consider(requiredRuleAnchors(sub))
		}
		flush()
		return best, best != nil
	default:
		return nil, false
	}
}

func literalRuleAnchor(runes []rune, fold bool) ([]ruleAnchor, bool) {
	if len(runes) == 0 {
		return nil, false
	}
	var b strings.Builder
	for _, r := range runes {
		if r == utf8.RuneError || r < 0 || r > unicode.MaxRune {
			// Invalid input bytes match U+FFFD in the regex but not as bytes.
			return nil, false
		}
		if fold {
			r = ruleFoldCanonicalRune(r)
		}
		b.WriteRune(r)
	}
	return []ruleAnchor{{text: b.String(), fold: fold}}, true
}

// ruleAnchorScore is the rune length of the set's shortest anchor.
func ruleAnchorScore(anchors []ruleAnchor) int {
	score := -1
	for _, anchor := range anchors {
		if n := utf8.RuneCountInString(anchor.text); score < 0 || n < score {
			score = n
		}
	}
	return score
}

// ruleFoldCanonicalRune maps r to the smallest rune of its simple case-fold
// orbit, the equivalence regexp's (?i) matching uses (K, k and the Kelvin
// sign all map to K; s and the long s to S).
func ruleFoldCanonicalRune(r rune) rune {
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

func ruleFoldCanonical(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		if r == utf8.RuneError {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(ruleFoldCanonicalRune(r))
	}
	return b.String()
}

// rulePrefilterText is one scanned text and, once needed, its fold form.
type rulePrefilterText struct {
	text   string
	folded string
	done   bool
}

func newRulePrefilterText(text string) *rulePrefilterText {
	return &rulePrefilterText{text: text}
}

// mayMatch reports false only when re cannot match the text.
func (p *rulePrefilterText) mayMatch(re *regexp.Regexp) bool {
	if p == nil || re == nil || len(p.text) < rulePrefilterMinText {
		return true
	}
	set := ruleAnchorsFor(re)
	if !set.ok {
		return true
	}
	if set.fold && !p.done {
		p.folded, p.done = ruleFoldCanonical(p.text), true
	}
	for _, anchor := range set.anchors {
		haystack := p.text
		if anchor.fold {
			haystack = p.folded
		}
		if strings.Contains(haystack, anchor.text) {
			return true
		}
	}
	return false
}

// firstAcceptedRuleMatchIn is firstAcceptedRuleMatch for a text the scan
// checks against many rules.
func firstAcceptedRuleMatchIn(rule PatternRule, scan *rulePrefilterText) []int {
	if !scan.mayMatch(rule.Pattern) {
		return nil
	}
	return firstAcceptedRuleMatch(rule, scan.text)
}
