// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"regexp"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// midStreamScanState is what the mid-stream checks of one stream keep
// between them (rel-1-0-10:GAP-0515). A stream is checked every 500 bytes
// (every text frame on the raw forward), and every check reads the whole
// text so far, so a stream of n bytes cost O(n^2): the triage normalization
// of the whole text, the local PII data regexes over the text and its
// normalized form, and the rule pack's literal checks and regexes over the
// text and its shell-normalized form. The state keeps, per text the check
// reads (a role: the reply, its normalized form, ...), the answers the part
// that did not change cannot change, and computes only the rest, so every
// answer is the one the whole text gives (rxprefilter memo.go):
//
//   - a function that maps text piece by piece (the triage normalization,
//     the rule fold) is its value on the prefix up to a split point plus its
//     value on the rest (rxprefilter.SplitMemo, triageSplitAt);
//   - a literal check keeps the first index of the literal and searches only
//     the bytes a new occurrence can use (rxprefilter.Presence);
//   - a regex whose matches lie in runs of the bytes it names (GAP-1040,
//     rxprefilter windows.go) keeps the matches of every run that ended
//     before the changed part. A rule or PII validator still reads the
//     whole current text, in match order, every check.
//
// Nothing is a window: a regex not searched in runs is read whole every
// check, as before, and a text that is not an extension of the one before
// (a lane grew before the last one, GAP-0623) goes back to the last point
// before its first changed byte.
type midStreamScanState struct {
	norm rxprefilter.SplitMemo

	mu    sync.Mutex
	roles map[string]*midStreamTextMemo
}

// midStreamTextMemo is the memo of one role and the views of its current
// text: every part of one check that reads the text shares them.
type midStreamTextMemo struct {
	rx   rxprefilter.Memo
	fold rxprefilter.SplitMemo // foldRuleText
	lits rxprefilter.Presence  // literals of the fold

	text string
	rule *ruleScanText
	scan *rxprefilter.Text
}

func newMidStreamScanState() *midStreamScanState { return &midStreamScanState{} }

type midStreamScanStateKey struct{}

// withMidStreamScanState is ctx for the mid-stream checks of one stream.
func withMidStreamScanState(ctx context.Context, st *midStreamScanState) context.Context {
	return context.WithValue(ctx, midStreamScanStateKey{}, st)
}

func midStreamScanStateOf(ctx context.Context) *midStreamScanState {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(midStreamScanStateKey{}).(*midStreamScanState)
	return st
}

// scanTexts is the rule-scan and regex views of text in role: the ones of
// the role's current text when text is it, else new ones that make text
// the current text.
func (st *midStreamScanState) scanTexts(role, text string) (*ruleScanText, *rxprefilter.Text) {
	st.mu.Lock()
	defer st.mu.Unlock()
	m := st.roles[role]
	if m == nil {
		if st.roles == nil {
			st.roles = make(map[string]*midStreamTextMemo)
		}
		m = &midStreamTextMemo{}
		st.roles[role] = m
	}
	if m.scan == nil || m.text != text {
		m.text = text
		m.rule = &ruleScanText{text: text, memo: m}
		m.scan = rxprefilter.NewTextMemo(text, &m.rx)
	}
	return m.rule, m.scan
}

// normalizeForTriage is normalizeForTriage(content); st nil reads it whole.
func (st *midStreamScanState) normalizeForTriage(content string) string {
	if st == nil {
		return normalizeForTriage(content)
	}
	return st.norm.Apply(content, normalizeForTriage, triageSplitAt)
}

// findAcceptedLocalPIIMatch is findAcceptedLocalPIIMatch(original,
// normalized, pattern); st nil reads both texts whole.
func (st *midStreamScanState) findAcceptedLocalPIIMatch(original, normalized string, pattern *regexp.Regexp) (match string, wasNormalized, ok bool) {
	if st == nil {
		return findAcceptedLocalPIIMatch(original, normalized, pattern)
	}
	accept := func(text string) func(string, int, int) bool {
		return func(match string, start, end int) bool { return acceptedLocalPIIMatchAt(text, match, start, end) }
	}
	_, scan := st.scanTexts("content", original)
	if loc := firstAcceptedMatchBy(pattern, original, scanMatches(pattern, scan), accept(original)); loc != nil {
		return original[loc[0]:loc[1]], false, true
	}
	if normalized != original {
		_, scan := st.scanTexts("triage", normalized)
		if loc := firstAcceptedMatchBy(pattern, normalized, scanMatches(pattern, scan), accept(normalized)); loc != nil {
			return normalized[loc[0]:loc[1]], true, true
		}
	}
	return "", false, false
}

// scanMatches is the matches of pattern in scan's text.
func scanMatches(pattern *regexp.Regexp, scan *rxprefilter.Text) textMatches {
	return textMatches{
		first: func() []int { return scan.FindStringIndex(pattern) },
		all:   func() [][]int { return scan.FindAllStringIndex(pattern) },
	}
}

// triageSplitByte is a byte normalizeForTriage leaves as it is, apart from
// its case, whatever is around it: printable ASCII other than a slash or a
// backslash. NFC composes nothing into or out of an ASCII character that
// follows another one (ASCII is a starter, and no composition pair ends in
// ASCII), the zero-width strip and the lowercase map one rune at a time,
// and the slash rules match only whitespace and slashes.
func triageSplitByte(b byte) bool {
	return b > ' ' && b < 0x7f && b != '/' && b != '\\'
}

// triageSplitAt reports that s splits at c for normalizeForTriage:
// normalizeForTriage(s) == normalizeForTriage(s[:c]) + normalizeForTriage(s[c:]).
// It holds when the bytes on both sides of c are triageSplitByte.
func triageSplitAt(s string, c int) bool {
	return c > 0 && c < len(s) && triageSplitByte(s[c-1]) && triageSplitByte(s[c])
}
