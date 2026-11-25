// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package rxprefilter

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var memoAtoms = []string{
	"a", "b", "ab", "K", "k", "\u212a", "\u017f", "s", "S", "x", "token", "TOKEN", "key", " ", "  ", "\n", "-", "_",
	"0", "12", "345", "6789", ".", ",", "/", "\\", "e\u0301", "\u00e9", "\u4e2d", "\xff", "\xe2\x82", "\u00a0",
	"\xe2", "\x82\xac", "\xf3\xa0", "\x80\x81", "\U000e0041", "\U000e0042", "\r", ";", "nc ", "\ufffd",
}

func memoText(r *rand.Rand, n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(memoAtoms[r.Intn(len(memoAtoms))])
	}
	return b.String()
}

// memoSteps is the texts of one role: growing prefixes of a random text,
// with now and then a piece rewritten before the end (a lane that grew
// before the last one) and now and then the same text again.
func memoSteps(r *rand.Rand, n int) []string {
	text := memoText(r, n)
	var out []string
	for at := 0; at < len(text); {
		step := []int{3, 40, 600}[r.Intn(3)]
		if n > WindowMinText {
			step = 4000
		}
		at = min(len(text), at+1+r.Intn(step))
		s := text[:at]
		switch r.Intn(12) {
		case 0:
			i := r.Intn(len(s))
			s = s[:i] + memoText(r, r.Intn(20)) + s[min(len(s), i+r.Intn(20)):]
		case 1:
			if len(out) > 0 {
				s = out[len(out)-1]
			}
		}
		out = append(out, s)
	}
	return out
}

// TestMemoAnswersEqualWholeText: for the texts of a role, the memo's fold,
// literal answers, required-literal checks and matches by run equal those
// of each text read alone (GAP-0515).
func TestMemoAnswersEqualWholeText(t *testing.T) {
	r := rand.New(rand.NewSource(515))
	exprs := []string{
		`\b\d{3}-\d{2}-\d{4}\b`, `\d{4}`, `\B\d{2}\B`, `(?i)ab+`, `(?i)token\s*\d+`, `a|ab`, `(?:ab)+`,
		`[a-z]{2,}x`, `x{0}\d`, `[\-_ ]+\d`, `^\d+`, `\d+$`, `.\d`, `\d*`, `(?i)k\d`, `(?i)key[_-]?\d{2,}`,
		`[^\r\n]{3,}\d`, `[\x{E0000}-\x{E007F}]{2,}`, `(?i)\bnc\b\s+\S+`, `\x{FFFD}\d`, `[^ ]{2}\b`, `(?s)a.b`, `\pL{3}`,
	}
	var res []*regexp.Regexp
	for _, e := range exprs {
		res = append(res, regexp.MustCompile(e))
	}
	literals := []string{"a", "ab", "K", "TOKEN", "KEY", "12", "-0", "\u212a", "\u4e2d", "S\u00c9"}
	byRun, longest := 0, 0
	for i := 0; i < 40; i++ {
		var m Memo
		var fold SplitMemo
		var lits Presence
		size := 3000
		if i%20 == 0 {
			size = WindowMinText + 3000
		}
		for _, s := range memoSteps(r, size) {
			longest = max(longest, len(s))
			text := NewTextMemo(s, &m)
			plain := NewText(s)
			folded := fold.Apply(s, foldCanonical, SplitBeforeASCII)
			if want := foldCanonical(s); folded != want {
				t.Fatalf("fold of %q: got %q, want %q", s, folded, want)
			}
			view := lits.View(folded)
			for _, l := range literals {
				if got, want := view.Contains(l), strings.Contains(folded, l); got != want {
					t.Fatalf("literal %q in %q: got %v, want %v", l, folded, got, want)
				}
			}
			for _, re := range res {
				if got, want := text.MayMatch(re), plain.MayMatch(re); got != want {
					t.Fatalf("%s may match %q: got %v, want %v", re, s, got, want)
				}
				if got, want := text.FindAllStringIndex(re), re.FindAllStringIndex(s, -1); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s in %q: got %v, want %v", re, s, got, want)
				}
				if got, want := text.FindStringIndex(re), re.FindStringIndex(s); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s first in %q: got %v, want %v", re, s, got, want)
				}
			}
		}
	}
	for _, re := range res {
		if windowPlanFor(re).ok {
			byRun++
		}
	}
	if byRun < 8 || longest < WindowMinText {
		t.Fatalf("too little read: %d expressions by run, longest text %d", byRun, longest)
	}
}

// TestMemoTextsOfOneRoleInterleaved: two texts of one role checked in turn
// (a later text moves the memo on before an earlier one is read) still get
// their own answers.
func TestMemoTextsOfOneRoleInterleaved(t *testing.T) {
	r := rand.New(rand.NewSource(5151))
	re := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	var m Memo
	for i := 0; i < 300; i++ {
		a, b := memoText(r, 2000)+" 123-45-6789", memoText(r, 2000)
		ta := NewTextMemo(a, &m)
		tb := NewTextMemo(b, &m)
		for _, x := range []struct {
			text *Text
			s    string
		}{{tb, b}, {ta, a}, {tb, b}} {
			if got, want := x.text.FindAllStringIndex(re), re.FindAllStringIndex(x.s, -1); !reflect.DeepEqual(got, want) {
				t.Fatalf("interleaved: got %v, want %v", got, want)
			}
		}
	}
}
