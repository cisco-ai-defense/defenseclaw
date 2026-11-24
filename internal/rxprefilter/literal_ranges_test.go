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

// gap1697Assign is the expression of the credential-named assignment rule
// (SEC-SECRET-ASSIGN, internal/gateway rules catalog), whose case-folded
// keywords and \s runs made it read the whole text (GAP-1697).
var gap1697Assign = regexp.MustCompile(`(?i)\b[a-z0-9_-]{0,48}?(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|private[_-]?key|encryption[_-]?key|signing[_-]?key|credential)s?[a-z0-9_-]{0,48}\\*["']?\s*(?:[:=,(]|\s+is\s+|=>)\s*\\*["']?[A-Za-z0-9_\-+/=.!@#$%^&*~()]{12,128}`)

// gap1697Expressions are expressions with a bound literal reach, of the
// shapes the search relies on: assertions at the range edge, a multi-line
// anchor, a literal behind a bounded prefix, a case-sensitive literal, an
// alternation and a match that runs far past its literal.
var gap1697Expressions = []*regexp.Regexp{
	gap1697Assign,
	regexp.MustCompile(`(?i)\b[a-z]{0,6}token\b`),
	regexp.MustCompile(`(?m)^[ \t]{0,4}key\s*=\s*\S+`),
	regexp.MustCompile(`(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}=*`),
	regexp.MustCompile(`\B.{0,3}KEY[^\n]*`),
	regexp.MustCompile(`(?i)[^a-z]{0,2}secret(?:s|_value)?\s*[:=]\s*"[^"]{4,}"`),
	regexp.MustCompile(`(?s)begin.{0,10}end`),
}

// gap1697Value is a random-looking credential value made at run time.
func gap1697Value(r *rand.Rand, n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

func gap1697Filler(n int) string {
	const line = "The deployment notes describe how the service starts, which ports it opens and how it logs. "
	return strings.Repeat(line, n/len(line)+1)[:n]
}

// gap1697Check fails when the ranged search of text differs from the
// whole-text search for any expression.
func gap1697Check(t *testing.T, label, text string, expressions ...*regexp.Regexp) {
	t.Helper()
	for _, re := range expressions {
		scan := NewText(text)
		if got, want := scan.FindStringIndex(re), re.FindStringIndex(text); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %s: FindStringIndex=%v, want %v", label, re, got, want)
		}
		scan = NewText(text)
		if got, want := scan.FindAllStringIndex(re), re.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %s: FindAllStringIndex=%v, want %v", label, re, got, want)
		}
	}
}

// GAP-1697: the credential-named assignment has a bound literal reach, so a
// long text with one of its keywords is searched in ranges, not whole.
func TestGAP1697AssignmentRuleIsSearchedAroundItsKeywords(t *testing.T) {
	plan := literalPlanFor(gap1697Assign)
	if !plan.ok || plan.reach < 48 || plan.reach > 64 {
		t.Fatalf("plan ok=%t reach=%d, want a plan with the 48-rune prefix bound", plan.ok, plan.reach)
	}
	text := gap1697Filler(60<<10) + " We rotate the private key of the build server every month. " + gap1697Filler(4<<10)
	offsets, ok := NewText(text).hits(plan)
	if !ok || len(offsets) == 0 || len(offsets) > 4 {
		t.Fatalf("hits=%v ok=%t, want the few keyword hits", offsets, ok)
	}
	gap1697Check(t, "prose mention", text, gap1697Assign)
}

// GAP-1697: a credential at every offset around the range edges is found
// exactly as the whole-text search finds it: the keyword at the start and at
// the end of the text, after a prefix of every length up to and past the
// reach, glued to a word character (no \b) or after a space, and the value
// running past the reach.
func TestGAP1697CredentialAtEveryRangeBoundary(t *testing.T) {
	r := rand.New(rand.NewSource(1697))
	plan := literalPlanFor(gap1697Assign)
	value := gap1697Value(r, 40)
	for prefix := 0; prefix <= plan.reach+8; prefix++ {
		for _, before := range []string{"", " ", "x", "é"} {
			for _, keyword := range []string{"password", "Private_Key"} {
				assignment := strings.Repeat("a", prefix) + keyword + " = " + value
				for _, at := range []int{0, 4095} {
					filler := gap1697Filler(at)
					text := filler + before + assignment + " " + gap1697Filler(MinText)
					gap1697Check(t, "middle", text, gap1697Assign)
					// The credential last: the match runs to the end of the text.
					gap1697Check(t, "end", gap1697Filler(MinText)+filler+before+assignment, gap1697Assign)
				}
			}
		}
	}
	// Separators with long whitespace runs, escapes and quotes: a match far
	// longer than the reach.
	for _, sep := range []string{"=", ":", " is ", "=>", "(", ","} {
		for _, ws := range []int{0, 1, 300, 5000} {
			assignment := "secret" + strings.Repeat(" ", ws) + sep + strings.Repeat("\t", ws) + `\\"` + value
			gap1697Check(t, "long run", gap1697Filler(MinText)+assignment+gap1697Filler(100), gap1697Expressions...)
		}
	}
}

// GAP-1697: random texts built from the expressions' keywords, separators,
// whitespace, escapes and non-ASCII runes: the ranged search agrees with the
// whole-text search on every text, also where it falls back (a fold that
// changes a rune's width, invalid UTF-8, too many hits).
func TestGAP1697RangedSearchAgreesWithTheWholeText(t *testing.T) {
	r := rand.New(rand.NewSource(16970))
	pieces := []string{
		"password", "PassWord", "pwd", "token", "TOKEN", "secret", "api_key", "apikey", "private-key",
		"signing_key", "credential", "key", "KEY", "bearer", "Basic", "begin", "end",
		" ", "  ", "\t", "\n", "=", ":", " is ", "=>", ",", "(", "\\", "\"", "'", "-", "_",
		"é", "ß", "日本", "abc", "Q9x", "word", "the ", "service ", "0123456789",
	}
	rare := []string{"K", "ſ", "\xff", "\xe2\x84"} // Kelvin sign, long s, invalid bytes
	plan := literalPlanFor(gap1697Assign)
	ranged := 0
	for i := 0; i < 200; i++ {
		// Odd texts are mostly prose with a few keywords, so most are
		// searched in ranges; even texts are dense, so many fall back.
		sparse := i%2 == 1
		var b strings.Builder
		for b.Len() < MinText+r.Intn(3*MinText) {
			switch n := r.Intn(100); {
			case n < 3 && i%4 == 0:
				b.WriteString(rare[r.Intn(len(rare))])
			case n < 15:
				b.WriteString(gap1697Value(r, 4+r.Intn(30)))
			case n < 40 || (sparse && n < 96):
				b.WriteString(gap1697Filler(1 + r.Intn(200)))
			default:
				b.WriteString(pieces[r.Intn(len(pieces))])
			}
		}
		text := b.String()
		if _, ok := NewText(text).hits(plan); ok {
			ranged++
		}
		gap1697Check(t, "random", text, gap1697Expressions...)
	}
	if ranged < 40 {
		t.Fatalf("%d of 200 texts searched in ranges, want the sparse ones", ranged)
	}
	t.Logf("%d of 200 texts searched in ranges", ranged)
}

// GAP-1697: an expression whose literal may lie any distance after the match
// start (a star or plus in front of every literal) is searched whole; one
// over the reach limit too. A sentence-start rule of the trust pack, whose
// literals all follow \s runs, matched where its literal hits were more than
// any bound after the match start.
func TestGAP1697UnboundReachIsSearchedWhole(t *testing.T) {
	for _, expr := range []string{
		`\s*token`,
		`(?im)(?:^|[.!?;]\s*|\b(?:task|system)\s*:\s*)(?:enable|enter)\s+(?:debug|admin)\s+mode`,
		`(?i)\s*(?:new\s+)+system`,
		`a{0,300}token`,
		`[a-z]*y{0,2}token`,
	} {
		re := regexp.MustCompile(expr)
		if plan := literalPlanFor(re); plan.ok {
			t.Errorf("%s: plan with reach %d, want the whole-text search", expr, plan.reach)
		}
		text := gap1697Filler(MinText) + "System: enter   debug mode now. token  new new system" + gap1697Filler(MinText)
		gap1697Check(t, expr, text, re)
	}
	// A literal that starts the match, also in the first repetition of a
	// plus, has reach 0; a bounded prefix gives its bound.
	for expr, reach := range map[string]int{`a{0,200}token`: 200, `(?i)(?:new\s+)+system`: 0, `x+y{0,2}token`: 0, `\b[a-z]{0,6}(?:key|secret)`: 6} {
		if plan := literalPlanFor(regexp.MustCompile(expr)); !plan.ok || plan.reach != reach {
			t.Errorf("%s: plan ok=%t reach=%d, want reach %d", expr, plan.ok, plan.reach, reach)
		}
	}
}

// GAP-1697: the ranged search falls back to the whole text where its offsets
// would not be the text's, and where the hits are too many to save work.
func TestGAP1697RangedSearchFallsBack(t *testing.T) {
	plan := literalPlanFor(gap1697Assign)
	value := gap1697Value(rand.New(rand.NewSource(7)), 30)
	cases := map[string]string{
		"kelvin sign":  gap1697Filler(MinText) + "Key token = " + value,
		"invalid utf8": gap1697Filler(MinText) + "\xff token = " + value,
		"many hits":    strings.Repeat("token ", MinText),
	}
	for name, text := range cases {
		if _, ok := NewText(text).hits(plan); ok {
			t.Errorf("%s: searched in ranges, want the whole text", name)
		}
		gap1697Check(t, name, text, gap1697Expressions...)
	}
}
