// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestGAP0299TrigramIndexAnswersLikeTheSearch: a large text's literal
// answers with the trigram index are the answers of a search of the whole
// folded text, for literals in the text, literals that are not, and short
// literals the index cannot answer. Literals come folded (upper case), as
// ruleRequiredLiterals gives them.
func TestGAP0299TrigramIndexAnswersLikeTheSearch(t *testing.T) {
	rng := rand.New(rand.NewSource(299))
	alphabet := "abcdefgh .-/_\n"
	word := func(n int) string {
		var b strings.Builder
		for range n {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	asked, missed := 0, 0
	for text := range 12 {
		var b strings.Builder
		for b.Len() < ruleTrigramMin+rng.Intn(ruleTrigramMin) {
			b.WriteString(word(1 + rng.Intn(12)))
		}
		if text%3 == 0 {
			b.WriteString(strings.ToUpper(word(5000))) // folded before the search
		}
		scan := &ruleScanText{text: b.String()}
		folded := foldRuleText(scan.text)
		literals := []string{"", "A", "AB", "ZZZ", "SSHX", "CURL", ".ENV"}
		for range 400 {
			if rng.Intn(2) == 0 {
				at := rng.Intn(len(folded) - 16)
				literals = append(literals, folded[at:at+1+rng.Intn(15)])
			} else {
				literals = append(literals, foldRuleText(word(1+rng.Intn(9))+"q"+word(rng.Intn(4))))
			}
		}
		for _, literal := range literals {
			asked++
			want := strings.Contains(folded, literal)
			if !want {
				missed++
			}
			if got := scan.holdsLiteral(literal); got != want {
				t.Fatalf("text %d literal %q: index answer %v, search %v", text, literal, got, want)
			}
		}
		if scan.grams == nil {
			t.Fatalf("text %d of %d bytes kept no trigram index", text, len(folded))
		}
	}
	small := &ruleScanText{text: "ssh -i key host"}
	if !small.holdsLiteral("SSH") || small.holdsLiteral("CURL") || small.grams != nil {
		t.Fatalf("small text: want SSH held, CURL missed and no index")
	}
	t.Logf("%d literal questions, %d misses", asked, missed)
}

// TestGAP0299TrigramIndexKeepsEveryShippedRuleAnswer: on a 1 MiB benign
// text every shipped rule pattern gets the same prefilter answer with the
// trigram index as with a search of the whole text per literal. The log has
// the time of both readings (one pass over all patterns each).
func TestGAP0299TrigramIndexKeepsEveryShippedRuleAnswer(t *testing.T) {
	words := strings.Fields("the quarterly report lists totals for each region and month, " +
		"with notes on staffing, travel budgets and the schedule of reviews")
	var b strings.Builder
	for i := 0; b.Len() < 1<<20; i++ {
		b.WriteString(words[i*7%len(words)])
		if i%13 == 12 {
			b.WriteString(".\n")
		} else {
			b.WriteByte(' ')
		}
	}
	text := b.String()
	patterns := shippedRulePatterns(t, false)
	ids := make([]string, 0, len(patterns))
	for id := range patterns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	indexed := &ruleScanText{text: text}
	searched := &ruleScanText{text: text, folded: foldRuleText(text), ready: true}
	start := time.Now()
	for _, id := range ids {
		_ = searched.mayMatch(patterns[id])
	}
	searchTime := time.Since(start)
	start = time.Now()
	may := 0
	for _, id := range ids {
		got := indexed.mayMatch(patterns[id])
		if want := searched.mayMatch(patterns[id]); got != want {
			t.Fatalf("rule %s: prefilter %v with the index, %v with the search", id, got, want)
		}
		if got {
			may++
		}
	}
	indexTime := time.Since(start)
	if indexed.grams == nil || searched.grams != nil {
		t.Fatalf("index kept: indexed %v, searched %v", indexed.grams != nil, searched.grams != nil)
	}
	t.Logf("%d shipped patterns, %d may match, %d distinct literals; search %v, index (incl. its build and the search pass) %v",
		len(ids), may, len(searched.holds), searchTime, indexTime)
}
