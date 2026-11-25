// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// gap1697Mention names a keyword of the credential-named assignment rule
// (SEC-SECRET-ASSIGN) in prose, with no assignment: no rule matches it.
const gap1697Mention = "We rotate the private key of the build server every month.\n"

// gap1697Checks runs the mid-stream content check (scanLocalPatternsFor, the
// local rules of InspectMidStream) at every 500 bytes of text, as a streamed
// reply is checked, and returns the total and the 99th percentile check.
func gap1697Checks(text string) (total, p99 time.Duration) {
	var each []time.Duration
	for n := 500; ; n += 500 {
		n = min(n, len(text))
		start := time.Now()
		_ = scanLocalPatternsFor(context.Background(), "completion", text[:n])
		d := time.Since(start)
		each, total = append(each, d), total+d
		if n == len(text) {
			break
		}
	}
	slices.Sort(each)
	return total, each[(len(each)*99+99)/100-1]
}

// GAP-1697: a keyword of the credential-named assignment rule anywhere in a
// long streamed reply no longer makes every mid-stream check read the whole
// reply with the rule's regex: the 61 KB reply with "private key" in one
// prose line costs about what the same reply without it costs. Before the
// fix it cost about 1.7 times as much (each check ran the case-folded regex
// over the whole text so far).
func TestGAP1697MidStreamCheckCostWithAKeywordInProse(t *testing.T) {
	if testing.Short() || hookAnswerRaceBuild {
		t.Skip("cost measure: not under -short or the race detector")
	}
	filler := retestFiller(61 << 10)
	texts := map[string]string{"plain": "Here is the summary:\n" + filler, "mention": "Here is the summary:\n" + gap1697Mention + filler}
	for kind, text := range texts {
		if v := scanLocalPatternsFor(context.Background(), "completion", text); v != nil && v.Severity != "" && v.Severity != "NONE" {
			t.Fatalf("%s: the benign reply has findings %v", kind, v.Findings)
		}
	}
	best := map[string][2]time.Duration{}
	for round := 0; round < 3; round++ {
		for _, kind := range []string{"plain", "mention"} {
			total, p99 := gap1697Checks(texts[kind])
			if b, ok := best[kind]; !ok || total < b[0] {
				best[kind] = [2]time.Duration{total, p99}
			}
		}
	}
	t.Logf("mid-stream checks of a 61 KB reply, best of 3: plain total %v p99 %v; with %q total %v p99 %v",
		best["plain"][0], best["plain"][1], strings.TrimSpace(gap1697Mention), best["mention"][0], best["mention"][1])
	if limit := best["plain"][0]*5/4 + 20*time.Millisecond; best["mention"][0] > limit {
		t.Errorf("checks with the keyword cost %v, without it %v (limit %v)", best["mention"][0], best["plain"][0], limit)
	}

	// The same reply streamed through /llm in 24-byte pieces.
	llm := map[string]time.Duration{}
	for round := 0; round < 2; round++ {
		for _, kind := range []string{"plain", "mention"} {
			start := time.Now()
			out := retestLLM(t, retestPieces(texts[kind], 24))
			d := time.Since(start)
			if got := streamedContent(out); got != texts[kind] {
				t.Fatalf("llm %s: the client got %d of %d text bytes (blocked or held)", kind, len(got), len(texts[kind]))
			}
			if c, ok := llm[kind]; !ok || d < c {
				llm[kind] = d
			}
		}
	}
	t.Logf("/llm stream of the 61 KB reply in 24-byte pieces, best of 2: plain %v, with the keyword %v", llm["plain"], llm["mention"])
	if limit := llm["plain"]*13/10 + 150*time.Millisecond; llm["mention"] > limit {
		t.Errorf("/llm stream with the keyword cost %v, without it %v (limit %v)", llm["mention"], llm["plain"], limit)
	}
}

// GAP-1697: every shipped rule, in every pack, finds in a long text the
// matches (first, all and the first accepted, offsets included) it finds
// when its regex reads the whole text, so searching around a rule's literals
// changes no finding. The texts are the security suite's corpus and its
// case-fold variants in 6 KB pieces, and generated replies with credential
// assignments at every offset around the keyword and the prefix bound.
func TestGAP1697RuleMatchesAroundLiteralsAreTheWholeTextMatches(t *testing.T) {
	if testing.Short() || hookAnswerRaceBuild {
		t.Skip("corpus sweep: not under -short or the race detector")
	}
	var texts []string
	corpus := prefilterCorpus(t)
	for len(corpus) > 0 {
		n := min(len(corpus), 6<<10)
		texts = append(texts, corpus[:n])
		corpus = corpus[n:]
	}
	rng := rand.New(rand.NewSource(1697))
	value := func(n int) string {
		const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(b)
	}
	filler := retestFiller(5 << 10)
	for _, key := range []string{"password", "db_passwd", "API_KEY", "private-key", "signing_key", "auth_token", "client_secret", "credentials"} {
		for _, sep := range []string{"=", ": ", " is ", " => ", "(\"", "=\\\""} {
			for _, prefix := range []int{0, 1, 47, 48, 49, 60} {
				assignment := strings.Repeat("x", prefix) + key + sep + value(24)
				texts = append(texts,
					filler+" "+assignment+" "+filler,
					filler+assignment,
					assignment+" "+filler,
					filler[:rng.Intn(len(filler))]+"x"+assignment+"\n"+filler)
			}
		}
	}
	compared, total := 0, 0
	for _, pack := range []string{"", "strict", "permissive"} {
		generation := snapshotRulePackGeneration(pack)
		for _, text := range texts {
			raw := &ruleScanText{text: text}
			for ci := range generation.categories {
				for ri := range generation.categories[ci].Rules {
					rule := generation.categories[ci].Rules[ri]
					if rule.Pattern == nil {
						continue
					}
					total++
					if !raw.mayMatch(rule.Pattern) {
						continue
					}
					compared++
					scan := rxprefilter.NewText(text)
					if got, want := scan.FindStringIndex(rule.Pattern), rule.Pattern.FindStringIndex(text); !reflect.DeepEqual(got, want) {
						t.Fatalf("pack %q rule %s: first match %v, whole-text %v", pack, rule.ID, got, want)
					}
					if got, want := scan.FindAllStringIndex(rule.Pattern), rule.Pattern.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
						t.Fatalf("pack %q rule %s: all matches %v, whole-text %v", pack, rule.ID, got, want)
					}
					if got, want := firstAcceptedRuleMatchIn(rule, rxprefilter.NewText(text)), firstAcceptedRuleMatch(rule, text); !reflect.DeepEqual(got, want) {
						t.Fatalf("pack %q rule %s: first accepted match %v, whole-text %v", pack, rule.ID, got, want)
					}
				}
			}
		}
	}
	if compared < 1000 {
		t.Fatalf("compared %d of %d rule and text pairs, want the rules whose literals the texts hold", compared, total)
	}
	t.Logf("compared %d of %d rule and text pairs over %d texts", compared, total, len(texts))
}
