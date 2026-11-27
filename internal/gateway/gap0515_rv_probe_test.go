// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

// The RV-0515 review probes of the GAP-0515 mid-stream memo: one check per
// byte, texts of two streams through one role, concurrent checks of one
// stream, and (DC_RV0515_REPORT=1) the memo's held heap and costs.

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// rv0515Atoms adds to gap0515Atoms the byte shapes the memo margin is about:
// lead bytes of 2, 3 and 4 byte runes alone and in pieces, lone
// continuation bytes, the encoded U+FFFD, tag characters, a full-width digit,
// the Kelvin sign and long s, and word/non-word neighbours of \b.
var rv0515Atoms = append(append([]string(nil), gap0515Atoms...),
	"\xf0", "\xf0\x9f", "\xf0\x9f\x98", "\x80", "\x98\x80", "\x9f\x98\x80",
	"\xe2", "\x82", "\xac", "\xc3", "\xa9", "\xef\xbf\xbd", "�",
	"\U000e0041", "\U000e007f", "１", "K", "ſ", "ß", "ẞ",
	"_", "a_b", "Straße", "STRASSE", "κόσμε", "İ", "i̇", "--", "@", "x@y.z",
)

func rv0515Text(r *rand.Rand, n int) string {
	var b strings.Builder
	for b.Len() < n {
		if r.Intn(20) == 0 {
			b.WriteString(gap0515SSN(r))
			continue
		}
		b.WriteString(rv0515Atoms[r.Intn(len(rv0515Atoms))])
	}
	return b.String()
}

// rv0515Regexes are shapes the memo's run plan accepts that the GAP-1040
// window plan never did: non-ASCII literal folds, Unicode classes, negated
// classes, U+FFFD classes (invalid bytes), any-character, \b/\B beside
// non-ASCII, plus the default PII regexes.
func rv0515Regexes() []*regexp.Regexp {
	out := append([]*regexp.Regexp(nil), compileBaseline(defaultPIIDataRegexSources)...)
	for _, src := range []string{
		`(?i)straße`, `(?i)ſ\w`, `(?i)k[a-z]`, `\p{Greek}+`, `[^\x00-\x7f]{2,}`, `[\x{FFFD}]+`,
		`[^ ]+`, `\B[^ ]{3}\B`, `(?:a|\b)b`, `\b\pL+\b`, `[\p{Z}\s]+x`, `[^\r\n]{5,}`,
		`(?U)a+b`, `(?:\b|x)y`, `x*y`, `\w+@\w+`, `[a-z]+\b`, `\Ba`, `é+`, `(?i)É`,
		`[^\n]*\d`, `.{3}\d`, `(?s).\d`, `[\x{E0000}-\x{E007F}]+`, `\d+\b`, `\b\d+`,
		`[0-9\-]{11}`, `(?i)i\x{307}`, `[^a-z0-9 ]+`, `\S{8,}`, `\s+\S`, `\W\w`,
	} {
		out = append(out, regexp.MustCompile(src))
	}
	return out
}

// TestRV0515ByteStepRegexExact: every byte of a stream is a check (the raw
// forward checks every text frame), so every partial rune at the end of the
// text is seen; with now and then an edit before the end and now and then a
// shorter text (a lane-joined text whose later lane is gone). Every regex's
// FindAll and first match through the memo equal the whole-text answers.
func TestRV0515ByteStepRegexExact(t *testing.T) {
	r := rand.New(rand.NewSource(0x515))
	regexes := rv0515Regexes()
	rounds := 16
	if gap0515Scale > 1 {
		rounds = 4
	}
	checks := 0
	for i := 0; i < rounds; i++ {
		st := newMidStreamScanState()
		text := rv0515Text(r, 200+r.Intn(500))
		for at := 1; at <= len(text); at++ {
			s := text[:at]
			switch r.Intn(40) {
			case 0:
				s = gap0515Edit(r, s)
			case 1:
				s = s[:r.Intn(len(s))+1]
			}
			_, scan := st.scanTexts("content", s)
			for _, re := range regexes {
				checks++
				if got, want := scan.FindAllStringIndex(re), re.FindAllStringIndex(s, -1); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s on %q: got %v, want %v", re, s, got, want)
				}
				if got, want := scan.FindStringIndex(re), re.FindStringIndex(s); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s first on %q: got %v, want %v", re, s, got, want)
				}
			}
		}
	}
	t.Logf("RV0515 byte-step regex checks=%d", checks)
}

// TestRV0515ByteStepVerdictExact: the full local-pattern verdict and the
// mid-stream verdict, one check per byte, PII and secret shapes and every
// partial rune at the end, against the whole-text check.
func TestRV0515ByteStepVerdictExact(t *testing.T) {
	insp := NewGuardrailInspector("local", nil, nil)
	r := rand.New(rand.NewSource(0x5150))
	rounds := 4
	if gap0515Scale > 1 {
		rounds = 1
	}
	secrets := secretRuleTruePositives()
	flagged := 0
	for i := 0; i < rounds; i++ {
		st := newMidStreamScanState()
		text := rv0515Text(r, 150) + secrets[r.Intn(len(secrets))].input + rv0515Text(r, 150) + gap0515Card(r, " ") + rv0515Text(r, 100)
		for at := 1; at <= len(text); at++ {
			s := text[:at]
			if r.Intn(30) == 0 {
				s = gap0515Edit(r, s)
			}
			gap0515Equal(t, insp, st, fmt.Sprintf("bytestep %d", i), s)
		}
		if v := scanLocalPatternsWithActivation("completion", text, snapshotRulePackGeneration(""), nil); v.Severity != "NONE" {
			flagged++
		}
	}
	if flagged == 0 {
		t.Fatalf("no text had a finding: the probe reads too little")
	}
}

// TestRV0515InterleavedTextsOneRole: two unrelated streams' texts read
// through one memo role in turn (a role reused for another text in the same
// check, or two checks of one stream racing): every answer stays exact.
func TestRV0515InterleavedTextsOneRole(t *testing.T) {
	insp := NewGuardrailInspector("local", nil, nil)
	r := rand.New(rand.NewSource(0x51500))
	a, b := gap0515Text(r, 5000), gap0515Text(r, 5000)
	st := newMidStreamScanState()
	for at := 50; at <= 5000; at += 37 + r.Intn(300) {
		gap0515Equal(t, insp, st, "A", a[:at])
		gap0515Equal(t, insp, st, "B", b[:min(len(b), at+r.Intn(100))])
	}
}

// TestRV0515ConcurrentChecksShareState: checks of one stream from several
// goroutines at once (the age-due timer and the read loop), random prefix
// lengths in any order, one memo: every verdict equals the whole-text one.
// Run under -race.
func TestRV0515ConcurrentChecksShareState(t *testing.T) {
	insp := NewGuardrailInspector("local", nil, nil)
	r := rand.New(rand.NewSource(0x515000))
	text := gap0515Text(r, 20000)
	rules := snapshotRulePackGeneration("")
	st := newMidStreamScanState()
	workers, per := 8, 20
	if gap0515Scale > 1 {
		per = 4
	}
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		seed := r.Int63()
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := rand.New(rand.NewSource(seed))
			for i := 0; i < per; i++ {
				s := text[:1+rr.Intn(len(text))]
				if rr.Intn(5) == 0 {
					s = gap0515Edit(rr, s)
				}
				got := scanLocalPatternsWithState("completion", s, rules, nil, st)
				want := scanLocalPatternsWithActivation("completion", s, rules, nil)
				if !reflect.DeepEqual(got, want) {
					errs <- fmt.Sprintf("local patterns at %d bytes:\n got  %+v\n want %+v", len(s), got, want)
					return
				}
				msgs := []ChatMessage{{Role: "assistant", Content: s}}
				gv := insp.InspectMidStream(withMidStreamScanState(context.Background(), st), "completion", s, msgs, "m", "action")
				wv := insp.InspectMidStream(context.Background(), "completion", s, msgs, "m", "action")
				if g, w := gap0515Verdict(gv), gap0515Verdict(wv); !reflect.DeepEqual(g, w) {
					errs <- fmt.Sprintf("mid-stream verdict at %d bytes:\n got  %+v\n want %+v", len(s), g, w)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func rv0515HeapAfterGC() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// rv0515Digits is n bytes of a benign number table: every cell is a match
// of a 4-digit shape and of the digit runs of the PII regexes, none a PII
// value (no SSN layout, no Luhn-valid card).
func rv0515Digits(n int, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for b.Len() < n {
		fmt.Fprintf(&b, "| %04d | %03d | %02d.%d |\n", r.Intn(10000), r.Intn(1000), r.Intn(100), r.Intn(10))
	}
	return b.String()[:n]
}

// TestRV0515MemoRetainedHeap reports (DC_RV0515_REPORT=1) the heap a stream's
// memo holds after 1 MiB of text checked every 512 bytes, and the check
// times with and without the memo, for prose and for a number table.
func TestRV0515MemoRetainedHeap(t *testing.T) {
	if os.Getenv("DC_RV0515_REPORT") == "" {
		t.Skip("set DC_RV0515_REPORT=1")
	}
	insp := NewGuardrailInspector("local", nil, nil)
	for _, c := range []struct {
		name, text string
	}{
		{"prose-1MiB", gap0515Prose(1<<20, 21)},
		{"digits-1MiB", rv0515Digits(1<<20, 22)},
	} {
		base := rv0515HeapAfterGC()
		st := newMidStreamScanState()
		ctx := withMidStreamScanState(context.Background(), st)
		var memoTotal time.Duration
		var last *ScanVerdict
		n := 0
		for at := 512; ; at += 512 {
			at = min(at, len(c.text))
			s := c.text[:at]
			t0 := time.Now()
			last = insp.InspectMidStream(ctx, "completion", s, []ChatMessage{{Role: "assistant", Content: s}}, "m", "action")
			memoTotal += time.Since(t0)
			n++
			if at == len(c.text) {
				break
			}
		}
		held := rv0515HeapAfterGC()
		runtime.KeepAlive(st)
		whole := gap0515WholeCheck(c.text, 3)
		t.Logf("RV0515 case=%s bytes=%d checks=%d sev=%s action=%s memo_total=%v memo_mean=%v whole_last=%v roles=%d retained_heap=%.1fMiB (%.1fx text)",
			c.name, len(c.text), n, last.Severity, last.Action, memoTotal, memoTotal/time.Duration(n), whole, len(st.roles),
			float64(held-base)/(1<<20), float64(held-base)/float64(len(c.text)))
	}
}

// TestRV0515TwoLaneAlternatingCost reports (DC_RV0515_REPORT=1) a two-choice
// stream whose lanes grow in turn, so every check's text differs from the
// last one at the end of lane 0: total check time with the memo against the
// same checks without it (rel/1.0.11).
func TestRV0515TwoLaneAlternatingCost(t *testing.T) {
	if os.Getenv("DC_RV0515_REPORT") == "" {
		t.Skip("set DC_RV0515_REPORT=1")
	}
	insp := NewGuardrailInspector("local", nil, nil)
	for _, c := range []struct {
		name string
		gen  func(int, int64) string
	}{{"prose", gap0515Prose}, {"digits", rv0515Digits}} {
		lane0, lane1 := c.gen(256<<10, 31), c.gen(256<<10, 32)
		var acc responseText
		st := newMidStreamScanState()
		ctx := withMidStreamScanState(context.Background(), st)
		var memoTotal, relTotal time.Duration
		checks := 0
		for off := 0; off < len(lane0); off += 512 {
			for lane, text := range []string{lane0, lane1} {
				acc.Add(answerPiece(lane, text[off:min(off+512, len(text))]))
				s := acc.String()
				msgs := []ChatMessage{{Role: "assistant", Content: s}}
				t0 := time.Now()
				gv := insp.InspectMidStream(ctx, "completion", s, msgs, "m", "action")
				memoTotal += time.Since(t0)
				t1 := time.Now()
				wv := insp.InspectMidStream(context.Background(), "completion", s, msgs, "m", "action")
				relTotal += time.Since(t1)
				checks++
				if g, w := gap0515Verdict(gv), gap0515Verdict(wv); !reflect.DeepEqual(g, w) {
					t.Fatalf("%s: verdict at %d bytes differs:\n got  %+v\n want %+v", c.name, len(s), g, w)
				}
			}
		}
		t.Logf("RV0515 lanes case=%s checks=%d memo_total=%v rel_total=%v ratio=%.2f", c.name, checks, memoTotal, relTotal, float64(memoTotal)/float64(relTotal))
	}
}

// TestRV0515FirstMatchOnlyCost reports (DC_RV0515_REPORT=1) the per-check
// cost of a first-match-only lookup (no validator: matches.first()) through
// the memo on a text whose first match is at its start and that has a match
// every few bytes: rel's FindStringIndex stops at the first match, the
// memo's builds every match each check.
func TestRV0515FirstMatchOnlyCost(t *testing.T) {
	if os.Getenv("DC_RV0515_REPORT") == "" {
		t.Skip("set DC_RV0515_REPORT=1")
	}
	re := regexp.MustCompile(`\d{4}`)
	text := rv0515Digits(1<<20, 41)
	var memo rxprefilter.Memo
	var memoTotal, relTotal time.Duration
	checks := 0
	for at := 512; ; at += 512 {
		at = min(at, len(text))
		s := text[:at]
		t0 := time.Now()
		got := rxprefilter.NewTextMemo(s, &memo).FindStringIndex(re)
		memoTotal += time.Since(t0)
		t1 := time.Now()
		want := re.FindStringIndex(s)
		relTotal += time.Since(t1)
		checks++
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("first match differs at %d", at)
		}
		if at == len(text) {
			break
		}
	}
	t.Logf("RV0515 first-only checks=%d memo_total=%v rel_total=%v", checks, memoTotal, relTotal)
}
