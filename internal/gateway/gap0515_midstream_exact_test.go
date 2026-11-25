// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// gap0515Atoms are the pieces the random texts of the GAP-0515 property
// tests are made of: prose, every character class the normalization and
// the PII runs care about (whitespace and slash runs, NBSP and other Z
// spaces, zero-width and format characters, combining marks after ASCII,
// Hangul jamo, invalid UTF-8), and number shapes near the PII regexes.
var gap0515Atoms = []string{
	"the ", "data ", "Value ", "KEY ", "e", "a", "Z", "k", "x", "_",
	" ", "  ", "\t", "\n", "\r\n", "\f", "\v",
	"/", "//", "///", "\\", "\\\\", " / ", "  /  ", " \\ ", "/ ", " /",
	"\u00a0", " \u00a0/ ", "\u3000", "\u2028", "\u2029", "\u202f",
	"\u200b", "\u00ad", "\u034f", "\u200d", "\ufeff", "\u2060", "\u202e",
	"\u0301", "\u0338", "<", "=", ">", "\u00e9", "\u226e", "e\u0301", "<\u0338",
	"\u1100", "\u1161", "\u11a8", "\u212a", "\u017f", "\u00c9", "\u1e9e", "\u4e2d\u6587",
	"\xff", "\xe2\x82", "\xc3", "\x80",
	"0", "1", "4", "5", "9", "12", "123", "1234", "-", "--", " - ",
	"ssn: ", "social security ", "card ", ",", ";", "|", ".",
	"name,ssn\n", "id\tssn\n",
}

// gap0515SSN is a valid-looking social security number made at run time.
func gap0515SSN(r *rand.Rand) string {
	return fmt.Sprintf("%03d-%02d-%04d", 100+r.Intn(565), 10+r.Intn(89), 1000+r.Intn(8999))
}

// gap0515Card is a Luhn-valid 16-digit number with a Visa prefix, grouped
// with sep, made at run time.
func gap0515Card(r *rand.Rand, sep string) string {
	d := make([]int, 16)
	d[0] = 4
	for i := 1; i < 15; i++ {
		d[i] = r.Intn(10)
	}
	sum := 0
	for i := 0; i < 15; i++ {
		v := d[14-i]
		if i%2 == 0 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	d[15] = (10 - sum%10) % 10
	var b strings.Builder
	for i, v := range d {
		if i > 0 && i%4 == 0 {
			b.WriteString(sep)
		}
		b.WriteByte(byte('0' + v))
	}
	return b.String()
}

// gap0515Text is a random text of about n bytes from the atoms, prose,
// PII shapes and the secret-rule fixtures.
func gap0515Text(r *rand.Rand, n int) string {
	secrets := secretRuleTruePositives()
	var b strings.Builder
	for b.Len() < n {
		switch k := r.Intn(100); {
		case k < 3:
			b.WriteString(gap0515SSN(r))
		case k < 5:
			b.WriteString(gap0515Card(r, []string{"", " ", "-"}[r.Intn(3)]))
		case k < 6:
			b.WriteString(secrets[r.Intn(len(secrets))].input)
		case k < 12:
			b.WriteString(gap0515Prose(20+r.Intn(200), r.Int63()))
		default:
			b.WriteString(gap0515Atoms[r.Intn(len(gap0515Atoms))])
		}
	}
	return b.String()
}

// gap0515Checkpoints is a random increasing list of prefix lengths of a
// text of n bytes, ending at n.
func gap0515Checkpoints(r *rand.Rand, n int) []int {
	var out []int
	for at := 0; at < n; {
		switch r.Intn(4) {
		case 0:
			at += 1 + r.Intn(3)
		case 1:
			at += 1 + r.Intn(40)
		default:
			at += 1 + r.Intn(700)
		}
		out = append(out, min(at, n))
	}
	return out
}

// gap0515Edit is text with a random piece replaced or inserted before its
// end: a text that is not an extension of the one before (a lane grew
// before the last one).
func gap0515Edit(r *rand.Rand, text string) string {
	if text == "" {
		return gap0515Text(r, 10)
	}
	at := r.Intn(len(text))
	cut := min(len(text), at+r.Intn(20))
	return text[:at] + gap0515Text(r, r.Intn(30)) + text[cut:]
}

// TestGAP0515TriageSplitPoints: at every split point the normalization of
// a text is the normalization of its two parts, and the memo of a stream
// gives normalizeForTriage of every text, extensions and edits alike.
func TestGAP0515TriageSplitPoints(t *testing.T) {
	r := rand.New(rand.NewSource(515))
	splits := 0
	for i := 0; i < 400/gap0515Scale; i++ {
		s := gap0515Text(r, 1+r.Intn(400))
		want := normalizeForTriage(s)
		for c := 1; c < len(s); c++ {
			if !triageSplitAt(s, c) {
				continue
			}
			splits++
			if got := normalizeForTriage(s[:c]) + normalizeForTriage(s[c:]); got != want {
				t.Fatalf("split %d of %q: got %q, want %q", c, s, got, want)
			}
		}
	}
	if splits < 1000/gap0515Scale {
		t.Fatalf("only %d split points checked", splits)
	}
	for i := 0; i < 200/gap0515Scale; i++ {
		var m rxprefilter.SplitMemo
		text := gap0515Text(r, 3000)
		for _, at := range gap0515Checkpoints(r, len(text)) {
			s := text[:at]
			if r.Intn(10) == 0 {
				s = gap0515Edit(r, s)
			}
			if got, want := m.Apply(s, normalizeForTriage, triageSplitAt), normalizeForTriage(s); got != want {
				t.Fatalf("memo of %q: got %q, want %q", s, got, want)
			}
		}
	}
}

// gap0515Regexes are the default PII data regexes and other shapes an
// operator's pii_data_regexes can take: searched in runs (ASCII classes,
// \b, \B, alternation, repeats) and not (anchors, any character, a match
// that can be empty, a non-ASCII class, a folded k), which read the whole
// text.
func gap0515Regexes() []*regexp.Regexp {
	out := append([]*regexp.Regexp(nil), compileBaseline(defaultPIIDataRegexSources)...)
	for _, src := range []string{
		`\b\d{3}-\d{2}-\d{4}\b`, `\d{4}`, `\B\d{2}\B`, `(?i)ab+c`, `(?i)ssn\s*\d+`, `a|ab`, `(?:ab)+c`,
		`[a-z]{2,}x`, `\b(?:4\d{3}|5[1-5]\d{2})[- ]?\d{4}\b`, `x{0}\d`, `[\-/\\ ]+\d`,
		`^\d+`, `\d+$`, `(?m)^\d+`, `.\d`, `\d*`, `\p{Z}\d`, `[^a]\d`, `(?s)a.b`, `(?i)k\d`,
	} {
		out = append(out, regexp.MustCompile(src))
	}
	return out
}

// TestGAP0515RuleAndPIIMatchesEqualWholeText: through the memo of a stream,
// every text of the stream (extensions and edits alike) gives every regex
// the matches FindAll gives the whole text, every PII regex its first
// accepted match, and every rule of the default pack its literal check and
// first accepted match as the scan of the text alone does.
func TestGAP0515RuleAndPIIMatchesEqualWholeText(t *testing.T) {
	r := rand.New(rand.NewSource(5150))
	regexes := gap0515Regexes()
	generation := snapshotRulePackGeneration("")
	var rules []*PatternRule
	for ci := range generation.categories {
		for ri := range generation.categories[ci].Rules {
			if rule := &generation.categories[ci].Rules[ri]; rule.Pattern != nil {
				rules = append(rules, rule)
			}
		}
	}
	if len(rules) < 50 {
		t.Fatalf("only %d rules in the default pack", len(rules))
	}
	ruleHits := 0
	for i := 0; i < 8/gap0515Scale; i++ {
		st := newMidStreamScanState()
		size := 4000
		if i%4 == 0 {
			size = 70 << 10 // over rxprefilter.WindowMinText
		}
		text := gap0515Text(r, size)
		points := gap0515Checkpoints(r, len(text))
		if len(points) > 20 {
			points = points[len(points)-20:]
		}
		for _, at := range points {
			s := text[:at]
			if r.Intn(10) == 0 {
				s = gap0515Edit(r, s)
			}
			rule, scan := st.scanTexts("content", s)
			plainRule, plainScan := &ruleScanText{text: s}, rxprefilter.NewText(s)
			for _, re := range regexes {
				if got, want := scan.FindAllStringIndex(re), re.FindAllStringIndex(s, -1); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s on %d bytes: got %v, want %v", re, len(s), got, want)
				}
				if got, want := scan.FindStringIndex(re), re.FindStringIndex(s); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s first on %d bytes: got %v, want %v", re, len(s), got, want)
				}
				lower := normalizeForTriage(s)
				gm, gn, gok := st.findAcceptedLocalPIIMatch(s, st.normalizeForTriage(s), re)
				wm, wn, wok := findAcceptedLocalPIIMatch(s, lower, re)
				if gm != wm || gn != wn || gok != wok {
					t.Fatalf("PII %s on %d bytes: got %q %v %v, want %q %v %v", re, len(s), gm, gn, gok, wm, wn, wok)
				}
			}
			for _, pr := range rules {
				if got, want := rule.mayMatch(pr.Pattern), plainRule.mayMatch(pr.Pattern); got != want {
					t.Fatalf("rule %s literals on %d bytes: got %v, want %v", pr.ID, len(s), got, want)
				}
				if got, want := scan.MayMatch(pr.Pattern), plainScan.MayMatch(pr.Pattern); got != want {
					t.Fatalf("rule %s required literals on %d bytes: got %v, want %v", pr.ID, len(s), got, want)
				}
				got, want := firstAcceptedRuleMatchIn(*pr, scan), firstAcceptedRuleMatchIn(*pr, plainScan)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("rule %s on %d bytes: got %v, want %v", pr.ID, len(s), got, want)
				}
				if want != nil {
					ruleHits++
				}
			}
		}
	}
	if ruleHits < 50/gap0515Scale {
		t.Fatalf("only %d rule matches: the property test reads too little", ruleHits)
	}
}

// gap0515RSA8192 is a PKCS #1 RSA private key PEM of the length of an
// 8192-bit key (GAP-0622: longer than any window), made at run time from
// fixed pseudo-random integers: the secret rule checks the PEM structure
// (nine positive integers), not the arithmetic, so no key generation is
// needed.
var gap0515RSA8192 = sync.OnceValue(func() string {
	r := rand.New(rand.NewSource(8192))
	integer := func(n int) *big.Int {
		b := make([]byte, n)
		r.Read(b)
		b[0] |= 0x80
		return new(big.Int).SetBytes(b)
	}
	der, err := asn1.Marshal(struct {
		Version                     int
		N, E, D, P, Q, Dp, Dq, QInv *big.Int
	}{0, integer(1024), big.NewInt(65537), integer(1024), integer(512), integer(512), integer(512), integer(512), integer(512)})
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE" + " KEY", Bytes: der}))
})

// gap0515Verdict is what a mid-stream check decides and reports: every
// field of the verdict but the in-process trace identity.
func gap0515Verdict(v *ScanVerdict) ScanVerdict {
	if v == nil {
		return ScanVerdict{}
	}
	c := *v
	c.EvaluationID, c.ScanID, c.EnforcementID = "", "", ""
	c.GeneratedTraceOwned, c.FindingsEmitted = false, false
	c.TraceContext = ScanVerdict{}.TraceContext
	return c
}

// gap0515Equal checks the mid-stream check of s with the stream's memo
// against the check of s read whole: the local-pattern verdict and the
// inspector's verdict, every field.
func gap0515Equal(t *testing.T, insp *GuardrailInspector, st *midStreamScanState, name, s string) {
	t.Helper()
	rules := snapshotRulePackGeneration("")
	got := scanLocalPatternsWithState("completion", s, rules, nil, st)
	want := scanLocalPatternsWithActivation("completion", s, rules, nil)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: local patterns at %d bytes:\n got  %+v\n want %+v", name, len(s), got, want)
	}
	msgs := []ChatMessage{{Role: "assistant", Content: s}}
	gv := insp.InspectMidStream(withMidStreamScanState(context.Background(), st), "completion", s, msgs, "m", "action")
	wv := insp.InspectMidStream(context.Background(), "completion", s, msgs, "m", "action")
	if g, w := gap0515Verdict(gv), gap0515Verdict(wv); !reflect.DeepEqual(g, w) {
		t.Fatalf("%s: mid-stream verdict at %d bytes:\n got  %+v\n want %+v", name, len(s), g, w)
	}
}

// TestGAP0515MidStreamVerdictsEqualWholeText: for random texts and random
// checkpoints, every mid-stream check with the stream's memo decides and
// reports exactly what the check of the whole text does (rel-1-0-10:
// GAP-0515): the same action, severity, reason, findings and PII dedupe.
// The texts hold the GAP-0622 RSA-8192 key (longer than any window), PII
// and secret shapes, whitespace and slash runs, and lane-joined text where
// an earlier lane grows after a later one (GAP-0623).
func TestGAP0515MidStreamVerdictsEqualWholeText(t *testing.T) {
	insp := NewGuardrailInspector("local", nil, nil)
	r := rand.New(rand.NewSource(51500))
	flagged := 0
	for i := 0; i < 20/gap0515Scale; i++ {
		size := 6000
		if i%10 == 9 {
			size = 80 << 10 // the parallel rule scan and the windows
		}
		text := gap0515Text(r, size)
		if i%8 == 0 {
			at := r.Intn(len(text))
			text = text[:at] + "\n" + gap0515RSA8192() + "\n" + text[at:]
		}
		st := newMidStreamScanState()
		points := gap0515Checkpoints(r, len(text))
		if len(points) > 30 {
			points = append(points[:10:10], points[len(points)-20:]...)
		}
		for _, at := range points {
			s := text[:at]
			if r.Intn(12) == 0 {
				s = gap0515Edit(r, s)
			}
			gap0515Equal(t, insp, st, fmt.Sprintf("text %d", i), s)
		}
		if v := scanLocalPatternsWithActivation("completion", text, snapshotRulePackGeneration(""), nil); v.Severity != "NONE" {
			flagged++
		}
	}
	if flagged < 5/gap0515Scale {
		t.Fatalf("only %d of 20 texts have a finding: the property test reads too little", flagged)
	}

	// The RSA-8192 key alone, checked every 500 bytes and every 37 bytes.
	key := gap0515Prose(1100, 3) + gap0515RSA8192() + gap0515Prose(3000, 4)
	for _, step := range []int{500, 211}[:2-gap0515Scale/4] {
		st := newMidStreamScanState()
		blocked := false
		for at := step; ; at += step {
			at = min(at, len(key))
			gap0515Equal(t, insp, st, fmt.Sprintf("rsa8192/%d", step), key[:at])
			if !blocked {
				v := insp.InspectMidStream(withMidStreamScanState(context.Background(), st), "completion", key[:at], nil, "m", "action")
				blocked = v.Action == "block"
			}
			if at == len(key) {
				break
			}
		}
		if !blocked {
			t.Fatalf("rsa8192/%d: the key was never blocked", step)
		}
	}

	// Lane-joined text: two choices, the first grows after the second.
	for i := 0; i < 8/gap0515Scale; i++ {
		var acc responseText
		st := newMidStreamScanState()
		for step := 0; step < 80; step++ {
			lane := 0
			if r.Intn(3) > 0 {
				lane = 1
			}
			acc.Add(answerPiece(lane, gap0515Text(r, 1+r.Intn(120))))
			gap0515Equal(t, insp, st, fmt.Sprintf("lanes %d", i), acc.String())
		}
	}
}
