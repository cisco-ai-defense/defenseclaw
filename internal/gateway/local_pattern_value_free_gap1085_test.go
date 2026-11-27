// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1085 (class of GAP-0429 (b)): the legacy local secret and
// PII detectors put the matched value into their flags, and the flags are
// the verdict reason (the block message the agent and the user read) and the
// findings every sink receives: hook answers, audit rows, telemetry, log
// lines, alerts. A blocked raw-forward reply carried the assignment it
// withheld. The flags now name the finding only.

// gap1085Value is one value a legacy local detector matches: label + value
// is the text, value the bytes no sink may carry.
type gap1085Value struct {
	name, label, value string
}

// gap1085Luhn appends the check digit that makes p pass the Luhn test.
func gap1085Luhn(p string) string {
	sum, double := 0, true
	for i := len(p) - 1; i >= 0; i-- {
		d := int(p[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return p + string(rune('0'+(10-sum%10)%10))
}

// gap1085Values are run-time values of every legacy local detector: the five
// secret assignments, a US SSN and a payment card number.
func gap1085Values(t testing.TB) []gap1085Value {
	t.Helper()
	return gap1085ValuesFrom(t, gap0429Random)
}

// gap1085ValuesFrom is gap1085Values with the random draw given.
func gap1085ValuesFrom(t testing.TB, draw func(testing.TB, string, int) string) []gap1085Value {
	t.Helper()
	r := func(alphabet string, n int) string { return draw(t, alphabet, n) }
	// assigned draws the value of a credential-named assignment. The rule
	// reads a value with no digit, or one made mostly of words, as a name and
	// not a secret (secretAssignmentRejection); a uniform draw is one about
	// once in 800, so the row redraws until it holds a generated secret
	// (rel-1-0-10:GAP-2251).
	assigned := func(n int) string {
		for range 64 {
			if value := r(gap0429Alnum, n); secretAssignmentValueLooksSecret(value) {
				return value
			}
		}
		t.Fatalf("64 draws of %d characters were all values the assignment rule rejects", n)
		return ""
	}
	const digits, nonzero = "0123456789", "123456789"
	card := gap1085Luhn("4" + r(digits, 14))
	return []gap1085Value{
		{"token", gap0429Label("tok", "en: "), assigned(40)},
		{"password", gap0429Label("pass", "word = "), assigned(24)},
		{"api-key", gap0429Label("api", "_key = "), assigned(40)},
		{"bearer", gap0429Label("Authorization: ", "Bearer "), r(gap0429Alnum, 40)},
		{"aws-secret-key", gap0429Label("aws_secret", "_access_key = "), r(gap0429Alnum+"+/", 40)},
		{"ssn", "SSN ", "2" + r(digits, 2) + "-1" + r(nonzero, 1) + "-" + r(nonzero, 1) + r(digits, 3)},
		{"card", "card ", card[:4] + " " + card[4:8] + " " + card[8:12] + " " + card[12:]},
	}
}

// gap1085Text is a reply or prompt that holds v.
func gap1085Text(v gap1085Value) string {
	return "The build passed on the second run.\n" + v.label + v.value + " is the value.\n"
}

// gap1085Leaked counts the 8-byte windows of the value (as written, and with
// its separators removed) found in sink: 0 when no run of value bytes long
// enough to tell the value is there.
func gap1085Leaked(sink, value string) int {
	n := 0
	for _, form := range []string{value, strings.NewReplacer(" ", "", "-", "").Replace(value)} {
		for i := 0; i+8 <= len(form); i++ {
			if strings.Contains(sink, form[i:i+8]) {
				n++
			}
		}
	}
	return n
}

// TestGAP1085LocalPatternVerdictCarriesNoMatchedValue: for every legacy
// detector, in both directions, the verdict (reason, findings, every field),
// the block message, the normalized findings of the audit boundary and the
// gateway log line (with DEFENSECLAW_REVEAL_PII on, so the log redaction
// does not hide a value the verdict holds) carry 0 bytes of the value, and
// the verdict still names a finding. An operator's literal indicator is a
// row too: it can be a canary value itself.
func TestGAP1085LocalPatternVerdictCarriesNoMatchedValue(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	values := gap1085Values(t)
	canary := "dccanary" + gap0429Random(t, "abcdefghijklmnopqrstuvwxyz0123456789", 24)
	localPatternsMu.Lock()
	previous := secretPatterns
	secretPatterns = []string{canary}
	localPatternsMu.Unlock()
	t.Cleanup(func() {
		localPatternsMu.Lock()
		secretPatterns = previous
		localPatternsMu.Unlock()
	})
	values = append(values, gap1085Value{"operator-literal", "the canary ", canary})
	for _, v := range values {
		for _, direction := range []string{"completion", "prompt"} {
			verdict := scanLocalPatterns(direction, gap1085Text(v))
			if verdict == nil || verdict.Severity == "NONE" || len(verdict.Findings) == 0 {
				t.Errorf("%s/%s: no finding (the row needs a match): %+v", v.name, direction, verdict)
				continue
			}
			whole, _ := json.Marshal(verdict)
			normalized, _ := json.Marshal(NormalizeScanVerdict(verdict))
			sinks := map[string]string{
				"verdict":             string(whole),
				"block message":       blockMessage("", direction, verdict.Reason),
				"normalized findings": string(normalized),
				"log line": captureStderr(t, func() {
					logVerdict(verdict.Severity, verdict.Action, verdict, time.Millisecond)
				}),
			}
			for sink, text := range sinks {
				if n := gap1085Leaked(text, v.value); n > 0 {
					t.Errorf("%s/%s: the %s carries the matched value (%d value windows)", v.name, direction, sink, n)
				}
			}
		}
	}
}

// TestGAP2251GAP1085ValuesAlwaysMatch (rel-1-0-10:GAP-2251): the token and
// api-key rows carry only the credential-named assignment rule, and that
// rule by design reads a value with no digit, or one made mostly of words,
// as a name and not a secret. A uniform 40-character draw is such a value
// about once in 800 runs, so TestGAP1085LocalPatternVerdictCarriesNoMatchedValue
// failed with "no finding" on one native Windows run. A draw that gives the
// rejected shapes first must still yield rows that every detector matches.
func TestGAP2251GAP1085ValuesAlwaysMatch(t *testing.T) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rejected := []string{
		gap0429Random(t, letters, 40),
		"BuildPipelineReleaseNotesSummary2026Done",
	}
	for _, value := range rejected {
		if reason := secretAssignmentRejection(value); reason == "" {
			t.Fatalf("fixture %q is not a value the assignment rule rejects", value)
		}
	}
	draw := func(tb testing.TB, alphabet string, n int) string {
		if alphabet == gap0429Alnum && n == 40 && len(rejected) > 0 {
			value := rejected[0]
			rejected = rejected[1:]
			return value
		}
		return gap0429Random(tb, alphabet, n)
	}
	for _, v := range gap1085ValuesFrom(t, draw) {
		for _, direction := range []string{"completion", "prompt"} {
			if verdict := scanLocalPatterns(direction, gap1085Text(v)); verdict == nil || verdict.Severity == "NONE" || len(verdict.Findings) == 0 {
				t.Errorf("%s/%s: no finding for a fixture value: %+v", v.name, direction, verdict)
			}
		}
	}
}
