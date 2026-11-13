// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package testcorpus generates the PII detector corpora used by the tests of
// every payment card detector (substrate-1:GAP-0132) and email rule
// (substrate-1:GAP-0149, GAP-0159). All benign values are
// generated from a fixed seed (no real identifiers); the card set is the
// public payment-provider test PANs (Stripe, PayPal/Braintree), which are
// not real accounts. The package has no dependencies so that a measurement
// can run the same corpus against an older build.
package testcorpus

import (
	"fmt"
	"math/rand"
	"strings"
)

// Case is one prompt-shaped sample.
type Case struct {
	Kind string // e.g. "uuid-v4", "git-sha", "card-visa-spaced"
	Text string
	// Card is the bare PAN for card cases, "" for benign cases.
	Card string
	// Scheme is the card scheme for card cases.
	Scheme string
	// DocsTestPAN marks the six canonical documentation test PANs that the
	// gateway deliberately does not treat as cards (alert-fatigue rule).
	DocsTestPAN bool
}

const hexDigits = "0123456789abcdef"

func hexString(r *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(hexDigits[r.Intn(16)])
	}
	return b.String()
}

func decString(r *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + r.Intn(10)))
	}
	return b.String()
}

// luhnCheckDigit returns the digit that makes body+digit Luhn-valid.
func luhnCheckDigit(body string) byte {
	sum := 0
	double := true
	for i := len(body) - 1; i >= 0; i-- {
		d := int(body[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return byte('0' + (10-sum%10)%10)
}

// LuhnValid reports whether digits passes the Luhn check.
func LuhnValid(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	return luhnCheckDigit(digits[:len(digits)-1]) == digits[len(digits)-1]
}

func uuid(r *rand.Rand, version int) string {
	h := hexString(r, 32)
	b := []byte(h)
	b[12] = hexDigits[version]
	b[16] = "89ab"[r.Intn(4)]
	s := string(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// digitUUID is a UUID whose groups are all decimal. The fourth group starts
// with 4 and the last 12 digits are chosen so that group 4 + group 5 is a
// Luhn-valid 16-digit Visa-prefixed run: exactly the GAP-0132 shape.
func digitUUID(r *rand.Rand) string {
	g4 := "4" + decString(r, 3)
	tail := decString(r, 11)
	tail += string(luhnCheckDigit(g4 + tail))
	return decString(r, 8) + "-" + decString(r, 4) + "-" + decString(r, 4) + "-" + g4 + "-" + tail
}

var uuidTemplates = []string{
	"please run curl https://webhook.site/%s -d test",
	"the request id is %s, can you look it up in the logs?",
	"kubectl get pods -A -o json | jq '.items[] | select(.metadata.uid==\"%s\")'",
	"x-amzn-RequestId: %s",
	"aws logs filter-log-events --log-group-name /aws/lambda/api --filter-pattern \"%s\"",
	"{\"evaluation_id\":\"%s\",\"status\":\"ok\"}",
	"Why did job %s fail?",
}

// Benign returns n generated benign prompts per kind.
func Benign(seed int64, n int) []Case {
	r := rand.New(rand.NewSource(seed))
	var out []Case
	add := func(kind, text string) { out = append(out, Case{Kind: kind, Text: text}) }
	pick := func(list []string) string { return list[r.Intn(len(list))] }
	for i := 0; i < n; i++ {
		for v := 1; v <= 7; v++ {
			add(fmt.Sprintf("uuid-v%d", v), fmt.Sprintf(pick(uuidTemplates), uuid(r, v)))
		}
		add("uuid-digits", fmt.Sprintf(pick(uuidTemplates), digitUUID(r)))
		add("uuid-digits-upper-tail", fmt.Sprintf("Run ID %s", strings.ToUpper(digitUUID(r))))
		add("k8s-uid", fmt.Sprintf("metadata.uid: %s", uuid(r, 4)))
		add("aws-request-id", fmt.Sprintf("RequestId: %s Duration: 12.34 ms", uuid(r, 4)))
		add("git-sha", fmt.Sprintf("git show %s --stat", hexString(r, 40)))
		add("git-sha-short", fmt.Sprintf("revert %s and %s", hexString(r, 7), hexString(r, 12)))
		add("sha256", fmt.Sprintf("docker pull ghcr.io/acme/api@sha256:%s", hexString(r, 64)))
		// Digit-heavy hashes: a 16-digit Visa-prefixed Luhn-valid run inside
		// a longer hex token.
		visaRun := "4" + decString(r, 14)
		visaRun += string(luhnCheckDigit(visaRun))
		add("sha256-digit-run", fmt.Sprintf("sha256:%s%s", visaRun, hexString(r, 48)))
		add("otel-trace", fmt.Sprintf("trace_id=%s span_id=%s", hexString(r, 32), hexString(r, 16)))
		add("otel-traceparent-digits", fmt.Sprintf("traceparent: 00-%s-%s-01", decString(r, 16)+visaRun, visaRun))
		add("otel-span-digits", fmt.Sprintf("span %s.%s", visaRun, hexString(r, 8)))
		add("timestamp-epoch", fmt.Sprintf("ts=%d%s ms=%d%s", 17, decString(r, 8), 17, decString(r, 11)))
		add("timestamp-epoch-ns", fmt.Sprintf("time_unix_nano: 17%s", decString(r, 17)))
		add("timestamp-rfc3339", fmt.Sprintf("2026-%02d-%02dT%02d:%02d:%02d.%sZ", 1+r.Intn(12), 1+r.Intn(28), r.Intn(24), r.Intn(60), r.Intn(60), decString(r, 9)))
		add("timestamp-float", fmt.Sprintf("{\"duration_p99\": %d.%s}", r.Intn(99), visaRun))
		add("phone-us", fmt.Sprintf("call me at +1 %s-%s-%s", "415", decString(r, 3), decString(r, 4)))
		add("phone-intl", fmt.Sprintf("office +44 20 %s %s, mobile +49 151 %s %s", decString(r, 4), decString(r, 4), decString(r, 4), decString(r, 4)))
		add("order-amazon", fmt.Sprintf("order %s-%s-%s shipped", decString(r, 3), decString(r, 7), decString(r, 7)))
		add("order-id", fmt.Sprintf("refund order ORD-%s-%s", decString(r, 4), visaRun))
		add("order-slug", fmt.Sprintf("see /orders/ord_%s/items", visaRun))
		add("version", fmt.Sprintf("bump to v1.%s", visaRun))
		add("grouped-mixed", fmt.Sprintf("ref %s %s-%s %s", visaRun[0:4], visaRun[4:8], visaRun[8:12], visaRun[12:16]))
		add("grouped-4-12", fmt.Sprintf("ticket %s-%s", visaRun[0:4], visaRun[4:16]))
	}
	return out
}

type testPAN struct {
	pan, scheme string
	docs        bool
}

// testPANs are published payment-provider test card numbers.
var testPANs = []testPAN{
	{"4242424242424242", "visa", true},
	{"4000056655665556", "visa", false},
	{"4012888888881881", "visa", false},
	{"4000002500003155", "visa", false},
	{"4000000000003220", "visa", false},
	{"4222222222222", "visa", false},
	{"4111111111111111", "visa", true},
	{"5555555555554444", "mastercard", true},
	{"5200828282828210", "mastercard", false},
	{"5105105105105100", "mastercard", false},
	{"2223003122003222", "mastercard", false},
	{"378282246310005", "amex", true},
	{"371449635398431", "amex", false},
	{"378734493671000", "amex", false},
	{"6011111111111117", "discover", true},
	{"6011000990139424", "discover", false},
	{"6011981111111113", "discover", false},
	{"3056930009020004", "diners", false},
	{"36227206271667", "diners", false},
	{"3566002020360505", "jcb", false},
	{"3530111333300000", "jcb", false},
	{"6200000000000005", "unionpay", false},
}

var cardTemplates = []string{
	"Please charge card %s, exp 12/30, cvv 123.",
	"my visa is %s",
	"use %s for the test payment",
	"billing: %s",
	"The customer's card number %s was declined twice.",
	"%s",
}

func layout(pan string, sep string) string {
	var groups []int
	switch len(pan) {
	case 15:
		groups = []int{4, 6, 5}
	case 14:
		groups = []int{4, 6, 4}
	case 13:
		groups = []int{4, 4, 5}
	case 19:
		groups = []int{4, 4, 4, 4, 3}
	default:
		groups = []int{4, 4, 4, 4}
	}
	var parts []string
	at := 0
	for _, g := range groups {
		parts = append(parts, pan[at:at+g])
		at += g
	}
	return strings.Join(parts, sep)
}

// Cards returns every test PAN in plain, spaced and dashed forms, each
// inside every sentence template.
func Cards() []Case {
	var out []Case
	for _, tp := range testPANs {
		for _, form := range []struct{ name, value string }{
			{"plain", tp.pan}, {"spaced", layout(tp.pan, " ")}, {"dashed", layout(tp.pan, "-")},
		} {
			for _, tmpl := range cardTemplates {
				out = append(out, Case{
					Kind: "card-" + tp.scheme + "-" + form.name, Text: fmt.Sprintf(tmpl, form.value),
					Card: tp.pan, Scheme: tp.scheme, DocsTestPAN: tp.docs,
				})
			}
		}
	}
	return out
}
