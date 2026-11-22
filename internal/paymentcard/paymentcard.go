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

// Package paymentcard decides whether a regex candidate is a payment card
// number (PAN). Every card detector (guardrail rule packs, triage, local
// patterns, the clawshield file scanner) shares it, so a digit run counts as
// a card only when all of these hold:
//
//  1. it passes the Luhn check;
//  2. its length and issuer prefix match a real card scheme;
//  3. it looks like a card: digits alone, or groups in a card layout with one
//     consistent separator, and it is not part of a longer token such as a
//     UUID, hash, trace id, version or decimal number.
//
// Context words ("card", "visa", "cvv", ...) may raise confidence; they are
// never enough on their own.
package paymentcard

import "regexp"

// Digits returns the ASCII digits of value in order.
func Digits(value string) string {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if c := value[i]; c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return string(out)
}

// Luhn reports whether digits (ASCII digits only) passes the Luhn checksum.
func Luhn(digits string) bool {
	if digits == "" {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

type scheme struct {
	name       string
	low, high  int // inclusive issuer-prefix range over the first prefixLen digits
	prefixLen  int
	minLength  int
	maxLength  int
	lengthMask uint32 // optional: bit n set = length n allowed (overrides min/max)
}

func lengths(values ...int) uint32 {
	var mask uint32
	for _, v := range values {
		mask |= 1 << uint(v)
	}
	return mask
}

// schemes lists issuer prefixes (IIN ranges) and PAN lengths. The list is
// deliberately conservative: a range is here only when the scheme publishes it.
var schemes = []scheme{
	{name: "visa", low: 4, high: 4, prefixLen: 1, lengthMask: lengths(13, 16, 19)},
	{name: "mastercard", low: 51, high: 55, prefixLen: 2, minLength: 16, maxLength: 16},
	{name: "mastercard", low: 2221, high: 2720, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "amex", low: 34, high: 34, prefixLen: 2, minLength: 15, maxLength: 15},
	{name: "amex", low: 37, high: 37, prefixLen: 2, minLength: 15, maxLength: 15},
	{name: "discover", low: 6011, high: 6011, prefixLen: 4, minLength: 16, maxLength: 19},
	{name: "discover", low: 644, high: 649, prefixLen: 3, minLength: 16, maxLength: 19},
	{name: "discover", low: 65, high: 65, prefixLen: 2, minLength: 16, maxLength: 19},
	{name: "unionpay", low: 62, high: 62, prefixLen: 2, minLength: 16, maxLength: 19},
	{name: "jcb", low: 3528, high: 3589, prefixLen: 4, minLength: 16, maxLength: 19},
	{name: "diners", low: 300, high: 305, prefixLen: 3, minLength: 14, maxLength: 19},
	{name: "diners", low: 36, high: 36, prefixLen: 2, minLength: 14, maxLength: 19},
	{name: "diners", low: 38, high: 39, prefixLen: 2, minLength: 16, maxLength: 19},
	{name: "mir", low: 2200, high: 2204, prefixLen: 4, minLength: 16, maxLength: 19},
	{name: "diners", low: 3095, high: 3095, prefixLen: 4, minLength: 14, maxLength: 19},
	{name: "rupay", low: 60, high: 60, prefixLen: 2, minLength: 16, maxLength: 16},
	{name: "rupay", low: 81, high: 82, prefixLen: 2, minLength: 16, maxLength: 16},
	{name: "rupay", low: 508, high: 508, prefixLen: 3, minLength: 16, maxLength: 16},
	{name: "elo", low: 509, high: 509, prefixLen: 3, minLength: 16, maxLength: 16},
	{name: "elo", low: 5041, high: 5041, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "elo", low: 5066, high: 5067, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "elo", low: 6277, high: 6277, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "elo", low: 6362, high: 6363, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "verve", low: 5060, high: 5061, prefixLen: 4, minLength: 16, maxLength: 19},
	{name: "dankort", low: 5019, high: 5019, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "troy", low: 9792, high: 9792, prefixLen: 4, minLength: 16, maxLength: 16},
	{name: "instapayment", low: 637, high: 639, prefixLen: 3, minLength: 16, maxLength: 16},
	{name: "maestro", low: 5018, high: 5018, prefixLen: 4, minLength: 12, maxLength: 19},
	{name: "maestro", low: 5020, high: 5020, prefixLen: 4, minLength: 12, maxLength: 19},
	{name: "maestro", low: 5038, high: 5038, prefixLen: 4, minLength: 12, maxLength: 19},
	{name: "maestro", low: 5893, high: 5893, prefixLen: 4, minLength: 12, maxLength: 19},
	{name: "maestro", low: 6304, high: 6304, prefixLen: 4, minLength: 12, maxLength: 19},
	{name: "maestro", low: 6759, high: 6759, prefixLen: 4, minLength: 12, maxLength: 19},
	{name: "maestro", low: 6761, high: 6763, prefixLen: 4, minLength: 12, maxLength: 19},
}

// Scheme returns the card scheme whose issuer prefix and PAN length match
// digits, or "" when none does.
func Scheme(digits string) string {
	n := len(digits)
	for _, s := range schemes {
		if n < s.prefixLen {
			continue
		}
		prefix := 0
		for i := 0; i < s.prefixLen; i++ {
			c := digits[i]
			if c < '0' || c > '9' {
				return ""
			}
			prefix = prefix*10 + int(c-'0')
		}
		if prefix < s.low || prefix > s.high {
			continue
		}
		if s.lengthMask != 0 {
			if n < 32 && s.lengthMask&(1<<uint(n)) != 0 {
				return s.name
			}
			continue
		}
		if n >= s.minLength && n <= s.maxLength {
			return s.name
		}
	}
	return ""
}

// cardGroupings are the printed layouts of a grouped PAN, by group length.
var cardGroupings = [][]int{
	{4, 4, 4, 4},    // 16: Visa, Mastercard, Discover, JCB, UnionPay
	{4, 4, 4, 4, 3}, // 19: Visa, Discover, UnionPay
	{4, 6, 5},       // 15: American Express
	{4, 6, 4},       // 14: Diners Club
	{4, 4, 5},       // 13: Visa
	{6, 13},         // 19: Maestro / UnionPay
}

// Grouped reports whether value has a card layout: digits only, or digit
// groups in one of the printed card layouts joined by a single consistent
// separator (one space, tab, hyphen or dot; the built-in rules search only for
// spaces and hyphens, operator local patterns may search for dots).
// "4444-555555555555" (the tail of a UUID) and "4532 0151-1283 0366" are not
// card layouts.
func Grouped(value string) bool {
	var groups []int
	sep := byte(0)
	run := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= '0' && c <= '9':
			run++
		case c == ' ' || c == '\t' || c == '-' || c == '.':
			if run == 0 {
				return false // leading or doubled separator
			}
			if sep == 0 {
				sep = c
			} else if sep != c {
				return false
			}
			groups = append(groups, run)
			run = 0
		default:
			return false
		}
	}
	if run == 0 {
		return false
	}
	if sep == 0 {
		return true
	}
	groups = append(groups, run)
	for _, layout := range cardGroupings {
		if equalInts(groups, layout) {
			return true
		}
	}
	return false
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// segmentBefore and segmentAfter return the run of ASCII letters and digits
// that ends at index i (exclusive) or starts at index i.
func segmentBefore(text string, i int) string {
	j := i
	for j > 0 && isAlnum(text[j-1]) {
		j--
	}
	return text[j:i]
}

func segmentAfter(text string, i int) string {
	j := i
	for j < len(text) && isAlnum(text[j]) {
		j++
	}
	return text[i:j]
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return s != ""
}

// joinedSegment reports whether joiner glues the number to segment, the
// alphanumeric run on the joiner's far side, into one machine token:
//   - '_' joins identifiers (ord_4532..., span_4532...): any segment;
//   - '.' joins decimals, versions and hex ids (0.4532..., v1.4532...,
//     4532....9fa1c3d2): a segment with a digit, or 4+ hex characters.
//     Prose ("Card no.4532...", "4532....Thanks") is not joined;
//   - '-' joins UUID groups, trace ids and numbered ids (3333-4444...,
//     ORD-2026-4532..., deadbeef-4532...): a segment of 3+ characters with a
//     digit, or 4+ hex characters. Labels ("VISA-4532...", "cc-4532...", a
//     prefix such as "x-") and a trailing expiry ("4532...-12/27") are not.
func joinedSegment(joiner byte, segment string) bool {
	switch joiner {
	case '_':
		return segment != ""
	case '.':
		return hasDigit(segment) || len(segment) >= 4 && allHex(segment)
	case '-':
		return len(segment) >= 3 && hasDigit(segment) || len(segment) >= 4 && allHex(segment)
	}
	return false
}

// escapeEndsAt reports a JSON or C escape that ends right before index i: a
// one-letter escape (\n, \t, \r) or \uXXXX. Its last character is a
// boundary, not part of the number's token.
func escapeEndsAt(text string, i int) bool {
	if i >= 2 && text[i-2] == '\\' {
		return true
	}
	if i >= 6 && text[i-6] == '\\' && (text[i-5] == 'u' || text[i-5] == 'U') {
		for k := i - 4; k < i; k++ {
			if !isHex(text[k]) {
				return false
			}
		}
		return true
	}
	return false
}

// Embedded reports whether text[start:end] is part of a longer token rather
// than a standalone number: it touches a letter or digit (other than the end
// of an escape such as \n or \u00a0), or a joiner that glues it to a
// machine-token segment (see joinedSegment). That covers UUIDs and
// Kubernetes uids (11111111-2222-3333-4444-555555555555), trace, request and
// order ids, hashes, decimals (0.4532015112830366) and versions, while
// "Card no.4532...", "VISA-4532..." and "4532....Thanks" stay cards.
func Embedded(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	if start > 0 {
		before := text[start-1]
		if isAlnum(before) && !escapeEndsAt(text, start) {
			return true
		}
		if before == '-' || before == '_' || before == '.' {
			if joinedSegment(before, segmentBefore(text, start-1)) {
				return true
			}
		}
	}
	if end < len(text) {
		after := text[end]
		if isAlnum(after) {
			return true
		}
		if after == '-' || after == '_' || after == '.' {
			if joinedSegment(after, segmentAfter(text, end+1)) {
				return true
			}
		}
	}
	return false
}

// Valid reports whether value alone (no surrounding text) is a card number:
// 12-19 digits in a card layout, a real scheme prefix and length, and Luhn.
func Valid(value string) bool {
	digits := Digits(value)
	if len(digits) < 12 || len(digits) > 19 || !Grouped(value) {
		return false
	}
	return Scheme(digits) != "" && Luhn(digits)
}

// ValidAt reports whether text[start:end] is a card number in its context:
// Valid, and not embedded in a longer token.
func ValidAt(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	return Valid(text[start:end]) && !Embedded(text, start, end)
}

var contextWordRE = regexp.MustCompile(`(?i)\b(?:card|cards|visa|master ?card|amex|american express|discover|jcb|unionpay|diners|maestro|cc|ccn|cvv|cvc|cvv2|exp|expiry|expires|expiration|pan|payment|billing)\b`)

// contextWindow is how far (in bytes) before and after a candidate a card
// context word may sit.
const contextWindow = 48

// ContextNear reports a payment-card context word within a short window
// around text[start:end]. Use it to raise confidence only.
func ContextNear(text string, start, end int) bool {
	if start < 0 || end > len(text) || start > end {
		return false
	}
	lo := start - contextWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + contextWindow
	if hi > len(text) {
		hi = len(text)
	}
	return contextWordRE.MatchString(text[lo:start]) || contextWordRE.MatchString(text[end:hi])
}

// LabeledRunAt reports whether the digit run that ends a label-bound match
// (text[start:end], e.g. "Credit Card Number: 3529 0442 5964 7174") is a
// standalone number: one consistent separator and not glued to a longer
// token. Label-bound rules keep their own Luhn/scheme policy (private-label
// cards carry neither); this only rejects digits lifted from a UUID or id.
func LabeledRunAt(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	runStart := -1
	for i := start; i < end; i++ {
		if text[i] >= '0' && text[i] <= '9' {
			runStart = i
			break
		}
	}
	if runStart < 0 {
		return false
	}
	sep := byte(0)
	for i := runStart; i < end; i++ {
		c := text[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if sep == 0 {
			sep = c
		} else if c != sep {
			return false
		}
	}
	return !Embedded(text, runStart, end)
}
