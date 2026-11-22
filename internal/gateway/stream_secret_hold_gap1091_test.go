// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1091 (P2, folded into the GAP-0429 train by the S7 lead):
// anything a response rule would block is held from its first matching
// prefix until it is decided, and that covers the PII the packs block (card
// numbers, SSN) as well as keys and tokens. The table streams each value
// through every stream path (the /llm proxy, the passthrough stream in every
// wire format, the raw forward stream), in pieces of 1, 7, 24 and 4096 bytes
// and whole, in the 3 packs, and counts the value bytes the client had when
// the first check read the whole value or decided on it (gap0429Watch). That
// count is 0. Every number is generated at run time (Luhn-valid cards of a
// real scheme prefix, SSNs of a valid area, group and serial).

func gap1091Digits(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = byte('0' + k.Int64())
	}
	return string(b)
}

// gap1091Card is a Luhn-valid card number of n digits that starts with prefix.
func gap1091Card(t testing.TB, prefix string, n int) string {
	t.Helper()
	body := prefix + gap1091Digits(t, n-len(prefix)-1)
	sum := 0
	for i := len(body) - 1; i >= 0; i-- {
		d := int(body[i] - '0')
		if (len(body)-1-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return body + string(rune('0'+(10-sum%10)%10))
}

// gap1091Group splits digits into groups of the sizes given, joined by sep.
func gap1091Group(digits, sep string, sizes ...int) string {
	var parts []string
	for _, n := range sizes {
		parts = append(parts, digits[:n])
		digits = digits[n:]
	}
	return strings.Join(parts, sep)
}

func gap1091Ranged(t testing.TB, lo, hi int64) int64 {
	t.Helper()
	k, err := rand.Int(rand.Reader, big.NewInt(hi-lo+1))
	if err != nil {
		t.Fatal(err)
	}
	return lo + k.Int64()
}

const gap1091Lead = "The number on file is "

func gap1091Value(name, v string) gap0429Secret {
	return gap0429Secret{name: name, class: "pii", text: gap1091Lead + v, body: len(gap1091Lead), end: len(gap1091Lead) + len(v)}
}

// gap1091Values are the card numbers and SSNs of the table.
func gap1091Values(t testing.TB) []gap0429Secret {
	t.Helper()
	mc := gap1091Card(t, fmt.Sprintf("5%d", gap1091Ranged(t, 1, 5)), 16)
	amex := gap1091Card(t, "37", 15)
	ssn := fmt.Sprintf("%03d-%02d-%04d", gap1091Ranged(t, 100, 665), gap1091Ranged(t, 10, 99), gap1091Ranged(t, 1000, 9999))
	return []gap0429Secret{
		gap1091Value("card-visa", gap1091Card(t, "4", 16)),
		gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)),
		gap1091Value("card-mc-dashed", gap1091Group(mc, "-", 4, 4, 4, 4)),
		gap1091Value("card-amex-spaced", gap1091Group(amex, " ", 4, 6, 5)),
		gap1091Value("card-discover", gap1091Card(t, "6011", 16)),
		gap1091Value("ssn", ssn),
	}
}

func gap1091Run(t *testing.T, paths []gap0429Path) {
	values := gap1091Values(t)
	type tally struct{ rows, blocked, leaking, maxBefore, sumBefore int }
	tallies := map[string]*tally{}
	dropped := 0
	for _, path := range paths {
		for _, pack := range gap0429Packs() {
			for _, size := range gap0429Sizes() {
				for _, v := range values {
					// Three offsets: inside a scan window, and with the /llm and
					// passthrough 500-byte scan boundary (after the 1024-byte
					// initial buffer) falling inside the number.
					for _, fill := range []int{1100, 1520 - v.body - 3, 2020 - v.body - 3} {
						row := gap0429Row{path: path, pack: pack, secret: v,
							shape: gap0429Shape{name: fmt.Sprintf("at%d", fill), pre: func(f string) string { return f }},
							size:  size, filler: fill, trailer: " is the value. The build passed on the second run.\n"}
						if gap0429IsWholeAgain(row) {
							dropped++
							continue
						}
						name := fmt.Sprintf("%s/%s/%s/at%d/size=%d", path.name, pack, v.name, fill, size)
						res := gap0429Serve(t, row)
						n := v.end - v.body
						key := fmt.Sprintf("%s/%s/%s", path.name, pack, v.name)
						tl := tallies[key]
						if tl == nil {
							tl = &tally{}
							tallies[key] = tl
						}
						tl.rows++
						tl.sumBefore += res.before
						if res.blocked {
							tl.blocked++
						}
						if res.before > 0 {
							tl.leaking++
							tl.maxBefore = max(tl.maxBefore, res.before)
							t.Errorf("%s: %d of %d value bytes reached the client before the verdict", name, res.before, n)
						}
						if res.blocked && res.final > 0 {
							t.Errorf("%s: blocked, but %d of %d value bytes reached the client", name, res.final, n)
						}
						if !res.blocked && !strings.Contains(res.text, v.text[:v.body]) {
							t.Errorf("%s: not blocked, and the reply text read from the client has no lead (%d bytes): not measured", name, len(res.text))
						}
					}
				}
			}
		}
	}
	t.Logf("GAP0429-TALLY gap1091 skipped %d rows of 4096-byte pieces whose reply text is at most 4096 bytes (the same pieces as their whole rows)", dropped)
	keys := make([]string, 0, len(tallies))
	for k := range tallies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		tl := tallies[k]
		t.Logf("GAP0429-TALLY gap1091 %s rows=%d blocked=%d rows_releasing=%d max_released=%d sum_released=%d", k, tl.rows, tl.blocked, tl.leaking, tl.maxBefore, tl.sumBefore)
	}
}

func TestGAP1091StreamedPIIHeldLLM(t *testing.T) {
	gap1091Run(t, gap0429Paths()[:1])
}

func TestGAP1091StreamedPIIHeldPassthrough(t *testing.T) {
	paths := gap0429Paths()
	gap1091Run(t, paths[1:len(paths)-1])
}

func TestGAP1091StreamedPIIHeldRawForward(t *testing.T) {
	paths := gap0429Paths()
	gap1091Run(t, paths[len(paths)-1:])
}

// TestGAP1091ResponsePIIDecisions records which PII kinds a whole reply
// blocks in each pack on the raw forward path (the scope of the hold), and
// requires the card numbers to be blocked in every pack. The SSN is held by
// the same open shape whether its pack blocks it or not.
func TestGAP1091ResponsePIIDecisions(t *testing.T) {
	path := gap0429Paths()[len(gap0429Paths())-1]
	kinds := gap1091Values(t)
	for _, extra := range []struct{ name, v string }{
		{"iban", "GB" + gap1091Digits(t, 2) + "WEST" + gap1091Digits(t, 14)},
		{"passport-us", "C" + gap1091Digits(t, 8)},
		{"nhs", gap1091Group(gap1091Digits(t, 10), " ", 3, 3, 4)},
		{"medical-record", "MRN: " + gap1091Digits(t, 8)},
		{"dob", "DOB: 04/12/1987"},
		{"us-phone", "(415) 555-" + gap1091Digits(t, 4)},
		{"ssn-labelled-nohyphen", fmt.Sprintf("SSN %03d%02d%04d", gap1091Ranged(t, 100, 665), gap1091Ranged(t, 10, 99), gap1091Ranged(t, 1000, 9999))},
	} {
		v := gap1091Value(extra.name, extra.v)
		v.class = "pii-other"
		kinds = append(kinds, v)
	}
	for _, pack := range []string{"default", "strict", "permissive"} {
		for _, v := range kinds {
			rec := httptest.NewRecorder()
			w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: v.text, rec: rec}
			path.run(t, rec, w, pack, []string{retestFiller(400) + v.text + " is the value.\n"})
			t.Logf("GAP1091-DECISION pack=%s kind=%s class=%s blocked=%v", pack, v.name, v.class, w.blocked)
			if strings.HasPrefix(v.name, "card-") && !w.blocked {
				t.Errorf("%s/%s: a whole reply with it is not blocked", pack, v.name)
			}
		}
	}
}
