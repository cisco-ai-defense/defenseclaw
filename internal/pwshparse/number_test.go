// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import (
	"testing"
	"time"
)

// TestDecimalLiteralBounds pins decimal.TryParse behaviour of .NET (checked with pwsh 7.6.6) for exponents
// far outside the decimal range: the parse must be bounded (a fuzz input "0e10000000d" took 8 s once).
func TestDecimalLiteralBounds(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"0e10000000", true},
		{"0e-10000000", true},
		{"1e-1000", true},
		{"1e-28", true},
		{"1e28", true},
		{"1e29", false},
		{"7.9e28", true},
		{"8e28", false},
		{"0.0e5000", true},
		{"1e10000000", false},
		{"00001e-27", true},
	}
	for _, c := range cases {
		start := time.Now()
		_, ok := tryGetNumberValue(c.in, nfDecimal, sfDecimal, true, 1)
		if ok != c.ok {
			t.Errorf("decimal %q: ok=%v, want %v", c.in, ok, c.ok)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("decimal %q took %v", c.in, d)
		}
	}
}
