// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import (
	"strings"
	"testing"
	"time"
)

// TestErrorHeavyInputsParseLinearly: inputs of thousands of unclosed levels
// report an error per level. Each shape at 8x the size of its fixture row
// (39003 "${`", 39850 "$(", 39852 "& ") parses within a linear bound of the
// 1x input (a quadratic parse is 64x), and well under a second.
func TestErrorHeavyInputsParseLinearly(t *testing.T) {
	shapes := []struct {
		name, unit string
		n          int
	}{{"brace", "${`", 4000}, {"sub", "$(", 5000}, {"amp", "& ", 5000}}
	best := func(s string) time.Duration {
		b := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			st := time.Now()
			ParseTree(s)
			if d := time.Since(st); d < b {
				b = d
			}
		}
		return b
	}
	for _, sh := range shapes {
		small := best(strings.Repeat(sh.unit, sh.n) + "x")
		big := best(strings.Repeat(sh.unit, 8*sh.n) + "x")
		if big > time.Second || big > 24*small+20*time.Millisecond {
			t.Errorf("%s: 1x %v, 8x %v: want a linear parse (8x within 24x of 1x, under 1 s)", sh.name, small, big)
		}
	}
}
