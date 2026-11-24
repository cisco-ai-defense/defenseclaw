// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1600 is an accepted equal-end sampling limit. The prefix reader did
// not exist in 1.0.10, and every prefix reading is additive to the call's own
// verdict. No concrete call was found with this synthetic A..B..A key run.
// The no-parse signal guard cannot mirror the quote-sensitive dialect
// inference exactly; DET111 ruled this by design on 2026-11-24. This pin
// preserves the exact limit so a future reader cannot mistake "no cap" for
// proof that all equal-end spans were examined.
func TestGAP1600EqualEndRunLimitIsExplicit(t *testing.T) {
	const count = 33
	whole := windowsListPrefixKey{dialect: actionfacts.DialectPOSIX, status: actionfacts.StatusComplete}
	key := func(i int) windowsListPrefixKey {
		if i >= 16 && i < 20 {
			return windowsListPrefixKey{dialect: actionfacts.DialectPowerShell, status: actionfacts.StatusComplete}
		}
		return whole
	}
	ends, capped := windowsListPrefixRunEnds(count, whole, key, windowsListPrefixMaxKeys)
	if len(ends) != 0 || capped {
		t.Fatalf("equal-end hidden run: ends=%d capped=%v; document any change to the accepted limit", len(ends), capped)
	}
	// A run whose different key reaches a sampled boundary is still read:
	// the pin only covers the unobserved equal-end span.
	visible := func(i int) windowsListPrefixKey {
		if i >= 16 && i < 32 {
			return windowsListPrefixKey{dialect: actionfacts.DialectPowerShell, status: actionfacts.StatusComplete}
		}
		return whole
	}
	ends, capped = windowsListPrefixRunEnds(count, whole, visible, windowsListPrefixMaxKeys)
	if len(ends) == 0 || capped {
		t.Fatalf("sampled run: ends=%d capped=%v; want a reading without a cap", len(ends), capped)
	}
}
