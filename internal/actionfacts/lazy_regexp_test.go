// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"testing"
)

// Every package-level pattern still compiles, as MustCompile at start
// proved before the patterns became lazy.
func TestLazyRegexpsCompile(t *testing.T) {
	if len(lazyRegexps) < 70 {
		t.Fatalf("lazyRegexps lists %d patterns, want every package-level pattern (at least 70)", len(lazyRegexps))
	}
	for _, pattern := range lazyRegexps {
		if _, err := regexp.Compile(pattern.expr); err != nil {
			t.Errorf("pattern %q does not compile: %v", pattern.expr, err)
		}
		if got := pattern.compiled().String(); got != pattern.expr {
			t.Errorf("compiled pattern %q, want %q", got, pattern.expr)
		}
	}
}
