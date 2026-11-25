//go:build !race

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

func perlSpecPaddedInput() string {
	prefix := `open(F,">.claude/settings.json");`
	return prefix + "#" + strings.Repeat("x", 16<<10-len(prefix)-1)
}

func TestPerlSpecPaddedAllocs(t *testing.T) {
	code := perlSpecPaddedInput()
	if len(code) != 16<<10 {
		t.Fatalf("size %d", len(code))
	}
	allocs := testing.AllocsPerRun(100, func() {
		_ = literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
	})
	t.Logf("padded reader allocations=%.0f", allocs)
	if allocs > 64 {
		t.Fatalf("padded allocs %.0f, want <=64", allocs)
	}
}

func BenchmarkPerlSpecPadded(b *testing.B) {
	code := perlSpecPaddedInput()
	b.Run("rel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = literalInterpreterWritesBase(code, "perl", "/tmp", "/tmp")
		}
	})
	b.Run("spec", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
		}
	})
}

