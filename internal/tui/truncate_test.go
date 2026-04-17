// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

// Regression tests for the shared `truncate` helper. An earlier
// byte-indexed implementation panicked with a negative slice bound
// when callers (e.g. overview.go renderDoctorBox on narrow terminals)
// passed budgets below 3, and also sliced mid-codepoint on multi-byte
// input. The current implementation is rune-aware and safe at every
// budget >= 0.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate_ShortString_NoMutation(t *testing.T) {
	t.Parallel()
	if got := truncate("abc", 10); got != "abc" {
		t.Fatalf("short string mutated: %q", got)
	}
}

func TestTruncate_Ellipsis(t *testing.T) {
	t.Parallel()
	got := truncate("abcdefghij", 5)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("missing ellipsis: %q", got)
	}
	if got == "abcdefghij" {
		t.Fatalf("did not truncate: %q", got)
	}
}

func TestTruncate_SmallBudgets_NoPanic(t *testing.T) {
	t.Parallel()
	// The critical property — budgets that used to trigger
	// `s[:-2]`-style panics must now degrade gracefully.
	for _, max := range []int{-1, 0, 1, 2, 3} {
		got := truncate("abcdefghij", max)
		if max <= 0 && got != "" {
			t.Fatalf("truncate(%d) should be empty, got %q", max, got)
		}
		if max > 0 && utf8.RuneCountInString(got) > max {
			t.Fatalf("truncate(%d) exceeded budget: %q", max, got)
		}
	}
}

func TestTruncate_UTF8Safe(t *testing.T) {
	t.Parallel()
	// Regression: the old byte-indexed truncate could slice inside a
	// multi-byte codepoint and produce invalid UTF-8 (displayed as a
	// replacement character in the terminal).
	in := "héllo wörld ☃☃☃☃☃☃☃☃"
	got := truncate(in, 5)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("missing ellipsis: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 5 {
		t.Fatalf("rune count=%d want 5: %q",
			utf8.RuneCountInString(got), got)
	}
}
