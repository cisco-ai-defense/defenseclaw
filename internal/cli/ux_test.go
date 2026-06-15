// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
	"testing"
)

func TestColorEnabled_forceOverridesTTYAndNO_COLOR(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "")
	if !ColorEnabled() {
		t.Fatal("FORCE_COLOR truthy must enable colors before NO_COLOR check order per ux.py")
	}
}

func TestColorEnabled_cliColorForce(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")
	if !ColorEnabled() {
		t.Fatal("CLICOLOR_FORCE must enable colors")
	}
}

func TestColorEnabled_noColorDisablesWhenNotForced(t *testing.T) {
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("NO_COLOR", "")
	if ColorEnabled() {
		t.Fatal("empty NO_COLOR must disable colors when not forced (no-color.org)")
	}
}

func TestColorEnabled_noTTYWithoutForce(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	// stdout is not a TTY under go test
	if ColorEnabled() {
		t.Fatal("expected colors off when stdout is not a TTY and force vars unset")
	}
}

func TestStyle_plainWhenColorsOff(t *testing.T) {
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("NO_COLOR", "1")
	got := Style("hello", "bold", "fg=red")
	if got != "hello" {
		t.Fatalf("got %q, want plain hello", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Fatal("ansi leaked into output")
	}
}

func TestStyle_prefixWhenColorsForced(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "")
	got := Style("x", "fg=green")
	if !strings.HasPrefix(got, "\x1b[32m") {
		t.Fatalf("expected green prefix, got %q", got)
	}
	if !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("expected reset suffix, got %q", got)
	}
}

func TestBoldAccentDim_noEscapeWhenOff(t *testing.T) {
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("NO_COLOR", "1")
	for _, tc := range []struct {
		name string
		fn   func(string) string
	}{
		{"Bold", Bold},
		{"Dim", Dim},
		{"Accent", Accent},
	} {
		if tc.fn("abc") != "abc" {
			t.Fatalf("%s: expected plain text", tc.name)
		}
	}
}

func TestKV_plainLabelsUnderNoColor(t *testing.T) {
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("NO_COLOR", "1")
	// Capture would require redirecting fmt output; instead assert Style parts only.
	label := fmt.Sprintf("%-*s", 30, "k:")
	st := Style(label, "fg=bright_black", "bold")
	if st != label {
		t.Fatalf("KV label styling should no-op: got %q", st)
	}
}
