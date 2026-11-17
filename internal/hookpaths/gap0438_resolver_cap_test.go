// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10 GAP-0438: a write operand that expands to more paths than the
// resolver reads is truncated at the bounded.Paths cap, and the hook client
// tells a managed gateway so under UnprovenReasonKey.
func TestGAP0438ResolverCapReachesTheCallDecision(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged home")
	}
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "project")
	for _, size := range []int{MaxResolvedCandidates, MaxResolvedCandidates + 1} {
		folder := filepath.Join(project, fmt.Sprintf("fan%d", size))
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := range size {
			if err := os.WriteFile(filepath.Join(folder, fmt.Sprintf("f%d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		name, command string
		hit           bool
	}{
		{"at the bound", "touch fan256/*", false},
		{"past the bound", "touch fan257/*", true},
		{"past the bound in a nested shell", "bash -c 'touch fan257/*'", true},
		{"past the bound, delete", "rm fan257/*", true},
		{"past the bound, permission change", "chmod 600 fan257/*", true},
		{"a redirect is not a glob operand", "echo x > fan257/*", false},
		{"a read of a wide glob is not a write", "cat fan257/*", false},
		{"a listing of a wide glob is not a write", "ls fan257/* 2>/dev/null", false},
		{"a search with a wide glob and a redirect", "find fan257/* -name x 2>/dev/null | head -9", false},
		{"text without an expansion is not read", "touch fan257", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := WriteOperandCaps(tc.command, project, home)
			if got := caps.Has(bounded.Paths); got != tc.hit {
				t.Fatalf("caps %q, hit %v, want %v", caps.Reason(), got, tc.hit)
			}
		})
	}
}
