// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// TestIsValidOTLPScope_NegativeCases protects the lazy-reload path
// in api.go's lookupOTLPPathToken: every disk-touching code path is
// gated by IsValidOTLPScope, so a regression that accepts arbitrary
// strings here would turn the OTLP auth check into a per-request
// disk syscall stampede primitive — exactly the M1 risk we are
// closing.
//
// The cases below cover the four shape classes we expect attackers
// to probe with: path traversal, case mismatches, control characters,
// and length / Unicode tricks. Anything that returns true must be in
// OTLPPathTokenScopes() and pass the on-disk regex; every other shape
// must return false.
func TestIsValidOTLPScope_NegativeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		scope OTLPPathTokenScope
		want  bool
	}{
		{"empty", "", false},
		{"validGemini", OTLPScopeGeminiCLI, true},
		{"upper", "GEMINICLI", false},
		{"trailingSpace", "geminicli ", false},
		{"leadingSpace", " geminicli", false},
		{"pathTraversal", "../etc/passwd", false},
		{"forwardSlash", "geminicli/extra", false},
		{"newline", "geminicli\nclaude", false},
		{"nul", "\x00", false},
		{"nulSuffix", "geminicli\x00", false},
		{"unicodeHomoglyph", "geminіcli", false}, // contains Cyrillic 'і' (U+0456)
		{"plus", "gemini+cli", false},
		{"unknownVendor", "openai", false},
		{"length128", OTLPPathTokenScope(repeat('a', 128)), false},
		{"underscore", "gemini_cli", false}, // underscore not in scope list
		{"dotPrefix", ".geminicli", false},
		{"dashOnly", "-", false},
		{"singleChar", "g", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidOTLPScope(tc.scope)
			if got != tc.want {
				t.Errorf("IsValidOTLPScope(%q) = %v, want %v", string(tc.scope), got, tc.want)
			}
		})
	}
}

func repeat(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

func TestLoadOTLPPathToken_RejectsUnsafeFiles(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("a", 64) + "\n"
	cases := []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{
			name: "wide_mode",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(token), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(path), "target.token")
				if err := os.WriteFile(target, []byte(token), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink privilege unavailable; reparse-point rejection has dedicated Windows coverage: %v", err)
					}
					t.Fatal(err)
				}
			},
		},
		{
			name: "non_hex",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(strings.Repeat("z", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(strings.Repeat("a", otlpPathTokenMaxReadBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			hooks := filepath.Join(dir, "hooks")
			if err := os.MkdirAll(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			path, err := OTLPPathTokenFilePath(dir, OTLPScopeGeminiCLI)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(t, path)
			if got, err := LoadOTLPPathToken(dir, OTLPScopeGeminiCLI); err == nil {
				t.Fatalf("LoadOTLPPathToken succeeded with token %q, want error", got)
			}
		})
	}
}

func TestLoadOTLPPathToken_AcceptsStrictTokenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("b", 64)
	if err := safefile.WritePrivate(path, []byte(want+"\n")); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOTLPPathToken(dir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
}
