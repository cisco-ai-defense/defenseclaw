// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
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
		{"validCodex", OTLPScopeCodex, true},
		{"validClaude", OTLPScopeClaude, true},
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
				if runtime.GOOS == "windows" {
					t.Skip("POSIX mode bits do not represent an NTFS DACL; see native DACL coverage")
				}
				if err := os.WriteFile(path, []byte(token), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					hooksDir := filepath.Dir(path)
					targetHooksDir := filepath.Join(t.TempDir(), "hooks")
					if err := os.Mkdir(targetHooksDir, 0o700); err != nil {
						t.Fatalf("create redirected hooks directory: %v", err)
					}
					target := filepath.Join(targetHooksDir, filepath.Base(path))
					if err := safefile.WritePrivate(target, []byte(token)); err != nil {
						t.Fatalf("write redirected token: %v", err)
					}
					if err := os.Remove(hooksDir); err != nil {
						t.Fatalf("remove empty hooks directory: %v", err)
					}
					createTestDirectoryRedirect(t, hooksDir, targetHooksDir)
					return
				}
				target := filepath.Join(filepath.Dir(path), "target.token")
				if err := os.WriteFile(target, []byte(token), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
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
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read unsafe token before provisioning attempt: %v", err)
			}
			if got, err := LoadOTLPPathToken(dir, OTLPScopeGeminiCLI); err == nil {
				t.Fatalf("LoadOTLPPathToken succeeded with token %q, want error", got)
			}
			if got, err := EnsureOTLPPathToken(dir, OTLPScopeGeminiCLI); err == nil {
				t.Fatalf("EnsureOTLPPathToken succeeded with token %q, want error", got)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read unsafe token after provisioning attempt: %v", err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("rejected provisioning modified the existing unsafe token")
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

func TestRemoveOTLPPathTokenRevokesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(path+".tmp", []byte(strings.Repeat("d", 64)+"\n")); err != nil {
		t.Fatal(err)
	}

	if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
		t.Fatalf("RemoveOTLPPathToken: %v", err)
	}
	for _, artifact := range []string{path, path + ".tmp"} {
		if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
			t.Fatalf("token artifact survived removal: %s (err=%v)", artifact, err)
		}
	}
	if got, err := LoadOTLPPathToken(dir, OTLPScopeCodex); err != nil || got != "" {
		t.Fatalf("LoadOTLPPathToken after removal = %q, %v", got, err)
	}
	if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
		t.Fatalf("idempotent RemoveOTLPPathToken: %v", err)
	}
	second, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("token was reused after revocation")
	}
}

func TestOTLPPathTokenScopeForConnector(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		scope OTLPPathTokenScope
		ok    bool
	}{
		{name: "codex", scope: OTLPScopeCodex, ok: true},
		{name: " ClaudeCode ", scope: OTLPScopeClaude, ok: true},
		{name: "geminicli", scope: OTLPScopeGeminiCLI, ok: true},
		{name: "cursor", ok: false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := OTLPPathTokenScopeForConnector(tc.name)
			if got != tc.scope || ok != tc.ok {
				t.Fatalf("OTLPPathTokenScopeForConnector(%q) = %q, %v; want %q, %v", tc.name, got, ok, tc.scope, tc.ok)
			}
		})
	}
}

func TestResolveSetupOTLPPathTokenUsesSuppliedTokenWithoutLocalSidecar(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := strings.Repeat("c", 64)
	got, err := resolveSetupOTLPPathToken(dir, OTLPScopeCodex, "  "+want+"\n")
	if err != nil {
		t.Fatalf("resolveSetupOTLPPathToken: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want supplied token", got)
	}
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("per-user token sidecar exists after supplied token: %v", err)
	}
}

func TestResolveSetupOTLPPathTokenRejectsInvalidSuppliedToken(t *testing.T) {
	t.Parallel()
	if _, err := resolveSetupOTLPPathToken(t.TempDir(), OTLPScopeClaude, "not-a-token"); err == nil {
		t.Fatal("resolveSetupOTLPPathToken accepted an invalid supplied token")
	}
}
