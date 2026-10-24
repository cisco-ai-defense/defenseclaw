//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestPolicyViewDigestDoesNotPinAnotherMacAccount(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	before, err := PolicyViewDigest(opts, ConnectorCodex)
	if err != nil {
		t.Fatal(err)
	}
	other := rooted(opts, "/Library/Managed Preferences/another-user/com.openai.codex.plist")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("private policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := PolicyViewDigest(opts, ConnectorCodex)
	if err != nil || after != before {
		t.Fatalf("another account's preference changed this account's shared pin: before %q, after %q, error %v", before, after, err)
	}
}

func TestMacPolicyViewUserAttestationScopesAndCloses(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	write := func(account, content string) string {
		t.Helper()
		path, err := accountPreferencePath(opts, ConnectorCodex, account)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	alice := write("alice", "alice policy")
	bob := write("bob", "bob policy")
	pins, err := PolicyViewUserPins(opts, ConnectorCodex)
	if err != nil || len(pins) != 2 {
		t.Fatalf("root attestation = %+v, %v", pins, err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "alice", pins["alice"]); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "charlie", managed.PolicyViewFilePin{}); err != nil {
		t.Fatal(err)
	}
	// The root's attestation cannot prove the hook's process view if its own
	// relevant preference is unreadable. Every read failure stays closed.
	before := policyViewUserReadFile
	t.Cleanup(func() { policyViewUserReadFile = before })
	policyViewUserReadFile = func(Options, string) ([]byte, bool, error) { return nil, false, os.ErrPermission }
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "alice", pins["alice"]); err == nil {
		t.Fatal("unreadable relevant preference accepted through root attestation")
	}
	policyViewUserReadFile = func(Options, string) ([]byte, bool, error) { return nil, false, os.ErrInvalid }
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "alice", pins["alice"]); err == nil {
		t.Fatal("non-permission read failure accepted")
	}
	policyViewUserReadFile = before
	if err := os.WriteFile(bob, []byte("changed bob"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "alice", pins["alice"]); err != nil {
		t.Fatalf("another account's drift blocked alice: %v", err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "bob", pins["bob"]); err == nil {
		t.Fatal("changed relevant preference accepted")
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "alice", managed.PolicyViewFilePin{}); err == nil {
		t.Fatal("unattested relevant preference accepted")
	}
	if err := os.Remove(alice); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "alice", pins["alice"]); err == nil {
		t.Fatal("hidden relevant preference accepted")
	}
	newPath := write("charlie", "new preference")
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "charlie", managed.PolicyViewFilePin{}); err == nil {
		t.Fatal("new unpinned preference accepted")
	}
	// A same-size edit and permission change remain refused even if an
	// administrator restores the old modification time before reconcile.
	info, err := os.Stat(newPath)
	if err != nil {
		t.Fatal(err)
	}
	current, err := PolicyViewUserPins(opts, ConnectorCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("NEW preference"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(newPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorCodex, "charlie", current["charlie"]); err == nil {
		t.Fatal("same-size edit with restored mtime accepted")
	}
	unrelated := filepath.Join(rooted(opts, managedPreferencesRoot), "unrelated.plist")
	if err := os.Symlink(newPath, unrelated); err != nil {
		t.Fatal(err)
	}
	if _, err := PolicyViewUserPins(opts, ConnectorCodex); err != nil {
		t.Fatalf("unrelated preference symlink blocked account attestation: %v", err)
	}
	accountLink := filepath.Join(rooted(opts, managedPreferencesRoot), "mallory")
	if err := os.Symlink(filepath.Dir(newPath), accountLink); err != nil {
		t.Fatal(err)
	}
	if _, err := PolicyViewUserPins(opts, ConnectorCodex); err == nil {
		t.Fatal("symlinked account directory was attested")
	}
}

func TestClaudeMacPolicyViewUsesItsAccountPreference(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	path, err := accountPreferencePath(opts, ConnectorClaudeCode, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("managed Claude settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	pins, err := PolicyViewUserPins(opts, ConnectorClaudeCode)
	if err != nil || len(pins) != 1 || pins["alice"].SHA256 == "" {
		t.Fatalf("Claude preference was not attested: %+v, %v", pins, err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorClaudeCode, "alice", pins["alice"]); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyViewUserPin(opts, ConnectorClaudeCode, "bob", managed.PolicyViewFilePin{}); err != nil {
		t.Fatalf("alice's Claude preference blocked bob: %v", err)
	}
}
