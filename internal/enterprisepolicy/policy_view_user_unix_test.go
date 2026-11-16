//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func writeAccountPreference(t *testing.T, opts Options, connector, account, content string) string {
	t.Helper()
	path, err := accountPreferencePath(opts, connector, account)
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

func TestPolicyViewDigestDoesNotPinAnotherMacAccount(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	before, err := PolicyViewDigest(opts, ConnectorCodex)
	if err != nil {
		t.Fatal(err)
	}
	other := writeAccountPreference(t, opts, ConnectorCodex, "another-user", "private policy")
	// The hook never reads another account's preference, even when it is
	// unreadable to the invoking account.
	if err := os.Chmod(other, 0o000); err != nil {
		t.Fatal(err)
	}
	after, err := PolicyViewDigest(opts, ConnectorCodex)
	if err != nil || after != before {
		t.Fatalf("another account's preference changed this account's shared pin: before %q, after %q, error %v", before, after, err)
	}
}

func TestMacPolicyViewUserPinsCompareContentOnly(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	alice := writeAccountPreference(t, opts, ConnectorCodex, "alice", "alice policy")
	bob := writeAccountPreference(t, opts, ConnectorCodex, "bob", "bob policy")
	pins, problems, err := PolicyViewUserPins(opts, ConnectorCodex)
	if err != nil || len(problems) != 0 || len(pins) != 2 || pins["alice"] != sha256Hex([]byte("alice policy")) {
		t.Fatalf("root pins = %v, problems %v, error %v", pins, problems, err)
	}
	unproven := func(what string, want ...string) {
		t.Helper()
		got, err := PolicyViewAccountsUnproven(opts, ConnectorCodex, pins)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: unproven accounts = %v, want %v", what, got, want)
		}
		for _, account := range want {
			if !got[account] {
				t.Fatalf("%s: unproven accounts = %v, want %v", what, got, want)
			}
		}
	}
	unproven("pinned preferences")
	// An MDM agent rewrites the same bytes through a new file: a new inode,
	// times and mode. Only content counts.
	replacement := alice + ".new"
	if err := os.WriteFile(replacement, []byte("alice policy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, alice); err != nil {
		t.Fatal(err)
	}
	unproven("a byte-identical rewrite of alice's preference")
	// Another account's drift is that account's only.
	if err := os.WriteFile(bob, []byte("changed bob"), 0o600); err != nil {
		t.Fatal(err)
	}
	unproven("bob's changed preference", "bob")
	writeAccountPreference(t, opts, ConnectorCodex, "charlie", "unpinned")
	unproven("charlie's unpinned preference", "bob", "charlie")
	if err := os.Remove(alice); err != nil {
		t.Fatal(err)
	}
	unproven("alice's hidden pinned preference", "alice", "bob", "charlie")
}

// One account entry that can not be pinned is reported and left out; every
// other account keeps its pin, and the host never fails for it.
func TestMacPolicyViewUserPinsIsolateBadAccountEntries(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	writeAccountPreference(t, opts, ConnectorCodex, "alice", "alice policy")
	root := rooted(opts, managedPreferencesRoot)
	mustMkdir := func(path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Not a regular file.
	mustMkdir(filepath.Join(root, "bob", "com.openai.codex.plist"))
	// Oversize.
	big := filepath.Join(root, "carol", "com.openai.codex.plist")
	mustMkdir(filepath.Dir(big))
	if err := os.WriteFile(big, make([]byte, policyFileLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	// An invalid account name.
	mustMkdir(filepath.Join(root, `corp\dave`))
	if err := os.WriteFile(filepath.Join(root, `corp\dave`, "com.openai.codex.plist"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink standing in for an account folder, and an unrelated
	// preference symlink, which is fine.
	if err := os.Symlink(filepath.Join(root, "alice"), filepath.Join(root, "mallory")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "alice", "com.openai.codex.plist"), filepath.Join(root, "unrelated.plist")); err != nil {
		t.Fatal(err)
	}
	pins, problems, err := PolicyViewUserPins(opts, ConnectorCodex)
	if err != nil {
		t.Fatalf("a bad account entry failed every account: %v", err)
	}
	if len(pins) != 1 || pins["alice"] == "" {
		t.Fatalf("pins = %v, want only alice", pins)
	}
	joined := strings.Join(problems, "\n")
	for _, name := range []string{"bob", "carol", `corp\\dave`, "mallory"} {
		if !strings.Contains(joined, name) {
			t.Errorf("problem for %s not reported: %q", name, problems)
		}
	}
	if len(problems) != 4 {
		t.Fatalf("problems = %q, want 4", problems)
	}
}

// A crowded managed-preferences folder can not push the descriptor over its
// size limit: pins stop at the budget and the rest are reported.
func TestMacPolicyViewUserPinsFitTheDescriptor(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	descriptor := &managed.RuntimeDescriptor{
		SchemaVersion: managed.RuntimeDescriptorSchemaVersion, Profile: managed.ProfileStandalone,
		ServiceUser: "defenseclaw", ServiceUID: 995, ServiceGID: 985, APIAddr: managed.StandaloneAPIAddr,
		HookSocket: "/var/run/defenseclaw-hook/hook.sock", MachinePolicyConnectors: []string{"claudecode", "codex"},
		PolicyViewDigests:     map[string]string{"claudecode": strings.Repeat("a", 64), "codex": strings.Repeat("b", 64)},
		PolicyViewUserSources: map[string]map[string]string{},
	}
	total := 0
	for _, connector := range []string{ConnectorCodex, ConnectorClaudeCode} {
		for i := range 140 {
			writeAccountPreference(t, opts, connector, fmt.Sprintf("%s%03d", strings.Repeat("u", 240), i), "policy")
		}
		pins, problems, err := PolicyViewUserPins(opts, connector)
		if err != nil || len(pins) == 0 || len(pins) > maxPolicyViewUserPins || len(pins)+len(problems) != 140 {
			t.Fatalf("%s: pins %d problems %d error %v", connector, len(pins), len(problems), err)
		}
		descriptor.PolicyViewUserSources[connector] = pins
		total += len(pins)
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.MarshalRuntimeDescriptor(descriptor); err != nil {
		t.Fatalf("%d budgeted pins do not fit the descriptor: %v", total, err)
	}
}

func TestClaudeMacPolicyViewUsesItsAccountPreference(t *testing.T) {
	opts := Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	writeAccountPreference(t, opts, ConnectorClaudeCode, "alice", "managed Claude settings")
	pins, problems, err := PolicyViewUserPins(opts, ConnectorClaudeCode)
	if err != nil || len(problems) != 0 || len(pins) != 1 || pins["alice"] == "" {
		t.Fatalf("Claude preference was not pinned: %v, %v, %v", pins, problems, err)
	}
	if unproven, err := PolicyViewAccountsUnproven(opts, ConnectorClaudeCode, pins); err != nil || len(unproven) != 0 {
		t.Fatalf("alice's pinned Claude preference = %v, %v", unproven, err)
	}
	writeAccountPreference(t, opts, ConnectorCodex, "bob", "a Codex preference")
	if unproven, err := PolicyViewAccountsUnproven(opts, ConnectorClaudeCode, pins); err != nil || len(unproven) != 0 {
		t.Fatalf("bob's Codex preference affected the Claude view: %v, %v", unproven, err)
	}
}
