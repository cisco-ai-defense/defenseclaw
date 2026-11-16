// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package codesig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubCodesign installs a codesign stand-in that records its arguments and
// runs body, and makes this host count as macOS.
func stubCodesign(t *testing.T, body string) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := filepath.Join(dir, "codesign")
	content := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argsFile + "\n" + body + "\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBinary, oldHost, oldEUID := codesignBinary, darwinHost, geteuid
	// An unprivileged caller unless a test says otherwise, whoever runs it.
	codesignBinary, darwinHost, geteuid = script, true, func() int { return 1000 }
	t.Cleanup(func() { codesignBinary, darwinHost, geteuid = oldBinary, oldHost, oldEUID })
	return argsFile
}

// engineBundle lays out a Claude Desktop engine bundle.
func engineBundle(t *testing.T) (bundle, exe, plist string) {
	t.Helper()
	bundle = filepath.Join(t.TempDir(), "claude-code", "2.1.309", "5af865b9901c", "claude.app")
	exe = filepath.Join(bundle, "Contents", "MacOS", "claude")
	plist = filepath.Join(bundle, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{exe, plist} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return bundle, exe, plist
}

func TestVerifyDarwinAcceptsTheAnthropicRequirement(t *testing.T) {
	argsFile := stubCodesign(t, "exit 0")
	bundle, exe, plist := engineBundle(t)
	got := VerifyDarwin(context.Background(), bundle, ClaudeCodeDarwin, DarwinOptions{Pin: []string{exe, plist}})
	if !got.Verified || got.Reason != "" {
		t.Fatalf("VerifyDarwin = %+v, want verified", got)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--verify", "--strict",
		`-R=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "Q6L2SF6YDW" and identifier "com.anthropic.claude-code"`,
		bundle}
	if got := strings.Split(strings.TrimSpace(string(data)), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("codesign arguments = %q, want %q", got, want)
	}
}

func TestVerifyDarwinRefusals(t *testing.T) {
	bundle, exe, plist := engineBundle(t)
	link := filepath.Join(t.TempDir(), "claude.app")
	if err := os.Symlink(bundle, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, path, want string
		pin                    []string
	}{
		{name: "another team or identifier", body: "exit 3", path: bundle, want: "is not signed by Apple Developer ID team Q6L2SF6YDW with identifier com.anthropic.claude-code"},
		{name: "unsigned", body: "echo \"$5: code object is not signed at all\" >&2; exit 1", path: bundle, want: "code object is not signed at all"},
		{name: "modified while checked", body: "printf y >> " + exe + "; exit 0", path: bundle, pin: []string{exe, plist}, want: "changed while its signature was checked"},
		{name: "pinned file missing", body: "exit 0", path: bundle, pin: []string{filepath.Join(bundle, "missing")}, want: "cannot be read"},
		{name: "link", body: "exit 0", path: link, want: "is a symbolic link"},
		{name: "relative", body: "exit 0", path: "claude.app", want: "not a clean absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubCodesign(t, tc.body)
			got := VerifyDarwin(context.Background(), tc.path, ClaudeCodeDarwin, DarwinOptions{Pin: tc.pin})
			if got.Verified || !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("VerifyDarwin = %+v, want a refusal containing %q", got, tc.want)
			}
			if got.Unsigned != (tc.name == "unsigned") {
				t.Fatalf("VerifyDarwin = %+v: Unsigned must say only that the code has no signature", got)
			}
		})
	}
}

func TestVerifyDarwinIsBounded(t *testing.T) {
	stubCodesign(t, "exec sleep 5")
	old := VerifyTimeout
	VerifyTimeout = 100 * time.Millisecond
	t.Cleanup(func() { VerifyTimeout = old })
	bundle, _, _ := engineBundle(t)
	start := time.Now()
	got := VerifyDarwin(context.Background(), bundle, ClaudeCodeDarwin, DarwinOptions{})
	if got.Verified || !strings.Contains(got.Reason, "did not finish") {
		t.Fatalf("VerifyDarwin = %+v, want a timeout refusal", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("VerifyDarwin took %s, want it bounded", elapsed)
	}
}

func TestVerifyDarwinOnlyOnMacOS(t *testing.T) {
	old := darwinHost
	darwinHost = false
	t.Cleanup(func() { darwinHost = old })
	if got := VerifyDarwin(context.Background(), "/Applications/Claude.app", ClaudeCodeDarwin, DarwinOptions{}); got.Verified || !strings.Contains(got.Reason, "only on macOS") {
		t.Fatalf("VerifyDarwin = %+v, want refused off macOS", got)
	}
	if got := VerifyAuthenticode("/x/claude.exe", AnthropicPublishers); got.Verified {
		t.Fatalf("VerifyAuthenticode = %+v, want refused off Windows", got)
	}
}

func TestDarwinRequirementRefusesInjectedValues(t *testing.T) {
	for _, want := range []Darwin{
		{TeamID: `Q6L2SF6YDW" or identifier "x`, Identifier: ClaudeCodeSigningID},
		{TeamID: AnthropicTeamID, Identifier: `com.anthropic.claude-code" or anchor apple`},
		{TeamID: "", Identifier: ClaudeCodeSigningID},
	} {
		if requirement, err := want.Requirement(); err == nil {
			t.Fatalf("Requirement(%+v) = %q, want an error", want, requirement)
		}
	}
	stubCodesign(t, "exit 0")
	bundle, _, _ := engineBundle(t)
	if got := VerifyDarwin(context.Background(), bundle, Darwin{TeamID: "bad"}, DarwinOptions{}); got.Verified {
		t.Fatalf("VerifyDarwin with an invalid team = %+v, want refused", got)
	}
}

func TestPublisherAllowedIsExact(t *testing.T) {
	for signer, want := range map[string]bool{
		"Anthropic PBC": true, "Anthropic, PBC": true, "anthropic pbc": false, "Anthropic PBC Ltd": false, "": false,
	} {
		if got := PublisherAllowed(signer, AnthropicPublishers); got != want {
			t.Fatalf("PublisherAllowed(%q) = %v, want %v", signer, got, want)
		}
	}
}

// As root, codesign runs as the account with its passwd primary group and no
// supplementary group: never root's groups, never a group the bundle names.
func TestCodesignCredentialDropsRootGroups(t *testing.T) {
	if got := codesignCredential(DarwinOptions{UID: 501, GID: 20}, 501); got != nil {
		t.Fatalf("an unprivileged caller changed credentials: %+v", got)
	}
	got := codesignCredential(DarwinOptions{UID: 501, GID: 20}, 0)
	if got == nil || got.Uid != 501 || got.Gid != 20 || got.NoSetGroups || got.Groups == nil || len(got.Groups) != 0 {
		t.Fatalf("root credential = %+v, want uid 501, gid 20, setgroups to an empty list", got)
	}
}

// A root caller that names no account (or root) is refused before codesign
// runs on a user's folder.
func TestVerifyDarwinNeverRunsAsRoot(t *testing.T) {
	argsFile := stubCodesign(t, "exit 0")
	old := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = old })
	bundle, _, _ := engineBundle(t)
	for _, opts := range []DarwinOptions{{}, {UID: 0, GID: 20}, {UID: 501, GID: 0}} {
		if got := VerifyDarwin(context.Background(), bundle, ClaudeCodeDarwin, opts); got.Verified || !strings.Contains(got.Reason, "never as root") {
			t.Fatalf("opts %+v: VerifyDarwin = %+v, want refused", opts, got)
		}
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("codesign ran for a root caller without an account")
	}
}

// Run as root, the codesign child really has the account's group only.
func TestVerifyDarwinChildHasOnlyTheAccountGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to change credentials")
	}
	groupsFile := filepath.Join(t.TempDir(), "groups")
	if err := os.Chmod(filepath.Dir(groupsFile), 0o777); err != nil {
		t.Fatal(err)
	}
	stubCodesign(t, "id -G > "+groupsFile+"; exit 0")
	geteuid = os.Geteuid // really root here
	bundle, _, _ := engineBundle(t)
	// The account must reach the stub, the bundle and the groups file.
	for _, path := range []string{filepath.Dir(codesignBinary), bundle, filepath.Dir(groupsFile)} {
		for dir := path; dir != os.TempDir() && dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
			if info, err := os.Stat(dir); err == nil && info.IsDir() && info.Mode().Perm()&0o005 != 0o005 {
				_ = os.Chmod(dir, info.Mode().Perm()|0o755)
			}
		}
	}
	if got := VerifyDarwin(context.Background(), bundle, ClaudeCodeDarwin, DarwinOptions{UID: 65534, GID: 65534}); !got.Verified {
		t.Fatalf("VerifyDarwin = %+v", got)
	}
	data, err := os.ReadFile(groupsFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "65534" {
		t.Fatalf("codesign child groups = %q, want only 65534", data)
	}
}
