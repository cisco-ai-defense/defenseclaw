//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// An agent CLI that exists for the user but prints no usable version used to
// read as "not installed": no row, no hook, and nothing in status.
func TestDiscoverUnixAgentVersionReportsAnInstalledAgentWithoutAVersion(t *testing.T) {
	origPrefixes := machinePrefixes
	machinePrefixes = func() []string { return nil }
	t.Cleanup(func() { machinePrefixes = origPrefixes })
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	silent := []byte("#!/bin/sh\nexit 0\n")
	for _, name := range []string{"opencode", "agent"} {
		if err := os.WriteFile(filepath.Join(bin, name), silent, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	version, reason := DiscoverUnixAgentVersion(context.Background(), home, "opencode", true)
	if version != "" || !UnixAgentInstalledWithoutVersion(reason) || !strings.HasSuffix(reason, filepath.Join(bin, "opencode")) {
		t.Fatalf("opencode = %q (%s), want an installed-without-version reason naming the binary", version, reason)
	}
	// "agent" is Cursor's generic alias; alone it is no evidence of Cursor.
	if _, reason := DiscoverUnixAgentVersion(context.Background(), home, "cursor", true); UnixAgentInstalledWithoutVersion(reason) {
		t.Fatalf("a generic alias must not count as a Cursor install: %s", reason)
	}
	if _, reason := DiscoverUnixAgentVersion(context.Background(), t.TempDir(), "opencode", true); UnixAgentInstalledWithoutVersion(reason) {
		t.Fatalf("an empty home reported an install: %s", reason)
	}
}

func TestEnumerateUnixReportsInstalledAgentsItCannotEnroll(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"},
		},
		listed: []string{"alice"},
	}
	opts := UnixEnumerateOptions{
		Resolver:  resolver,
		HomeRoots: []string{homes},
		UIDMin:    uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, map[string]string{
				"opencode": UnixAgentUnversionedReasonPrefix + filepath.Join(alice, ".local", "bin", "opencode"),
				"amp":      "no amp installation found for this user",
			}, nil
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("codex", "opencode", "amp"), connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].Connector != "codex" {
		t.Fatalf("rows = %+v, want only the versioned codex row", manifest.Targets)
	}
	if len(report.Unprotected) != 1 {
		t.Fatalf("unprotected = %+v, want the installed opencode only", report.Unprotected)
	}
	got := report.Unprotected[0]
	if got.User != "alice" || got.Connector != "opencode" || got.Code != UnprotectedCodeAgentUnprotected ||
		got.UID == nil || *got.UID != uid || !strings.Contains(got.Reason, "runs without DefenseClaw hooks") {
		t.Fatalf("unprotected entry = %+v", got)
	}
	if !strings.Contains(got.Message(), "opencode for user alice is not protected: installed, but its version could not be read") {
		t.Fatalf("status message = %q", got.Message())
	}
}

func TestUnixUnprotectedAgentsRecordRoundTrip(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := UnprotectedAgentsPath(filepath.Join(root, "targets.yaml"))
	if path != filepath.Join(root, UnprotectedAgentsFileName) {
		t.Fatalf("record path %s", path)
	}
	agents := []UnprotectedAgent{
		{User: "bob", Connector: "amp", Reason: "version 9.9.9 is not verified against a known hook contract"},
		{User: "alice", Connector: "opencode", Code: UnprotectedCodeAgentUnprotected, Reason: "installed, but its version could not be read: /x\n"},
	}
	if err := WriteUnixUnprotectedAgents(path, agents); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode: %v %v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].User != "alice" || got[1].Code != UnprotectedCodeHookContractUnverified || strings.ContainsAny(got[0].Reason, "\n") {
		t.Fatalf("round trip = %+v", got)
	}
	// An unchanged set leaves the file alone.
	before, _ := os.Stat(path)
	if err := WriteUnixUnprotectedAgents(path, agents); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); !os.SameFile(before, after) {
		t.Fatal("an identical record was rewritten")
	}
}
