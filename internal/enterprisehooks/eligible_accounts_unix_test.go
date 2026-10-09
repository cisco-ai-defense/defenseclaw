// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixEligibleAccountsRoundTripAndTrust(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	manifest := filepath.Join(root, "targets.yaml")
	path := UnixEligibleAccountsPath(manifest)
	if path != filepath.Join(root, UnixEligibleAccountsFileName) {
		t.Fatalf("record path %s", path)
	}
	if accounts, err := LoadUnixEligibleAccounts(path); err != nil || len(accounts) != 0 {
		t.Fatalf("a missing record is empty: %v %v", accounts, err)
	}
	want := []UnixEligibleAccount{
		{User: "bob", UID: 1002, GID: 1002, Home: "/home/bob"},
		{User: "alice", UID: 1001, GID: 1001, Home: "/home/alice", HomeInode: 42},
		{User: "root", UID: 0, GID: 0, Home: "/root"},
	}
	if err := WriteUnixEligibleAccounts(path, want); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %o, want 0600", info.Mode().Perm())
	}
	got, err := LoadUnixEligibleAccounts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].User != "alice" || got[0].HomeInode != 42 || got[1].User != "bob" {
		t.Fatalf("round trip must sort and drop uid 0: %+v", got)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUnixEligibleAccounts(path); err == nil {
		t.Fatal("a readable-by-others record must be refused")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "second-link")
	if err := os.Link(path, link); err == nil {
		if _, err := LoadUnixEligibleAccounts(path); err == nil {
			t.Fatal("a hard-linked record must be refused")
		}
	}
}

func TestManifestEnrolledAccountsHomeOnlyTarget(t *testing.T) {
	accounts := []UnixEligibleAccount{
		{User: "alice", UID: 1001, Home: "/home/alice"},
		{User: "bob", UID: 1002, Home: "/home/bob"},
	}
	manifest := Manifest{Targets: []ManifestTarget{{UserHome: "/home/alice/.", Connector: "copilot"}}}
	got := ManifestEnrolledAccounts(accounts, manifest)
	if len(got) != 1 || got[0].UID != 1001 {
		t.Fatalf("home-only target enrolled accounts = %+v, want alice", got)
	}
}
