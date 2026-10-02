//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func withStandaloneUnix(t *testing.T, enabled bool, resolver unixidentity.Resolver) {
	t.Helper()
	previous := StandaloneUnix()
	SetStandaloneUnix(enabled)
	if resolver != nil {
		SetStandaloneResolver(resolver)
	}
	t.Cleanup(func() {
		SetStandaloneUnix(previous)
		SetStandaloneResolver(nil)
	})
}

func TestUnixManifestDeferredRowsOnlyInStandalone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	body := "version: 1\ntargets:\n  - user: alice\n    user_home: /home/alice\n    connector: codex\n    deferred: true\n    home_inode: 42\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	withStandaloneUnix(t, false, nil)
	if _, err := LoadManifest(path); err == nil || !strings.Contains(err.Error(), "Windows-only deferred") {
		t.Fatalf("Secure Client/legacy Unix manifests must keep rejecting deferred rows, got %v", err)
	}
	SetStandaloneUnix(true)
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("standalone manifests accept deferred rows: %v", err)
	}
	if !manifest.Targets[0].IsDeferred() || manifest.Targets[0].HomeInode != 42 {
		t.Fatalf("unexpected row %+v", manifest.Targets[0])
	}
}

func TestLookupTargetPrimaryGIDFallsBackToDirectoryOnlyInStandalone(t *testing.T) {
	const directoryUID = 3141592
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
		"ldapuser": {Name: "ldapuser", UID: directoryUID, GID: 70001},
	}}
	withStandaloneUnix(t, false, resolver)
	_, err := lookupTargetPrimaryGID(directoryUID)
	if err == nil || !strings.Contains(err.Error(), "enterprise hooks: resolve target uid") || strings.Contains(err.Error(), "directory") {
		t.Fatalf("non-standalone lookup must keep the original error, got %v", err)
	}
	SetStandaloneUnix(true)
	gid, err := lookupTargetPrimaryGID(directoryUID)
	if err != nil || gid != 70001 {
		t.Fatalf("standalone directory fallback = %d, %v", gid, err)
	}
	if _, err := lookupTargetPrimaryGID(directoryUID + 1); err == nil || !strings.Contains(err.Error(), "through the directory") {
		t.Fatalf("unknown directory uid error = %v", err)
	}
	// os/user still answers first for local accounts.
	if gid, err := lookupTargetPrimaryGID(os.Getuid()); err != nil || gid < 0 {
		t.Fatalf("local account lookup = %d, %v", gid, err)
	}
}

func TestRefuseStandaloneRootInProcess(t *testing.T) {
	withStandaloneUnix(t, true, nil)
	err := refuseStandaloneRootInProcess("install")
	if os.Geteuid() == 0 {
		if err == nil {
			t.Fatal("a root standalone process must refuse in-process user-home mutation")
		}
		return
	}
	if err != nil {
		t.Fatalf("a non-root worker must be allowed: %v", err)
	}
}
