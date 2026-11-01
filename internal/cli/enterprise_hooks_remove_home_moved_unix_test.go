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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-2482: the home of a live enrolled account was moved aside in its home
// root (mv /Users/u /Users/.u-away). remove-all called it gone, so the
// uninstall warned and removed the hook binary while the moved home kept
// DefenseClaw entries calling it. A home the account still has a folder for
// next to it is only not available: the row is pending with no reason (the
// uninstall precheck refuses on it) and its state is not purged. A home
// deleted outright stays clean (#1287).
func TestRemoveAllKeepsAHomeMovedAsideNotAvailable(t *testing.T) {
	movedUID, goneUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getgid()
	f := newStandaloneFixture(t, standaloneTestResolver{accounts: map[string]unixidentity.Account{}})
	moved := filepath.Join(f.homes, "sample-moved")
	gone := filepath.Join(f.homes, "sample-gone")
	f.home(t, "sample-other", 0o700) // the home root holds other entries
	enterpriseHookCheckHome = func(home string, uid int) enterprisehooks.HomeCheck {
		if (home == moved && uid == movedUID) || (home == gone && uid == goneUID) {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	previous := enterpriseHookHomeMovedAside
	t.Cleanup(func() { enterpriseHookHomeMovedAside = previous })
	asked := map[string]int{}
	enterpriseHookHomeMovedAside = func(home string, uid int) bool {
		asked[home] = uid
		return home == moved && uid == movedUID
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{Connector: "hermes", User: "sample-moved", UID: &movedUID, GID: &gid, UserHome: moved},
		enterprisehooks.ManifestTarget{Connector: "hermes", User: "sample-gone", UID: &goneUID, GID: &gid, UserHome: gone},
	)
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rows := resolveEnterpriseHookRemoveRows(manifest)
	jobs, pending, failed := enterpriseHookRemoveJobs(rows)
	if len(failed) != 0 || len(jobs) != 0 {
		t.Fatalf("jobs=%+v failed=%v", jobs, failed)
	}
	if len(pending) != 2 || pending[0] != "sample-moved/hermes" ||
		pending[1] != enterpriseHookHomeGoneEntry("sample-gone/hermes", gone, "hermes") {
		t.Fatalf("pending = %q, want the moved home pending without a reason and the deleted one gone", pending)
	}
	if asked[moved] != movedUID || asked[gone] != goneUID {
		t.Fatalf("the moved-aside check must get the account uid: %v", asked)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, nil)
	if len(notPurged) != 1 || notPurged[0] != "sample-moved: its home is not available; rerun the purge when it is" {
		t.Fatalf("not purged = %q, want only the moved home", notPurged)
	}
}

// The real check: a folder the account owns in the home root, other than
// the missing home itself, is the home moved aside; a symlink, a plain file
// or another account s folder is not.
func TestEnterpriseHookHomeMovedAsideSeesAnOwnedFolderInTheHomeRoot(t *testing.T) {
	root := t.TempDir()
	uid := os.Getuid()
	home := filepath.Join(root, "sample")
	if err := os.WriteFile(filepath.Join(root, "notes"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if enterpriseHookHomeMovedAside(home, uid) {
		t.Fatal("a file and a symlink are not a moved home")
	}
	if enterpriseHookHomeMovedAside(home, uid+1) {
		t.Fatal("folders of another uid are not a moved home")
	}
	if err := os.Mkdir(filepath.Join(root, ".sample-away"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !enterpriseHookHomeMovedAside(home, uid) {
		t.Fatal("a folder the account owns next to its missing home is the home moved aside")
	}
	if enterpriseHookHomeMovedAside(home, uid+1) {
		t.Fatal("the folder belongs to another uid")
	}
	if !enterpriseHookHomeMovedAside(filepath.Join(root, "missing-root", "sample"), uid) {
		t.Fatal("a home root that cannot be read cannot rule out a moved home")
	}
}
