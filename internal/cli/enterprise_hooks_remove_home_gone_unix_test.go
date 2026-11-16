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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// #1287: the home folder of a live enrolled account is gone (a macOS mobile
// account's home moved away). Its registrations and ~/.defenseclaw went
// with it, so remove-all reports the account already clean, with the home
// in the reason, adds no purge for it and does not name its state as left;
// another account is removed and purged as usual. A home whose parent is
// missing too (an unmounted volume) stays "not available".
func TestRemoveAllTreatsTheGoneHomeOfALiveAccountAsClean(t *testing.T) {
	goneUID, mountUID, otherUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getuid()+3, os.Getgid()
	f := newStandaloneFixture(t, standaloneTestResolver{accounts: map[string]unixidentity.Account{}})
	gone := filepath.Join(f.homes, "sample-gone")
	unmounted := filepath.Join(f.root, "volume", "sample-mount")
	other := f.home(t, "sample-enrolled", 0o700)
	enterpriseHookCheckHome = func(home string, uid int) enterprisehooks.HomeCheck {
		switch {
		case home == other && uid == otherUID:
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		case (home == gone && uid == goneUID) || (home == unmounted && uid == mountUID):
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-gone", UID: &goneUID, GID: &gid, UserHome: gone},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-mount", UID: &mountUID, GID: &gid, UserHome: unmounted},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-enrolled", UID: &otherUID, GID: &gid, UserHome: other},
	)
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rows := resolveEnterpriseHookRemoveRows(manifest)
	jobs, pending, failed := enterpriseHookRemoveJobs(rows)
	if len(failed) != 0 || len(jobs) != 1 || jobs[otherUID] == nil {
		t.Fatalf("removal jobs: jobs=%+v failed=%v", jobs, failed)
	}
	want := "sample-gone/codex: its home " + gone + " no longer exists, so no DefenseClaw hook registration is left there"
	if len(pending) != 2 || !strings.HasPrefix(pending[0], want) || pending[1] != "sample-mount/codex" {
		t.Fatalf("pending = %q, want the gone home first with its reason, then the unmounted one", pending)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, nil)
	if len(notPurged) != 1 || notPurged[0] != "sample-mount: its home is not available; rerun the purge when it is" {
		t.Fatalf("not purged = %q, want only the unmounted home", notPurged)
	}
	purgeTestTargetCount(t, jobs[otherUID], 1)
}
