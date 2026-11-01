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

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// tmpfilesStateDirs creates what the package's tmpfiles.d entry creates
// before its postinstall ensure runs (packaging/systemd/defenseclaw.conf):
// the state directories, empty.
func tmpfilesStateDirs(t *testing.T, h *testHost) {
	t.Helper()
	for _, dir := range []string{h.env.Layout.DataDir, filepath.Join(h.env.Layout.DataDir, "acp"), h.env.Layout.GuardianAuthDir} {
		if err := os.MkdirAll(h.env.P(dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

// writesStateDuringActivation makes the services leave state while the
// activation runs: the gateway its audit database, the guardian its
// activation record and identity folder.
func writesStateDuringActivation(h *testHost) {
	health := h.env.HealthGet
	h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		_ = os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, "audit.db")), []byte("x"), 0o600)
		_ = os.WriteFile(h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, "activation.json")), []byte("{}"), 0o640)
		_ = os.MkdirAll(h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, "identity")), 0o750)
		return health(ctx)
	}
}

// rel-1-0-6:GAP-0286: rpm -i (or dpkg -i) creates the empty state
// directories through tmpfiles.d before its postinstall ensure. That ensure
// failed activation and rolled back, but the rollback kept the directories
// it had found (present) with the state the services wrote into them, so
// the printed retry, ensure --from-package, refused unmanaged_layout_present
// until --adopt-existing. A state directory that held no state goes back to
// none, its empty subdirectories kept, and the plain retry succeeds.
func TestFailedPackageInstallEmptiesTheTmpfilesStateDirectories(t *testing.T) {
	h := packageHost(t, "1.2.0")
	tmpfilesStateDirs(t, h)
	h.healthy = false
	writesStateDuringActivation(h)
	requireError(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}), codeActivate)
	for _, dir := range []string{h.env.Layout.DataDir, h.env.Layout.GuardianAuthDir} {
		if !exists(h.env.P(dir)) {
			t.Fatalf("the rollback removed %s, which the package created", dir)
		}
		if holdsState(h.env.P(dir)) {
			t.Fatalf("the rollback left the activation's state in %s", dir)
		}
	}
	if !exists(h.env.P(filepath.Join(h.env.Layout.DataDir, "acp"))) {
		t.Fatal("the rollback removed an empty directory the package created")
	}
	if leftovers := h.env.unmanagedLeftovers(h.env.Services, ChannelPackage); len(leftovers) != 0 {
		t.Fatalf("the rollback left %v for the adoption guard", leftovers)
	}
	h.healthy = true
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
}

// rel-1-0-6:GAP-0286, the reported form: a non-purge uninstall kept the
// sandbox state in the data directory, rpm -e removed the package, rpm -i
// put it back (tmpfiles creating the empty guardian directory) and its
// postinstall ensure failed and rolled back. The kept state stays, the
// guardian directory holds nothing, and the plain retry adopts the kept
// state without --adopt-existing.
func TestFailedPackageReinstallKeepsTheKeptStateAndEmptiesTheGuardianDirectory(t *testing.T) {
	h := keptDockerHost(t, "linux", true)
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	homeRecord, store, key := retrySandboxPaths(h)
	if exists(h.env.P(h.env.Layout.GuardianAuthDir)) {
		t.Fatal("the fixture's uninstall kept the guardian directory; the case needs it gone, as on the host")
	}
	tmpfilesStateDirs(t, h.testHost)
	h.healthy = false
	writesStateDuringActivation(h.testHost)
	requireError(t, ensureKeptHost(t, h, keptDockerSettings), codeActivate)
	if holdsState(h.env.P(h.env.Layout.GuardianAuthDir)) {
		t.Fatal("the rollback left the activation's state in the guardian directory")
	}
	if !physicalExists(store) || !physicalExists(key) || !physicalExists(homeRecord) || !physicalExists(retainedMarkerPath(h.env.P(h.env.Layout.DataDir))) {
		t.Fatal("the rolled-back reinstall lost the kept sandbox state")
	}
	h.healthy = true
	r := ensureKeptHost(t, h, keptDockerSettings)
	requireOK(t, r)
	if !physicalExists(store) || !physicalExists(key) || !physicalExists(homeRecord) {
		t.Fatalf("the retry lost the kept sandbox state: %v", r.Changes)
	}
}
