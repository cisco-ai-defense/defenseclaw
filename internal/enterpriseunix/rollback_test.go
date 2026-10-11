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
	"strings"
	"sync"
	"syscall"
	"testing"
)

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(info.Sys().(*syscall.Stat_t).Ino)
}

// Rollback must not need free space: a failed upgrade on a full disk has to
// get the previous binaries back. The snapshot hard-links them, so restoring
// relinks the preserved inode instead of copying its bytes.
func TestRollbackRelinksThePreservedFiles(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	config := h.env.P(h.env.Layout.ConfigPath)
	gatewayInode, configInode := inodeOf(t, gateway), inodeOf(t, config)
	h.healthy = false
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, r, codeActivate)
	if !hasWarning(r, codeRolledBack) {
		t.Fatalf("expected a rollback: %+v %+v", r.Errors, r.Warnings)
	}
	if got := inodeOf(t, gateway); got != gatewayInode {
		t.Fatalf("the replaced gateway was restored as a copy (inode %d, preserved %d)", got, gatewayInode)
	}
	if got := inodeOf(t, config); got != configInode {
		t.Fatalf("an unchanged file was rewritten by the rollback (inode %d, was %d)", got, configInode)
	}
	if got := h.read(filepath.Join(h.env.Layout.BinDir, binGateway)); got != "defenseclaw-gateway 1.0.0\n" {
		t.Fatalf("gateway not restored: %q", got)
	}
}

// When a file cannot be put back, the snapshot and the pending intent are
// the only record of the previous deployment. They are kept, later runs
// refuse to change the host until the restore succeeds, and the retry
// finishes the rollback.
func TestFailedRestoreKeepsTheSnapshotForARetry(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	// Something the restore cannot replace takes the gateway's place while
	// the new version is being activated (a stand-in for ENOSPC, which the
	// test cannot provoke).
	blocker := func() {
		if err := os.Remove(gateway); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(gateway, "busy"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var once sync.Once
	h.healthy = false
	health := h.env.HealthGet
	h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		once.Do(blocker)
		return health(ctx)
	}
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, r, codeRollbackFailed)
	pending, err := h.env.loadPending()
	if err != nil || pending == nil {
		t.Fatalf("a failed restore discarded the pending transaction: %v", err)
	}
	if !exists(filepath.Join(pending.SnapshotDir, snapshotIndexName)) {
		t.Fatal("a failed restore discarded the snapshot")
	}

	// Still blocked: the next run retries, fails again and changes nothing,
	// not even the running services (a full disk would otherwise restart
	// the gateway on every trigger).
	h.env.HealthGet = health
	h.healthy = true
	h.services.calls = nil
	blocked := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("3.0.0")})
	requireError(t, blocked, codeRollbackFailed)
	for _, call := range h.services.calls {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "start ") || strings.HasPrefix(call, "restart ") {
			t.Fatalf("a retry that could not restore the files touched the services: %v", h.services.calls)
		}
	}
	if record, _ := h.env.loadDeployment(); record == nil || record.ProductVersion != "1.0.0" {
		t.Fatalf("a run proceeded past an unrestored snapshot: %+v", record)
	}
	if !exists(h.env.pendingPath()) {
		t.Fatal("the retry dropped the pending transaction")
	}

	// Once the obstacle is gone the retry completes the rollback.
	if err := os.RemoveAll(gateway); err != nil {
		t.Fatal(err)
	}
	h.services.calls = nil
	recovered := h.run(Options{Action: ActionEnsure})
	requireOK(t, recovered)
	if !hasWarning(recovered, codeRecovered) {
		t.Fatalf("expected the retried rollback to be reported: %+v", recovered.Warnings)
	}
	// Once the files are back the services restart onto them.
	if countCalls(h.services.calls, "stop "+unitGateway) == 0 || !h.services.isActive(unitGateway) {
		t.Fatalf("the completed rollback did not restart the gateway onto the restored files: %v", h.services.calls)
	}
	if got := h.read(filepath.Join(h.env.Layout.BinDir, binGateway)); got != "defenseclaw-gateway 1.0.0\n" {
		t.Fatalf("the retry did not restore the previous gateway: %q", got)
	}
	if exists(h.env.pendingPath()) || exists(pending.SnapshotDir) {
		t.Fatal("the completed rollback left its pending intent or snapshot")
	}
}

func countCalls(calls []string, want string) int {
	n := 0
	for _, call := range calls {
		if call == want {
			n++
		}
	}
	return n
}

// Activation enables every managed unit before it waits for the gateway.
// A packaged unit file stays in /usr/lib/systemd/system after a rollback,
// so whatever the failed transaction enabled must be disabled again:
// otherwise the next boot starts an uncommitted gateway (a failed first
// install) or the new sockets next to the restored legacy units (a failed
// adoption).
func TestRollbackDisablesTheUnitsTheTransactionEnabled(t *testing.T) {
	requireNotEnabled := func(t *testing.T, h *testHost, keep map[string]bool) {
		t.Helper()
		for _, unit := range h.services.Units() {
			if !keep[unit.Name] && h.services.enabled[unit.Name] {
				t.Errorf("%s is still enabled after the rollback", unit.Name)
			}
		}
	}
	t.Run("package install", func(t *testing.T) {
		h := packageHost(t, "1.2.0")
		h.healthy = false
		r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
		requireError(t, r, codeActivate)
		if !hasWarning(r, codeRolledBack) {
			t.Fatalf("expected a rollback: %+v %+v", r.Errors, r.Warnings)
		}
		requireNotEnabled(t, h, nil)
		h.healthy = true
		requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	})
	t.Run("package adoption", func(t *testing.T) {
		h := packageHost(t, "1.2.0")
		keep := map[string]bool{}
		for path, content := range legacyUnits {
			writeHostFile(t, h, path, content)
			name := filepath.Base(path)
			h.services.active[name], h.services.enabled[name], keep[name] = true, true, true
		}
		h.healthy = false
		r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", AdoptExisting: true})
		requireError(t, r, codeActivate)
		requireLegacyIntact(t, h)
		requireNotEnabled(t, h, keep)
	})
	t.Run("upgrade keeps what was enabled", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		h.healthy = false
		requireError(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")}), codeActivate)
		for _, unit := range h.services.Units() {
			if unit.Activate && !h.services.enabled[unit.Name] {
				t.Errorf("the rolled-back upgrade left %s disabled", unit.Name)
			}
		}
	})
}

// separateVar puts the host's /var on another filesystem than /opt and
// /etc, as CIS partitioning does, or skips the test when the machine has no
// second filesystem to use.
func separateVar(t *testing.T, h *testHost) {
	t.Helper()
	other, err := os.MkdirTemp("/dev/shm", "dc-var-")
	if err != nil {
		t.Skipf("no second filesystem for /var: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(other) })
	root, rootErr := os.Stat(h.env.Root)
	moved, movedErr := os.Stat(other)
	if rootErr != nil || movedErr != nil || sameDevice(root, moved) {
		t.Skip("/dev/shm is on the test root's filesystem")
	}
	if err := os.Symlink(other, h.env.P("/var")); err != nil {
		t.Fatal(err)
	}
}

// With /var on its own filesystem the lifecycle state cannot hard-link the
// files under /opt and /etc, and a snapshot copy needs free space on the
// target to be restored. The preserved links go to a store on the files'
// own filesystem instead, the rollback relinks them, and the store is gone
// once the transaction settles.
func TestRollbackRelinksAcrossFilesystems(t *testing.T) {
	h := newTestHost(t, "linux")
	separateVar(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	config := h.env.P(h.env.Layout.ConfigPath)
	gatewayInode, configInode := inodeOf(t, gateway), inodeOf(t, config)
	stores := func() []string {
		var found []string
		for _, root := range h.env.sideStoreRoots() {
			matches, _ := filepath.Glob(filepath.Join(h.env.P(root), sideStoreName, "*", "*"))
			found = append(found, matches...)
		}
		return found
	}

	var during []string
	checked := false
	h.healthy = false
	health := h.env.HealthGet
	h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		if !checked {
			checked, during = true, stores()
		}
		return health(ctx)
	}
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, r, codeActivate)
	if !hasWarning(r, codeRolledBack) {
		t.Fatalf("expected a rollback: %+v %+v", r.Errors, r.Warnings)
	}
	if len(during) == 0 {
		t.Fatal("the snapshot kept no preserved link on the files' own filesystem")
	}
	if got := inodeOf(t, gateway); got != gatewayInode {
		t.Fatalf("the replaced gateway was restored as a copy (inode %d, preserved %d)", got, gatewayInode)
	}
	if got := inodeOf(t, config); got != configInode {
		t.Fatalf("an unchanged file was rewritten by the rollback (inode %d, was %d)", got, configInode)
	}
	if left := stores(); len(left) > 0 {
		t.Fatalf("the settled rollback left preserved links behind: %v", left)
	}

	h.env.HealthGet = health
	h.healthy = true
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")}))
	if left := stores(); len(left) > 0 {
		t.Fatalf("the committed upgrade left preserved links behind: %v", left)
	}
	// Uninstall removes a store a kept snapshot left, with the snapshots.
	writeHostFile(t, h, filepath.Join(h.env.Layout.InstallRoot, sideStoreName, "kept", "0"), "preserved\n")
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	for _, root := range h.env.sideStoreRoots() {
		if exists(filepath.Join(h.env.P(root), sideStoreName)) {
			t.Fatalf("uninstall left the snapshot store below %s", root)
		}
	}
}

// The CI upgrade gate's rollback drill: a root-owned, owner-only test fault
// file fails an upgrade after its services start and the previous release
// comes back. The same file owned by another account is ignored.
func TestLifecycleTestFaultRollsBackOnlyWhenRootOwned(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	fault := filepath.Join(h.env.Layout.LifecycleDir, testFaultFileName)
	writeHostFile(t, h, fault, testFaultAfterServices+"\n")
	if err := os.Chmod(h.env.P(fault), 0o600); err != nil {
		t.Fatal(err)
	}

	h.owners[h.env.P(fault)] = [2]int{1000, 1000}
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireOK(t, r)
	if !strings.Contains(messagesOf(r.Warnings, codeLifecycleTestFault), "not owned by root") {
		t.Fatalf("a test fault file another account owns must be ignored with a warning: %+v", r.Warnings)
	}

	h.owners[h.env.P(fault)] = [2]int{0, 0}
	r = h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("3.0.0")})
	requireError(t, r, codeLifecycleTestFault)
	if !hasWarning(r, codeLifecycleTestFault) || !hasWarning(r, codeRolledBack) {
		t.Fatalf("expected the test fault warning and a rollback: %+v %+v", r.Errors, r.Warnings)
	}
	if got := h.read(filepath.Join(h.env.Layout.BinDir, binGateway)); got != "defenseclaw-gateway 2.0.0\n" {
		t.Fatalf("the previous gateway was not restored: %q", got)
	}
}

// GAP-0552: a pack copied with cp -a keeps a standard user's file owner;
// that user could switch the pack's posture or break its digest for every
// user. Every folder and file of the pack must be root's and not writable by
// group or others.
func TestRulePackTreeTrustRefusesAForeignOwnedOrWritableFile(t *testing.T) {
	pack := t.TempDir()
	manifest := filepath.Join(pack, "defenseclaw-pack.json")
	if err := os.WriteFile(manifest, []byte(`{"posture":"strict"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid())
	if err := rulePackTreeTrust(pack, func(uid uint32) bool { return uid == me }); err != nil {
		t.Fatalf("a trusted pack was refused: %v", err)
	}
	if err := rulePackTreeTrust(pack, func(uid uint32) bool { return uid != me }); err == nil || !strings.Contains(err.Error(), " is owned by uid") {
		t.Fatalf("a foreign-owned file was accepted: %v", err)
	}
	if err := os.Chmod(manifest, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := rulePackTreeTrust(pack, func(uid uint32) bool { return uid == me }); err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("a writable file was accepted: %v", err)
	}
}
