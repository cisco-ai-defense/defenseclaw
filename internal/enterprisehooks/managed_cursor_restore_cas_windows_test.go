// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A snapshot restore (the rollback of a refused uninstall, or of a failed
// install or upgrade) writes the shared hooks.json back. Administrators and
// Cursor save that file without the DefenseClaw lock, so a save made while
// the restore runs must be kept: the journaled file is published only over
// the file the restore validated, a newer save gets DefenseClaw's journaled
// registration merged in (or taken out, for an inactive snapshot), and the
// restore's own rollback puts hooks.json back only over the bytes it wrote.

const windowsCursorRestoreAdminHooksForTest = `{"version":1,"hooks":{"admin-original":[{"type":"command","command":"admin-original"}]}}`

// saveAfterWindowsCursorHooksWriteForTest runs save once, just after
// DefenseClaw replaced hooks.json, whichever writer it uses.
func saveAfterWindowsCursorHooksWriteForTest(t *testing.T, hooksPath string, save func()) *bool {
	t.Helper()
	done := false
	previousWriter, previousSwap := windowsManagedPolicyWriter, windowsCursorManagedFileSwap
	windowsManagedPolicyWriter = func(path string, data []byte, userReadable bool) error {
		err := previousWriter(path, data, userReadable)
		if err == nil && !done && strings.EqualFold(path, hooksPath) {
			done = true
			save()
		}
		return err
	}
	windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
		result, err := previousSwap(request)
		if result.swapped && !done && strings.EqualFold(request.path, hooksPath) {
			done = true
			save()
		}
		return result, err
	}
	t.Cleanup(func() { windowsManagedPolicyWriter, windowsCursorManagedFileSwap = previousWriter, previousSwap })
	return &done
}

// installWindowsCursorEmptyGuardForRestoreTest installs the closed guard with
// no enrolled account over an administrator's hooks.json and returns the
// lifecycle options that match it.
func installWindowsCursorEmptyGuardForRestoreTest(t *testing.T, paths windowsCursorPaths) WindowsCursorManagedPolicyTeardownOptions {
	t.Helper()
	if err := EnsureWindowsStandaloneCursorManagedPolicy(connector.SetupOpts{
		APIAddr: "127.0.0.1:18970", HookExecutable: windowsCursorSharedHooksTestHook,
	}); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, err := os.ReadFile(paths.State)
	if err != nil {
		t.Fatal(err)
	}
	var state windowsCursorManagedPolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return WindowsCursorManagedPolicyTeardownOptions{
		HookExecutable:     state.HookExecutable,
		GatewayAddr:        state.GatewayAddr,
		GatewayServiceName: state.GatewayServiceName,
		Targets:            []WindowsCursorManagedRuntimeTarget{},
	}
}

func writeWindowsCursorAdminHooksForRestoreTest(t *testing.T, paths windowsCursorPaths) {
	t.Helper()
	if err := os.WriteFile(paths.Hooks, []byte(windowsCursorRestoreAdminHooksForTest), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tearDownWindowsCursorEmptyGuardForRestoreTest installs the empty guard and
// tears it down, as an uninstall does before it is refused, and returns the
// journaled snapshot.
func tearDownWindowsCursorEmptyGuardForRestoreTest(t *testing.T, paths windowsCursorPaths) (WindowsCursorManagedPolicyTeardownOptions, WindowsCursorManagedPolicyTeardownSnapshot) {
	t.Helper()
	writeWindowsCursorAdminHooksForRestoreTest(t, paths)
	opts := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
	snapshot, err := PrepareWindowsCursorManagedPolicyTeardown(opts, func(WindowsCursorManagedPolicyTeardownSnapshot) error { return nil })
	if err != nil || !snapshot.PolicyActive {
		t.Fatalf("teardown: active=%t err=%v", snapshot.PolicyActive, err)
	}
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || active {
		t.Fatalf("after teardown: active=%t err=%v", active, err)
	}
	return opts, snapshot
}

// The rollback of a refused uninstall restores the empty guard. A save after
// the restore validated hooks.json and before it writes it is kept, with the
// closed registration merged in.
func TestWindowsCursorTeardownRestoreKeepsAConcurrentHooksSave(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	opts, snapshot := tearDownWindowsCursorEmptyGuardForRestoreTest(t, paths)
	saveBeforeWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
		addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-concurrent")
	})
	if err := RestoreWindowsCursorManagedPolicyTeardown(opts, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-concurrent")
	if err := connector.VerifyWindowsCursorEnterpriseHooks(after, paths.Adapter, "closed"); err != nil {
		t.Fatalf("the restored registration is not the closed guard: %v", err)
	}
	if targets, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active || len(targets) != 0 {
		t.Fatalf("restored guard: active=%t targets=%v err=%v", active, targets, err)
	}
}

// The rollback of a failed install restores the inactive pre-install
// snapshot. A save after the restore validated hooks.json and before it
// writes it is kept, without DefenseClaw's entries.
func TestWindowsCursorLifecycleRestoreKeepsAConcurrentHooksSave(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	writeWindowsCursorAdminHooksForRestoreTest(t, paths)
	prior := WindowsCursorManagedPolicyTeardownOptions{}
	snapshot, err := CaptureWindowsCursorManagedPolicySnapshot(prior)
	if err != nil || snapshot.PolicyActive {
		t.Fatalf("capture: active=%t err=%v", snapshot.PolicyActive, err)
	}
	installed := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
	saveBeforeWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
		addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-concurrent")
	})
	if err := RestoreWindowsCursorManagedPolicySnapshot(prior, installed, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-concurrent")
	if cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(after, paths.Adapter); err != nil || !bytes.Equal(cleaned, after) {
		t.Fatalf("the restore left DefenseClaw entries in hooks.json (err %v):\n%s", err, after)
	}
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || active {
		t.Fatalf("after restore: active=%t err=%v", active, err)
	}
}

// When a restore fails after it wrote hooks.json, its rollback puts the file
// back only while it still holds the restore's bytes. A save made after the
// restore's write is newer and is kept; the restore reports the failure, and
// a later repair or restore starts from the saved file.
func TestWindowsCursorRestoreRollbackKeepsANewerHooksSave(t *testing.T) {
	t.Run("failed install rollback", func(t *testing.T) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		writeWindowsCursorAdminHooksForRestoreTest(t, paths)
		prior := WindowsCursorManagedPolicyTeardownOptions{}
		snapshot, err := CaptureWindowsCursorManagedPolicySnapshot(prior)
		if err != nil {
			t.Fatal(err)
		}
		installed := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
		// The save lands after the restore's write, so its exact check fails
		// and the restore rolls back.
		saved := saveAfterWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
			addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-after")
		})
		if err := RestoreWindowsCursorManagedPolicySnapshot(prior, installed, snapshot); err == nil {
			t.Fatal("a restore whose hooks.json changed under it reported success")
		}
		if !*saved {
			t.Fatal("fixture: the save did not land after the restore's write")
		}
		requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-after")
	})
	t.Run("refused uninstall rollback", func(t *testing.T) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		opts, snapshot := tearDownWindowsCursorEmptyGuardForRestoreTest(t, paths)
		// A save in progress: not JSON yet, so the restored guard does not
		// validate and the restore rolls back.
		partial := []byte(`{"version":1,"hooks":{"admin-in-progress":`)
		saved := saveAfterWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
			if err := os.WriteFile(paths.Hooks, partial, 0o600); err != nil {
				t.Fatal(err)
			}
		})
		if err := RestoreWindowsCursorManagedPolicyTeardown(opts, snapshot); err == nil {
			t.Fatal("a restore whose hooks.json changed under it reported success")
		}
		if !*saved {
			t.Fatal("fixture: the save did not land after the restore's write")
		}
		if data, err := os.ReadFile(paths.Hooks); err != nil || !bytes.Equal(data, partial) {
			t.Fatalf("the rollback replaced the administrator's newer file (err %v):\n%s", err, data)
		}
	})
}
