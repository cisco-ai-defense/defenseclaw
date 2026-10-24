// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A save another writer makes after a snapshot restore wrote hooks.json is
// newer and is kept. The restore is complete when the save already is what
// the snapshot needs, it edits the save when not, and a rollback to an active
// guard puts that guard's registration back into the save before the
// adapter, receipt and state go back. The machine guard is never left active
// without its registration.

// failAfterWindowsCursorHooksSwapForTest makes DefenseClaw's next hooks.json
// compare-and-swap publish and then fail, as a metadata failure after the
// rename does, with save run in between. Later swaps run normally.
func failAfterWindowsCursorHooksSwapForTest(t *testing.T, hooksPath string, save func()) *bool {
	t.Helper()
	done := false
	previousSwap := windowsCursorManagedFileSwap
	windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
		result, err := previousSwap(request)
		if result.swapped && err == nil && !done && strings.EqualFold(request.path, hooksPath) {
			done = true
			save()
			return result, errors.New("injected: hooks.json metadata failed after publication")
		}
		return result, err
	}
	t.Cleanup(func() { windowsCursorManagedFileSwap = previousSwap })
	return &done
}

// saveWindowsCursorHooksWithoutGuardForTest is an administrator's save that
// drops DefenseClaw's entries and adds one hook of its own.
func saveWindowsCursorHooksWithoutGuardForTest(t *testing.T, paths windowsCursorPaths, command string) {
	t.Helper()
	data, err := os.ReadFile(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(data, paths.Adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Hooks, cleaned, 0o600); err != nil {
		t.Fatal(err)
	}
	addWindowsCursorAdminHookForTest(t, paths.Hooks, command)
}

// requireWindowsCursorClosedGuardForTest checks that hooks carries the closed
// registration and that the guard on disk is complete and active with no
// enrolled account.
func requireWindowsCursorClosedGuardForTest(t *testing.T, paths windowsCursorPaths, hooks []byte) {
	t.Helper()
	if err := connector.VerifyWindowsCursorEnterpriseHooks(hooks, paths.Adapter, "closed"); err != nil {
		t.Fatalf("hooks.json does not carry the closed guard's registration: %v\n%s", err, hooks)
	}
	if targets, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active || len(targets) != 0 {
		t.Fatalf("the machine guard is not complete: active=%t targets=%v err=%v", active, targets, err)
	}
}

func requireWindowsCursorInactiveForTest(t *testing.T, paths windowsCursorPaths) {
	t.Helper()
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || active {
		t.Fatalf("after restore: active=%t err=%v", active, err)
	}
	for _, path := range []string{paths.State, paths.Receipt} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the inactive restore left %s (err %v)", path, err)
		}
	}
}

// The rollback of a failed install restores the inactive pre-install
// snapshot. A save after the restore's write completes it when the save has
// no DefenseClaw entry (kept byte for byte), and is cleaned when it has some.
func TestWindowsCursorInactiveRestoreCompletesOverANewerSave(t *testing.T) {
	rows := []struct {
		name  string
		save  func(t *testing.T, paths windowsCursorPaths, installed []byte) []byte
		check func(t *testing.T, paths windowsCursorPaths, saved []byte)
	}{
		{
			name: "administrator-only save",
			save: func(t *testing.T, paths windowsCursorPaths, _ []byte) []byte {
				addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-after")
				saved, err := os.ReadFile(paths.Hooks)
				if err != nil {
					t.Fatal(err)
				}
				return saved
			},
			check: func(t *testing.T, paths windowsCursorPaths, saved []byte) {
				if data, err := os.ReadFile(paths.Hooks); err != nil || !bytes.Equal(data, saved) {
					t.Fatalf("the restore changed the administrator's save (err %v):\n%s", err, data)
				}
			},
		},
		{
			name: "administrator deletes hooks.json",
			save: func(t *testing.T, paths windowsCursorPaths, _ []byte) []byte {
				if err := os.Remove(paths.Hooks); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			check: func(t *testing.T, paths windowsCursorPaths, _ []byte) {
				if _, err := os.Stat(paths.Hooks); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the restore recreated the hooks.json the administrator deleted (err %v)", err)
				}
			},
		},
		{
			name: "stale copy with DefenseClaw entries",
			save: func(t *testing.T, paths windowsCursorPaths, installed []byte) []byte {
				// Cursor writes back the file it read while the guard was
				// active, with one more hook.
				if err := os.WriteFile(paths.Hooks, installed, 0o600); err != nil {
					t.Fatal(err)
				}
				addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-after")
				return nil
			},
			check: func(t *testing.T, paths windowsCursorPaths, _ []byte) {
				after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-after")
				if cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(after, paths.Adapter); err != nil || !bytes.Equal(cleaned, after) {
					t.Fatalf("the restore left DefenseClaw entries in hooks.json (err %v):\n%s", err, after)
				}
			},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths := withWindowsCursorStandaloneSeamsForTest(t)
			writeWindowsCursorAdminHooksForRestoreTest(t, paths)
			prior := WindowsCursorManagedPolicyTeardownOptions{}
			snapshot, err := CaptureWindowsCursorManagedPolicySnapshot(prior)
			if err != nil || snapshot.PolicyActive {
				t.Fatalf("capture: active=%t err=%v", snapshot.PolicyActive, err)
			}
			installed := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
			installedHooks, err := os.ReadFile(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			var saved []byte
			landed := saveAfterWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
				saved = row.save(t, paths, installedHooks)
			})
			if err := RestoreWindowsCursorManagedPolicySnapshot(prior, installed, snapshot); err != nil {
				t.Fatalf("restore over a newer save: %v", err)
			}
			if !*landed {
				t.Fatal("fixture: the save did not land after the restore's write")
			}
			row.check(t, paths, saved)
			requireWindowsCursorInactiveForTest(t, paths)
		})
	}
}

// The rollback of a refused uninstall restores the active empty guard. A
// save after the restore's write that drops DefenseClaw's entries is kept,
// with the closed registration merged back in.
func TestWindowsCursorActiveRestoreMergesItsRegistrationIntoANewerSave(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	opts, snapshot := tearDownWindowsCursorEmptyGuardForRestoreTest(t, paths)
	landed := saveAfterWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
		saveWindowsCursorHooksWithoutGuardForTest(t, paths, "admin-after")
	})
	if err := RestoreWindowsCursorManagedPolicyTeardown(opts, snapshot); err != nil {
		t.Fatalf("restore over a newer save: %v", err)
	}
	if !*landed {
		t.Fatal("fixture: the save did not land after the restore's write")
	}
	after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-after")
	requireWindowsCursorClosedGuardForTest(t, paths, after)
}

// A rollback to an active guard over a newer save puts the registration back
// into it (TestWindowsCursorRestoreRollbackKeepsANewerHooksSave covers a save
// without it). A save that already carries it is left alone; a save in
// progress that is not JSON is kept byte for byte, the rollback says the
// guard is incomplete, the guard's record stays, and the repair rebuilds the
// complete guard from it.
func TestWindowsCursorRestoreRollbackToAnActiveGuardRestoresItsRegistration(t *testing.T) {
	t.Run("save that keeps the registration", func(t *testing.T) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		writeWindowsCursorAdminHooksForRestoreTest(t, paths)
		prior := WindowsCursorManagedPolicyTeardownOptions{}
		snapshot, err := CaptureWindowsCursorManagedPolicySnapshot(prior)
		if err != nil {
			t.Fatal(err)
		}
		installed := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
		installedHooks, err := os.ReadFile(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		// The restore publishes the pre-install file and fails; meanwhile
		// Cursor writes back the file it read while the guard was active,
		// with one more hook. That file already carries the registration and
		// is left byte for byte.
		var saved []byte
		landed := failAfterWindowsCursorHooksSwapForTest(t, paths.Hooks, func() {
			if err := os.WriteFile(paths.Hooks, installedHooks, 0o600); err != nil {
				t.Fatal(err)
			}
			addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-after")
			if saved, err = os.ReadFile(paths.Hooks); err != nil {
				t.Fatal(err)
			}
		})
		if err := RestoreWindowsCursorManagedPolicySnapshot(prior, installed, snapshot); err == nil {
			t.Fatal("a restore whose hooks.json write failed reported success")
		}
		if !*landed {
			t.Fatal("fixture: the save did not land after the restore's write")
		}
		after, err := os.ReadFile(paths.Hooks)
		if err != nil || !bytes.Equal(after, saved) {
			t.Fatalf("the rollback rewrote a save that carries the registration (err %v):\n%s", err, after)
		}
		requireWindowsCursorClosedGuardForTest(t, paths, after)
	})
	t.Run("save in progress", func(t *testing.T) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		writeWindowsCursorAdminHooksForRestoreTest(t, paths)
		prior := WindowsCursorManagedPolicyTeardownOptions{}
		snapshot, err := CaptureWindowsCursorManagedPolicySnapshot(prior)
		if err != nil {
			t.Fatal(err)
		}
		installed := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
		partial := []byte(`{"version":1,"hooks":{"admin-in-progress":`)
		saved := failAfterWindowsCursorHooksSwapForTest(t, paths.Hooks, func() {
			if err := os.WriteFile(paths.Hooks, partial, 0o600); err != nil {
				t.Fatal(err)
			}
		})
		err = RestoreWindowsCursorManagedPolicySnapshot(prior, installed, snapshot)
		if err == nil || !strings.Contains(err.Error(), "incomplete until a repair") {
			t.Fatalf("the rollback did not report the incomplete guard: %v", err)
		}
		if !*saved {
			t.Fatal("fixture: the save did not land after the restore's write")
		}
		if data, readErr := os.ReadFile(paths.Hooks); readErr != nil || !bytes.Equal(data, partial) {
			t.Fatalf("the rollback replaced the administrator's save in progress (err %v):\n%s", readErr, data)
		}
		for _, path := range []string{paths.State, paths.Receipt} {
			if _, statErr := os.Stat(path); statErr != nil {
				t.Fatalf("the rollback dropped the guard's record %s: %v", path, statErr)
			}
		}
		if _, err := RestoreWindowsCursorManagedAdapter(windowsCursorSharedHooksTestHook); err != nil {
			t.Fatalf("repair: %v", err)
		}
		hooks, err := os.ReadFile(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		requireWindowsCursorClosedGuardForTest(t, paths, hooks)
	})
}
