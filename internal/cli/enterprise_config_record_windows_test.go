//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0646: the guardian leaves config.yaml to a lifecycle run that holds
// lifecycle.lock or whose install transaction is pending, and while it
// records an edit it holds lifecycle.lock itself, so no run starts writing
// in between.
func TestClaimWindowsEnterpriseConfigFromLifecycle(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	lock := filepath.Join(dir, "lifecycle", "lifecycle.lock")
	for _, folder := range []string{etc, filepath.Dir(lock), filepath.Join(dir, "install")} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	layoutOf := func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: filepath.Join(etc, "config.yaml"), ConfigDir: etc}, nil
	}

	owner := claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf)
	if owner.reason != "" || owner.release == nil {
		t.Fatalf("free lifecycle: owner %+v", owner)
	}
	if other, err := tryWindowsEnterpriseLifecycleLock(lock); err == nil {
		other()
		t.Fatal("a lifecycle run took lifecycle.lock while the guardian recorded")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("lifecycle.lock during the record: %v, want a sharing violation", err)
	}
	owner.release()

	held, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	if owner := claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf); !strings.Contains(owner.reason, "holds lifecycle.lock") || owner.release != nil || owner.restored {
		t.Fatalf("held lifecycle.lock: owner %+v", owner)
	}
	held()

	pending := filepath.Join(dir, "install", "pending.json")
	if err := os.WriteFile(pending, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if owner := claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf); !strings.Contains(owner.reason, "transaction is pending") || owner.release != nil || !owner.restored {
		t.Fatalf("pending transaction: owner %+v", owner)
	}
	if again, err := tryWindowsEnterpriseLifecycleLock(lock); err != nil {
		t.Fatalf("the pending check kept lifecycle.lock: %v", err)
	} else {
		again()
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	owner = claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf)
	if owner.reason != "" || owner.release == nil {
		t.Fatalf("no lock file: owner %+v", owner)
	}
	owner.release()
}

// GAP-0646 review L1: a lifecycle.lock that is not there says so as before
// ("is not a regular file"), and still wraps fs.ErrNotExist, which the
// guardian's claim reads as "no run".
func TestTryWindowsEnterpriseLifecycleLockNamesAMissingLock(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "lifecycle.lock")
	release, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err == nil {
		release()
		t.Fatal("took a lifecycle.lock that is not there")
	}
	if !strings.Contains(err.Error(), "lifecycle lock "+lock+" is not a regular file") || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing lifecycle.lock: %v, want the base message wrapping fs.ErrNotExist", err)
	}
	if _, err := acquireWindowsEnterpriseLifecycleLock(lock); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("the waiting take of a missing lifecycle.lock: %v", err)
	}
}

// GAP-0646 review L2: a lifecycle.lock the guardian cannot open for any
// reason but a sharing violation or a missing file (a directory, a DACL that
// denies it) says the guardian cannot tell whether a run owns config.yaml.
// It records nothing, keeps the edit, and records it as a hand edit once it
// can open the lock again.
func TestTheGuardianKeepsAnEditBehindALifecycleLockItCannotOpen(t *testing.T) {
	t.Cleanup(func() { managedConfigRecordDeferredTo = "" })
	for _, tc := range []struct {
		name  string
		block func(t *testing.T, lock string) (unblock func())
	}{
		{name: "lifecycle.lock is a directory", block: func(t *testing.T, lock string) func() {
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(lock, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "lifecycle.lock denies the guardian", block: func(t *testing.T, lock string) func() {
			if err := os.WriteFile(lock, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			setTestFileDACL(t, lock, "D:P")
			// The test account opens it again whoever runs the tests: a
			// standard user is neither SYSTEM nor an administrator
			// (cowork-1-0-8 GAP-0094).
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil || user == nil || user.User.Sid == nil {
				t.Fatalf("resolve the test account: %v", err)
			}
			me := user.User.Sid.String()
			restore := func() { setTestFileDACL(t, lock, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+me+")") }
			t.Cleanup(restore)
			return restore
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			etc := filepath.Join(dir, "etc")
			lock := filepath.Join(dir, "lifecycle", "lifecycle.lock")
			for _, folder := range []string{etc, filepath.Dir(lock), filepath.Join(dir, "install")} {
				if err := os.MkdirAll(folder, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(etc, "config.yaml")
			if err := os.WriteFile(path, []byte("config_version: 9\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := configwrite.Locked(t.Context(), path, configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "test install"},
				func() (bool, error) { return true, nil }); err != nil {
				t.Fatal(err)
			}
			edit := []byte("config_version: 9\n# an administrator's edit\n")
			if err := os.WriteFile(path, edit, 0o600); err != nil {
				t.Fatal(err)
			}
			layoutOf := func() (managed.StandaloneLayout, error) {
				return managed.StandaloneLayout{ConfigPath: path, ConfigDir: etc}, nil
			}
			claim := func() managedConfigOwnership { return claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf) }
			unblock := tc.block(t, lock)

			owner := claim()
			if owner.release != nil || owner.restored || !strings.Contains(owner.reason, "cannot tell whether a lifecycle run owns config.yaml") {
				t.Fatalf("blocked lifecycle.lock: owner %+v", owner)
			}
			var log strings.Builder
			recordUnrecordedManagedConfig(path, &log, claim)
			recordUnrecordedManagedConfig(path, &log, claim)
			if state, err := configwrite.ReadGenerationState(path); err != nil || state.Generation != 1 || state.Actor != configwrite.ActorLifecycle {
				t.Fatalf("recorded behind a lifecycle.lock it cannot open: %+v, %v", state, err)
			}
			if strings.Count(log.String(), "retried each cycle") != 1 {
				t.Fatalf("log = %q, want one line", log.String())
			}
			if note, kept := readManagedConfigHandEdit(path); !kept || note.ConfigSHA256 != configwrite.SHA256Hex(edit) {
				t.Fatalf("kept edit = %+v, %t", note, kept)
			}

			unblock()
			log.Reset()
			recordUnrecordedManagedConfig(path, &log, claim)
			state, err := configwrite.ReadGenerationState(path)
			if err != nil || state.Generation != 2 || state.Actor != configwrite.ActorUnattributedHandEdit || state.ConfigSHA256 != configwrite.SHA256Hex(edit) {
				t.Fatalf("record once lifecycle.lock opens = %+v, %v\n%s", state, err, log.String())
			}
			if note, kept := readManagedConfigHandEdit(path); !kept || note.ConfigSHA256 != configwrite.SHA256Hex(edit) {
				t.Fatalf("the recorded hand edit is not kept: %+v, %t", note, kept)
			}
			if again, err := tryWindowsEnterpriseLifecycleLock(lock); err != nil {
				t.Fatalf("the guardian kept lifecycle.lock: %v", err)
			} else {
				again()
			}
		})
	}
}

func setTestFileDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// GAP-0646: a Go lifecycle step waits for the guardian's short hold of
// lifecycle.lock, and still reads a run that keeps the lock as busy.
func TestAcquireWindowsEnterpriseLifecycleLockWaitsForAShortHold(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "lifecycle.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := windowsEnterpriseLifecycleLockWait
	t.Cleanup(func() { windowsEnterpriseLifecycleLockWait = saved })

	windowsEnterpriseLifecycleLockWait = 3 * time.Second
	held, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(300*time.Millisecond, held)
	release, err := acquireWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatalf("after a short hold: %v", err)
	}
	release()

	kept, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer kept()
	windowsEnterpriseLifecycleLockWait = 300 * time.Millisecond
	start := time.Now()
	if release, err := acquireWindowsEnterpriseLifecycleLock(lock); err == nil {
		release()
		t.Fatal("took lifecycle.lock from a run that keeps it")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("a kept lock: %v after %s, want a sharing violation after the wait", err, time.Since(start))
	}
}
