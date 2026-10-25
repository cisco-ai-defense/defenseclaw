// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/safefile/sharedfiletest"
	"golang.org/x/sys/windows"
)

// Cursor reads C:\ProgramData\Cursor\hooks.json with each user's own token.
// A hooks.json that carries the machine guard but that ordinary users cannot
// read leaves every user's Cursor without the machine hook, so DefenseClaw
// never publishes one: every write of the guard (setup, publication, repair,
// rollback) ends with a file every user can read, keeps the administrator's
// own access entries while it adds the read, and verification refuses an
// active guard users cannot read. A hooks.json without the guard keeps the
// administrator's access list: it is not DefenseClaw's to change.

// windowsCursorAdminOnlyAccessListForTest is an administrator's protected
// access list: Administrators, SYSTEM and the administrator's own Backup
// Operators read, and no read for ordinary users.
const windowsCursorAdminOnlyAccessListForTest = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BO)"

func protectWindowsCursorHooksForAdminsForTest(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(windowsCursorAdminOnlyAccessListForTest)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	requireWindowsCursorHooksUnreadableForTest(t, path)
}

// denyWindowsCursorHooksUserReadForTest adds a deny-read entry for one domain
// user, as icacls /deny does, and keeps the other entries.
func denyWindowsCursorHooksUserReadForTest(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_GENERIC_READ,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user),
		},
	}}, dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	requireWindowsCursorHooksUnreadableForTest(t, path)
}

func requireWindowsCursorHooksUnreadableForTest(t *testing.T, path string) {
	t.Helper()
	metadata, err := safefile.ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if safefile.UsersCanRead(metadata) == nil {
		t.Fatalf("fixture: ordinary users can still read %s (%s)", path, metadata.SecurityDescriptor)
	}
}

func requireWindowsCursorHooksReadableForTest(t *testing.T, path string) {
	t.Helper()
	metadata, err := safefile.ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.UsersCanRead(metadata); err != nil {
		t.Fatalf("ordinary users cannot read the Cursor machine hooks: %v (%s)", err, metadata.SecurityDescriptor)
	}
}

func TestWindowsCursorMachineGuardKeepsHooksReadableByUsers(t *testing.T) {
	setupOpts := connector.SetupOpts{APIAddr: "127.0.0.1:18970", HookExecutable: windowsCursorSharedHooksTestHook}
	adminOnly := func(t *testing.T, paths windowsCursorPaths) {
		protectWindowsCursorHooksForAdminsForTest(t, paths.Hooks)
	}
	denyUser := func(t *testing.T, paths windowsCursorPaths) {
		denyWindowsCursorHooksUserReadForTest(t, paths.Hooks)
	}
	setup := func(t *testing.T, protect func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		writeWindowsCursorAdminHooksForRestoreTest(t, paths)
		if protect != nil {
			protect(t, paths)
		}
		return paths, func() error { return EnsureWindowsStandaloneCursorManagedPolicy(setupOpts) }
	}
	publish := func(t *testing.T, protect func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error) {
		paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
		enrollWindowsCursorOpenAliceForTest(t, paths)
		if protect != nil {
			protect(t, paths)
		} else {
			// Closed hooks no longer need a content rewrite on target
			// publication. Require an ACL repair to exercise that writer.
			protectWindowsCursorHooksForAdminsForTest(t, paths.Hooks)
		}
		return paths, func() error {
			return PublishWindowsCursorManagedPolicyTargets([]WindowsCursorManagedRuntimeTarget{})
		}
	}
	repairLost := func(t *testing.T, protect func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error) {
		paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
		if protect != nil {
			protect(t, paths)
		}
		removeWindowsCursorRegistrationForTest(t, paths)
		return paths, func() error {
			_, err := RestoreWindowsCursorManagedAdapter(windowsCursorSharedHooksTestHook)
			return err
		}
	}
	repairHealthy := func(refresh func(string) (bool, error)) func(*testing.T, func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error) {
		return func(t *testing.T, protect func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error) {
			paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
			protect(t, paths)
			return paths, func() error {
				repaired, err := refresh(windowsCursorSharedHooksTestHook)
				if err == nil && !repaired {
					err = errors.New("the repair left a guard ordinary users cannot read")
				}
				return err
			}
		}
	}
	// A restore refuses a hooks.json whose access list changed since the
	// teardown it reverses, so the administrator protects it only during the
	// restore.
	refusedUninstall := func(t *testing.T, _ func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		opts, snapshot := tearDownWindowsCursorEmptyGuardForRestoreTest(t, paths)
		return paths, func() error { return RestoreWindowsCursorManagedPolicyTeardown(opts, snapshot) }
	}
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, func(*testing.T, windowsCursorPaths)) (windowsCursorPaths, func() error)
		// protect lays out the access list before the operation; during,
		// when set, changes it during the operation instead: just before its
		// first hooks.json swap (beforeSwap) or once that write has landed.
		protect    func(*testing.T, windowsCursorPaths)
		during     func(*testing.T, windowsCursorPaths)
		beforeSwap bool
		// fail makes the first hooks.json publication fail after it lands,
		// so the operation rolls back to the guard it started with.
		fail bool
		want string
		// steady: the registration is in hooks.json at every moment.
		steady bool
		// keepsEntries: the administrator's own access entries survive.
		keepsEntries bool
	}{
		{name: "publication while the administrator protects hooks.json", prepare: publish,
			during: adminOnly, beforeSwap: true, want: "closed", steady: true, keepsEntries: true},
		{name: "publication just after the write lands", prepare: publish,
			during: adminOnly, want: "closed", steady: true, keepsEntries: true},
		{name: "publication rollback while the administrator protects hooks.json", prepare: publish,
			during: adminOnly, beforeSwap: true, fail: true, want: "closed", steady: true, keepsEntries: true},
		{name: "publication over a protected hooks.json", prepare: publish,
			protect: adminOnly, want: "closed", steady: true, keepsEntries: true},
		{name: "publication while the administrator denies a user the read", prepare: publish,
			during: denyUser, beforeSwap: true, want: "closed", steady: true},
		{name: "restore of a refused uninstall while the administrator protects hooks.json", prepare: refusedUninstall,
			during: adminOnly, beforeSwap: true, want: "closed", keepsEntries: true},
		{name: "restore of a refused uninstall just after the write lands", prepare: refusedUninstall,
			during: adminOnly, want: "closed", keepsEntries: true},
		{name: "setup over a protected hooks.json", prepare: setup,
			protect: adminOnly, want: "closed", keepsEntries: true},
		{name: "setup while the administrator protects hooks.json", prepare: setup,
			during: adminOnly, beforeSwap: true, want: "closed", keepsEntries: true},
		{name: "repair while the administrator protects hooks.json", prepare: repairLost,
			during: adminOnly, beforeSwap: true, want: "closed", keepsEntries: true},
		{name: "repair just after the write lands", prepare: repairLost,
			during: adminOnly, want: "closed", keepsEntries: true},
		{name: "repair of a protected hooks.json", prepare: repairLost,
			protect: adminOnly, want: "closed", keepsEntries: true},
		{name: "repair of a hooks.json that denies a user the read", prepare: repairLost,
			protect: denyUser, want: "closed"},
		{name: "repair of a healthy guard in a protected hooks.json", prepare: repairHealthy(RestoreWindowsCursorManagedAdapter),
			protect: adminOnly, want: "closed", steady: true, keepsEntries: true},
		{name: "guardian refresh of a healthy guard in a protected hooks.json", prepare: repairHealthy(RefreshWindowsCursorManagedAdapter),
			protect: adminOnly, want: "closed", steady: true, keepsEntries: true},
		{name: "repair of a healthy guard that denies a user the read", prepare: repairHealthy(RestoreWindowsCursorManagedAdapter),
			protect: denyUser, want: "closed", steady: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, run := test.prepare(t, test.protect)
			changed := new(bool)
			if test.during != nil || test.fail {
				change := func() {}
				if test.during != nil {
					change = func() { test.during(t, paths) }
				}
				var failNext func()
				if test.fail {
					failNext = func() {}
				}
				changed = interleaveWindowsCursorSharedWriterForTest(t, paths.Hooks, test.beforeSwap, change, failNext)
			}
			watch := watchWindowsCursorMachineGuardForTest(paths, test.steady, true)
			err := run()
			watchErr := watch.Stop()
			if test.fail != (err != nil) {
				t.Fatalf("operation: err=%v, want an error %t", err, test.fail)
			}
			if test.during != nil && !*changed {
				t.Fatal("fixture: the administrator's access list change did not land")
			}
			if watchErr != nil {
				t.Fatalf("watch: %v", watchErr)
			}
			windowsCursorManagedFileSwap = swapWindowsCursorManagedFile
			requireWindowsCursorHooksReadableForTest(t, paths.Hooks)
			if test.keepsEntries {
				sharedfiletest.RequireBackupOperatorsRead(t, paths.Hooks)
			}
			requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original")
			requireWindowsCursorSharedWriterOutcomeForTest(t, paths, test.want)
			if err := verifyWindowsCursorManagedGuardActive(); err != nil {
				t.Fatalf("verify the guard: %v", err)
			}
			if repaired, err := RestoreWindowsCursorManagedAdapter(windowsCursorSharedHooksTestHook); err != nil || repaired {
				t.Fatalf("second repair of the guard: repaired=%t err=%v", repaired, err)
			}
		})
	}
}

// Elevated verification reads hooks.json as an administrator; it must still
// refuse an active guard ordinary users cannot read.
func TestVerifyWindowsCursorMachineGuardRefusesHooksUsersCannotRead(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(t *testing.T, path string)
	}{
		{name: "protected for administrators", apply: protectWindowsCursorHooksForAdminsForTest},
		{name: "a user denied the read", apply: denyWindowsCursorHooksUserReadForTest},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
			if err := verifyWindowsCursorManagedGuardActive(); err != nil {
				t.Fatalf("the installed guard does not verify: %v", err)
			}
			test.apply(t, paths.Hooks)
			err := verifyWindowsCursorManagedGuardActive()
			if err == nil || !strings.Contains(err.Error(), "ordinary users cannot read") {
				t.Fatalf("verify of hooks.json ordinary users cannot read = %v, want a refusal", err)
			}
		})
	}
}

// A guard installed over a hooks.json ordinary users cannot read adds the
// read while it is there; its teardown gives the administrator's original
// access list back exactly. Without the guard the file is not DefenseClaw's
// to change.
func TestWindowsCursorTeardownGivesBackTheAdministratorsAccessList(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	writeWindowsCursorAdminHooksForRestoreTest(t, paths)
	protectWindowsCursorHooksForAdminsForTest(t, paths.Hooks)
	original, err := safefile.ReadPathMetadata(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	installWindowsCursorEmptyGuardForRestoreTest(t, paths)
	requireWindowsCursorHooksReadableForTest(t, paths.Hooks)
	sharedfiletest.RequireBackupOperatorsRead(t, paths.Hooks)
	if err := DeactivateWindowsCursorManagedPolicy(); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	requireWindowsCursorSharedWriterOutcomeForTest(t, paths, "inactive")
	requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original")
	after, err := safefile.ReadPathMetadata(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	if after != original {
		t.Fatalf("the teardown did not give back the administrator's metadata:\n%+v\nwant\n%+v", after, original)
	}
}
