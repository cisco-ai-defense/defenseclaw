// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/safefile/sharedfiletest"
	"golang.org/x/sys/windows"
)

// Codex reads requirements.toml with each user's own token. A requirements
// file that ordinary users cannot read leaves every user's Codex without the
// managed hooks, so a reconcile (setup or repair) never publishes one, keeps
// the administrator's own access entries while it restores the read, and
// verification refuses one.

// windowsCodexAdminOnlyAccessListForTest is an administrator's protected
// access list: Administrators, SYSTEM and the administrator's own Backup
// Operators read, and no read for ordinary users.
const windowsCodexAdminOnlyAccessListForTest = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BO)"

func setWindowsCodexAccessListForTest(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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
	requireWindowsCodexRequirementsUnreadableForTest(t, path)
}

// denyWindowsCodexUserReadForTest adds a deny-read entry for one domain user
// to the access list, as icacls /deny does, and keeps the other entries.
func denyWindowsCodexUserReadForTest(t *testing.T, path string) {
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
	requireWindowsCodexRequirementsUnreadableForTest(t, path)
}

func requireWindowsCodexRequirementsUnreadableForTest(t *testing.T, path string) {
	t.Helper()
	metadata, err := safefile.ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if safefile.UsersCanRead(metadata) == nil {
		t.Fatalf("fixture: ordinary users can still read %s (%s)", path, metadata.SecurityDescriptor)
	}
}

func requireWindowsCodexRequirementsReadableForTest(t *testing.T, path string) {
	t.Helper()
	metadata, err := safefile.ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.UsersCanRead(metadata); err != nil {
		t.Fatalf("ordinary users cannot read the published requirements: %v (%s)", err, metadata.SecurityDescriptor)
	}
}

func TestWindowsCodexReconcileKeepsRequirementsReadableByUsers(t *testing.T) {
	removeHook := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
		// An administrator's save in place drops the managed hooks and
		// keeps the file's access list.
		sharedfiletest.Admin{Path: opts.RequirementsPath, Edit: func([]byte) []byte {
			return []byte(windowsCodexOperatorRequirementForTest)
		}}.Apply(t, sharedfiletest.Content)
	}
	install := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
		if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
			t.Fatalf("install the configured guard: %+v err=%v", report, err)
		}
	}
	adminOnly := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
		setWindowsCodexAccessListForTest(t, opts.RequirementsPath, windowsCodexAdminOnlyAccessListForTest)
	}
	for _, test := range []struct {
		name string
		// prepare lays out the file before the reconcile.
		prepare func(t *testing.T, opts WindowsCodexMachineRequirementsOptions)
		// during, when set, runs during the reconcile: just before its
		// requirements swap (beforeSwap), or once its write has landed.
		during     func(t *testing.T, opts WindowsCodexMachineRequirementsOptions)
		beforeSwap bool
		// keepsEntries: the administrator's own access entries survive.
		keepsEntries bool
	}{
		{
			name:    "repair while the administrator protects the file",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) { install(t, opts); removeHook(t, opts) },
			during:  adminOnly, beforeSwap: true, keepsEntries: true,
		},
		{
			name:    "repair just after the write lands",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) { install(t, opts); removeHook(t, opts) },
			during:  adminOnly, keepsEntries: true,
		},
		{
			name: "repair of a protected file",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
				install(t, opts)
				removeHook(t, opts)
				adminOnly(t, opts)
			},
			keepsEntries: true,
		},
		{
			name: "healthy guard in a protected file",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
				install(t, opts)
				adminOnly(t, opts)
			},
			keepsEntries: true,
		},
		{
			name: "setup over a protected file",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
				adminOnly(t, opts)
			},
			keepsEntries: true,
		},
		{
			name: "repair of a file that denies a user the read",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
				install(t, opts)
				removeHook(t, opts)
				denyWindowsCodexUserReadForTest(t, opts.RequirementsPath)
			},
		},
		{
			name:    "repair while the administrator denies a user the read",
			prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) { install(t, opts); removeHook(t, opts) },
			during: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
				denyWindowsCodexUserReadForTest(t, opts.RequirementsPath)
			},
			beforeSwap: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
			test.prepare(t, opts)
			changed := new(bool)
			if test.during != nil {
				changed = interleaveWindowsCodexSharedWriterForTest(t, opts, test.beforeSwap, func() { test.during(t, opts) })
			}
			report, err := ReconcileWindowsCodexMachineRequirements(opts)
			if err != nil || !report.OK {
				t.Fatalf("reconcile: %+v err=%v", report, err)
			}
			if test.during != nil && !*changed {
				t.Fatal("fixture: the administrator's access list change did not land")
			}
			requireWindowsCodexRequirementsReadableForTest(t, opts.RequirementsPath)
			if test.keepsEntries {
				sharedfiletest.RequireBackupOperatorsRead(t, opts.RequirementsPath)
			}
			requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{}, "allowed_sandbox_modes")
			data, _, err := sharedfiletest.ReadShared(opts.RequirementsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte("allowed_sandbox_modes")) {
				t.Fatalf("the reconcile lost the administrator's requirement:\n%s", data)
			}
			if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || report.Changed {
				t.Fatalf("second reconcile of the repaired guard: %+v err=%v", report, err)
			}
		})
	}
}

// Elevated verification reads the file as an administrator; it must still
// refuse a requirements file ordinary users cannot read.
func TestVerifyWindowsCodexMachineRequirementsRefusesAFileUsersCannotRead(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(t *testing.T, path string)
	}{
		{name: "protected for administrators", apply: func(t *testing.T, path string) {
			setWindowsCodexAccessListForTest(t, path, windowsCodexAdminOnlyAccessListForTest)
		}},
		{name: "a user denied the read", apply: denyWindowsCodexUserReadForTest},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
			if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
				t.Fatalf("install the configured guard: %+v err=%v", report, err)
			}
			if _, err := VerifyWindowsCodexMachineRequirements(opts); err != nil {
				t.Fatalf("the installed guard does not verify: %v", err)
			}
			test.apply(t, opts.RequirementsPath)
			_, err := VerifyWindowsCodexMachineRequirements(opts)
			if err == nil || !strings.Contains(err.Error(), "ordinary users cannot read") {
				t.Fatalf("verify of requirements ordinary users cannot read = %v, want a refusal", err)
			}
		})
	}
}
