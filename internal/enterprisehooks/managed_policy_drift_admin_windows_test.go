//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-2336: Setup /repair and `enterprise windows repair` run in the
// administrator's elevated token, not as LocalSystem. With the guardian
// stopped, the drop-in an administrator changed stayed changed, because the
// restore refused every token but LocalSystem, and the repair's snapshot then
// refused it as an administrator edit (1603). An elevated administrator puts
// it back now, edited or deleted.
func TestWindowsClaudeManagedPolicyDriftIsPutBackByAnElevatedAdministrator(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and preflight hosts run elevated)")
	}
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return errWindowsEnterpriseNotLocalSystem }
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = previous })

	edited := bytes.Replace(original, []byte("TeammateIdle"), []byte("TeammateIdleRemoved"), 1)
	if bytes.Equal(edited, original) {
		edited = append(append([]byte(nil), original...), ' ')
	}
	for name, change := range map[string]func() error{
		"edited":  func() error { return os.WriteFile(fixture.policyPath, edited, 0o600) },
		"deleted": func() error { return os.Remove(fixture.policyPath) },
	} {
		if err := change(); err != nil {
			t.Fatal(err)
		}
		if restored, err := RestoreWindowsClaudeManagedPolicyDrift(); err != nil || !restored {
			t.Fatalf("%s drop-in as an elevated administrator: restored=%v err=%v, want it put back", name, restored, err)
		}
		if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, original) {
			t.Fatalf("%s drop-in: restored bytes differ from the ones DefenseClaw wrote (err=%v)", name, err)
		}
	}
}

// GAP-2336: status and verify name a changed or removed drop-in (read only).
func TestWindowsClaudeManagedPolicyDriftNamesAChangedOrRemovedDropIn(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	if path, removed := WindowsClaudeManagedPolicyDrift(); path != "" || removed {
		t.Fatalf("untouched drop-in: drift=%q removed=%v, want none", path, removed)
	}
	original, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.policyPath, append(append([]byte(nil), original...), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if path, removed := WindowsClaudeManagedPolicyDrift(); path != fixture.policyPath || removed {
		t.Fatalf("edited drop-in: drift=%q removed=%v, want %q not removed", path, removed, fixture.policyPath)
	}
	before, _ := os.ReadFile(fixture.policyPath)
	if path, _ := WindowsClaudeManagedPolicyDrift(); path == "" {
		t.Fatal("second read lost the drift")
	}
	if after, _ := os.ReadFile(fixture.policyPath); !bytes.Equal(before, after) {
		t.Fatal("the drift check changed the drop-in")
	}
	if err := os.Remove(fixture.policyPath); err != nil {
		t.Fatal(err)
	}
	if path, removed := WindowsClaudeManagedPolicyDrift(); path != fixture.policyPath || !removed {
		t.Fatalf("deleted drop-in: drift=%q removed=%v, want %q removed", path, removed, fixture.policyPath)
	}
	if restored, err := RestoreWindowsClaudeManagedPolicyDrift(); err != nil || !restored {
		t.Fatalf("restore: restored=%v err=%v", restored, err)
	}
	if path, _ := WindowsClaudeManagedPolicyDrift(); path != "" {
		t.Fatalf("after the restore: drift=%q, want none", path)
	}
}
