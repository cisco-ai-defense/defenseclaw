// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// pinWindowsEffectiveUserSIDForTest stands in for a thread token naming another
// principal, which a test process cannot obtain without a second account.
func pinWindowsEffectiveUserSIDForTest(t *testing.T, sid *windows.SID) {
	t.Helper()
	previous := windowsEffectiveUserSID
	windowsEffectiveUserSID = func() (*windows.SID, error) { return sid, nil }
	t.Cleanup(func() { windowsEffectiveUserSID = previous })
}

func windowsProcessUserSIDForTest(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve process token user: %v", err)
	}
	return user.User.Sid
}

// The descriptor a creator stamps must name the principal Windows records as
// owner, which is the effective token's user.
func TestAtomicTransformPrivateDescriptorNamesTheEffectiveUser(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	if target.Equals(windowsProcessUserSIDForTest(t)) {
		t.Skip("fixture SID collides with the process user")
	}
	pinWindowsEffectiveUserSIDForTest(t, target)

	descriptor, err := atomicTransformPrivateSecurityDescriptor()
	if err != nil {
		t.Fatalf("build private CAS descriptor: %v", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatalf("read private CAS descriptor owner: %v", err)
	}
	if owner == nil || !owner.Equals(target) {
		t.Fatalf("private CAS descriptor owner = %v, want %v", owner, target)
	}
	if !strings.Contains(descriptor.String(), target.String()) {
		t.Fatalf("private CAS DACL omits the effective user: %s", descriptor.String())
	}
}

// The validator must demand the same identity the creator stamps.
func TestAtomicTransformPrivateValidationNamesTheEffectiveUser(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	file, err := openAtomicTransformBoundDirectoryPlatform(dir)
	if err != nil {
		t.Fatalf("open bound directory: %v", err)
	}
	defer file.Close()

	pinWindowsEffectiveUserSIDForTest(t, windowsProcessUserSIDForTest(t))
	if err := validateAtomicTransformBoundDirectoryPlatform(file, true); err != nil {
		t.Fatalf("validate owner-created bound directory: %v", err)
	}

	foreign, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Equals(windowsProcessUserSIDForTest(t)) {
		t.Skip("fixture SID collides with the process user")
	}
	pinWindowsEffectiveUserSIDForTest(t, foreign)
	err = validateAtomicTransformBoundDirectoryPlatform(file, true)
	if err == nil || !strings.Contains(err.Error(), "not owned by current user") {
		t.Fatalf("validation ignored the effective user: %v", err)
	}
}

// NTFS may swap the two equivalent allow ACEs during a rename. The witness
// absorbs that only for the effective user, so a wrong identity mismatches.
func TestAtomicTransformProtectionWitnessToleratesACEReorderForEffectiveUser(t *testing.T) {
	owner := windowsProcessUserSIDForTest(t)
	foreign, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Equals(owner) {
		t.Skip("fixture SID collides with the process user")
	}
	path := filepath.Join(testenv.PrivateTempDir(t), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	file := openWindowsWritableDACLHandleForTest(t, path)
	defer file.Close()
	// The witness normalizes ACE order only when the effective user owns the
	// file, and elevated processes create files owned by BUILTIN\Administrators.
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil,
	); err != nil {
		t.Fatalf("set config owner: %v", err)
	}

	systemFirst := fmt.Sprintf("D:P(A;;FA;;;SY)(A;;FA;;;%s)", owner)
	userFirst := fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)", owner)
	// The canonicalizer keys on the owner's numeric SID text.
	round, err := windows.SecurityDescriptorFromString(systemFirst)
	if err != nil {
		t.Fatalf("parse fixture DACL %s: %v", systemFirst, err)
	}
	if !strings.Contains(round.String(), owner.String()) {
		t.Skip("process user SID renders as an SDDL alias")
	}

	pinWindowsEffectiveUserSIDForTest(t, owner)
	ownerSystemFirst := protectionWitnessForDACL(t, file, systemFirst)
	ownerUserFirst := protectionWitnessForDACL(t, file, userFirst)
	if ownerSystemFirst != ownerUserFirst {
		t.Fatal("witness rejected an equivalent ACE order for the effective user")
	}

	pinWindowsEffectiveUserSIDForTest(t, foreign)
	foreignSystemFirst := protectionWitnessForDACL(t, file, systemFirst)
	foreignUserFirst := protectionWitnessForDACL(t, file, userFirst)
	if foreignSystemFirst == foreignUserFirst {
		t.Fatal("witness normalization is not keyed on the effective user")
	}
}

func protectionWitnessForDACL(t *testing.T, file *os.File, sddl string) string {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse fixture DACL %s: %v", sddl, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read fixture DACL %s: %v", sddl, err)
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatalf("apply fixture DACL %s: %v", sddl, err)
	}
	witness, err := atomicTransformProtectionDigest(file)
	if err != nil {
		t.Fatalf("compute protection witness: %v", err)
	}
	return witness
}

func openWindowsWritableDACLHandleForTest(t *testing.T, path string) *os.File {
	t.Helper()
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL, 0,
	)
	if err != nil {
		t.Fatalf("open %s for DACL rewrite: %v", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("wrap handle for %s", path)
	}
	return file
}
