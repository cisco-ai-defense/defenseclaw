// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A standard user cannot list the hook guardian's state folder, and the
// guardian's rewrites in it move the folder's modified time every pass. The
// service-folder fingerprint of a folder this identity cannot list leaves
// that time out, so a standard-user run is not failed by the guardian's own
// passes (GAP-0093, REVIEW-g672 L2). The fixture denies only
// FILE_LIST_DIRECTORY to the test account, which can still write a file in
// it, as the service does.
func TestTestMachineServiceFolderThisIdentityCannotListIgnoresTheServicesPasses(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "hook-guardian-state")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve the test account: %v", err)
	}
	me := user.User.Sid.String()
	setDACL := func(sddl string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(locked, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatalf("set the DACL of %s: %v", locked, err)
		}
	}
	allow := "(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	setDACL("D:P(D;;0x1;;;" + me + ")" + allow) // 0x1: FILE_LIST_DIRECTORY
	t.Cleanup(func() { setDACL("D:P" + allow) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("this token lists the folder through the deny entry (its backup privilege is enabled); a standard user cannot")
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(locked, past, past); err != nil {
		t.Fatal(err)
	}
	folders := testServiceFolders{roots: []string{locked}}
	snapshot := func(before map[string]string) map[string]string {
		folders.before = before
		out := map[string]string{}
		fingerprintTestServiceFolders(out, folders)
		return out
	}
	before := snapshot(nil)
	if got := before["file "+locked]; !strings.HasPrefix(got, "service folder, contents unreadable: ") {
		t.Fatalf("unlistable service folder fingerprint %q, want an unreadable note without its time", got)
	}
	// The guardian's pass: a record replaced in the folder, which moves its
	// modified time.
	if err := os.WriteFile(filepath.Join(locked, "activation.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changes := diffTestMachineRegistry(before, snapshot(before)); len(changes) != 0 {
		t.Fatalf("the service's pass in a folder this identity cannot list is reported as a test's write: %v", changes)
	}
}
