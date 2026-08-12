// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func denyTestDirectoryListing(t *testing.T, path string) func() {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("capture test directory DACL: %v", err)
	}
	originalDACL, _, err := descriptor.DACL()
	if err != nil || originalDACL == nil {
		t.Fatalf("capture test directory DACL entries: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("capture test directory DACL control: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current Windows user: %v", err)
	}
	deniedDACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_LIST_DIRECTORY,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, originalDACL)
	if err != nil {
		t.Fatalf("build access-denied test DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		deniedDACL,
		nil,
	); err != nil {
		t.Fatalf("apply access-denied test DACL: %v", err)
	}

	var once sync.Once
	restore := func() {
		once.Do(func() {
			securityInformation := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
			if control&windows.SE_DACL_PROTECTED != 0 {
				securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
			} else {
				securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
			}
			if err := windows.SetNamedSecurityInfo(
				extended,
				windows.SE_FILE_OBJECT,
				securityInformation,
				nil,
				nil,
				originalDACL,
				nil,
			); err != nil {
				t.Errorf("restore test directory DACL: %v", err)
			}
		})
	}
	t.Cleanup(restore)
	if _, err := os.ReadDir(path); !errors.Is(err, os.ErrPermission) {
		restore()
		t.Fatalf("access-denied directory read error = %v, want permission denied", err)
	}
	return restore
}
