//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsWriteLikeAccess(t *testing.T) {
	for name, mask := range map[string]windows.ACCESS_MASK{
		"generic write": windows.GENERIC_WRITE,
		"write data":    windows.FILE_WRITE_DATA,
		"delete child":  0x00000040,
		"change dacl":   windows.WRITE_DAC,
	} {
		t.Run(name, func(t *testing.T) {
			if !windowsWriteLikeAccess(mask) {
				t.Fatalf("windowsWriteLikeAccess(0x%x) = false, want true", uint32(mask))
			}
		})
	}
	if windowsWriteLikeAccess(windows.GENERIC_READ | windows.FILE_READ_DATA) {
		t.Fatal("read-only access classified as write-like")
	}
}

func TestWindowsTrustedOwner(t *testing.T) {
	for _, raw := range []string{
		"S-1-5-18",     // LocalSystem
		"S-1-5-32-544", // Builtin Administrators
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
	} {
		sid, err := windows.StringToSid(raw)
		if err != nil {
			t.Fatalf("StringToSid(%q): %v", raw, err)
		}
		if !windowsTrustedOwner(sid) {
			t.Fatalf("windowsTrustedOwner(%q) = false, want true", raw)
		}
	}

	standardUser, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatalf("StringToSid standard user: %v", err)
	}
	if windowsTrustedOwner(standardUser) {
		t.Fatal("standard user SID classified as trusted owner")
	}
	if windowsTrustedOwner(nil) {
		t.Fatal("nil SID classified as trusted owner")
	}
}

func TestRejectUntrustedWindowsWriteACEs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{
			name: "standard users read only",
			sddl: "D:P(A;;GR;;;BU)(A;;GA;;;BA)",
		},
		{
			name:    "standard users generic write",
			sddl:    "D:P(A;;GW;;;BU)(A;;GA;;;BA)",
			wantErr: "untrusted Windows principal",
		},
		{
			name: "local system write",
			sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			dacl, present, err := descriptor.DACL()
			if err != nil {
				t.Fatalf("DACL: %v", err)
			}
			if !present || dacl == nil {
				t.Fatal("test descriptor has no DACL")
			}
			err = rejectUntrustedWindowsWriteACEs("test-path", dacl)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("rejectUntrustedWindowsWriteACEs: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("rejectUntrustedWindowsWriteACEs error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
