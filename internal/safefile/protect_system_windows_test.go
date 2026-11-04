// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"testing"

	"golang.org/x/sys/windows"
)

// A LocalSystem caller's private DACL has one SYSTEM entry that is both the
// owner entry and the SYSTEM entry; it must read back as safe instead of being
// rewritten on every call.
func TestPrivateDescriptorIsSafeForLocalSystemSubject(t *testing.T) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	safe, err := privateSecurityDescriptorIsSafeForSubject(descriptor, windowsProtectionSubject{sid: system})
	if err != nil {
		t.Fatal(err)
	}
	if !safe {
		t.Fatal("SYSTEM-only private DACL for a LocalSystem caller reported unsafe")
	}
	extra, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	if safe, err := privateSecurityDescriptorIsSafeForSubject(extra, windowsProtectionSubject{sid: system}); err != nil || safe {
		t.Fatalf("extra Users entry: safe=%t err=%v, want unsafe", safe, err)
	}
}
