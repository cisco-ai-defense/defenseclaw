// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import "testing"

// The installer, the enterprise module, and the Secure Client GUI all use
// these literals. Only the Go side comes from these variables, so the test
// spells the values out instead of deriving them.
func TestManagedSecureClientLayoutMatchesInstaller(t *testing.T) {
	if got, want := ManagedInstallRelativeDir, `Cisco\Cisco Secure Client\DefenseClaw`; got != want {
		t.Fatalf("ManagedInstallRelativeDir = %q, want %q", got, want)
	}
	if got, want := ManagedIPCRelativeDir, `Cisco\Cisco Secure Client\DefenseClaw\ipc`; got != want {
		t.Fatalf("ManagedIPCRelativeDir = %q, want %q", got, want)
	}
}

func TestManagedStandaloneLayoutMatchesInstaller(t *testing.T) {
	if got, want := StandaloneManagedInstallRelativeDir, `Cisco\DefenseClaw`; got != want {
		t.Fatalf("StandaloneManagedInstallRelativeDir = %q, want %q", got, want)
	}
	if got, want := StandaloneManagedIPCRelativeDir, `Cisco\DefenseClaw\ipc`; got != want {
		t.Fatalf("StandaloneManagedIPCRelativeDir = %q, want %q", got, want)
	}
}
