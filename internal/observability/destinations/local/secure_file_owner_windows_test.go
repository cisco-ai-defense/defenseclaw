//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The LocalSystem gateway owns its JSONL files as its service SID, as the
// 1.0.0 virtual account did; the owner check follows that identity and no
// other service SID.
func TestWindowsAllowedOwnerFollowsGatewayServiceSID(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-555-444-333-222-111")
	if err != nil {
		t.Fatal(err)
	}
	foreignSID, err := windows.StringToSid("S-1-5-80-111-222-333-444-555")
	if err != nil {
		t.Fatal(err)
	}
	previous := windowsCurrentOwnerSID
	t.Cleanup(func() { windowsCurrentOwnerSID = previous })
	windowsCurrentOwnerSID = func() (*windows.SID, error) { return serviceSID, nil }
	if !windowsAllowedOwner(serviceSID) || !windowsAllowedACEPrincipal(serviceSID) {
		t.Fatal("the gateway's own service SID was not an allowed owner")
	}
	if windowsAllowedOwner(foreignSID) || windowsAllowedACEPrincipal(foreignSID) {
		t.Fatal("a foreign service SID was an allowed owner")
	}
}
