// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0574: a CRITICAL skill an administrator copied into a user folder is
// owned by the administrator, and the guardian refused to remove it. The
// user, the Administrators group, SYSTEM and the built-in Administrator own
// a removable folder; another user does not.
func TestEnrolledAssetOwnerAllowed(t *testing.T) {
	sid := func(s string) *windows.SID {
		parsed, err := windows.StringToSid(s)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	name, err := windows.ComputerName()
	if err != nil {
		t.Fatal(err)
	}
	machine, _, _, err := windows.LookupSID("", name)
	if err != nil {
		t.Fatal(err)
	}
	target := sid(machine.String() + "-1116")
	for owner, want := range map[string]bool{
		target.String():            true,
		"S-1-5-32-544":             true,
		"S-1-5-18":                 true,
		machine.String() + "-500":  true,
		machine.String() + "-1117": false,
	} {
		if got := enrolledAssetOwnerAllowed(sid(owner), target); got != want {
			t.Errorf("owner %s allowed = %v, want %v", owner, got, want)
		}
	}
}
