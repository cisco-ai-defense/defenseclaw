// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import "testing"

// The marker counts only where the uninstall would write it: the account's
// own folder or one Windows owns, and a file owned the same way
// (cowork-1-0-8 GAP-0085).
func TestCoworkOwnersTrustedUsesTheWindowsOwnerTrustSet(t *testing.T) {
	const (
		current = "S-1-5-21-1-2-3-1001"
		other   = "S-1-5-21-1-2-3-1002"
		admins  = "S-1-5-32-544"
		system  = "S-1-5-18"
		trusted = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
		users   = "S-1-5-32-545"
	)
	for _, tc := range []struct {
		name           string
		marker, folder string
		want           bool
	}{
		{"own marker in own profile", current, current, true},
		{"own marker in an Administrators-owned profile", current, admins, true},
		{"Administrators marker in an Administrators-owned profile", admins, admins, true},
		{"own marker in a SYSTEM-owned folder", current, system, true},
		{"own marker in a TrustedInstaller-owned folder", current, trusted, true},
		{"own marker in another account's profile", current, other, false},
		{"marker another account planted", other, current, false},
		{"marker another account planted in its own folder", other, other, false},
		{"Users-owned marker", users, current, false},
		{"Users-owned folder", current, users, false},
		{"unknown marker owner", "", current, false},
		{"unknown folder owner", current, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := coworkOwnersTrusted(tc.marker, tc.folder, current); got != tc.want {
				t.Fatalf("coworkOwnersTrusted(%q, %q) = %v, want %v", tc.marker, tc.folder, got, tc.want)
			}
		})
	}
}
