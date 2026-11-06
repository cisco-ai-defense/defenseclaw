// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winowner

import "testing"

func TestTrustedWriterAddsOnlyOwnerRights(t *testing.T) {
	const current = "S-1-5-21-1-2-3-1001"
	for _, tc := range []struct {
		name, sid string
		want      bool
	}{
		{"the account", current, true},
		{"BUILTIN Administrators", "S-1-5-32-544", true},
		{"OWNER RIGHTS", "S-1-3-4", true},
		{"CREATOR OWNER", "S-1-3-0", false},
		{"BUILTIN Users", "S-1-5-32-545", false},
		{"Authenticated Users", "S-1-5-11", false},
		{"another account", "S-1-5-21-1-2-3-1002", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrustedWriter(tc.sid, current); got != tc.want {
				t.Fatalf("TrustedWriter(%q) = %v, want %v", tc.sid, got, tc.want)
			}
		})
	}
}

func TestTrustedAcceptsTheAccountAndWindowsSystemOwnersOnly(t *testing.T) {
	const current = "S-1-5-21-1-2-3-1001"
	for _, tc := range []struct {
		name, owner, current string
		want                 bool
	}{
		{"the account", current, current, true},
		{"LocalSystem", "S-1-5-18", current, true},
		{"BUILTIN Administrators", "S-1-5-32-544", current, true},
		{"TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", current, true},
		{"system owner without a known account", "S-1-5-32-544", "", true},
		{"BUILTIN Users", "S-1-5-32-545", current, false},
		{"Authenticated Users", "S-1-5-11", current, false},
		{"Everyone", "S-1-1-0", current, false},
		{"another account", "S-1-5-21-1-2-3-1002", current, false},
		{"another account without a known account", "S-1-5-21-1-2-3-1002", "", false},
		{"a domain Administrators lookalike", "S-1-5-21-1-2-3-512", current, false},
		{"no owner", "", current, false},
		{"no owner and no account", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Trusted(tc.owner, tc.current); got != tc.want {
				t.Fatalf("Trusted(%q, %q) = %v, want %v", tc.owner, tc.current, got, tc.want)
			}
		})
	}
}
