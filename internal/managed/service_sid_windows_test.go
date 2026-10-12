//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

// Uninstall deletes the LocalSystem gateway's service before the teardown
// finalize loads the managed config, and a deleted LocalSystem service's
// NT SERVICE name no longer maps (Setup /uninstall failed with "No mapping
// between account names and security IDs was done"). The pinned service SID
// must still resolve, to exactly the SID SCM derives from the name.
func TestWindowsVirtualServiceSIDResolvesDeletedService(t *testing.T) {
	for _, test := range []struct{ name, want string }{
		// Values read from `sc.exe showsid` and live services on Windows
		// Server 2025; TrustedInstaller exists on every host.
		{"TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"},
		{"DefenseClawGateway_NoSuchService_1186", ""},
		{"DCProbeLS1186b", "S-1-5-80-3966068464-132393573-132497650-1292823767-79231673"},
	} {
		derived, err := windowsDerivedServiceSID(test.name)
		if err != nil {
			t.Fatalf("derive %s: %v", test.name, err)
		}
		if test.want != "" && derived.String() != test.want {
			t.Fatalf("derived SID for %s = %s, want %s", test.name, derived, test.want)
		}
		resolved, err := windowsVirtualServiceSID(`NT SERVICE\` + test.name)
		if err != nil {
			t.Fatalf("resolve NT SERVICE\\%s: %v", test.name, err)
		}
		if !resolved.Equals(derived) {
			t.Fatalf("resolved SID for %s = %s, want derived %s", test.name, resolved, derived)
		}
	}
	lower, err := windowsDerivedServiceSID("trustedinstaller")
	if err != nil {
		t.Fatal(err)
	}
	if lower.String() != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
		t.Fatalf("service SID derivation is case-sensitive: %s", lower)
	}
}
