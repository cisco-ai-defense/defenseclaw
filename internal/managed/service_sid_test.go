// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

func TestWindowsServiceSIDStringMatchesWindows(t *testing.T) {
	// sc showsid TrustedInstaller
	const want = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, name := range []string{"TrustedInstaller", "trustedinstaller"} {
		if got := WindowsServiceSIDString(name); got != want {
			t.Fatalf("WindowsServiceSIDString(%q) = %s, want %s", name, got, want)
		}
	}
	// sc showsid for a name with no SCM row: the SID needs no service.
	const probe = "S-1-5-80-557343067-3914267301-595778489-1841644181-1709292513"
	if got := WindowsServiceSIDString("DefenseClawRecoveryNoSuchServiceProbe_48A6"); got != probe {
		t.Fatalf("WindowsServiceSIDString(probe) = %s, want %s", got, probe)
	}
}
