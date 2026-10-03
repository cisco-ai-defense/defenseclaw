// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

func TestWindowsServiceSIDStringMatchesWindows(t *testing.T) {
	// sc showsid TrustedInstaller
	const want = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, name := range []string{"TrustedInstaller", "trustedinstaller"} {
		if got := windowsServiceSIDString(name); got != want {
			t.Fatalf("windowsServiceSIDString(%q) = %s, want %s", name, got, want)
		}
	}
}
