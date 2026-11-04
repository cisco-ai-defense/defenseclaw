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

import "testing"

func TestVirtualServiceSIDStringMatchesWindows(t *testing.T) {
	for name, want := range map[string]string{
		// Well-known SID Windows documents for NT SERVICE\TrustedInstaller.
		"TrustedInstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"trustedinstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		// Recorded from sc.exe showsid for a name with no SCM row.
		"DefenseClawRecoveryNoSuchServiceProbe_48A6": "S-1-5-80-557343067-3914267301-595778489-1841644181-1709292513",
	} {
		if got := virtualServiceSIDString(name); got != want {
			t.Fatalf("virtualServiceSIDString(%q) = %s, want %s", name, got, want)
		}
	}
}
