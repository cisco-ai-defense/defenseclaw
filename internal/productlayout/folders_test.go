// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package productlayout

import "testing"

func TestIsFolderName(t *testing.T) {
	t.Parallel()
	for _, name := range FolderNames() {
		if !IsFolderName(name) {
			t.Errorf("%q is registered but not recognized", name)
		}
	}
	if !IsFolderName("DEFENSECLAW-HOOKRUNTIME") || !IsFolderName("defenseclaw-lifecycle") {
		t.Error("folder names are matched case-insensitively")
	}
	for _, name := range []string{"", "DefenseClaw-", "DefenseClaw-HookRuntime2", "xDefenseClaw-Cert", "DefenseClaw-Cert\\", "Cisco"} {
		if IsFolderName(name) {
			t.Errorf("%q is not a product folder", name)
		}
	}
}

func TestFolderNamesReturnsACopy(t *testing.T) {
	t.Parallel()
	names := FolderNames()
	names[0] = "changed"
	if FolderNames()[0] != ProductFolder {
		t.Error("FolderNames exposed the registry")
	}
}
