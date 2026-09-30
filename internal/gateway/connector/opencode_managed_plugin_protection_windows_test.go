// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A Windows enterprise guardian verifies a per-user OpenCode plugin as
// LocalSystem or an administrator, without the user's token, and the plugin
// carries the managed plugin DACL (target and LocalSystem full control,
// Administrators read-only). The current-user safefile shape cannot apply
// there; with ManagedTargetSID the check trusts exactly that account and
// still refuses foreign write authority.
func TestOpenCodeManagedPluginProtectionTrustsTheManagedTarget(t *testing.T) {
	owner := windowsProcessUserSIDForTest(t)
	dir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "defenseclaw.js")
	if err := os.WriteFile(path, []byte("// plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, element := range []string{dir, path} {
		if err := windows.SetNamedSecurityInfo(element, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
			t.Skipf("test token cannot own its fixture: %v", err)
		}
	}
	setDACL := func(target, sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setDACL(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+owner.String()+")(A;OICI;FA;;;BA)")
	setDACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;"+owner.String()+")(A;;FR;;;BA)")
	// The guardian's LocalSystem identity, not the plugin owner.
	pinWindowsEffectiveUserSIDForTest(t, mustSIDForTrustedOwnerTest(t, "S-1-5-18"))

	managed := SetupOpts{ManagedTargetSID: owner.String()}
	if err := validateOpenCodeManagedPluginProtection(path, managed); err != nil {
		t.Fatalf("managed plugin DACL refused for the managed target: %v", err)
	}
	if err := validateOpenCodeManagedPluginProtection(path, SetupOpts{}); err == nil {
		t.Fatal("the current-user check accepted a DACL with an Administrators entry")
	}
	other := SetupOpts{ManagedTargetSID: "S-1-5-21-111-222-333-1018"}
	if err := validateOpenCodeManagedPluginProtection(path, other); err == nil {
		// Only fails when the owner is not otherwise trusted; an elevated
		// test token's own SID is never a well-known trusted principal.
		t.Fatal("plugin owned by another account passed for a different managed target")
	}
	setDACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;"+owner.String()+")(A;;FR;;;BA)(A;;FW;;;WD)")
	if err := validateOpenCodeManagedPluginProtection(path, managed); err == nil {
		t.Fatal("plugin writable by Everyone passed for the managed target")
	}
}
