// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// custodyTestProfileList is the machine's list of user profiles.
const custodyTestProfileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// custodyTestTargetSID is a fresh local-user-shaped SID no account has: the
// per-user target a managed guardian verifies without that user's token
// (opts.ManagedTargetSID).
func custodyTestTargetSID(t *testing.T) *windows.SID {
	t.Helper()
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	sid, err := windows.StringToSid(fmt.Sprintf("S-1-5-21-%d-%d-%d-1001",
		binary.LittleEndian.Uint32(random[0:4]), binary.LittleEndian.Uint32(random[4:8]), binary.LittleEndian.Uint32(random[8:12])))
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// custodyTestProfileEntry gives sid a ProfileList entry whose ProfileImagePath
// is value (REG_EXPAND_SZ when expand), as Windows records a user's profile
// folder; the entry is removed when the test ends.
func custodyTestProfileEntry(t *testing.T, sid *windows.SID, value string, expand bool) {
	t.Helper()
	name := custodyTestProfileList + `\` + sid.String()
	key, existed, err := registry.CreateKey(registry.LOCAL_MACHINE, name, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("create the ProfileList entry of %s: %v", sid, err)
	}
	if existed {
		_ = key.Close()
		t.Fatalf("ProfileList already has an entry for %s", sid)
	}
	t.Cleanup(func() {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, name); err != nil {
			t.Errorf("remove the ProfileList entry of %s: %v", sid, err)
		}
	})
	if expand {
		err = key.SetExpandStringValue("ProfileImagePath", value)
	} else {
		err = key.SetStringValue("ProfileImagePath", value)
	}
	_ = key.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// custodyTestTargetFolder is a new folder at the system drive's root owned by
// sid, with the protected access list of a profile folder: full control for
// sid, LocalSystem and Administrators.
func custodyTestTargetFolder(t *testing.T, prefix string, sid *windows.SID) string {
	t.Helper()
	windowsDir, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(filepath.VolumeName(windowsDir)+`\`, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		custodyTestFullControl(sid),
		custodyTestFullControl(custodyTestSID(t, windows.WinLocalSystemSid)),
		custodyTestFullControl(custodyTestSID(t, windows.WinBuiltinAdministratorsSid)),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			sid, nil, acl, nil)
	}); err != nil {
		t.Fatalf("give %s to %s: %v", dir, sid, err)
	}
	return dir
}

// custodyTestTargetTree is <root>\.config\opencode\plugins\defenseclaw.js as
// the target account has it after one elevated OpenCode run: Administrators
// owns .config, the target owns opencode and the plugin folder, and all three
// inherit root's access list. The guardian's target run accepts it.
func custodyTestTargetTree(t *testing.T, root string, sid *windows.SID) (config, plugin string) {
	t.Helper()
	config = filepath.Join(root, ".config")
	opencode := filepath.Join(config, "opencode")
	plugins := filepath.Join(opencode, "plugins")
	for _, dir := range []string{config, opencode, plugins} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	custodyTestOwner(t, config, custodyTestSID(t, windows.WinBuiltinAdministratorsSid))
	custodyTestOwner(t, opencode, sid)
	custodyTestOwner(t, plugins, sid)
	plugin = filepath.Join(plugins, "defenseclaw.js")
	if err := validatePluginArtifactDestinationFor(plugin, sid.String()); err != nil {
		t.Fatalf("the target's plugin folder below %s was refused before any change: %v", root, err)
	}
	return config, plugin
}

// custodyTestTakeOwnership is the step for a write entry granted at folder,
// a folder Administrators owns that the check leaves out (GAP-1917).
func custodyTestTakeOwnership(trustee, folder string) string {
	return "Administrators owns " + pluginCustodyQuote(folder) + ", so no command is printed for the write entry of " + trustee +
		" on it: take ownership of " + pluginCustodyQuote(folder) + " and remove the entry, or have an administrator remove it"
}

// custodyTestTakeOwnershipInherited is the step for a write entry path
// inherits from folder, a folder Administrators owns that the check leaves out
// (GAP-1917).
func custodyTestTakeOwnershipInherited(trustee, path, folder string) string {
	return "the write entry of " + trustee + " that " + pluginCustodyQuote(path) + " inherits is granted at " + pluginCustodyQuote(folder) +
		", which Administrators owns, so no command is printed for it: take ownership of " + pluginCustodyQuote(folder) +
		" and remove the entry there, or have an administrator remove it"
}

// GAP-1916: the guardian's run for a managed target account (a target SID)
// takes a folder Administrators owns in that account's own profile for the
// account's own, as rel did: the target once ran OpenCode elevated, so its
// .config is Administrators-owned, and a foreign write entry there gets the
// icacls command, not a step to move the plugin folder. The profile is the one
// Windows records for the account (ProfileList\<SID>\ProfileImagePath, which
// only administrators can change), spelled plainly or with %SystemDrive%.
func TestGAP1916AdministratorsOwnedFolderInTheTargetProfileKeepsItsCommand(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a profile entry in HKLM and a folder another account owns need an elevated token; run elevated")
	}
	for _, expand := range []bool{false, true} {
		t.Run(fmt.Sprintf("expand=%v", expand), func(t *testing.T) {
			target := custodyTestTargetSID(t)
			profile := custodyTestTargetFolder(t, "dc-gap1916-", target)
			config, plugin := custodyTestTargetTree(t, profile, target)
			custodyTestGrant(t, config, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
			value := profile
			if expand {
				value = "%SystemDrive%" + strings.TrimPrefix(profile, filepath.VolumeName(profile))
			}
			custodyTestProfileEntry(t, target, value, expand)
			want := `icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-5-32-546'`
			err := validatePluginArtifactDestinationFor(plugin, target.String())
			fix, manual := custodyTestRepair(t, err)
			if fix != want {
				t.Fatalf("target run: fix = %q, want %q (the folder is in the target's own profile; rel printed the command)\nmanual: %s\n%v", fix, want, manual, err)
			}
			if strings.Contains(manual, "move the plugin folder") {
				t.Fatalf("target run: manual step tells the user to move the plugin folder: %s", manual)
			}
			custodyTestRunFix(t, want)
			if err := validatePluginArtifactDestinationFor(plugin, target.String()); err != nil {
				t.Fatalf("target run: still refused after the printed fix: %v", err)
			}
		})
	}
}

// GAP-1916 (GAP-1910 kept for a target run): a folder Administrators owns
// outside the target's own profile is shared by every administrator, so an
// entry granted there gets a step by hand and no command; the entry granted at
// the target's own folder below it keeps its command.
func TestGAP1916AdministratorsOwnedFolderOutsideTheTargetProfileGetsNoCommand(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a profile entry in HKLM and a folder another account owns need an elevated token; run elevated")
	}
	target := custodyTestTargetSID(t)
	custodyTestProfileEntry(t, target, custodyTestTargetFolder(t, "dc-gap1916p-", target), false)
	administrators := custodyTestSID(t, windows.WinBuiltinAdministratorsSid)
	shared := custodyTestTargetFolder(t, "dc-gap1916s-", target)
	custodyTestOwner(t, shared, administrators)
	cfg := filepath.Join(shared, "cfg")
	opencode := filepath.Join(cfg, "opencode")
	plugins := filepath.Join(opencode, "plugins")
	for _, dir := range []string{cfg, opencode, plugins} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	custodyTestOwner(t, cfg, target)
	custodyTestOwner(t, opencode, administrators)
	custodyTestOwner(t, plugins, target)
	plugin := filepath.Join(plugins, "defenseclaw.js")
	if err := validatePluginArtifactDestinationFor(plugin, target.String()); err != nil {
		t.Fatalf("the target's plugin folder below %s was refused before any change: %v", shared, err)
	}
	custodyTestGrant(t, shared, custodyTestSID(t, windows.WinWorldSid),
		windows.ACCESS_MASK(0x1301bf), windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) // Everyone:(OI)(CI)M
	custodyTestGrant(t, cfg, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	err := validatePluginArtifactDestinationFor(plugin, target.String())
	fix, manual := custodyTestRepair(t, err)
	if want := `icacls ` + managed.PowerShellLiteral(cfg) + ` /remove:g '*S-1-5-32-546'`; fix != want {
		t.Fatalf("fix = %q, want %q (only the entry granted at the target's own folder gets a command):\n%v", fix, want, err)
	}
	if want := "is granted at " + pluginCustodyQuote(shared) + ", outside the folders this account owns"; !strings.Contains(manual, want) {
		t.Fatalf("manual step lacks %q:\n%v", want, err)
	}
}

// GAP-1917: a folder Administrators owns that the check leaves out although
// it is in the account's own profile (the target's profile entry spelled
// oddly or missing, a profile folder that is a junction, a subst spelling of
// the account's own profile) gets a step to take ownership of it or have an
// administrator remove the entry, never one to move the plugin folder: the
// folder is already in the profile.
func TestGAP1917AdministratorsOwnedFolderLeftOutOfTheProfileSaysTakeOwnership(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a profile entry in HKLM and a folder Administrators owns need an elevated token; run elevated")
	}
	const guests = "*S-1-5-32-546"
	guestsSID := custodyTestSID(t, windows.WinBuiltinGuestsSid)
	check := func(t *testing.T, plugin, trustedOwnerSID, want string) {
		t.Helper()
		err := validatePluginArtifactDestinationFor(plugin, trustedOwnerSID)
		fix, manual := custodyTestRepair(t, err)
		if fix != "" {
			t.Fatalf("fix = %q, want none (the folder is left out of this account's tree):\n%v", fix, err)
		}
		if manual != want {
			t.Fatalf("manual = %q\nwant     %q\n%v", manual, want, err)
		}
	}
	t.Run("target profile entry spelled with a trailing separator", func(t *testing.T) {
		target := custodyTestTargetSID(t)
		profile := custodyTestTargetFolder(t, "dc-gap1917a-", target)
		config, plugin := custodyTestTargetTree(t, profile, target)
		custodyTestGrant(t, config, guestsSID, windows.GENERIC_ALL, windows.NO_INHERITANCE)
		custodyTestProfileEntry(t, target, profile+`\`, false)
		check(t, plugin, target.String(), custodyTestTakeOwnership(guests, config))
	})
	t.Run("target has no profile entry", func(t *testing.T) {
		target := custodyTestTargetSID(t)
		config, plugin := custodyTestTargetTree(t, custodyTestTargetFolder(t, "dc-gap1917b-", target), target)
		custodyTestGrant(t, config, guestsSID, windows.GENERIC_ALL, windows.NO_INHERITANCE)
		check(t, plugin, target.String(), custodyTestTakeOwnership(guests, config))
	})
	t.Run("target profile folder is a junction", func(t *testing.T) {
		target := custodyTestTargetSID(t)
		profile := custodyTestTargetFolder(t, "dc-gap1917c-", target)
		config, plugin := custodyTestTargetTree(t, profile, target)
		custodyTestGrant(t, config, guestsSID, windows.GENERIC_ALL, windows.NO_INHERITANCE)
		redirected := profile + "-link"
		if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", redirected, profile).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v\n%s", err, out)
		}
		t.Cleanup(func() { _ = os.Remove(redirected) })
		custodyTestProfileEntry(t, target, redirected, false)
		check(t, plugin, target.String(), custodyTestTakeOwnership(guests, config))
	})
	t.Run("target entry inherited from a folder left out", func(t *testing.T) {
		target := custodyTestTargetSID(t)
		profile := custodyTestTargetFolder(t, "dc-gap1917d-", target)
		config, plugin := custodyTestTargetTree(t, profile, target)
		custodyTestGrant(t, config, guestsSID, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
		// Full control is a replace entry, refused wherever it is inherited:
		// opencode first, then the plugin folder (one step for both).
		custodyTestProfileEntry(t, target, profile+`\`, false)
		check(t, plugin, target.String(), custodyTestTakeOwnership(guests, config)+"; "+
			custodyTestTakeOwnershipInherited(guests, filepath.Join(config, "opencode"), config))
	})
	t.Run("own profile reached through a subst drive", func(t *testing.T) {
		config, _, _ := custodyTestTree(t)
		custodyTestOwner(t, config, custodyTestSID(t, windows.WinBuiltinAdministratorsSid))
		custodyTestGrant(t, config, guestsSID, windows.GENERIC_ALL, windows.NO_INHERITANCE)
		root := custodyTestSubst(t, filepath.Dir(config))
		substConfig := filepath.Join(root, ".config")
		check(t, filepath.Join(substConfig, "opencode", "plugins", "defenseclaw.js"), "", custodyTestTakeOwnership(guests, substConfig))
	})
}

// The junction check of windowsCustodyOwnElement: a folder Administrators
// owns is the account's own only when reached from the profile through plain
// folders. Below a junction in the profile that leads to a shared folder it is
// not, whatever its name says; the same folder spelled plainly is.
func TestGAP1916AdministratorsOwnedFolderBehindAJunctionInTheProfileIsNotOwn(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("giving a folder to Administrators needs an elevated token; run elevated")
	}
	administrators := custodyTestSID(t, windows.WinBuiltinAdministratorsSid)
	profile := testenv.PrivateTempDir(t)
	plain := filepath.Join(profile, "plain")
	windowsDir, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := os.MkdirTemp(filepath.VolumeName(windowsDir)+`\`, "dc-gap1916j-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shared) })
	inner := filepath.Join(shared, "inner")
	for _, dir := range []string{plain, inner} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		custodyTestOwner(t, dir, administrators)
	}
	link := filepath.Join(profile, "link")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, shared).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if !windowsCustodyOwnElement(plain, nil, profile) {
		t.Fatalf("%s (Administrators-owned, plainly below %s) is not the account's own", plain, profile)
	}
	if through := filepath.Join(link, "inner"); windowsCustodyOwnElement(through, nil, profile) {
		t.Fatalf("%s (Administrators-owned, reached through a junction in %s) is the account's own", through, profile)
	}
}
