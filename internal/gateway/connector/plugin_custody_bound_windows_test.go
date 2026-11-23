// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

// custodyTestSubst maps a free drive letter to dir for this logon session
// (subst needs no privilege) and returns its root, X:\, a real volume root.
func custodyTestSubst(t *testing.T, dir string) string {
	t.Helper()
	used, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}
	for letter := 'Z'; letter >= 'M'; letter-- {
		if used&(1<<uint(letter-'A')) != 0 {
			continue
		}
		drive := string(letter) + ":"
		if out, err := exec.Command("subst.exe", drive, dir).CombinedOutput(); err != nil {
			t.Logf("subst %s: %v %s", drive, err, out)
			continue
		}
		t.Cleanup(func() { _ = exec.Command("subst.exe", drive, "/d").Run() })
		return drive + `\`
	}
	t.Fatal("no free drive letter for subst")
	return ""
}

// GAP-1899: an entry granted at a drive root is never removed there by the
// printed command (icacls on X:\ changes every folder of the drive that
// inherits from it). The plugin chain X:\cfg\opencode\plugins inherits
// Everyone:(OI)(CI)M from the root, as C:\cfg inherits Authenticated Users
// from a stock client C:\. The root here is a subst drive over a folder this
// account owns, so only the volume-root rule keeps the command off it.
func TestGAP1899EntryCarriedByADriveRootGetsNoCommand(t *testing.T) {
	root := custodyTestSubst(t, testenv.PrivateTempDir(t))
	cfg := filepath.Join(root, "cfg")
	opencode := filepath.Join(cfg, "opencode")
	for _, dir := range []string{cfg, opencode} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := safefile.CreatePrivateDirectory(filepath.Join(opencode, "plugins")); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(opencode, "plugins", "defenseclaw.js")
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin folder on %s was refused: %v", root, err)
	}
	custodyTestGrant(t, root, custodyTestSID(t, windows.WinWorldSid),
		windows.ACCESS_MASK(0x1301bf), windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) // Everyone:(OI)(CI)M
	err := validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if !strings.Contains(err.Error(), "untrusted Windows principal S-1-1-0 has write-like access mask") {
		t.Fatalf("refusal lost the principal text the enterprise parsers read:\n%v", err)
	}
	if bad := managed.PowerShellLiteral(root); strings.Contains(fix, bad) {
		t.Fatalf("fix names the drive root %s:\n%v", bad, err)
	}
	if fix != "" {
		t.Fatalf("fix = %q, want no command (the entry is granted only at the root):\n%v", fix, err)
	}
	if want := "is granted at " + pluginCustodyQuote(root) + ", outside the folders this account owns"; !strings.Contains(manual, want) {
		t.Fatalf("manual step lacks %q:\n%v", want, err)
	}
}

// GAP-1899: an entry carried by a parent an installer owns (TrustedInstaller,
// as under Program Files) gets a step by hand, never a command on that parent,
// while an entry granted at a folder of this account's tree below it keeps its
// command (the bound is per folder, not a blanket stop). Giving a folder to
// TrustedInstaller needs the restore privilege: run elevated.
func TestGAP1899EntryCarriedByAnInstallerOwnedParentGetsNoCommand(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("giving a folder to TrustedInstaller needs the restore privilege; run elevated")
	}
	installer := filepath.Join(testenv.PrivateTempDir(t), "vendor")
	cfg := filepath.Join(installer, "cfg")
	opencode := filepath.Join(cfg, "opencode")
	for _, dir := range []string{installer, cfg, opencode} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := safefile.CreatePrivateDirectory(filepath.Join(opencode, "plugins")); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(opencode, "plugins", "defenseclaw.js")
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin folder was refused: %v", err)
	}
	custodyTestGrant(t, installer, custodyTestSID(t, windows.WinWorldSid),
		windows.ACCESS_MASK(0x1301bf), windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) // Everyone:(OI)(CI)M
	custodyTestGrant(t, cfg, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(installer, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, trustedInstaller, nil, nil, nil)
	}); err != nil {
		t.Fatal(err)
	}
	err = validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if bad := managed.PowerShellLiteral(installer); strings.Contains(fix, bad) {
		t.Fatalf("fix names the installer-owned folder %s:\n%v", bad, err)
	}
	if want := `icacls ` + managed.PowerShellLiteral(cfg) + ` /remove:g '*S-1-5-32-546'`; fix != want {
		t.Fatalf("fix = %q, want %q (the entry granted in this account's tree keeps its command):\n%v", fix, want, err)
	}
	if want := "is granted at " + pluginCustodyQuote(installer) + ", outside the folders this account owns"; !strings.Contains(manual, want) {
		t.Fatalf("manual step lacks %q:\n%v", want, err)
	}
}

// GAP-1899: a safefile refusal whose entry is carried by a drive root or the
// Windows folder prints no command for that entry and a step by hand naming
// the folder; an entry carried by this account's own folder keeps its command.
func TestGAP1899SafefileCarrierOutsideTheUserTreeGetsNoCommand(t *testing.T) {
	config, opencode, plugin := custodyTestTree(t)
	volume := filepath.VolumeName(opencode) + `\`
	system, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	cause := &safefile.UnsafePrivateDACLError{
		Path: filepath.Dir(plugin),
		Entries: []safefile.UnsafeDACLEntry{
			{Trustee: `NT AUTHORITY\Authenticated Users`, Carriers: []string{volume, config}},
			{Trustee: `HOST\other`, Carriers: []string{opencode}},
			{Trustee: `HOST\third`, Carriers: []string{system}},
		},
	}
	err = explainPluginArtifactRefusal(plugin, "", cause)
	var repaired RepairedRefusal
	if !errors.Is(err, ErrPluginFolderCustody) || !errors.Is(err, cause) || !errors.As(err, &repaired) {
		t.Fatalf("err=%v", err)
	}
	fix, manual := repaired.Repair()
	if want := `icacls ` + managed.PowerShellLiteral(opencode) + ` /remove:g 'HOST\other'`; fix != want {
		t.Fatalf("fix = %q, want %q:\n%v", fix, want, err)
	}
	for _, outside := range []string{volume, system} {
		if !strings.Contains(manual, pluginCustodyQuote(outside)) {
			t.Fatalf("manual step does not name %s:\n%v", outside, err)
		}
	}
	if !strings.Contains(manual, `NT AUTHORITY\Authenticated Users`) || !strings.Contains(manual, `HOST\third`) {
		t.Fatalf("manual step does not name both accounts:\n%v", err)
	}
}

// custodyTestNullDACL gives path a null DACL through a handle, which does not
// propagate to the children (SetNamedSecurityInfo would re-stamp them).
func custodyTestNullDACL(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.WRITE_DAC|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Back to an inherited DACL so the temp tree can be removed.
		_ = exec.Command("icacls.exe", path, "/reset").Run()
	})
}

// GAP-1900: a null DACL on a folder this account owns above the plugin folder
// and above the hook API token directory is the widest grant there is, so both
// walks refuse it as they refuse Everyone full control there; owner-based drift
// acceptance does not cover it. A grant that cannot replace anything (write
// data, no DELETE, WRITE_DAC or WRITE_OWNER) on the same folder is still
// accepted and logged: no over-tightening.
func TestGAP1900NullDACLOnAUserOwnedAncestorIsRefusedLikeEveryoneFull(t *testing.T) {
	config, opencode, plugin := custodyTestTree(t)
	hooks := filepath.Join(opencode, "hooks")
	if _, err := safefile.CreatePrivateDirectory(hooks); err != nil {
		t.Fatal(err)
	}
	if err := hookAPIValidateDirectory(hooks); err != nil {
		t.Fatalf("a private hook API folder was refused: %v", err)
	}

	// The control first: a non-replace grant of another account on .config.
	custodyTestGrant(t, config, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.FILE_GENERIC_WRITE, windows.NO_INHERITANCE)
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a non-replace grant on a user-owned ancestor was refused (over-tightened): %v", err)
	}
	if err := hookAPIValidateDirectory(hooks); err != nil {
		t.Fatalf("a non-replace grant on a user-owned ancestor of the hook API folder was refused (over-tightened): %v", err)
	}

	custodyTestNullDACL(t, config)
	err := validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if !strings.Contains(err.Error(), "null Windows DACL is not trusted: "+config) {
		t.Fatalf("refusal lost its cause:\n%v", err)
	}
	if want := "give " + pluginCustodyQuote(config) + " an access list"; fix != "" || !strings.Contains(manual, want) {
		t.Fatalf("fix=%q manual=%q, want no command and %q", fix, manual, want)
	}
	for name, walk := range map[string]func() error{
		"hook API token folder walk": func() error { return hookAPIValidateDirectory(hooks) },
		"user config folder walk":    func() error { return hookAPIValidateUserConfigDirectory(opencode, false) },
	} {
		if err := walk(); err == nil || !strings.Contains(err.Error(), "null Windows DACL is not trusted: "+config) {
			t.Fatalf("%s: err=%v, want the null DACL on %s refused", name, err, config)
		}
	}
}
