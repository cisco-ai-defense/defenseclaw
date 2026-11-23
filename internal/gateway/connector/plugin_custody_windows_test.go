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

// GAP-0731: the refusal of a Windows plugin folder DACL carries the printed
// repair for every refused account; the rendering rows are in
// TestGAP0731IcaclsRemovalFix.
func TestGAP0731RefusalNamesTheCarrierAndTheIcaclsCommand(t *testing.T) {
	// The carrier is a real folder of this account's own tree: a command never
	// names one outside it (GAP-1899, TestGAP1899SafefileCarrierOutsideTheUserTreeGetsNoCommand).
	_, opencode, plugin := custodyTestTree(t)
	cause := &safefile.UnsafePrivateDACLError{
		Path: filepath.Dir(plugin),
		Entries: []safefile.UnsafeDACLEntry{
			{Trustee: `HOST\other`, Carriers: []string{opencode}},
			{Trustee: `HOST\third`, Carriers: []string{opencode}},
		},
	}
	err := explainPluginArtifactRefusal(plugin, "", cause)
	if !errors.Is(err, ErrPluginFolderCustody) || !errors.Is(err, cause) {
		t.Fatalf("err=%v", err)
	}
	want := `fix: icacls ` + managed.PowerShellLiteral(opencode) + ` /remove:g 'HOST\other'; icacls ` + managed.PowerShellLiteral(opencode) + ` /remove:g 'HOST\third'`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("message lacks %q:\n%v", want, err)
	}

	// Benign twins: a refusal naming no single entry, one naming an entry whose
	// folder cannot be found (a repair that leaves it would mislead), and any
	// other cause, are returned as they were.
	for _, other := range []error{
		&safefile.UnsafePrivateDACLError{Path: cause.Path},
		&safefile.UnsafePrivateDACLError{Path: cause.Path, Entries: []safefile.UnsafeDACLEntry{
			{Trustee: `HOST\other`, Carriers: []string{`C:\Users\lane\.config\opencode`}},
			{Trustee: `HOST\third`},
		}},
		errors.New("plugin target must be a regular file"),
	} {
		if got := explainPluginArtifactRefusal("", "", other); got != other {
			t.Fatalf("changed an unrelated refusal: %v", got)
		}
	}
}

// An existing plugin file with a foreign write entry is refused with the same
// explained fix as its folder (review 1 of GAP-0731).
func TestGAP0731PluginFileWithAForeignWriteEntryNamesTheIcaclsCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins")
	if _, err := safefile.CreatePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(dir, "defenseclaw.js")
	if err := os.WriteFile(plugin, []byte("// managed plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createOpenCodePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin file was refused: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(plugin, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(plugin, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	err = createOpenCodePluginArtifactDestination(plugin)
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("err=%v, want a custody refusal with a fix", err)
	}
	if !strings.Contains(err.Error(), `icacls `+managed.PowerShellLiteral(plugin)+` /remove:g 'Everyone'`) {
		t.Fatalf("refusal lacks the icacls command for the plugin file:\n%v", err)
	}
}

// GAP-1887: a write entry of another account on a folder above the plugin
// folder is a custody refusal, so Setup stops only this connector, and the
// refusal names the folder and the icacls command for that account.
func TestGAP1887PluginFolderAncestorWriteEntryIsACustodyRefusal(t *testing.T) {
	config := testenv.PrivateTempDir(t)
	dir := filepath.Join(config, "plugins")
	if _, err := safefile.CreatePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(dir, "defenseclaw.js")
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin folder was refused: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(config, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(config, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	err = validatePluginArtifactDestination(plugin)
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) || !PluginFolderRefusedBeforeChange(err) {
		t.Fatalf("err=%v, want a custody refusal before any change", err)
	}
	if want := `icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-1-0'`; !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal lacks %s:\n%v", want, err)
	}
	if !strings.Contains(err.Error(), "untrusted Windows principal S-1-1-0 has write-like access mask") {
		t.Fatalf("refusal lost the principal text the enterprise parsers read:\n%v", err)
	}
}

// custodyTestGrant adds an allow entry of sid with mask and inheritance to the
// DACL of path, keeping the entries it has.
func custodyTestGrant(t *testing.T, path string, sid *windows.SID, mask windows.ACCESS_MASK, inheritance uint32) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func custodyTestSID(t *testing.T, kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// custodyTestTree is <private temp>\.config\opencode\plugins\defenseclaw.js as
// a user has it: .config and opencode are ordinary folders that inherit, and
// the plugin folder is the private one Setup creates.
func custodyTestTree(t *testing.T) (config, opencode, plugin string) {
	t.Helper()
	config = filepath.Join(testenv.PrivateTempDir(t), ".config")
	opencode = filepath.Join(config, "opencode")
	for _, dir := range []string{config, opencode} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := safefile.CreatePrivateDirectory(filepath.Join(opencode, "plugins")); err != nil {
		t.Fatal(err)
	}
	plugin = filepath.Join(opencode, "plugins", "defenseclaw.js")
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin folder was refused: %v", err)
	}
	return config, opencode, plugin
}

// custodyTestRepair is the refusal's repair; err must be the custody refusal
// raised before any change, so OpenCode stays stopped and only it.
func custodyTestRepair(t *testing.T, err error) (fix, manual string) {
	t.Helper()
	var repaired RepairedRefusal
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) || !PluginFolderRefusedBeforeChange(err) || !errors.As(err, &repaired) {
		t.Fatalf("err=%v, want a custody refusal before any change", err)
	}
	return repaired.Repair()
}

// custodyTestRunFix runs the printed command as a user would paste it.
func custodyTestRunFix(t *testing.T, fix string) {
	t.Helper()
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fix).CombinedOutput()
	if err != nil {
		t.Fatalf("the printed fix failed: %v\n%s", err, out)
	}
}

// GAP-1889: an entry the plugin folder chain inherits is removed at the folder
// that grants it. Removing it from the folder that only inherits it (where the
// walk met it) does nothing, so that command is never printed, and the printed
// one clears the refusal.
func TestGAP1889InheritedWriteEntryIsRemovedWhereItIsGranted(t *testing.T) {
	config, opencode, plugin := custodyTestTree(t)
	custodyTestGrant(t, config, custodyTestSID(t, windows.WinWorldSid),
		windows.ACCESS_MASK(0x1301bf), windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) // Everyone:(OI)(CI)M
	err := validatePluginArtifactDestination(plugin)
	fix, _ := custodyTestRepair(t, err)
	if !strings.Contains(err.Error(), "untrusted Windows principal S-1-1-0 has write-like access mask") {
		t.Fatalf("refusal lost the principal text the enterprise parsers read:\n%v", err)
	}
	if want := `icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-1-0'`; !strings.Contains(fix, want) {
		t.Fatalf("fix lacks %s:\n%v", want, err)
	}
	if bad := `icacls ` + managed.PowerShellLiteral(opencode) + ` `; strings.Contains(fix, bad) {
		t.Fatalf("fix removes the entry where it is only inherited (does nothing):\n%v", err)
	}
	custodyTestRunFix(t, fix)
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("the printed fix left the refusal in place: %v", err)
	}
}

// GAP-1889: every refused account at every folder is named, not only the
// first one the walk met, and the one printed command clears them all.
func TestGAP1889EveryRefusedAccountAndFolderIsNamed(t *testing.T) {
	config, opencode, plugin := custodyTestTree(t)
	custodyTestGrant(t, config, custodyTestSID(t, windows.WinWorldSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	custodyTestGrant(t, opencode, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	err := validatePluginArtifactDestination(plugin)
	fix, _ := custodyTestRepair(t, err)
	for _, want := range []string{
		`icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-1-0'`,
		`icacls ` + managed.PowerShellLiteral(opencode) + ` /remove:g '*S-1-5-32-546'`,
	} {
		if !strings.Contains(fix, want) {
			t.Fatalf("fix lacks %s:\n%v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "every folder or file to fix, outermost first: "+pluginCustodyQuote(config)+", "+pluginCustodyQuote(opencode)) {
		t.Fatalf("refusal does not list both folders:\n%v", err)
	}
	custodyTestRunFix(t, fix)
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("the printed fix left the refusal in place: %v", err)
	}
}

// GAP-1888: a junction above the plugin folder is a custody refusal of this
// connector only, with a step by hand (no permission change clears it); a
// write entry above the junction still gets its command.
func TestGAP1888JunctionAboveThePluginFolderIsACustodyRefusal(t *testing.T) {
	config := filepath.Join(testenv.PrivateTempDir(t), ".config")
	real := filepath.Join(config, "real")
	for _, dir := range []string{config, real} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	opencode := filepath.Join(config, "opencode")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", opencode, real).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
	if _, err := safefile.CreatePrivateDirectory(filepath.Join(real, "plugins")); err != nil {
		t.Fatal(err)
	}
	custodyTestGrant(t, config, custodyTestSID(t, windows.WinWorldSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	err := validatePluginArtifactDestination(filepath.Join(opencode, "plugins", "defenseclaw.js"))
	fix, manual := custodyTestRepair(t, err)
	if !strings.Contains(err.Error(), "symlinks, junctions, and reparse points are not allowed") {
		t.Fatalf("refusal lost its cause:\n%v", err)
	}
	if want := "replace " + pluginCustodyQuote(opencode) + " with a real folder"; !strings.Contains(manual, want) {
		t.Fatalf("manual step lacks %q:\n%v", want, err)
	}
	if want := `icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-1-0'`; fix != want {
		t.Fatalf("fix = %q, want %q:\n%v", fix, want, err)
	}
}

// GAP-1888: a plugin folder with no DACL (every account may write) is a
// custody refusal of this connector only, with a step by hand.
func TestGAP1888NullDACLOnThePluginFolderIsACustodyRefusal(t *testing.T) {
	_, opencode, plugin := custodyTestTree(t)
	plugins := filepath.Join(opencode, "plugins")
	if err := windows.SetNamedSecurityInfo(plugins, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	err := validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if !strings.Contains(err.Error(), "null Windows DACL is not trusted") {
		t.Fatalf("refusal lost its cause:\n%v", err)
	}
	if want := "give " + pluginCustodyQuote(plugins) + " an access list"; fix != "" || !strings.Contains(manual, want) {
		t.Fatalf("fix=%q manual=%q, want no command and %q", fix, manual, want)
	}
}

// GAP-1888: a folder above the plugin folder owned by another account is a
// custody refusal of this connector only, with a step by hand. Giving a
// folder to another account needs the restore privilege: run elevated.
func TestGAP1888ForeignOwnerAboveThePluginFolderIsACustodyRefusal(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("giving a folder to another account needs the restore privilege; run elevated")
	}
	_, opencode, plugin := custodyTestTree(t)
	guests := custodyTestSID(t, windows.WinBuiltinGuestsSid)
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(opencode, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, guests, nil, nil, nil)
	}); err != nil {
		t.Fatal(err)
	}
	err := validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if !strings.Contains(err.Error(), "owner S-1-5-32-546 is not trusted for hook API token path") {
		t.Fatalf("refusal lost its cause:\n%v", err)
	}
	if want := "have an administrator give " + pluginCustodyQuote(opencode) + " back to this account"; fix != "" || !strings.Contains(manual, want) {
		t.Fatalf("fix=%q manual=%q, want no command and %q", fix, manual, want)
	}
}
