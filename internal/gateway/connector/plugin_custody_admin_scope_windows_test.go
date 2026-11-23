// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

// custodyTestOwner gives path to owner (an elevated administrator may give a
// folder to Administrators or to itself).
func custodyTestOwner(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}); err != nil {
		t.Fatalf("give %s to %s: %v", path, owner, err)
	}
}

// custodyTestFullControl is an inheritable full-control entry for sid.
func custodyTestFullControl(sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(0x1f01ff), // FILE_ALL_ACCESS
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// GAP-1910: an elevated run does not take every folder Administrators owns
// for this account's own. One outside this account's profile folder is shared
// by every administrator (another administrator's C:\src, an installer's or a
// vendor's ProgramData folder): an entry granted there gets a step by hand and
// no command, which would change the access of every account below it. An
// entry granted at this account's own folder below it keeps its command.
func TestGAP1910AdministratorsOwnedFolderOutsideTheProfileGetsNoCommand(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("making a folder at the drive root and giving it to Administrators need an elevated token; run elevated")
	}
	windowsDir, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := os.MkdirTemp(filepath.VolumeName(windowsDir)+`\`, "dc-gap1910-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shared) })
	profile, err := windows.GetCurrentProcessToken().GetUserProfileDirectory()
	if err != nil || strings.HasPrefix(strings.ToLower(shared), strings.ToLower(filepath.Clean(profile))+`\`) {
		t.Fatalf("profile %q (%v): the shared folder %s must be outside it", profile, err, shared)
	}
	administrators := custodyTestSID(t, windows.WinBuiltinAdministratorsSid)
	user, err := windowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	// A folder only Administrators, SYSTEM and this administrator can change,
	// owned by Administrators, as an elevated administrator makes C:\src.
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		custodyTestFullControl(administrators),
		custodyTestFullControl(custodyTestSID(t, windows.WinLocalSystemSid)),
		custodyTestFullControl(user),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(shared, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		administrators, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(shared, "cfg")
	opencode := filepath.Join(cfg, "opencode")
	for _, dir := range []string{cfg, opencode} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	custodyTestOwner(t, cfg, user)
	custodyTestOwner(t, opencode, administrators)
	if _, err := safefile.CreatePrivateDirectory(filepath.Join(opencode, "plugins")); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(opencode, "plugins", "defenseclaw.js")
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin folder below %s was refused: %v", shared, err)
	}
	custodyTestGrant(t, shared, custodyTestSID(t, windows.WinWorldSid),
		windows.ACCESS_MASK(0x1301bf), windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) // Everyone:(OI)(CI)M
	custodyTestGrant(t, cfg, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	err = validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if bad := managed.PowerShellLiteral(shared); strings.Contains(fix, bad) {
		t.Fatalf("fix names the Administrators-owned shared folder %s:\n%v", bad, err)
	}
	if want := `icacls ` + managed.PowerShellLiteral(cfg) + ` /remove:g '*S-1-5-32-546'`; fix != want {
		t.Fatalf("fix = %q, want %q (the entry granted at this account's own folder keeps its command):\n%v", fix, want, err)
	}
	if want := "is granted at " + pluginCustodyQuote(shared) + ", outside the folders this account owns"; !strings.Contains(manual, want) {
		t.Fatalf("manual step lacks %q:\n%v", want, err)
	}
}

// custodyTestChildEnv names the Administrators-owned folder the filtered-token
// child of TestGAP1911 judges.
const custodyTestChildEnv = "DEFENSECLAW_TEST_GAP1911_FOLDER"

// GAP-1911: a folder in this account's own profile that an elevated run made
// (so Administrators owns it) keeps its command when the next run is not
// elevated, as rel's repair printed it: the profile gives this account full
// control of it, and the command works without elevation. The elevated part
// makes the folder; the same account then judges it with a filtered token (no
// privileges, Administrators deny-only), as a normal run of a UAC
// administrator does. A standard account cannot give a folder to
// Administrators, so the test cannot run Limited.
func TestGAP1911AdministratorsOwnedFolderInTheProfileKeepsItsCommandWhenNotElevated(t *testing.T) {
	if config := os.Getenv(custodyTestChildEnv); config != "" {
		custodyTestGAP1911NotElevated(t, config)
		return
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("giving a folder to Administrators needs an elevated token; run elevated (the judgement itself runs in a filtered-token child)")
	}
	config, _, plugin := custodyTestTree(t)
	custodyTestOwner(t, config, custodyTestSID(t, windows.WinBuiltinAdministratorsSid))
	custodyTestGrant(t, config, custodyTestSID(t, windows.WinBuiltinGuestsSid), windows.GENERIC_ALL, windows.NO_INHERITANCE)
	want := `icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-5-32-546'`
	err := validatePluginArtifactDestination(plugin)
	if fix, _ := custodyTestRepair(t, err); fix != want {
		t.Fatalf("elevated: fix = %q, want %q:\n%v", fix, want, err)
	}

	// The same account, not elevated: a copy of this test binary in a folder
	// the filtered token can read.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(testenv.PrivateTempDir(t), "gap1911.test.exe")
	custodyTestCopyFile(t, self, child)
	token, err := custodyTestFilteredToken()
	if err != nil {
		t.Fatalf("filtered token: %v", err)
	}
	defer token.Close() //nolint:errcheck
	cmd := exec.Command(child, "-test.run=^TestGAP1911AdministratorsOwnedFolderInTheProfileKeepsItsCommandWhenNotElevated$", "-test.count=1", "-test.timeout=5m")
	cmd.Dir = filepath.Dir(child)
	cmd.Env = append(os.Environ(), custodyTestChildEnv+"="+config)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "GAP1911_CHILD_OK") {
		// The child's test lines are re-spelled so they are not read as this
		// run's own test events.
		text := strings.NewReplacer("--- ", "-- ", "=== ", "== ").Replace(string(out))
		t.Fatalf("not elevated (filtered-token child): %v\n%s", err, text)
	}
}

// custodyTestGAP1911NotElevated is the filtered-token child's judgement.
func custodyTestGAP1911NotElevated(t *testing.T, config string) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("the child runs elevated; want the filtered token of a normal run")
	}
	plugin := filepath.Join(config, "opencode", "plugins", "defenseclaw.js")
	want := `icacls ` + managed.PowerShellLiteral(config) + ` /remove:g '*S-1-5-32-546'`
	err := validatePluginArtifactDestination(plugin)
	fix, manual := custodyTestRepair(t, err)
	if fix != want {
		t.Fatalf("not elevated: fix = %q, want %q (the folder is in this account's own profile; rel printed the command)\nmanual: %s\n%v", fix, want, manual, err)
	}
	// rel's safefile repair: the entry is removed at the folder that carries it.
	cause := &safefile.UnsafePrivateDACLError{
		Path:    filepath.Dir(plugin),
		Entries: []safefile.UnsafeDACLEntry{{Trustee: `HOST\other`, Carriers: []string{config}}},
	}
	var repaired RepairedRefusal
	if explained := explainPluginArtifactRefusal(plugin, "", cause); !errors.As(explained, &repaired) {
		t.Fatalf("not elevated: safefile refusal not explained: %v", explained)
	}
	if fix, _ := repaired.Repair(); fix != `icacls `+managed.PowerShellLiteral(config)+` /remove:g 'HOST\other'` {
		t.Fatalf("not elevated: safefile fix = %q", fix)
	}
	// The printed command works without elevation and clears the refusal.
	custodyTestRunFix(t, want)
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("not elevated: still refused after the printed fix: %v", err)
	}
	fmt.Println("GAP1911_CHILD_OK")
}

// custodyTestCopyFile copies src to dst.
func custodyTestCopyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// custodyTestTokenDefaultDACL is TOKEN_DEFAULT_DACL.
type custodyTestTokenDefaultDACL struct {
	DefaultDacl *windows.ACL
}

// custodyTestFilteredToken is this process's primary token with every
// privilege but SeChangeNotify removed and Administrators deny-only, as a UAC
// administrator's normal run has it (LUA_TOKEN when Windows grants it). It is
// a restricted copy of this process's own token, which CreateProcessAsUser
// takes without further privilege. Its default DACL grants this account and
// SYSTEM, as a filtered UAC token's does: the elevated token's grants
// Administrators, which is deny-only here, so the child could not open the
// pipes and processes it creates.
func custodyTestFilteredToken() (windows.Token, error) {
	var process windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY |
		windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &process); err != nil {
		return 0, err
	}
	defer process.Close() //nolint:errcheck
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	disable := []windows.SIDAndAttributes{{Sid: administrators}}
	procedure := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	if err := procedure.Find(); err != nil {
		return 0, err
	}
	const disableMaxPrivilege, luaToken = 0x1, 0x4
	var lastErr error
	for _, flags := range []uintptr{disableMaxPrivilege | luaToken, disableMaxPrivilege} {
		var restricted windows.Token
		ok, _, callErr := procedure.Call(uintptr(process), flags,
			uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])),
			0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
		runtime.KeepAlive(disable)
		if ok != 0 {
			if err := custodyTestSetDefaultDACL(process, restricted); err != nil {
				_ = restricted.Close()
				return 0, err
			}
			return restricted, nil
		}
		lastErr = callErr
	}
	return 0, lastErr
}

// custodyTestSetDefaultDACL gives token a default DACL of full control for
// the user of process and for SYSTEM.
func custodyTestSetDefaultDACL(process, token windows.Token) error {
	user, err := process.GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	grant := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{grant(user.User.Sid), grant(system)}, nil)
	if err != nil {
		return err
	}
	dacl := custodyTestTokenDefaultDACL{DefaultDacl: acl}
	if err := windows.SetTokenInformation(token, windows.TokenDefaultDacl,
		(*byte)(unsafe.Pointer(&dacl)), uint32(unsafe.Sizeof(dacl))); err != nil {
		return fmt.Errorf("set the filtered token's default DACL: %w", err)
	}
	runtime.KeepAlive(acl)
	return nil
}
