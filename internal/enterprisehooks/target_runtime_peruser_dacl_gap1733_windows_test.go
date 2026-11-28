//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// gap1733SystemChildEnv marks the LocalSystem run of
// TestGAP1733PerUserInstallFoldersWithTheirOwnDACLAreSkipped that the
// elevated run starts.
const gap1733SystemChildEnv = "DEFENSECLAW_TEST_GAP1733_LOCALSYSTEM_CHILD"

// gap1733PerUserRootSDDL is the DACL a per-user 1.0.10 install puts on
// %USERPROFILE%\.defenseclaw (seen on every per-user account of the test
// hosts): the owner and LocalSystem, protected, nothing for Administrators.
const gap1733PerUserRootSDDL = "D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"

// TestGAP1733PerUserInstallFoldersWithTheirOwnDACLAreSkipped: two accounts
// keep a per-user 1.0.10 install, each folder owned by its account with the
// per-user DACL (owner and LocalSystem only). That DACL is also the
// guardian's setup shape, so the Upgrade/Repair plan read each folder as a
// stale setup relax and re-stamped it with the managed DACL, and the account
// was enrolled (dc-win2, TST-11648). Run as an elevated Administrator and as
// LocalSystem (the test starts itself as LocalSystem), the preflight and the
// install plan skip both users and name them, a third fresh account is still
// enrolled, the Upgrade/Repair plan refuses the folders, the guardian's
// pending proof for the signed-out accounts refuses them instead of
// repairing them (as LocalSystem it re-stamped both roots on dc-ent-win,
// TST-11800), and no owner, DACL or file changes.
func TestGAP1733PerUserInstallFoldersWithTheirOwnDACLAreSkipped(t *testing.T) {
	system := windowsTestRunsAsLocalSystem(t)
	if os.Getenv(gap1733SystemChildEnv) == "1" && !system {
		t.Fatal("the LocalSystem run does not run as LocalSystem")
	}
	if !system && !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated Administrator, which also starts the LocalSystem run")
	}
	leg := "elevated Administrator"
	if system {
		leg = "LocalSystem"
	}
	t.Run(leg, runGAP1733PerUserInstallLeg)
	if system {
		return
	}
	t.Run("LocalSystem", runGAP1733AsLocalSystem)
}

func runGAP1733PerUserInstallLeg(t *testing.T) {
	previousStandalone := windowsEnterpriseStandaloneProcess
	previousStale, previousWait := windowsSetupRelaxIsStale, windowsManagedRuntimeSetupRelaxWait
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsSetupRelaxIsStale, windowsManagedRuntimeSetupRelaxWait = previousStale, previousWait
	})
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	// No guardian setup runs: an owner-private DACL reads as a stale setup.
	windowsSetupRelaxIsStale = func(string, *windows.SID) bool { return true }
	windowsManagedRuntimeSetupRelaxWait = 50 * time.Millisecond
	t.Setenv(managed.TrustStrictAncestorsEnv, "")

	domain := fmt.Sprintf("S-1-5-21-1733%06d-%d-%d", os.Getpid()%1000000, time.Now().UnixNano()%1000000000, 1733)
	first := newGAP1733PerUserAccount(t, domain+"-1001")
	second := newGAP1733PerUserAccount(t, domain+"-1002")
	accounts := []gap1733Account{first, second}
	before := map[string]string{}
	for _, account := range accounts {
		for path, state := range gap1733FolderState(t, account) {
			before[path] = state
		}
	}
	unchanged := func(step string) {
		t.Helper()
		for _, account := range accounts {
			for path, state := range gap1733FolderState(t, account) {
				if before[path] != state {
					t.Errorf("%s changed %s:\n before %s\n after  %s", step, path, before[path], state)
				}
			}
		}
	}
	named := func(reason string, account gap1733Account) bool {
		return strings.Contains(reason, account.data) && strings.Contains(reason, "config.yaml") &&
			strings.Contains(reason, "per-user DefenseClaw install")
	}
	manifest := Manifest{Version: 1}
	for _, account := range accounts {
		manifest.Targets = append(manifest.Targets, windowsManagedRuntimeTestManifest(account.home, account.sid).Targets...)
	}
	manifestPath, digest := `C:\ProgramData\DefenseClaw\etc\targets.yaml`, strings.Repeat("7", 64)

	// The first-install preflight would enrol nobody: it refuses, naming
	// the per-user install.
	if err := PreflightWindowsManagedRuntimeRoots(manifest); err == nil || !named(err.Error(), first) {
		t.Errorf("preflight over two per-user install folders = %v, want the refusal naming %s", err, first.data)
	}
	unchanged("the preflight")

	// The install plan skips both users and names each.
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest)
	if err != nil || len(plan.Roots) != 0 || len(plan.RepairedProfiles) != 0 || len(plan.SkippedProfiles) != 2 {
		t.Errorf("install plan over two per-user install folders = roots %d, repaired %d, skipped %+v, %v; want both users skipped",
			len(plan.Roots), len(plan.RepairedProfiles), plan.SkippedProfiles, err)
	}
	for _, account := range accounts {
		found := false
		for _, skipped := range plan.SkippedProfiles {
			found = found || (skipped.SID == account.sid.String() && named(skipped.Reason, account))
		}
		if !found {
			t.Errorf("install plan did not skip %s naming its per-user install: %+v", account.sid, plan.SkippedProfiles)
		}
	}
	unchanged("the install plan")

	// A third, fresh account is still enrolled; the two stay skipped.
	fresh, err := windows.StringToSid(domain + "-1003")
	if err != nil {
		t.Fatal(err)
	}
	freshHome := newWindowsTargetOwnedTestHome(t, fresh)
	mixed := Manifest{Version: 1, Targets: append(append([]ManifestTarget(nil), manifest.Targets...),
		windowsManagedRuntimeTestManifest(freshHome, fresh).Targets...)}
	if err := PreflightWindowsManagedRuntimeRoots(mixed); err != nil {
		t.Errorf("preflight with a fresh third account = %v, want it to pass", err)
	}
	plan, err = PlanWindowsManagedRuntimeRoots(mixed, manifestPath, digest)
	if err != nil || len(plan.Roots) != 1 || plan.Roots[0].SID != fresh.String() || len(plan.SkippedProfiles) != 2 {
		t.Errorf("install plan with a fresh third account = roots %+v, skipped %+v, %v; want only the fresh account planned",
			plan.Roots, plan.SkippedProfiles, err)
	}
	unchanged("the install plan with a fresh account")

	// The Upgrade/Repair plan refuses the folder: its DACL is also the
	// guardian's setup shape, which the plan re-stamps when stale.
	if _, err := PlanWindowsManagedRuntimeRootsForValidation(manifest, manifestPath, digest); err == nil || !named(err.Error(), first) {
		t.Errorf("Upgrade/Repair plan over a per-user install folder = %v, want the refusal naming %s", err, first.data)
	}
	unchanged("the Upgrade/Repair plan")

	// The guardian's pass over the signed-out accounts: standalone writes
	// every discovered row deferred, and the pending proof repaired a
	// folder whose DACL is not the managed one. It refuses each per-user
	// install folder, naming it, before any repair; the status probe names
	// the same entry, and a fresh account is not named.
	for _, account := range accounts {
		for _, row := range windowsManagedRuntimeTestManifest(account.home, account.sid).Targets {
			row.Deferred = true
			if err := requireWindowsEnterpriseDeferredTargetPendingPlatform(row); err == nil || !named(err.Error(), account) {
				t.Errorf("guardian pending proof for %s %s = %v, want the refusal naming its per-user install", row.Connector, account.data, err)
			}
		}
		if finding := WindowsPerUserInstallDataDir(account.home, account.sid.String()); !strings.HasPrefix(finding, "config.yaml") {
			t.Errorf("WindowsPerUserInstallDataDir(%s) = %q, want config.yaml", account.home, finding)
		}
	}
	unchanged("the guardian's signed-out pass")
	if finding := WindowsPerUserInstallDataDir(freshHome, fresh.String()); finding != "" {
		t.Errorf("WindowsPerUserInstallDataDir(fresh account) = %q, want none", finding)
	}
}

type gap1733Account struct {
	sid        *windows.SID
	home, data string
	entries    []string
}

// newGAP1733PerUserAccount builds the folder a per-user 1.0.10 install
// leaves for sid: config, audit database, Python environment, installer
// state and hooks, every entry owned by the account, the root DACL
// gap1733PerUserRootSDDL and every entry inheriting it.
func newGAP1733PerUserAccount(t *testing.T, rawSID string) gap1733Account {
	t.Helper()
	sid, err := windows.StringToSid(rawSID)
	if err != nil {
		t.Fatal(err)
	}
	home := newWindowsTargetOwnedTestHome(t, sid)
	data := filepath.Join(home, ".defenseclaw")
	account := gap1733Account{sid: sid, home: home, data: data}
	files := map[string]string{
		"config.yaml":                                  "gateway:\n  port: 18970\n",
		"audit.db":                                     "SQLite format 3\x00per-user audit",
		filepath.Join(".venv", "pyvenv.cfg"):           "home = C:\\Python\n",
		filepath.Join("installer", "state.json"):       "{\"version\":\"1.0.10\"}\n",
		filepath.Join("hooks", "claude-code-hook.ps1"): "# per-user hook\n",
	}
	for leaf, content := range files {
		path := filepath.Join(data, leaf)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.WalkDir(data, func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			account.entries = append(account.entries, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(gap1733PerUserRootSDDL)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// Owners first, while the test can still reach every entry; then the
	// root DACL, which Windows propagates to every entry as inherited.
	if err := RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
		for _, path := range account.entries {
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
				return fmt.Errorf("own %s: %w", path, err)
			}
		}
		return windows.SetNamedSecurityInfo(data, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}); err != nil {
		t.Fatalf("build the per-user install folder: %v", err)
	}
	t.Cleanup(func() { releaseGAP1733PerUserAccount(t, account) })
	state := gap1733FolderState(t, account)
	if got := state[data]; !strings.Contains(got, "D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)") || !strings.HasPrefix(got, "O:"+sid.String()) {
		t.Fatalf("fixture root is %s, want owner %s and %s", got, sid, gap1733PerUserRootSDDL)
	}
	if got := state[filepath.Join(data, "hooks")]; !strings.Contains(got, "D:AI(A;OICIID;FA;;;OW)(A;OICIID;FA;;;SY)") {
		t.Fatalf("fixture hooks folder is %s, want the inherited per-user DACL", got)
	}
	// The live shape: an elevated Administrator cannot see config.yaml by
	// path, LocalSystem can.
	_, statErr := os.Lstat(filepath.Join(data, "config.yaml"))
	if windowsTestRunsAsLocalSystem(t) {
		if statErr != nil {
			t.Fatalf("LocalSystem cannot see the fixture config.yaml: %v", statErr)
		}
	} else if !errors.Is(statErr, fs.ErrPermission) {
		t.Fatalf("an elevated Administrator looking up the fixture config.yaml got %v, want access denied (the live shape)", statErr)
	}
	return account
}

// gap1733FolderState is the owner, DACL and, for a file, the SHA-256 of
// every fixture entry, read with backup intent.
func gap1733FolderState(t *testing.T, account gap1733Account) map[string]string {
	t.Helper()
	state := make(map[string]string, len(account.entries))
	if err := RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
		for _, path := range account.entries {
			entry, err := gap1733EntryState(path)
			if err != nil {
				return err
			}
			state[path] = entry
		}
		return nil
	}); err != nil {
		t.Fatalf("read the per-user install folder: %v", err)
	}
	return state
}

func gap1733EntryState(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("read the descriptor of %s: %w", path, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return descriptor.String(), nil
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return descriptor.String() + " sha256=" + hex.EncodeToString(digest.Sum(nil)), nil
}

// releaseGAP1733PerUserAccount gives the fixture back to Administrators so
// the test's temporary folder can be removed.
func releaseGAP1733PerUserAccount(t *testing.T, account gap1733Account) {
	t.Helper()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Error(err)
		return
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
	if err != nil {
		t.Error(err)
		return
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Error(err)
		return
	}
	if err := RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
		if err := windows.SetNamedSecurityInfo(account.data, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return err
		}
		for _, path := range account.entries {
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
				administrators, nil, nil, nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Errorf("release the per-user install fixture %s: %v", account.data, err)
	}
}

// runGAP1733AsLocalSystem runs the test again as LocalSystem, with the
// token of the console's winlogon.exe, and requires it to pass. cmd.exe
// writes its output to a file, so the LocalSystem run needs no pipes of this
// one.
func runGAP1733AsLocalSystem(t *testing.T) {
	token, err := gap1733LocalSystemToken()
	if err != nil {
		t.Fatalf("get a LocalSystem token for the LocalSystem run: %v", err)
	}
	defer token.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const name = "TestGAP1733PerUserInstallFoldersWithTheirOwnDACLAreSkipped"
	output := filepath.Join(work, "localsystem.out")
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	// No other test name starts with name, so -test.run needs no anchors
	// (cmd.exe would read ^ as its escape).
	line := windows.EscapeArg(cmdExe) + ` /d /c "` + windows.EscapeArg(exe) + " -test.run=" + name +
		" -test.count=1 -test.v > " + windows.EscapeArg(output) + ` 2>&1"`
	appName, err := windows.UTF16PtrFromString(cmdExe)
	if err != nil {
		t.Fatal(err)
	}
	cmdLine, err := windows.UTF16PtrFromString(line)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := windows.UTF16PtrFromString(work)
	if err != nil {
		t.Fatal(err)
	}
	block, err := windowsEnvironmentBlock(append(os.Environ(), gap1733SystemChildEnv+"=1"))
	if err != nil {
		t.Fatal(err)
	}
	// The interactive window station: LocalSystem may open it, while the
	// caller's own one (a batch logon's) refuses that token, and user32
	// then fails to initialize in the LocalSystem run.
	desktop, err := windows.UTF16PtrFromString(`WinSta0\Default`)
	if err != nil {
		t.Fatal(err)
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var info windows.ProcessInformation
	if err := withWindowsImpersonatePrivilege(func() error {
		return createWindowsProcessWithToken(token, 0, appName, cmdLine,
			windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT, block, dir, &startup, &info)
	}); err != nil {
		t.Fatalf("start the LocalSystem run: %v", err)
	}
	defer windows.CloseHandle(info.Process)
	windows.CloseHandle(info.Thread)
	if event, err := windows.WaitForSingleObject(info.Process, uint32((5 * time.Minute).Milliseconds())); err != nil || event != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(info.Process, 1)
		t.Fatalf("the LocalSystem run did not finish in 5 minutes (%d, %v)", event, err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.Process, &code); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read the LocalSystem run's output (exit %d): %v", code, err)
	}
	out := string(data)
	passed := strings.Contains(out, "--- PASS: "+name+"/LocalSystem ") && strings.Contains(out, "--- PASS: "+name+" ")
	if code != 0 || !passed || strings.Contains(out, "--- SKIP") {
		// Quoted so the run's own result lines are not read as this one's.
		var quoted strings.Builder
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			quoted.WriteString("system| " + strings.TrimRight(line, "\r") + "\n")
		}
		t.Fatalf("the LocalSystem run exited %d, passed=%v:\n%s", code, passed, quoted.String())
	}
	t.Logf("the LocalSystem run passed (exit %d, %d bytes of output)", code, len(data))
}

// gap1733LocalSystemToken duplicates a primary token of winlogon.exe, which
// runs as LocalSystem, on a thread that has SeDebugPrivilege enabled only
// for the open.
func gap1733LocalSystemToken() (windows.Token, error) {
	type result struct {
		token windows.Token
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			done <- result{err: err}
			return
		}
		defer windows.RevertToSelf() //nolint:errcheck
		var thread windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &thread); err != nil {
			done <- result{err: err}
			return
		}
		defer thread.Close()
		if err := enableWindowsThreadPrivilege(thread, "SeDebugPrivilege"); err != nil {
			done <- result{err: fmt.Errorf("enable SeDebugPrivilege: %w", err)}
			return
		}
		token, err := gap1733WinlogonPrimaryToken()
		done <- result{token, err}
	}()
	got := <-done
	return got.token, got.err
}

func gap1733WinlogonPrimaryToken() (windows.Token, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var errs []error
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "winlogon.exe") {
			continue
		}
		token, err := gap1733ProcessPrimaryToken(entry.ProcessID)
		if err == nil {
			return token, nil
		}
		errs = append(errs, fmt.Errorf("winlogon.exe %d: %w", entry.ProcessID, err))
	}
	if len(errs) == 0 {
		return 0, errors.New("no winlogon.exe runs")
	}
	return 0, errors.Join(errs...)
}

func gap1733ProcessPrimaryToken(pid uint32) (windows.Token, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); err != nil {
		return 0, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return 0, err
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return 0, fmt.Errorf("runs as %s, not LocalSystem", user.User.Sid)
	}
	var primary windows.Token
	if err := windows.DuplicateTokenEx(token,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return 0, err
	}
	return primary, nil
}
