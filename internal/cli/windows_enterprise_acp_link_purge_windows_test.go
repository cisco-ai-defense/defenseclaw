// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func g193AccountOwnedJunction(t *testing.T, link, target, sidText string) {
	t.Helper()
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("create account link: %v: %s", err, output)
	}
	sid, err := windows.StringToSid(sidText)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(link)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(ptr, windows.WRITE_OWNER|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	setOwner := func() error {
		return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)
	}
	if err := setOwner(); err != nil {
		if err := enterprisehooks.RunWithWindowsAdministratorOwnerRestorePrivilege(setOwner); err != nil {
			t.Fatalf("set account link owner: %v", err)
		}
	}
}

// GAP-0193: a canonical account-owned link covers the ACP path beneath it.
// A different account's ACP failure remains a failure, and a plain folder
// still follows the ordinary purge path.
func TestGAP0193PurgeAccountLinkDoesNotReportItsACPPathAsFailure(t *testing.T) {
	oldIdentity, oldState, oldBinaries := enterpriseHookWindowsUserCleanupIdentity,
		windowsManagedHooksStandaloneUserStatePurger, windowsManagedHooksStandaloneUserBinariesPurger
	oldLink := windowsEnterpriseAccountOwnedDataDirLink
	oldCopies, oldACP := windowsManagedHooksStandaloneACPUserCopies, windowsManagedHooksStandaloneACPUserPurger
	oldRegistrations, oldInventory := windowsManagedHooksStandaloneUserRegistrationRemover, windowsManagedHooksStandaloneInventoryACERevoker
	oldTransaction, oldFloor, oldCursor := windowsManagedClaudeTransactionLeftoverRemover,
		windowsManagedHooksStandaloneFloorPurger, windowsManagedHooksStandaloneCursorTombstonePurger
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity = oldIdentity
		windowsManagedHooksStandaloneUserStatePurger = oldState
		windowsManagedHooksStandaloneUserBinariesPurger = oldBinaries
		windowsEnterpriseAccountOwnedDataDirLink = oldLink
		windowsManagedHooksStandaloneACPUserCopies = oldCopies
		windowsManagedHooksStandaloneACPUserPurger = oldACP
		windowsManagedHooksStandaloneUserRegistrationRemover = oldRegistrations
		windowsManagedHooksStandaloneInventoryACERevoker = oldInventory
		windowsManagedClaudeTransactionLeftoverRemover = oldTransaction
		windowsManagedHooksStandaloneFloorPurger = oldFloor
		windowsManagedHooksStandaloneCursorTombstonePurger = oldCursor
	})
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	t.Setenv(windowsManagedHooksPurgeUserStateEnv, "1")
	sid := currentAccountSID()
	if sid == "" {
		t.Fatal("current account SID unavailable")
	}
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(filepath.Join(outside, "acp"), 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(outside, "acp", "canary.txt")
	if err := os.WriteFile(canary, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	g193AccountOwnedJunction(t, dataDir, outside, sid)
	t.Cleanup(func() { _ = os.Remove(dataDir) })
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
		User: "alice", UserHome: home, SID: sid, Connector: "claudecode", DataDir: dataDir,
	}}}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	windowsManagedHooksStandaloneUserRegistrationRemover = func(context.Context, string, enterprisehooks.Manifest) enterpriseHookUserCleanupResult {
		return enterpriseHookUserCleanupResult{}
	}
	windowsManagedHooksStandaloneInventoryACERevoker = func(enterprisehooks.Manifest) error { return nil }
	windowsManagedClaudeTransactionLeftoverRemover = func() error { return nil }
	windowsManagedHooksStandaloneFloorPurger = func() error { return nil }
	windowsManagedHooksStandaloneCursorTombstonePurger = func() error { return nil }
	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error {
		return enterprisehooks.ErrWindowsUserStateOnlyLink
	}
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) { return nil, nil }
	windowsEnterpriseAccountOwnedDataDirLink = func(string, string) bool { return true }
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) {
		return []enterprisehooks.WindowsACPUserCopy{{SID: sid, Home: home}}, nil
	}
	acpCalls := 0
	windowsManagedHooksStandaloneACPUserPurger = func(string, string) error {
		acpCalls++
		_ = os.Remove(canary)
		return errors.New("ACP folder was not available")
	}
	var report windowsManagedHooksTeardownReport
	completeWindowsManagedHooksTeardownUserCleanup(&report, "runtime", manifest)
	if acpCalls != 0 || len(report.UserStateRemaining) != 1 ||
		!strings.HasSuffix(report.UserStateRemaining[0], windowsManagedHooksAccountLinkKeptReason) {
		t.Fatalf("owned link: ACP calls %d, remaining %v", acpCalls, report.UserStateRemaining)
	}
	if body, err := os.ReadFile(canary); err != nil || string(body) != "kept" {
		t.Fatalf("link target changed: %q, %v", body, err)
	}
	remaining, err := json.Marshal(report.UserStateRemaining)
	if err != nil {
		t.Fatal(err)
	}
	result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "test")
	addWindowsEnterpriseUserStateWarning(result, &windowsEnterpriseInstallerReport{UserStateRemaining: remaining})
	if len(result.Errors) != 0 || len(result.Warnings) != 1 ||
		!strings.Contains(result.Warnings[0].Message, "remove each named link itself") {
		t.Fatalf("owned link result: errors %v warnings %v", result.Errors, result.Warnings)
	}
	if code := result.Finish("windows", windowsEnterpriseFailureCodeFor(result)); code != 0 || !result.OK {
		t.Fatalf("owned link purge exit=%d result=%+v", code, result)
	}

	foreignHome := filepath.Join(t.TempDir(), "other")
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) {
		return []enterprisehooks.WindowsACPUserCopy{{SID: sid, Home: home}, {SID: "S-1-5-21-1-2-3-1002", Home: foreignHome}}, nil
	}
	windowsManagedHooksStandaloneACPUserPurger = func(string, string) error {
		acpCalls++
		return errors.New("ACP folder was not available")
	}
	report = windowsManagedHooksTeardownReport{}
	completeWindowsManagedHooksTeardownUserCleanup(&report, "runtime", manifest)
	if acpCalls != 1 || len(report.UserStateRemaining) != 2 {
		t.Fatalf("other account: ACP calls %d, remaining %v", acpCalls, report.UserStateRemaining)
	}
	remaining, err = json.Marshal(report.UserStateRemaining)
	if err != nil {
		t.Fatal(err)
	}
	result = enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "test")
	addWindowsEnterpriseUserStateWarning(result, &windowsEnterpriseInstallerReport{UserStateRemaining: remaining})
	if len(result.Errors) != 1 {
		t.Fatalf("other account's ACP failure became a warning: %v", result.Warnings)
	}
	windowsManagedHooksStandaloneUserRegistrationRemover = func(context.Context, string, enterprisehooks.Manifest) enterpriseHookUserCleanupResult {
		return enterpriseHookUserCleanupResult{Pending: []string{"claudecode/" + sid + ": awaiting account session"}}
	}
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) {
		return []enterprisehooks.WindowsACPUserCopy{{SID: sid, Home: home}}, nil
	}
	report = windowsManagedHooksTeardownReport{}
	completeWindowsManagedHooksTeardownUserCleanup(&report, "runtime", manifest)
	if acpCalls != 1 || len(report.UserStateRemaining) != 1 ||
		!strings.HasSuffix(report.UserStateRemaining[0], windowsManagedHooksKeptForRegistrationsReason) {
		t.Fatalf("pending account link: ACP calls %d, remaining %v", acpCalls, report.UserStateRemaining)
	}

	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error { return nil }
	windowsManagedHooksStandaloneUserRegistrationRemover = func(context.Context, string, enterprisehooks.Manifest) enterpriseHookUserCleanupResult {
		return enterpriseHookUserCleanupResult{}
	}
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) { return nil, nil }
	report = windowsManagedHooksTeardownReport{}
	completeWindowsManagedHooksTeardownUserCleanup(&report, "runtime", manifest)
	if len(report.UserStateRemaining) != 0 || len(report.UserStatePurged) != 1 {
		t.Fatalf("plain folder: remaining %v, purged %v", report.UserStateRemaining, report.UserStatePurged)
	}
	if body, err := os.ReadFile(canary); err != nil || string(body) != "kept" {
		t.Fatalf("link target changed after plain purge: %q, %v", body, err)
	}
}

func TestGAP0193PurgeReportsLinkAppearingAfterInitialRead(t *testing.T) {
	oldIdentity := enterpriseHookWindowsUserCleanupIdentity
	oldRootLink := windowsManagedHooksAccountOwnedRootLink
	oldAccountLink := windowsEnterpriseAccountOwnedDataDirLink
	oldState := windowsManagedHooksStandaloneUserStatePurger
	oldBinaries := windowsManagedHooksStandaloneUserBinariesPurger
	oldCopies := windowsManagedHooksStandaloneACPUserCopies
	oldACP := windowsManagedHooksStandaloneACPUserPurger
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity = oldIdentity
		windowsManagedHooksAccountOwnedRootLink = oldRootLink
		windowsEnterpriseAccountOwnedDataDirLink = oldAccountLink
		windowsManagedHooksStandaloneUserStatePurger = oldState
		windowsManagedHooksStandaloneUserBinariesPurger = oldBinaries
		windowsManagedHooksStandaloneACPUserCopies = oldCopies
		windowsManagedHooksStandaloneACPUserPurger = oldACP
	})

	sid := currentAccountSID()
	if sid == "" {
		t.Fatal("current account SID unavailable")
	}
	home := filepath.Join(t.TempDir(), "account")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
		User: "account", UserHome: home, SID: sid, Connector: "claudecode", DataDir: dataDir,
	}}}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	checks := 0
	windowsManagedHooksAccountOwnedRootLink = func(gotHome, gotSID string) bool {
		checks++
		if checks == 1 {
			g193AccountOwnedJunction(t, dataDir, outside, sid)
			t.Cleanup(func() { _ = os.Remove(dataDir) })
		}
		return oldRootLink(gotHome, gotSID)
	}
	windowsEnterpriseAccountOwnedDataDirLink = func(gotHome, gotSID string) bool {
		return gotHome == home && gotSID == sid
	}
	stateCalls := 0
	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error {
		stateCalls++
		return enterprisehooks.ErrWindowsUserStateOnlyLink
	}
	binaryCalls := 0
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) {
		binaryCalls++
		return nil, nil
	}
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) {
		return []enterprisehooks.WindowsACPUserCopy{{SID: sid, Home: home}}, nil
	}
	acpCalls := 0
	windowsManagedHooksStandaloneACPUserPurger = func(string, string) error {
		acpCalls++
		return errors.New("ACP folder was not available")
	}

	remaining, purged, links := windowsManagedHooksStandaloneUserState(manifest, true, func(string) bool { return false })
	acpRemaining, _ := windowsManagedHooksStandaloneACPUserState(links)
	if stateCalls != 1 || binaryCalls != 1 || acpCalls != 0 || len(purged) != 0 ||
		len(links) != 1 || len(acpRemaining) != 0 || len(remaining) != 1 ||
		!strings.Contains(remaining[0], "account ("+sid+")") ||
		!strings.HasSuffix(remaining[0], windowsManagedHooksAccountLinkKeptReason) {
		t.Fatalf("late account link: state=%d binaries=%d ACP=%d purged=%v links=%v remaining=%v ACP remaining=%v",
			stateCalls, binaryCalls, acpCalls, purged, links, remaining, acpRemaining)
	}
	if body, err := os.ReadFile(canary); err != nil || string(body) != "kept" {
		t.Fatalf("link target changed: %q, %v", body, err)
	}
	body, err := json.Marshal(remaining)
	if err != nil {
		t.Fatal(err)
	}
	result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "test")
	addWindowsEnterpriseUserStateWarning(result, &windowsEnterpriseInstallerReport{UserStateRemaining: body})
	if code := result.Finish("windows", windowsEnterpriseFailureCodeFor(result)); code != 0 || !result.OK ||
		len(result.Warnings) != 1 || len(result.Errors) != 0 {
		t.Fatalf("late account link result: exit=%d result=%+v", code, result)
	}

	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	windowsManagedHooksAccountOwnedRootLink = oldRootLink
	remaining, purged, links = windowsManagedHooksStandaloneUserState(manifest, true, func(string) bool { return false })
	if stateCalls != 1 || binaryCalls != 2 || len(remaining) != 0 || len(purged) != 0 || len(links) != 0 {
		t.Fatalf("missing plain folder: state=%d binaries=%d purged=%v links=%v remaining=%v",
			stateCalls, binaryCalls, purged, links, remaining)
	}
}

func TestGAP0193PurgeRecordsLinkCreatedDuringStatePurge(t *testing.T) {
	oldIdentity := enterpriseHookWindowsUserCleanupIdentity
	oldState := windowsManagedHooksStandaloneUserStatePurger
	oldBinaries := windowsManagedHooksStandaloneUserBinariesPurger
	oldCopies := windowsManagedHooksStandaloneACPUserCopies
	oldACP := windowsManagedHooksStandaloneACPUserPurger
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity = oldIdentity
		windowsManagedHooksStandaloneUserStatePurger = oldState
		windowsManagedHooksStandaloneUserBinariesPurger = oldBinaries
		windowsManagedHooksStandaloneACPUserCopies = oldCopies
		windowsManagedHooksStandaloneACPUserPurger = oldACP
	})
	accountSID := currentAccountSID()
	if accountSID == "" {
		t.Fatal("current account SID unavailable")
	}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }

	for _, mode := range []string{"account link", "foreign link", "plain folder"} {
		t.Run(mode, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "account")
			dataDir := filepath.Join(home, ".defenseclaw")
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			canary := filepath.Join(outside, "canary.txt")
			if err := os.WriteFile(canary, []byte("kept"), 0o600); err != nil {
				t.Fatal(err)
			}
			sid := accountSID
			if mode == "foreign link" {
				sid = "S-1-5-21-1-2-3-1002"
				if strings.EqualFold(sid, accountSID) {
					sid = "S-1-5-21-1-2-3-1003"
				}
			}
			manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
				User: "account", UserHome: home, SID: sid, Connector: "claudecode", DataDir: dataDir,
			}}}
			if windowsManagedHooksAccountOwnedRootLink(home, sid) {
				t.Fatal("plain folder reported as a link before the state purge")
			}
			stateCalls := 0
			windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error {
				stateCalls++
				if mode == "plain folder" {
					return nil
				}
				if err := os.Remove(dataDir); err != nil {
					t.Fatal(err)
				}
				g193AccountOwnedJunction(t, dataDir, outside, accountSID)
				t.Cleanup(func() { _ = os.Remove(dataDir) })
				return enterprisehooks.ErrWindowsUserStateOnlyLink
			}
			windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) {
				return nil, nil
			}
			windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) {
				return []enterprisehooks.WindowsACPUserCopy{{SID: sid, Home: home}}, nil
			}
			acpCalls := 0
			windowsManagedHooksStandaloneACPUserPurger = func(string, string) error {
				acpCalls++
				if mode != "plain folder" {
					return errors.New("ACP folder was not available")
				}
				return nil
			}

			remaining, purged, links := windowsManagedHooksStandaloneUserState(manifest, true, func(string) bool { return false })
			acpRemaining, _ := windowsManagedHooksStandaloneACPUserState(links)
			if stateCalls != 1 {
				t.Fatalf("state purge calls: %d", stateCalls)
			}
			if body, err := os.ReadFile(canary); err != nil || string(body) != "kept" {
				t.Fatalf("link target changed: %q, %v", body, err)
			}
			body, err := json.Marshal(append(remaining, acpRemaining...))
			if err != nil {
				t.Fatal(err)
			}
			result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "test")
			addWindowsEnterpriseUserStateWarning(result, &windowsEnterpriseInstallerReport{UserStateRemaining: body})
			code := result.Finish("windows", windowsEnterpriseFailureCodeFor(result))
			switch mode {
			case "account link":
				if len(links) != 1 || acpCalls != 0 || len(acpRemaining) != 0 || len(remaining) != 1 ||
					!strings.HasSuffix(remaining[0], windowsManagedHooksAccountLinkKeptReason) ||
					code != 0 || !result.OK || len(result.Warnings) != 1 || len(result.Errors) != 0 {
					t.Fatalf("account link: links=%v ACP calls=%d remaining=%v ACP remaining=%v result=%+v", links, acpCalls, remaining, acpRemaining, result)
				}
			case "foreign link":
				if len(links) != 0 || acpCalls != 1 || len(acpRemaining) != 1 || len(remaining) != 1 ||
					code == 0 || len(result.Errors) == 0 {
					t.Fatalf("foreign link: links=%v ACP calls=%d remaining=%v ACP remaining=%v result=%+v", links, acpCalls, remaining, acpRemaining, result)
				}
			case "plain folder":
				if len(links) != 0 || acpCalls != 1 || len(remaining) != 0 || len(acpRemaining) != 0 ||
					len(purged) != 1 || code != 0 || !result.OK {
					t.Fatalf("plain folder: links=%v ACP calls=%d remaining=%v ACP remaining=%v purged=%v result=%+v", links, acpCalls, remaining, acpRemaining, purged, result)
				}
			}
		})
	}
}
