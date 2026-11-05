// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsPurgeAccountOwnLinkLeavesOnlyThatAccountAsWarning(t *testing.T) {
	oldIdentity, oldState, oldBinaries, oldLink := enterpriseHookWindowsUserCleanupIdentity,
		windowsManagedHooksStandaloneUserStatePurger, windowsManagedHooksStandaloneUserBinariesPurger,
		windowsEnterpriseAccountOwnedDataDirLink
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity = oldIdentity
		windowsManagedHooksStandaloneUserStatePurger = oldState
		windowsManagedHooksStandaloneUserBinariesPurger = oldBinaries
		windowsEnterpriseAccountOwnedDataDirLink = oldLink
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	home := filepath.Join(t.TempDir(), "alice")
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const sid = "S-1-5-21-1-2-3-1001"
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
		User: "alice", UserHome: home, SID: sid, Connector: "claudecode", DataDir: dataDir,
	}}}
	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error {
		return enterprisehooks.ErrWindowsUserStateOnlyLink
	}
	binaries := 0
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) {
		binaries++
		return nil, nil
	}
	windowsEnterpriseAccountOwnedDataDirLink = func(gotHome, gotSID string) bool {
		return gotHome == home && gotSID == sid
	}
	report := func() *enterprisestatus.Result {
		remaining, purged, _ := windowsManagedHooksStandaloneUserState(manifest, true, func(string) bool { return false })
		body, err := json.Marshal(remaining)
		if err != nil {
			t.Fatal(err)
		}
		result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "test")
		addWindowsEnterpriseUserStateWarning(result, &windowsEnterpriseInstallerReport{UserStateRemaining: body})
		if len(purged) != 0 || len(remaining) != 1 {
			t.Fatalf("purged=%v remaining=%v", purged, remaining)
		}
		return result
	}
	linked := report()
	if binaries != 1 || len(linked.Errors) != 0 || len(linked.Warnings) != 1 ||
		linked.Warnings[0].Code != "per_user_state_remaining" ||
		!strings.Contains(linked.Warnings[0].Message, "alice ("+sid+")") {
		t.Fatalf("account link purge: binaries=%d errors=%v warnings=%v", binaries, linked.Errors, linked.Warnings)
	}
	if code := linked.Finish("windows", windowsEnterpriseFailureCodeFor(linked)); code != 0 || !linked.OK {
		t.Fatalf("account link purge exit=%d result=%+v", code, linked)
	}

	windowsEnterpriseAccountOwnedDataDirLink = func(string, string) bool { return false }
	foreign := report()
	if binaries != 1 || len(foreign.Errors) != 1 || len(foreign.Warnings) != 0 {
		t.Fatalf("unowned link purge: binaries=%d errors=%v warnings=%v", binaries, foreign.Errors, foreign.Warnings)
	}

	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error { return nil }
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) {
		binaries++
		return nil, nil
	}
	remaining, purged, _ := windowsManagedHooksStandaloneUserState(manifest, true, func(string) bool { return false })
	if len(remaining) != 0 || len(purged) != 1 || binaries != 2 {
		t.Fatalf("plain folder: purged=%v remaining=%v binaries=%d", purged, remaining, binaries)
	}
}
