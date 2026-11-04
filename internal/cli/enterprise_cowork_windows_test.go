// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/coworkaudit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsEnterpriseCoworkBlockNamesEachEnrolledAccount(t *testing.T) {
	at := time.Date(2026, 11, 3, 13, 16, 5, 0, time.UTC)
	old, oldElevated := windowsCoworkLastEvents, windowsCoworkElevated
	var queried string
	windowsCoworkLastEvents = func(_ context.Context, path string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		queried = path
		return []enterprisestatus.CoworkAccountEvent{{UserID: "S-1-5-21-1-2-3-1001", At: at}}, false, nil
	}
	windowsCoworkElevated = func() bool { return true }
	oldFolders := windowsCoworkDesktopFolders
	var desktopChecked []string
	windowsCoworkDesktopFolders = func(sid string) ([]enterprisehooks.ClaudeDesktopFolder, error) {
		desktopChecked = append(desktopChecked, sid)
		return []enterprisehooks.ClaudeDesktopFolder{{Deployment: "3p", Path: `C:\Users\alice\AppData\Local\Claude-3p`, EngineVersion: "2.1.317", EnginePath: `C:\x\claude.exe`}}, nil
	}
	t.Cleanup(func() {
		windowsCoworkLastEvents, windowsCoworkElevated, windowsCoworkDesktopFolders = old, oldElevated, oldFolders
	})
	result := &enterprisestatus.Result{Action: "status"}
	result.Enrollment.Accounts = []enterprisestatus.EnrollmentAccount{
		{Account: `CORP\alice`, SID: "S-1-5-21-1-2-3-1001"}, {Account: `CORP\bob`, SID: "S-1-5-21-1-2-3-1002"},
	}
	cfg := &config.Config{}
	const store = `C:\ProgramData\Cisco\DefenseClaw\runtime\audit.db`
	auditStore := func() (string, error) { return store, nil }
	managedHook := true
	block := map[string]enterprisestatus.ConnectorState{"claudecode": {Enabled: true, HooksInstalled: enterprisestatus.HooksInstalledAll, ManagedHook: &managedHook}}
	result.MachinePolicy = map[string]enterprisestatus.MachinePolicyState{"claudecode": {Ownership: "merge", Lock: "enforce", OwnedEntries: 28}}
	cowork := windowsEnterpriseCoworkBlock(result, cfg, auditStore, block, nil)
	if cowork == nil || !cowork.Configured || cowork.ManagedHooksOnly != "enforce" || !cowork.AccountsKnown || len(cowork.Accounts) != 2 ||
		cowork.Accounts[0].LastEventAt != "2026-11-03T13:16:05Z" || cowork.Accounts[1].LastEventAt != "" || queried != store {
		t.Fatalf("cowork = %+v (queried %q)", cowork, queried)
	}
	// GAP-0057: the elevated view names each enrolled account's engine trust.
	if desktop := cowork.ClaudeDesktop; desktop == nil || len(desktop.Accounts) != 2 || desktop.Trusted != 2 || len(desktopChecked) != 2 {
		t.Fatalf("claude_desktop = %+v (checked %v)", cowork.ClaudeDesktop, desktopChecked)
	}
	windowsCoworkElevated = func() bool { return false }
	queried, desktopChecked = "", nil
	if got := windowsEnterpriseCoworkBlock(result, cfg, auditStore, block, nil); got == nil || got.AccountsKnown || queried != "" ||
		got.ClaudeDesktop != nil || desktopChecked != nil {
		t.Fatalf("unelevated cowork = %+v (queried %q, desktop checked %v)", got, queried, desktopChecked)
	}
	if got := windowsEnterpriseCoworkBlock(&enterprisestatus.Result{Action: "ensure"}, cfg, auditStore, block, nil); got != nil {
		t.Fatalf("ensure cowork = %+v", got)
	}
}

// cowork-1-0-8 GAP-0028: Cowork is configured only while DefenseClaw's
// Claude Code drop-in is in place: an entry with no owned hook or with a
// conflict is not, whatever the connectors block says.
func TestWindowsEnterpriseCoworkBlockNeedsTheClaudeCodeDropIn(t *testing.T) {
	managedHook := true
	block := map[string]enterprisestatus.ConnectorState{"claudecode": {Enabled: true, HooksInstalled: enterprisestatus.HooksInstalledAll, ManagedHook: &managedHook}}
	for name, policy := range map[string]*enterprisestatus.MachinePolicyState{
		"not listed": nil,
		"no entry":   {Ownership: "merge", Lock: "enforce"},
		"conflict":   {Ownership: "merge", Lock: "enforce", OwnedEntries: 27, Conflicts: []string{"PreToolUse has no DefenseClaw managed hook"}},
	} {
		result := &enterprisestatus.Result{Action: "verify", MachinePolicy: map[string]enterprisestatus.MachinePolicyState{}}
		if policy != nil {
			result.MachinePolicy["claudecode"] = *policy
		}
		cowork := windowsEnterpriseCoworkBlock(result, &config.Config{}, nil, block, nil)
		if cowork == nil || cowork.Configured || cowork.Reason != enterprisestatus.CoworkReasonMachinePolicyUnset {
			t.Fatalf("%s: cowork = %+v", name, cowork)
		}
	}
}

// The per-account line reads the audit store the gateway writes, resolved
// from the installed config of the Windows layout the way the gateway start
// resolves it (windowsEnterpriseAuditStore): the layout's runtime folder by
// default, observability.local.path when the config names one. Neither the
// path nor the lookup is replaced (cowork-1-0-8 GAP-0025).
func TestWindowsEnterpriseCoworkBlockReadsTheGatewayAuditStoreOfTheLayout(t *testing.T) {
	root := t.TempDir()
	layout, err := managed.StandaloneWindowsLayoutForRoots(filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData"))
	if err != nil {
		t.Fatal(err)
	}
	old, oldElevated := windowsCoworkLastEvents, windowsCoworkElevated
	windowsCoworkLastEvents, windowsCoworkElevated = coworkaudit.LastEvents, func() bool { return true }
	t.Cleanup(func() { windowsCoworkLastEvents, windowsCoworkElevated = old, oldElevated })
	base := "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
		"gateway:\n  api_bind: 127.0.0.1\n  api_port: 18970\nguardrail:\n  enabled: true\n  mode: observe\n"
	custom := filepath.Join(layout.DataDir, "stores", "events.db")
	for _, tc := range []struct{ name, source, store string }{
		{"layout default", base, filepath.Join(layout.DataDir, "audit.db")},
		{"observability.local.path", base + "observability:\n  local:\n    path: '" + custom + "'\n", custom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, dir := range []string{filepath.Dir(layout.ConfigPath), filepath.Dir(tc.store)} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(layout.ConfigPath, []byte(tc.source), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := windowsEnterpriseAuditStore(layout)
			if err != nil || filepath.Clean(got) != filepath.Clean(tc.store) {
				t.Fatalf("audit store = %q, %v; want %q", got, err, tc.store)
			}
			store, err := audit.NewStore(tc.store)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 11, 4, 1, 6, 30, 0, time.UTC)
			if err := store.LogEvent(audit.Event{Action: "connector-hook", Connector: "claudecode", Timestamp: at,
				Structured: map[string]any{"user.id": "S-1-5-21-1-2-3-1001", "defenseclaw.user.name": `CORP\alice`, "surface": "cowork"}}); err != nil {
				t.Fatal(err)
			}
			result := &enterprisestatus.Result{Action: "verify"}
			result.Enrollment.Accounts = []enterprisestatus.EnrollmentAccount{{Account: `CORP\alice`, SID: "S-1-5-21-1-2-3-1001"}}
			managedHook := true
			block := map[string]enterprisestatus.ConnectorState{"claudecode": {Enabled: true, HooksInstalled: enterprisestatus.HooksInstalledAll, ManagedHook: &managedHook}}
			cowork := windowsEnterpriseCoworkBlock(result, &config.Config{}, func() (string, error) { return windowsEnterpriseAuditStore(layout) }, block, nil)
			if cowork == nil || !cowork.AccountsKnown || len(cowork.Accounts) != 1 || cowork.Accounts[0].LastEventAt != "2026-11-04T01:06:30Z" {
				t.Fatalf("cowork = %+v", cowork)
			}
		})
	}
}
