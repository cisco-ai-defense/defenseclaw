//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	// recordAdminOnlySDDL: Administrators own the record and only SYSTEM
	// and Administrators may touch it.
	recordAdminOnlySDDL = "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)"
	// recordUsersOwnedSDDL: a record a standard user planted.
	recordUsersOwnedSDDL = "O:BUG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;BU)"
)

func stampRecordForTest(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
	}); err != nil {
		t.Fatalf("stamp %s on %s: %v", sddl, path, err)
	}
}

// recordLayoutForTest stands temporary folders in for the hook runtime,
// lifecycle and guardian folders, with no ledger.
func recordLayoutForTest(t *testing.T) StandaloneLayout {
	t.Helper()
	base := t.TempDir()
	layout := StandaloneLayout{
		HookRuntimeDir:  filepath.Join(base, "Cisco", StandaloneWindowsHookRuntimeDirName),
		LifecycleDir:    filepath.Join(base, "Cisco", "DefenseClaw", "install"),
		GuardianAuthDir: filepath.Join(base, "Cisco", "DefenseClaw", "hook-guardian-state"),
	}
	for _, dir := range []string{layout.HookRuntimeDir, layout.LifecycleDir, layout.GuardianAuthDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(HookGuardianAuthorizationDirEnv, layout.GuardianAuthDir)
	previous := windowsManagedFolderLayout
	windowsManagedFolderLayout = func() (StandaloneLayout, error) { return layout, nil }
	t.Cleanup(func() { windowsManagedFolderLayout = previous })
	return layout
}

// g582 review 5 M2: the Setup deployment record covered only the hook
// runtime folder and its parent. A per-connector enrollment folder under it
// (DefenseClaw-HookRuntime\copilot) whose enrollment.json and lock a user
// deleted, or where no user is enrolled, looked like a folder created before
// the first install and was taken over in place. No MDM, vendor installer or
// user creates folders there, so the record covers the whole subtree.
func TestWindowsDeploymentRecordCoversTheHookRuntimeSubtree(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, tc := range []struct {
		name     string
		record   string
		folder   func(StandaloneLayout) string
		recorded bool
	}{
		{name: "per-connector folder, admin-only record", record: recordAdminOnlySDDL,
			folder: func(l StandaloneLayout) string { return filepath.Join(l.HookRuntimeDir, "copilot") }, recorded: true},
		{name: "deeper folder, admin-only record", record: recordAdminOnlySDDL,
			folder: func(l StandaloneLayout) string { return filepath.Join(l.HookRuntimeDir, "copilot", "x") }, recorded: true},
		{name: "hook runtime folder itself, admin-only record", record: recordAdminOnlySDDL,
			folder: func(l StandaloneLayout) string { return l.HookRuntimeDir }, recorded: true},
		{name: "twin: per-connector folder, no record (before the first install)",
			folder: func(l StandaloneLayout) string { return filepath.Join(l.HookRuntimeDir, "copilot") }},
		{name: "twin: per-connector folder, a record a user planted", record: recordUsersOwnedSDDL,
			folder: func(l StandaloneLayout) string { return filepath.Join(l.HookRuntimeDir, "copilot") }},
		{name: "twin: a sibling folder whose name only starts with the runtime folder's", record: recordAdminOnlySDDL,
			folder: func(l StandaloneLayout) string { return l.HookRuntimeDir + "-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := recordLayoutForTest(t)
			if tc.record != "" {
				record := filepath.Join(layout.LifecycleDir, "deployment.json")
				if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				stampRecordForTest(t, record, tc.record)
			}
			folder := tc.folder(layout)
			if err := os.MkdirAll(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			got := windowsManagedFolderRecorded(filepath.Clean(folder))
			if tc.recorded && got == "" {
				t.Fatalf("%s is not recorded: deleting its markers would make it look pre-install", folder)
			}
			if !tc.recorded && got != "" {
				t.Fatalf("%s is recorded (%s), want the pre-install takeover kept", folder, got)
			}
		})
	}
}

// g582 review 5 S1: the hook guardian ledger counted a folder only when it
// named a path directly in it. A vendor folder above a recorded policy
// folder (C:\Program Files\ClaudeCode above managed-settings.d, or
// C:\ProgramData\OpenAI above the Codex requirements folder) was taken over
// in place once the policy folder was renamed away. Any recorded path under
// the folder now counts.
func TestWindowsGuardianLedgerCoversRecordedPathsAnywhereUnderAFolder(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, tc := range []struct {
		name     string
		target   func(vendor string) string
		recorded bool
	}{
		{name: "grandchild policy file", target: func(v string) string {
			return filepath.Join(v, "managed-settings.d", "90-defenseclaw.json")
		}, recorded: true},
		{name: "two levels deeper", target: func(v string) string {
			return filepath.Join(v, "Codex", "requirements", "defenseclaw.toml")
		}, recorded: true},
		{name: "direct child", target: func(v string) string { return filepath.Join(v, "policy.json") }, recorded: true},
		{name: "twin: a path in a sibling folder whose name only starts with the vendor's", target: func(v string) string {
			return filepath.Join(v+"X", "managed-settings.d", "90-defenseclaw.json")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := recordLayoutForTest(t)
			vendor := filepath.Join(t.TempDir(), "ClaudeCode")
			if err := os.Mkdir(vendor, 0o700); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(map[string]any{"protected_targets": []any{map[string]any{
				"result": map[string]any{"hook_config_paths": []string{tc.target(vendor)}},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			ledger := filepath.Join(layout.GuardianAuthDir, HookGuardianAuthorizationFile)
			if err := os.WriteFile(ledger, data, 0o600); err != nil {
				t.Fatal(err)
			}
			stampRecordForTest(t, ledger, recordAdminOnlySDDL)
			got := windowsManagedFolderRecorded(filepath.Clean(vendor))
			if tc.recorded && got == "" {
				t.Fatalf("%s is not recorded by a ledger naming %s", vendor, tc.target(vendor))
			}
			if !tc.recorded && got != "" {
				t.Fatalf("%s is recorded (%s) by a ledger naming only %s", vendor, got, tc.target(vendor))
			}
		})
	}
}
