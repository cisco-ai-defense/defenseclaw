// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Earlier builds put the macOS Devin config under ~/Library/Application
// Support/devin (os.UserConfigDir), which the Devin CLI never reads; the
// config root is now ~/.config/devin. Setup over a receipt bound to the old
// path must close that cycle instead of failing with a backup target
// mismatch: an unchanged old file is restored, and one the user edited keeps
// everything but DefenseClaw's entries.
func TestDevinSetupMigratesAReceiptBoundToTheOldMacOSConfigRoot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing string // old config before the earlier Setup; "" = none
		edit     bool   // the user edited the old config after that Setup
	}{
		{name: "created and unchanged"},
		{name: "existing and unchanged", existing: `{"theme":"dark"}` + "\n"},
		{name: "existing and edited", existing: `{"theme":"dark"}` + "\n", edit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := DevinHooksPathOverride
			DevinHooksPathOverride = ""
			t.Cleanup(func() { DevinHooksPathOverride = previous })
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			oldRoot := filepath.Join(home, "Library", "Application Support", "devin")
			newRoot := filepath.Join(home, ".config", "devin")
			oldConfig := filepath.Join(oldRoot, "config.json")
			newConfig := filepath.Join(newRoot, "config.json")
			if tc.existing != "" {
				if err := os.MkdirAll(oldRoot, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(oldConfig, []byte(tc.existing), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			conn := NewDevinConnector()
			earlier := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", ConfigHome: oldRoot}
			if err := conn.Setup(context.Background(), earlier); err != nil {
				t.Fatalf("earlier Setup: %v", err)
			}
			if tc.edit {
				cfg, err := readDevinJSONObject(oldConfig)
				if err != nil {
					t.Fatal(err)
				}
				cfg["model"] = "user-choice"
				if err := writeJSONObject(oldConfig, cfg); err != nil {
					t.Fatal(err)
				}
			}

			current := earlier
			current.ConfigHome = newRoot
			if err := conn.Setup(context.Background(), current); err != nil {
				t.Fatalf("Setup after the config root moved: %v", err)
			}
			present, err := OwnedHooksPresent(conn, current)
			if err != nil || !present {
				t.Fatalf("hooks at the new config root present = %v, %v", present, err)
			}
			if got := managedFileBackupTargetPath(dataDir, "devin", "config", ""); got != newConfig {
				t.Fatalf("receipt bound to %q, want %q", got, newConfig)
			}
			switch {
			case tc.existing == "":
				if _, err := os.Stat(oldConfig); !os.IsNotExist(err) {
					t.Fatalf("old config DefenseClaw created is still present (err=%v)", err)
				}
			case !tc.edit:
				if body, _ := os.ReadFile(oldConfig); string(body) != tc.existing {
					t.Fatalf("old config not restored: %s", body)
				}
			default:
				hooked, err := devinConfigReferencesHook(oldConfig, devinOwnedHookCommands(current, conn.hookCommand(current))...)
				if err != nil || hooked {
					t.Fatalf("old config still holds DefenseClaw entries = %v, %v", hooked, err)
				}
				if body, _ := os.ReadFile(oldConfig); !strings.Contains(string(body), "user-choice") || !strings.Contains(string(body), "dark") {
					t.Fatalf("surgical cleanup lost the user's settings: %s", body)
				}
			}

			if err := conn.Teardown(context.Background(), current); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if err := conn.VerifyClean(current); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}
		})
	}
}

func TestDevinTargetMoveDropsTheOldWorkspaceRestoreState(t *testing.T) {
	for _, tc := range []struct {
		name          string
		dropReceipt   bool
		dropOldNotice bool
	}{
		{name: "receipt present"},
		{name: "receipt missing", dropReceipt: true},
		{name: "copy only", dropReceipt: true, dropOldNotice: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := DevinHooksPathOverride
			DevinHooksPathOverride = ""
			t.Cleanup(func() { DevinHooksPathOverride = previous })
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			workspace := filepath.Join(home, "old-project")
			if err := os.MkdirAll(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			conn := NewDevinConnector()
			old := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: workspace}
			if err := conn.Setup(context.Background(), old); err != nil {
				t.Fatalf("workspace Setup: %v", err)
			}
			oldPath := devinHooksPath(old)
			spec, _ := agentConfigSpecFor("devin")
			if err := spec.writeNotice(dataDir, agentConfigNotice{
				Version: agentConfigCopyVersion, Path: oldPath, Source: AgentConfigHooksOnly,
				SettingsLost: true, At: "2026-11-06T00:00:00Z",
			}); err != nil {
				t.Fatal(err)
			}
			if tc.dropReceipt {
				discardManagedFileBackup(dataDir, "devin", "config")
			}
			if tc.dropOldNotice {
				if err := os.Remove(spec.noticePath(dataDir)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.RemoveAll(workspace); err != nil {
				t.Fatal(err)
			}
			global := old
			global.WorkspaceDir = ""
			global.ConfigHome = filepath.Join(home, ".config", "devin")
			if err := conn.Setup(context.Background(), global); err != nil {
				t.Fatalf("global Setup: %v", err)
			}
			if _, err := os.Lstat(workspace); !os.IsNotExist(err) {
				t.Fatalf("old project was recreated: %v", err)
			}
			if _, ok := spec.readNotice(dataDir); ok {
				t.Fatal("old workspace restore notice survived the target move")
			}
			if copy, ok := spec.readCopy(dataDir, devinHooksPath(global)); !ok || copy.Path != devinHooksPath(global) {
				t.Fatalf("global copy = %+v, valid=%t", copy, ok)
			}
		})
	}
}

func TestDevinCurrentReceiptRetiresOnlyPreviousTargetRestoreState(t *testing.T) {
	previous := DevinHooksPathOverride
	DevinHooksPathOverride = ""
	t.Cleanup(func() { DevinHooksPathOverride = previous })
	for _, tc := range []struct {
		name      string
		oldTarget bool
		viaStatus bool
	}{
		{name: "setup removes previous target notice", oldTarget: true},
		{name: "verify removes previous target notice", oldTarget: true, viaStatus: true},
		{name: "setup keeps current target notice"},
		{name: "verify keeps current target notice", viaStatus: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", ConfigHome: filepath.Join(home, ".config", "devin")}
			conn := NewDevinConnector()
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("initial Setup: %v", err)
			}
			currentPath := devinHooksPath(opts)
			if got := managedFileBackupTargetPath(dataDir, "devin", "config", ""); got != currentPath {
				t.Fatalf("receipt bound to %q, want %q", got, currentPath)
			}
			spec, _ := agentConfigSpecFor("devin")
			noticePath := currentPath
			if tc.oldTarget {
				noticePath = filepath.Join(home, "old-project", ".devin", "hooks.v1.json")
			}
			if err := spec.writeNotice(dataDir, agentConfigNotice{
				Version: agentConfigCopyVersion, Path: noticePath, Source: AgentConfigHooksOnly,
				SettingsLost: true, At: "2026-11-06T00:00:00Z",
			}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(spec.seenPath(dataDir), []byte("seen\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.viaStatus {
				_ = AgentConfigStatus("devin", opts, time.Time{}, true)
			} else if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("same-target Setup: %v", err)
			}
			_, noticePresent := spec.readNotice(dataDir)
			if noticePresent == tc.oldTarget {
				t.Fatalf("restore notice present = %t, old target = %t", noticePresent, tc.oldTarget)
			}
			if _, err := os.Stat(spec.seenPath(dataDir)); tc.oldTarget && !os.IsNotExist(err) {
				t.Fatalf("previous target seen marker remains: %v", err)
			} else if !tc.oldTarget && err != nil {
				t.Fatalf("current target seen marker missing: %v", err)
			}
			if _, ok := spec.readCopy(dataDir, currentPath); !ok {
				t.Fatal("current target copy was not retained")
			}
			if _, err := os.Lstat(filepath.Join(home, "old-project")); !os.IsNotExist(err) {
				t.Fatalf("previous project was created: %v", err)
			}
		})
	}
}

// RHEL-U3-03: `setup devin --workspace` pins claw.workspace_dir, which moves
// Copilot's hooks from ~/.copilot/hooks to <workspace>/.github/hooks. The
// gateway's Copilot Setup then failed with a backup target mismatch and Setup
// rolled the whole roster back.
func TestCopilotSetupMovesItsHooksWhenAWorkspaceIsPinned(t *testing.T) {
	previousPath, previousWorkspace := CopilotHooksPathOverride, CopilotWorkspaceDirOverride
	CopilotHooksPathOverride, CopilotWorkspaceDirOverride = "", ""
	t.Cleanup(func() { CopilotHooksPathOverride, CopilotWorkspaceDirOverride = previousPath, previousWorkspace })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("COPILOT_HOME", filepath.Join(home, ".copilot"))
	dataDir := filepath.Join(home, ".defenseclaw")
	workspace := filepath.Join(home, "proj")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	conn := NewCopilotConnector()
	global := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	if err := conn.Setup(context.Background(), global); err != nil {
		t.Fatalf("global Setup: %v", err)
	}
	globalConfig := copilotHooksPath(global)

	pinned := global
	pinned.WorkspaceDir = workspace
	if err := conn.Setup(context.Background(), pinned); err != nil {
		t.Fatalf("Setup after a workspace was pinned: %v", err)
	}
	if present, err := OwnedHooksPresent(conn, pinned); err != nil || !present {
		t.Fatalf("workspace hooks present = %v, %v", present, err)
	}
	if got, want := managedFileBackupTargetPath(dataDir, "copilot", "config", ""), filepath.Join(workspace, ".github", "hooks", "defenseclaw.json"); got != want {
		t.Fatalf("receipt bound to %q, want %q", got, want)
	}
	if _, err := os.Stat(globalConfig); !os.IsNotExist(err) {
		t.Fatalf("global hook file DefenseClaw created is still present (err=%v)", err)
	}
}
