// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
