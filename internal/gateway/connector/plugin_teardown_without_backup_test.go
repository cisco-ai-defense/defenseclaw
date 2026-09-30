// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A user who deletes the DefenseClaw data directory also deletes the plugin's
// backup receipt. Teardown must still remove DefenseClaw's own OpenCode and
// Amp plugin (identified by its ownership marker) and must keep any other
// file at that path.
func TestPluginTeardownWithoutBackupRemovesOnlyTheOwnedPlugin(t *testing.T) {
	type pluginConnector interface {
		Setup(context.Context, SetupOpts) error
		Teardown(context.Context, SetupOpts) error
		VerifyClean(SetupOpts) error
	}
	for _, test := range []struct {
		name    string
		conn    func() pluginConnector
		setPath func(string) func()
		prepare func(*testing.T, SetupOpts) SetupOpts
		file    string
	}{
		{
			name: "opencode",
			conn: func() pluginConnector { return NewOpenCodeConnector() },
			setPath: func(path string) func() {
				previous := OpenCodePluginPathOverride
				OpenCodePluginPathOverride = path
				return func() { OpenCodePluginPathOverride = previous }
			},
			prepare: prepareOpenCodeSetupOptsForTest,
			file:    "defenseclaw.js",
		},
		{
			name: "amp",
			conn: func() pluginConnector { return NewAMPConnector() },
			setPath: func(path string) func() {
				previous := AMPPluginPathOverride
				AMPPluginPathOverride = path
				return func() { AMPPluginPathOverride = previous }
			},
			prepare: prepareAmpSetupOptsForTest,
			file:    "defenseclaw.ts",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			pluginPath := filepath.Join(root, "plugins", test.file)
			t.Cleanup(test.setPath(pluginPath))
			conn := test.conn()
			opts := test.prepare(t, SetupOpts{
				DataDir:  filepath.Join(root, "defenseclaw"),
				APIAddr:  "127.0.0.1:18970",
				APIToken: test.name + "-scoped-token",
			})
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			if err := os.RemoveAll(filepath.Join(opts.DataDir, "connector_backups")); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown without a backup: %v", err)
			}
			if _, err := os.Lstat(pluginPath); !os.IsNotExist(err) {
				t.Fatalf("DefenseClaw plugin remains after teardown without a backup: %v", err)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}

			// An older DefenseClaw plugin is recognized by its marker too.
			older := []byte("// defenseclaw-managed-plugin v1\r\nexport default function managed() {}\r\n")
			if err := os.WriteFile(pluginPath, older, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown of an older plugin: %v", err)
			}
			if _, err := os.Lstat(pluginPath); !os.IsNotExist(err) {
				t.Fatalf("older DefenseClaw plugin remains after teardown: %v", err)
			}

			// A managed teardown whose backup holds DefenseClaw's own plugin
			// (one a rolled-back install left before setup captured it)
			// removes it instead of putting it back.
			if err := os.WriteFile(pluginPath, older, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := captureManagedFileBackup(opts.DataDir, test.name, "config", pluginPath); err != nil {
				t.Fatal(err)
			}
			managedOpts := opts
			managedOpts.ManagedEnterprise = true
			if err := conn.Teardown(context.Background(), managedOpts); err != nil {
				t.Fatalf("managed Teardown of a restored DefenseClaw plugin: %v", err)
			}
			if _, err := os.Lstat(pluginPath); !os.IsNotExist(err) {
				t.Fatalf("restored DefenseClaw plugin remains after a managed teardown: %v", err)
			}

			// A file without the marker is not DefenseClaw's.
			foreign := []byte("// operator plugin\n// defenseclaw-managed-plugin v1\nexport default function mine() {}\n")
			if err := os.WriteFile(pluginPath, foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown with an operator file: %v", err)
			}
			if got, err := os.ReadFile(pluginPath); err != nil || string(got) != string(foreign) {
				t.Fatalf("operator file changed by teardown: %q, %v", got, err)
			}

			if runtime.GOOS == "windows" {
				return
			}
			// In a plugin directory others can write, an operator file is
			// still left alone without an error, and a DefenseClaw plugin is
			// reported rather than removed through an untrusted path.
			if err := os.Chmod(filepath.Dir(pluginPath), 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(filepath.Dir(pluginPath), 0o700) })
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown with an operator file in a shared directory: %v", err)
			}
			if err := os.WriteFile(pluginPath, older, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err == nil {
				t.Fatal("Teardown removed a DefenseClaw plugin through an untrusted directory without an error")
			}
			if _, err := os.Lstat(pluginPath); err != nil {
				t.Fatalf("plugin in an untrusted directory: %v", err)
			}
		})
	}
}
