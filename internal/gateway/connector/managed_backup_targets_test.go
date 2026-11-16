// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestManagedFileBackupTargetsForConnectorFiltersAndValidates(t *testing.T) {
	dataDir := t.TempDir()
	write := func(name, logical, target string) string {
		t.Helper()
		path := managedFileBackupPath(dataDir, name, logical)
		if err := writeManagedFileBackup(path, managedFileBackup{
			Version: managedBackupVersion, Connector: name, LogicalName: logical, Path: target,
			PristineSHA256: managedBackupMissingHash,
		}); err != nil {
			t.Fatal(err)
		}
		return path
	}
	want := filepath.Join(dataDir, "sample-old", "config.toml")
	write("codex", "config.toml", want)
	write("hermes", "config.yaml", filepath.Join(dataDir, "unrelated", "config.yaml"))
	got, err := ManagedFileBackupTargetsForConnector(dataDir, "codex")
	if err != nil || !reflect.DeepEqual(got, []string{want}) {
		t.Fatalf("connector targets = %v, %v", got, err)
	}
	if _, err := ManagedFileBackupTargetsForConnector(dataDir, "../other"); err == nil {
		t.Fatal("accepted a connector path outside its backup folder")
	}
	corrupt := write("codex", "other.toml", filepath.Join(dataDir, "other"))
	if err := os.WriteFile(corrupt, []byte(strings.Repeat("x", 5)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ManagedFileBackupTargetsForConnector(dataDir, "codex"); err == nil {
		t.Fatal("ignored an unreadable receipt for the requested connector")
	}
}

func TestEditedPluginTeardownKeepsOperatorEditAndReceipt(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = ""
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	home := testenv.PrivateTempDir(t)
	conn := NewOpenCodeConnector()
	opts := prepareOpenCodeSetupOptsForTest(t, SetupOpts{
		DataDir: filepath.Join(home, ".defenseclaw"), APIAddr: "127.0.0.1:18970",
		APIToken: strings.Repeat("a", 64), HookFailMode: "closed",
	})
	if err := WithUserHomeDir(home, func() error { return conn.Setup(context.Background(), opts) }); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	original, err := os.ReadFile(plugin)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte(nil), original...), []byte("\n// operator edit\n")...)
	if err := os.WriteFile(plugin, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WithUserHomeDir(home, func() error { return conn.Teardown(context.Background(), opts) }); err != nil {
		t.Fatalf("ordinary edited-plugin teardown must leave it for the operator: %v", err)
	}
	if data, err := os.ReadFile(plugin); err != nil || !bytes.Equal(data, edited) {
		t.Fatalf("operator edit changed: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "opencode", "config")); err != nil {
		t.Fatalf("edited plugin receipt lost: %v", err)
	}
}

func TestCleanupConfigPathsForConnectorIncludesPluginWithoutReceipt(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = ""
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	home := t.TempDir()
	var paths []string
	if err := WithUserHomeDir(home, func() error {
		paths = CleanupConfigPathsForConnector(NewOpenCodeConnector(), SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	if !reflect.DeepEqual(paths, []string{want}) {
		t.Fatalf("plugin path = %v, want %s", paths, want)
	}
}
