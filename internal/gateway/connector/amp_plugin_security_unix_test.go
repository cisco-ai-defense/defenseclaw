// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAMPSetupRejectsSymlinkPluginTarget(t *testing.T) {
	root := t.TempDir()
	pluginPath := filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim.ts")
	const original = "operator-owned target\n"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, pluginPath); err != nil {
		t.Fatal(err)
	}

	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	err := NewAMPConnector().Setup(context.Background(), SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "must-not-be-written",
	})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Setup error=%v, want symlink rejection", err)
	}
	data, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != original {
		t.Fatalf("symlink target was changed: %q", data)
	}
	if _, statErr := os.Lstat(managedFileBackupPath(
		filepath.Join(root, "defenseclaw"), "amp", "config",
	)); !os.IsNotExist(statErr) {
		t.Fatalf("backup created before destination validation: %v", statErr)
	}
}

func TestAMPSetupRejectsInsecurePluginDirectory(t *testing.T) {
	root := t.TempDir()
	pluginDir := filepath.Join(root, ".config", "amp", "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pluginDir, 0o777); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(pluginDir, "defenseclaw.ts")

	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	err := NewAMPConnector().Setup(context.Background(), SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "must-not-be-written",
	})
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("Setup error=%v, want insecure-directory rejection", err)
	}
	if _, statErr := os.Lstat(pluginPath); !os.IsNotExist(statErr) {
		t.Fatalf("plugin written into insecure directory: %v", statErr)
	}
}

func TestAMPSetupRejectsNonRegularPluginTarget(t *testing.T) {
	root := t.TempDir()
	pluginPath := filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
	if err := os.MkdirAll(pluginPath, 0o700); err != nil {
		t.Fatal(err)
	}

	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	err := NewAMPConnector().Setup(context.Background(), SetupOpts{
		DataDir: filepath.Join(root, "defenseclaw"),
		APIAddr: "127.0.0.1:18970",
	})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Setup error=%v, want non-regular-target rejection", err)
	}
}
