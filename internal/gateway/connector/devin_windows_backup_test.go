//go:build windows

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

// GAP-1932: on Windows, a Devin backup captured while the account still held
// an earlier enrollment's DefenseClaw hooks (its own backup gone) must not
// leave those hooks behind after teardown.
func TestDevinWindowsManagedTeardownRemovesHooksARestoredBackupPutBack(t *testing.T) {
	previous := DevinHooksPathOverride
	DevinHooksPathOverride = ""
	t.Cleanup(func() { DevinHooksPathOverride = previous })
	home := t.TempDir()
	config := filepath.Join(home, "AppData", "Roaming", "devin", "config.json")
	opts := SetupOpts{
		DataDir:           filepath.Join(home, ".defenseclaw"),
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok-test",
		ConfigHome:        filepath.Dir(config),
		HookFailMode:      "closed",
		ManagedEnterprise: true,
	}
	conn := NewDevinConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if commands := devinConfigCommands(t, config); len(commands) == 0 {
		t.Fatalf("Setup registered no hooks in %s", config)
	}
	if err := os.RemoveAll(filepath.Join(opts.DataDir, "connector_backups")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over the earlier hooks: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if commands := devinConfigCommands(t, config); len(commands) != 0 {
		t.Fatalf("teardown left DefenseClaw's Devin hooks: %v", commands)
	}
	if remaining, err := OwnedHookConfigReferences(conn, opts); err != nil || len(remaining) != 0 {
		t.Fatalf("owned references after teardown = %v, %v", remaining, err)
	}
}

// GAP-1932: the uninstall runs from a maintenance copy, so the Devin hooks
// the managed install registered with the Program Files launcher are not the
// running binary's command; teardown still removes them.
func TestDevinWindowsTeardownRemovesTheStandaloneLauncherHooks(t *testing.T) {
	managedBinary := canonicalStandaloneWindowsHookBinary()
	if managedBinary == "" {
		t.Skip("no trusted Program Files root")
	}
	previous := DevinHooksPathOverride
	DevinHooksPathOverride = ""
	t.Cleanup(func() { DevinHooksPathOverride = previous })
	home := t.TempDir()
	config := filepath.Join(home, "AppData", "Roaming", "devin", "config.json")
	opts := SetupOpts{
		DataDir:           filepath.Join(home, ".defenseclaw"),
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok-test",
		ConfigHome:        filepath.Dir(config),
		HookFailMode:      "closed",
		ManagedEnterprise: true,
	}
	conn := NewDevinConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	running, standalone := conn.hookCommand(opts), windowsDevinBashHookCommand(managedBinary)
	if running == standalone {
		t.Skip("the test binary is the standalone launcher")
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(strings.ReplaceAll(string(data), running, standalone)), 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := devinConfigReferencesHook(config, devinOwnedHookCommands(opts, running)...); err != nil || !present {
		t.Fatalf("the standalone launcher hooks must count as DefenseClaw's: %v, %v", present, err)
	}
	if err := os.RemoveAll(filepath.Join(opts.DataDir, "connector_backups")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if commands := devinConfigCommands(t, config); len(commands) != 0 {
		t.Fatalf("teardown left the standalone launcher hooks: %v", commands)
	}
}
