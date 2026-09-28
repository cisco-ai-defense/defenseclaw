// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const devinTestAdminHookBinary = "/opt/defenseclaw/bin/defenseclaw-hook"

func devinConfigCommands(t *testing.T, path string) []string {
	t.Helper()
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	var commands []string
	hooks := devinHooksObject(path, cfg)
	for _, event := range devinHookEvents {
		groups, _ := hooks[event].([]interface{})
		for _, raw := range groups {
			group, _ := raw.(map[string]interface{})
			entries, _ := group["hooks"].([]interface{})
			for _, rawEntry := range entries {
				entry, _ := rawEntry.(map[string]interface{})
				if command, _ := entry["command"].(string); command != "" {
					commands = append(commands, event+"="+command)
				}
			}
		}
	}
	return commands
}

// A Unix standalone managed Devin install registers the administrator-owned
// hook binary in managed mode, as the machine-policy connectors do, so the
// foreign-hook guard runs for Devin and failures follow the managed
// fail-closed mode. The earlier per-user devin-hook.sh entry is DefenseClaw's
// own and is replaced; teardown removes the managed command even when the
// caller's options do not name the binary.
func TestDevinUnixStandaloneRegistersTheAdministratorHookCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Unix standalone command")
	}
	previous := DevinHooksPathOverride
	DevinHooksPathOverride = ""
	t.Cleanup(func() { DevinHooksPathOverride = previous })
	home := t.TempDir()
	config := filepath.Join(home, ".config", "devin", "config.json")
	earlier := SetupOpts{
		DataDir:           filepath.Join(home, ".defenseclaw"),
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok-test",
		ConfigHome:        filepath.Dir(config),
		HookFailMode:      "closed",
		ManagedEnterprise: true,
	}
	conn := NewDevinConnector()
	if err := conn.Setup(context.Background(), earlier); err != nil {
		t.Fatalf("earlier Setup: %v", err)
	}
	script := filepath.Join(earlier.DataDir, "hooks", "devin-hook.sh")
	if got := conn.hookCommand(earlier); got != script {
		t.Fatalf("without the admin binary the command stays the script: %q", got)
	}

	current := earlier
	current.ForeignHookGuardBinary = devinTestAdminHookBinary
	want := "'" + devinTestAdminHookBinary + "' hook --connector devin --enterprise-managed"
	if got := conn.hookCommand(current); got != want {
		t.Fatalf("managed command = %q, want %q", got, want)
	}
	if err := conn.Setup(context.Background(), current); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	commands := devinConfigCommands(t, config)
	if len(commands) != len(devinHookEvents) {
		t.Fatalf("want one command per event, got %v", commands)
	}
	for _, command := range commands {
		if !strings.HasSuffix(command, "="+want) {
			t.Fatalf("an event keeps another command: %v", commands)
		}
	}
	if present, err := OwnedHooksPresent(conn, current); err != nil || !present {
		t.Fatalf("managed registration present = %v, %v", present, err)
	}
	// The earlier rendering no longer verifies, so the guardian repairs a
	// host that still runs the script.
	if present, err := OwnedHooksPresent(conn, earlier); err != nil || present {
		t.Fatalf("the script rendering must not verify against the managed config: %v, %v", present, err)
	}

	if err := conn.Teardown(context.Background(), earlier); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(current); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if body, err := os.ReadFile(config); err == nil && strings.Contains(string(body), "defenseclaw-hook") {
		t.Fatalf("teardown left the managed command: %s", body)
	}
}

// Every other install keeps its command: per-user, and Windows (which
// already registers the administrator-owned binary for Devin).
func TestDevinManagedCommandOnlyForUnixStandalone(t *testing.T) {
	home := t.TempDir()
	perUser := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), ForeignHookGuardBinary: devinTestAdminHookBinary}
	conn := NewDevinConnector()
	if got, want := conn.hookCommandForOS("linux", perUser), filepath.Join(perUser.DataDir, "hooks", "devin-hook.sh"); got != want {
		t.Fatalf("per-user command = %q, want %q", got, want)
	}
	managedOpts := perUser
	managedOpts.ManagedEnterprise = true
	if got := devinManagedHookCommand("windows", managedOpts); got != "" {
		t.Fatalf("Windows must keep its Devin command, got %q", got)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the Linux and macOS commands take an absolute Unix path, which is not absolute on Windows")
	}
	if got := devinManagedHookCommand("darwin", managedOpts); !strings.Contains(got, "hook --connector devin --enterprise-managed") {
		t.Fatalf("macOS standalone command = %q", got)
	}
	managedOpts.ForeignHookGuardBinary = "relative/defenseclaw-hook"
	if got := devinManagedHookCommand("linux", managedOpts); got != "" {
		t.Fatalf("a relative binary must never be registered, got %q", got)
	}
}
