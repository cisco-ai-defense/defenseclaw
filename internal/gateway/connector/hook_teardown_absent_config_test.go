// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Teardown (the managed uninstall runs it for every enrolled user) must not
// create an agent's hooks file for a user who never had one. The JSON and
// YAML readers read a missing file as an empty document, and teardown
// wrote that document back, so an uninstall left "{}" in ~/.cursor/hooks.json,
// user.
func TestHookTeardownDoesNotCreateAMissingAgentConfig(t *testing.T) {
	overrides := map[string]*string{
		"cursor":      &CursorHooksPathOverride,
		"antigravity": &AntigravityHooksPathOverride,
		"devin":       &DevinHooksPathOverride,
		"copilot":     &CopilotHooksPathOverride,
	}
	absent := func(t *testing.T, path string) {
		t.Helper()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			body, _ := os.ReadFile(path)
			t.Fatalf("teardown created %s (%v): %q", path, err, body)
		}
		if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("teardown created the folder %s (%v)", filepath.Dir(path), err)
		}
	}
	for _, conn := range []*hookOnlyConnector{
		NewCursorConnector(),
		NewAntigravityConnector(),
		NewDevinConnector(),
		NewCopilotConnector(),
	} {
		t.Run(conn.Name(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent", "hooks.json")
			ptr := overrides[conn.Name()]
			prev := *ptr
			*ptr = path
			t.Cleanup(func() { *ptr = prev })
			opts := SetupOpts{
				DataDir:      filepath.Join(t.TempDir(), ".defenseclaw"),
				APIAddr:      "127.0.0.1:18970",
				APIToken:     "tok-test",
				WorkspaceDir: t.TempDir(),
			}
			if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("teardown: %v", err)
			}
			absent(t, path)
		})
	}

	// Copilot loads every *.json in its hooks folder, so an empty document an
	// earlier teardown left in DefenseClaw's own file is removed.
	t.Run("copilot leftover", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hooks", "defenseclaw.json")
		prev := CopilotHooksPathOverride
		CopilotHooksPathOverride = path
		t.Cleanup(func() { CopilotHooksPathOverride = prev })
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		opts := SetupOpts{DataDir: filepath.Join(t.TempDir(), ".defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: t.TempDir()}
		if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := NewCopilotConnector().Teardown(context.Background(), opts); err != nil {
			t.Fatalf("teardown: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			body, _ := os.ReadFile(path)
			t.Fatalf("teardown left %s (%v): %q", path, err, body)
		}
	})

	// Hermes keeps its YAML config under its own custody; the removal step
	// itself must not create the file either.
	t.Run("hermes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hermes", "config.yaml")
		conn := NewHermesConnector()
		if err := conn.removeConfigEntries(path, conn.hookCommand(SetupOpts{DataDir: t.TempDir()}), SetupOpts{}); err != nil {
			t.Fatalf("remove Hermes hooks: %v", err)
		}
		absent(t, path)
	})
}

// GAP-0650: a teardown that finds nothing of DefenseClaw's in a user's agent
// config leaves the file as the user has it, bytes and mode. Claude Code and
// Codex rewrote such a file 0644 -> 0600 (Claude Code also reformatted it),
// and the JSON hook connectors dropped an empty hooks object the user had.
func TestTeardownLeavesAConfigWithoutDefenseClawEntriesAsItIs(t *testing.T) {
	cases := []struct {
		conn  func() Connector
		point *string
		name  string
		body  string
	}{
		{func() Connector { return NewClaudeCodeConnector() }, &ClaudeCodeSettingsPathOverride, "settings.json", "{\"env\":{\"EDITOR\":\"vi\"}}\n"},
		{func() Connector { return NewCodexConnector() }, &CodexConfigPathOverride, "config.toml", "model = \"gpt-5\"\n"},
		{func() Connector { return NewCursorConnector() }, &CursorHooksPathOverride, "hooks.json", "{\"version\":1,\"hooks\":{}}\n"},
		{func() Connector { return NewAntigravityConnector() }, &AntigravityHooksPathOverride, "hooks.json", "{\"hooks\":{}}\n"},
	}
	for _, tc := range cases {
		conn := tc.conn()
		t.Run(conn.Name(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			prev := *tc.point
			*tc.point = path
			t.Cleanup(func() { *tc.point = prev })
			opts := SetupOpts{DataDir: filepath.Join(t.TempDir(), ".defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
			if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("teardown: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != tc.body {
				t.Fatalf("teardown rewrote %s: %q (%v), want %q", tc.name, after, err, tc.body)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
				t.Fatalf("teardown changed the mode of %s to %v, want 0644", tc.name, info.Mode().Perm())
			}
		})
	}
}
