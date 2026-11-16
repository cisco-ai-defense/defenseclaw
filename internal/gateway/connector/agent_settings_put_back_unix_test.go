// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0581: a per-user Claude Code settings.json or Codex config.toml that
// went missing was recreated by setup with DefenseClaw's entries alone, so the
// account's own keys were gone and nothing said so. Setup now puts back the
// copy it kept when the file last set up, before its hooks go in, and leaves
// a notice saying where the file came from; teardown removes the copy.
func TestPerUserSetupPutsBackAMissingClaudeAndCodexSettingsFile(t *testing.T) {
	for _, tc := range []struct {
		name, file, body, userKey string
		conn                      func() Connector
		point                     func(string) func()
	}{
		{
			name: "claudecode", file: "settings.json", userKey: "oo-user-model",
			body: `{"model": "oo-user-model", "permissions": {"allow": ["Bash(ls)"]}}`,
			conn: func() Connector { return NewClaudeCodeConnector() },
			point: func(p string) func() {
				ClaudeCodeSettingsPathOverride = p
				return func() { ClaudeCodeSettingsPathOverride = "" }
			},
		},
		{
			name: "codex", file: "config.toml", userKey: "oo-user-codex",
			body: "model = \"oo-user-codex\"\napproval_policy = \"on-request\"\n[mcp_servers.oo_user]\ncommand = \"true\"\n",
			conn: func() Connector { return NewCodexConnector() },
			point: func(p string) func() {
				previous := CodexConfigPathOverride
				CodexConfigPathOverride = p
				return func() { CodexConfigPathOverride = previous }
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "home", tc.file)
			t.Cleanup(tc.point(path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "api-token"}
			if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			conn := tc.conn()
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("first Setup: %v", err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup over the missing file: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(after), tc.userKey) || !strings.Contains(string(after), filepath.ToSlash(filepath.Join(opts.DataDir, "hooks"))) {
				t.Fatalf("Setup over a missing %s lost the account's keys or the hooks:\n%s", tc.file, after)
			}
			spec, _ := agentConfigSpecFor(tc.name)
			notice, ok := spec.readNotice(opts.DataDir)
			if !ok || notice.Source != AgentConfigFromLastGood || notice.SettingsLost {
				t.Fatalf("notice = %+v %v, want put back from the last good copy", notice, ok)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			for _, leftover := range []string{spec.copyPath(opts.DataDir), spec.noticePath(opts.DataDir)} {
				if _, err := os.Lstat(leftover); !os.IsNotExist(err) {
					t.Fatalf("Teardown left %s (%v)", leftover, err)
				}
			}
		})
	}
}

// A managed install keeps its own setup path for these files: no copy.
func TestManagedSetupKeepsNoClaudeOrCodexSettingsCopy(t *testing.T) {
	spec, _ := agentConfigSpecFor("codex")
	if spec.keepsCopy(SetupOpts{ManagedEnterprise: true}) || !spec.keepsCopy(SetupOpts{}) {
		t.Fatal("the Codex settings copy must be per-user only")
	}
	if AgentConfigStatus("claudecode", SetupOpts{DataDir: t.TempDir()}, time.Time{}, true) != "" {
		t.Fatal("the standalone guardian must not report the Claude Code settings copy")
	}
}
