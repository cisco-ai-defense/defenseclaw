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

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-4 RB1-1: an account with its own Claude Code install is enrolled
// while the machine policy covers Claude Code, so the enrollment writes the
// blocker over its hook script, and its ~/.claude/settings.json still runs
// that script. The purge keeps the install (GAP-0727) but not the blocker:
// otherwise every Claude Code tool call stays blocked on a computer that is
// no longer managed. Everything else stays byte for byte.
func TestPurgeUserStateKeptRemovesTheEnrollmentClaudeBlocker(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	settings := filepath.Join(home, ".claude", "settings.json")
	kept := map[string]string{
		filepath.Join(dataDir, "config.yaml"):            "gateway: {}\n",
		filepath.Join(dataDir, ".env"):                   "SAMPLE_KEY=placeholder\n",
		filepath.Join(dataDir, "audit.db"):               "sqlite",
		filepath.Join(dataDir, "claudecode_backup.json"): "{}",
		settings: `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + script + `"}]}]}}`,
	}
	for path, body := range kept {
		writePurgeTestFile(t, path, body)
	}
	writePurgeTestFile(t, script, PersonalClaudeHookBlocker)

	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Kept || summary.Data {
		t.Fatalf("summary = %+v, want the account's own install kept", summary)
	}
	if _, err := os.Lstat(script); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the enrollment's Claude Code blocker is still in place after the purge: %v", err)
	}
	for path, body := range kept {
		if got, err := os.ReadFile(path); err != nil || string(got) != body {
			t.Fatalf("the purge changed %s: %q %v", path, got, err)
		}
	}
}

// Only the exact blocker goes: the account's own script, a changed copy and
// a link to the blocker stay.
func TestRemovePersonalClaudeHookBlockerRemovesOnlyTheExactBlocker(t *testing.T) {
	skipIfRoot(t)
	for _, tc := range []struct {
		name, body string
		link, want bool
	}{
		{name: "blocker", body: PersonalClaudeHookBlocker, want: true},
		{name: "changed blocker", body: PersonalClaudeHookBlocker + "\n"},
		{name: "personal hook", body: "#!/bin/bash\n# defenseclaw-managed-hook v3\nexec defenseclaw-hook claude-code\n"},
		{name: "link to the blocker", body: PersonalClaudeHookBlocker, link: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := filepath.Join(newTestHome(t), ".defenseclaw")
			script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
			written := script
			if tc.link {
				written = filepath.Join(dataDir, "blocker.sh")
			}
			writePurgeTestFile(t, written, tc.body)
			if tc.link {
				if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(written, script); err != nil {
					t.Fatal(err)
				}
			}
			removed, err := RemovePersonalClaudeHookBlocker(dataDir)
			if err != nil || removed != tc.want {
				t.Fatalf("RemovePersonalClaudeHookBlocker = %t, %v; want %t", removed, err, tc.want)
			}
			_, statErr := os.Lstat(script)
			if gone := errors.Is(statErr, os.ErrNotExist); gone != tc.want {
				t.Fatalf("script gone = %t (%v), want %t", gone, statErr, tc.want)
			}
		})
	}
	if removed, err := RemovePersonalClaudeHookBlocker(filepath.Join(newTestHome(t), ".defenseclaw")); removed || err != nil {
		t.Fatalf("missing script: %t, %v", removed, err)
	}
}

// GAP-1904/GAP-1905: a ~/.defenseclaw/hooks folder (or script) the account
// cannot read, for example made by root with sudo, holds no blocker the
// account wrote: the unblock is not a failure, so a managed uninstall
// completes and the guardian's cleanup pass stays clean. The folder stays.
func TestRemovePersonalClaudeHookBlockerSkipsWhatTheAccountCannotRead(t *testing.T) {
	skipIfRoot(t)
	for _, tc := range []struct {
		name  string
		chmod func(hooks, script string) string
	}{
		{"unreadable hooks folder", func(hooks, _ string) string { return hooks }},
		{"unreadable blocker script", func(_, script string) string { return script }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := filepath.Join(newTestHome(t), ".defenseclaw")
			hooks := filepath.Join(dataDir, "hooks")
			script := filepath.Join(hooks, "claude-code-hook.sh")
			writePurgeTestFile(t, script, PersonalClaudeHookBlocker)
			locked := tc.chmod(hooks, script)
			if err := os.Chmod(locked, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
			removed, err := RemovePersonalClaudeHookBlocker(dataDir)
			if err != nil || removed {
				t.Fatalf("RemovePersonalClaudeHookBlocker = %t, %v; want false, nil", removed, err)
			}
			if err := os.Chmod(locked, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(script); err != nil {
				t.Fatalf("the unreadable blocker was changed: %v", err)
			}
		})
	}
}
