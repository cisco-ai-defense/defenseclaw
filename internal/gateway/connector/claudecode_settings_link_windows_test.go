// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0034: on Windows a per-user ~/.claude/settings.json that is a symbolic
// link failed setup with "settings source is not a regular file", which named
// neither the link nor its target. Setup now refuses it up front, names both
// and says how to fix it; it still changes nothing.
func TestClaudeCodeSettingsLinkOnWindowsIsRefusedNamingLinkAndTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = link
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	err := NewClaudeCodeConnector().checkAgentSettings(SetupOpts{})
	if err == nil {
		t.Fatal("setup accepted a settings.json symbolic link on Windows")
	}
	if !errors.Is(err, ErrAgentConfigRefusal) {
		t.Fatalf("refusal is not an agent-config refusal: %v", err)
	}
	for _, want := range []string{link, target, "symbolic link or junction", "replace the link with the file it points to"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not contain %q", err, want)
		}
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "{}\n" {
		t.Fatalf("link target changed: %q %v", data, readErr)
	}
}

func TestClaudeCodeSettingsReadPathOnWindowsKeepsARegularOrMissingFile(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(regular, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "settings.json")
	for _, path := range []string{regular, missing} {
		got, err := claudeCodeUserSettingsReadPath(path)
		if err != nil || got != path {
			t.Fatalf("claudeCodeUserSettingsReadPath(%q) = %q, %v; want the path unchanged", path, got, err)
		}
	}
}
