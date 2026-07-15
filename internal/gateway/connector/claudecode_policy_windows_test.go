//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestClaudeCodeManagedSettingsRootUsesProgramFilesKnownFolder(t *testing.T) {
	previous := claudeCodeWindowsProgramFilesRoot
	t.Cleanup(func() { claudeCodeWindowsProgramFilesRoot = previous })

	knownRoot := t.TempDir()
	claudeCodeWindowsProgramFilesRoot = func() (string, error) { return knownRoot, nil }
	t.Setenv("ProgramFiles", filepath.Join(t.TempDir(), "attacker-controlled"))

	got, err := claudeCodePlatformManagedSettingsRoot()
	if err != nil {
		t.Fatalf("resolve managed settings root: %v", err)
	}
	want := filepath.Join(knownRoot, "ClaudeCode")
	if got != want {
		t.Fatalf("managed settings root = %q, want trusted Known Folder path %q", got, want)
	}
}

func TestClaudeCodeManagedSettingsRootFailsClosedOnKnownFolderError(t *testing.T) {
	previous := claudeCodeWindowsProgramFilesRoot
	t.Cleanup(func() { claudeCodeWindowsProgramFilesRoot = previous })
	claudeCodeWindowsProgramFilesRoot = func() (string, error) {
		return "", errors.New("known folder unavailable")
	}

	if _, err := claudeCodePlatformManagedSettingsRoot(); err == nil {
		t.Fatal("managed settings root succeeded after Known Folder resolution failed")
	}
}
