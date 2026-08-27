// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeWindowsAgentPackageJSON drops a minimal package.json under
// `dir` with the given version. Parent directories are created
// with default (test-scoped) permissions.
func writeWindowsAgentPackageJSON(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	body, err := json.Marshal(map[string]any{
		"name":    "test-agent",
		"version": version,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestDiscoverWindowsAgentVersionReturnsEmptyForUnknownConnector(t *testing.T) {
	home := t.TempDir()
	if got := discoverWindowsAgentVersion(home, "openclaw"); got != "" {
		t.Fatalf("unknown connector: got %q, want empty", got)
	}
}

func TestDiscoverWindowsAgentVersionReturnsEmptyForRelativeHome(t *testing.T) {
	if got := discoverWindowsAgentVersion(`AppData\Local`, "cursor"); got != "" {
		t.Fatalf("relative home: got %q, want empty", got)
	}
}

func TestDiscoverWindowsAgentVersionReturnsEmptyWhenNoCLIInstalled(t *testing.T) {
	home := t.TempDir()
	for _, conn := range []string{"claudecode", "codex", "cursor"} {
		if got := discoverWindowsAgentVersion(home, conn); got != "" {
			t.Fatalf("connector %q on empty home: got %q, want empty (macOS parity)", conn, got)
		}
	}
}

func TestDiscoverWindowsAgentVersionClaudeCode(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code")
	writeWindowsAgentPackageJSON(t, dir, "0.2.3")
	got := discoverWindowsAgentVersion(home, "claudecode")
	if got != "0.2.3" {
		t.Fatalf("claudecode discovery: got %q, want 0.2.3", got)
	}
}

func TestDiscoverWindowsAgentVersionCodex(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex")
	writeWindowsAgentPackageJSON(t, dir, "0.42.0")
	got := discoverWindowsAgentVersion(home, "codex")
	if got != "0.42.0" {
		t.Fatalf("codex discovery: got %q, want 0.42.0", got)
	}
}

func TestDiscoverWindowsAgentVersionCursor(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Local", "Programs", "cursor", "resources", "app")
	writeWindowsAgentPackageJSON(t, dir, "1.6.14")
	got := discoverWindowsAgentVersion(home, "cursor")
	if got != "1.6.14" {
		t.Fatalf("cursor discovery: got %q, want 1.6.14", got)
	}
}

func TestDiscoverWindowsAgentVersionRejectsOversizedPackageJSON(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// One byte over the ceiling — guarantees the size check fires
	// even if the ceiling constant is later widened.
	oversize := make([]byte, windowsAgentVersionMaxBytes+1)
	for i := range oversize {
		oversize[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), oversize, 0o644); err != nil {
		t.Fatalf("write oversize fixture: %v", err)
	}
	if got := discoverWindowsAgentVersion(home, "codex"); got != "" {
		t.Fatalf("oversize package.json: got %q, want empty (drop)", got)
	}
}

func TestDiscoverWindowsAgentVersionRejectsMalformedJSON(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Local", "Programs", "cursor", "resources", "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	if got := discoverWindowsAgentVersion(home, "cursor"); got != "" {
		t.Fatalf("malformed json: got %q, want empty (drop)", got)
	}
}

func TestDiscoverWindowsAgentVersionRejectsEmptyVersionField(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code")
	writeWindowsAgentPackageJSON(t, dir, "  ") // whitespace-only version
	if got := discoverWindowsAgentVersion(home, "claudecode"); got != "" {
		t.Fatalf("whitespace-only version: got %q, want empty (drop)", got)
	}
}

func TestWindowsAgentVersionExplainSurfacesReasons(t *testing.T) {
	home := t.TempDir()
	// Not installed → explain should report "no <connector>
	// package.json under this profile".
	version, reason := windowsAgentVersionExplain(home, "codex")
	if version != "" {
		t.Fatalf("explain unexpectedly returned version %q for empty home", version)
	}
	if !strings.Contains(reason, "codex") {
		t.Fatalf("explain reason %q did not mention connector name", reason)
	}

	// Installed → explain returns the version and empty reason.
	dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex")
	writeWindowsAgentPackageJSON(t, dir, "0.42.0")
	version, reason = windowsAgentVersionExplain(home, "codex")
	if version != "0.42.0" {
		t.Fatalf("explain version: got %q, want 0.42.0", version)
	}
	if reason != "" {
		t.Fatalf("explain reason on success: got %q, want empty", reason)
	}
}
