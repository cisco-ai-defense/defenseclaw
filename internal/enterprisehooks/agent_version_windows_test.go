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

// TestDiscoverWindowsAgentVersionClaudeCodeBunGlobal covers the
// `bun install -g @anthropic-ai/claude-code` install flavour — the
// probe now walks `%USERPROFILE%\.bun\install\global\node_modules\...`
// in addition to the npm-global path.
func TestDiscoverWindowsAgentVersionClaudeCodeBunGlobal(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".bun", "install", "global", "node_modules", "@anthropic-ai", "claude-code")
	writeWindowsAgentPackageJSON(t, dir, "0.5.9")
	got := discoverWindowsAgentVersion(home, "claudecode")
	if got != "0.5.9" {
		t.Fatalf("bun-global claudecode: got %q, want 0.5.9", got)
	}
}

// TestDiscoverWindowsAgentVersionClaudeCodeYarnGlobal covers the
// Yarn Classic global install still common on legacy hosts.
func TestDiscoverWindowsAgentVersionClaudeCodeYarnGlobal(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Local", "Yarn", "Data", "global", "node_modules", "@anthropic-ai", "claude-code")
	writeWindowsAgentPackageJSON(t, dir, "0.5.10")
	got := discoverWindowsAgentVersion(home, "claudecode")
	if got != "0.5.10" {
		t.Fatalf("yarn-global claudecode: got %q, want 0.5.10", got)
	}
}

// TestDiscoverWindowsAgentVersionCodexBunGlobal + YarnGlobal cover
// the same alternative install channels for codex.
func TestDiscoverWindowsAgentVersionCodexBunGlobal(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".bun", "install", "global", "node_modules", "@openai", "codex")
	writeWindowsAgentPackageJSON(t, dir, "0.42.5")
	got := discoverWindowsAgentVersion(home, "codex")
	if got != "0.42.5" {
		t.Fatalf("bun-global codex: got %q, want 0.42.5", got)
	}
}

func TestDiscoverWindowsAgentVersionCodexYarnGlobal(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Local", "Yarn", "Data", "global", "node_modules", "@openai", "codex")
	writeWindowsAgentPackageJSON(t, dir, "0.42.7")
	got := discoverWindowsAgentVersion(home, "codex")
	if got != "0.42.7" {
		t.Fatalf("yarn-global codex: got %q, want 0.42.7", got)
	}
}

// TestDiscoverWindowsAgentVersionCursorMachineScoped covers the
// Cursor MSI (machine-scoped) install. The probe path is a
// package-level variable stubbed here to a temp fixture; production
// default is `C:\Program Files\Cursor\resources\app\package.json`.
func TestDiscoverWindowsAgentVersionCursorMachineScoped(t *testing.T) {
	prev := windowsMachineScopedCursorPackageJSON
	t.Cleanup(func() { windowsMachineScopedCursorPackageJSON = prev })

	machineRoot := t.TempDir()
	dir := filepath.Join(machineRoot, "Cursor", "resources", "app")
	writeWindowsAgentPackageJSON(t, dir, "1.7.0")
	windowsMachineScopedCursorPackageJSON = filepath.Join(dir, "package.json")

	// Per-user profile is empty — no Programs\cursor install — so the
	// probe must fall through to the machine-scoped candidate.
	got := discoverWindowsAgentVersion(t.TempDir(), "cursor")
	if got != "1.7.0" {
		t.Fatalf("machine-scoped cursor: got %q, want 1.7.0", got)
	}
}

// TestDiscoverWindowsAgentVersionOrderPrefersPerUserOverMachineScoped
// pins the "first match wins" ordering: when both a per-user and a
// machine-scoped install exist, the per-user version is reported.
func TestDiscoverWindowsAgentVersionOrderPrefersPerUserOverMachineScoped(t *testing.T) {
	prev := windowsMachineScopedCursorPackageJSON
	t.Cleanup(func() { windowsMachineScopedCursorPackageJSON = prev })

	home := t.TempDir()
	perUserDir := filepath.Join(home, "AppData", "Local", "Programs", "cursor", "resources", "app")
	writeWindowsAgentPackageJSON(t, perUserDir, "1.6.14")

	machineRoot := t.TempDir()
	machineDir := filepath.Join(machineRoot, "Cursor", "resources", "app")
	writeWindowsAgentPackageJSON(t, machineDir, "1.7.0")
	windowsMachineScopedCursorPackageJSON = filepath.Join(machineDir, "package.json")

	got := discoverWindowsAgentVersion(home, "cursor")
	if got != "1.6.14" {
		t.Fatalf("per-user precedence: got %q, want 1.6.14 (per-user wins over machine 1.7.0)", got)
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

// TestDiscoverWindowsAgentVersionRejectsControlCharsInVersion guards
// the auto-authorization audit line against a user-controlled
// package.json planting a multi-line "version" string that could
// forge additional log entries. Embedded LF / CR / other control
// characters must trip the version validator and cause a silent
// drop.
func TestDiscoverWindowsAgentVersionRejectsControlCharsInVersion(t *testing.T) {
	cases := map[string]string{
		"newline":       "1.2.3\nFAKE audit line",
		"carriage":      "1.2.3\rFAKE",
		"tab":           "1.2.3\tFAKE",
		"null":          "1.2.3\x00FAKE",
		"escape":        "1.2.3\x1b[31mFAKE",
		"del":           "1.2.3\x7fFAKE",
		"c1-nel":        "1.2.3\u0085FAKE", // C1 NEL (Next Line) — Unicode-aware terminals treat this as a line break
		"c1-csi":        "1.2.3\u009bFAKE", // C1 CSI — 8-bit terminal control sequence introducer
		"too-long":      strings.Repeat("9", windowsAgentVersionMaxRunes+1),
		"empty-trimmed": "",
	}
	for name, version := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code")
			writeWindowsAgentPackageJSON(t, dir, version)
			if got := discoverWindowsAgentVersion(home, "claudecode"); got != "" {
				t.Fatalf("hostile version %q: got %q, want empty (drop)", version, got)
			}
		})
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

// TestWindowsAgentVersionExplainRejectsControlCharsInVersion locks in
// that the operator-facing diagnostic path applies the same version
// validator as the primary silent-drop probe. Without this, a
// user-controlled package.json could inject a multi-line "version"
// string into the reason field, which the enumerator eventually
// forwards to the auto-authorization audit line.
func TestWindowsAgentVersionExplainRejectsControlCharsInVersion(t *testing.T) {
	cases := []string{
		"1.2.3\nFAKE audit line",
		"1.2.3\u0085FAKE", // C1 NEL
		"1.2.3\u009bFAKE", // C1 CSI
		"1.2.3\x7fFAKE",   // DEL
	}
	for _, hostile := range cases {
		home := t.TempDir()
		// Write the hostile package.json to ALL candidate paths for
		// codex so that later candidates don't overwrite lastReason
		// with "no codex package.json under this profile".
		for _, dir := range windowsAgentVersionCandidatePaths(home, "codex") {
			writeWindowsAgentPackageJSON(t, filepath.Dir(dir), hostile)
		}
		version, reason := windowsAgentVersionExplain(home, "codex")
		if version != "" {
			t.Fatalf("explain hostile version %q: got %q, want empty", hostile, version)
		}
		if !strings.Contains(reason, "failed validation") && !strings.Contains(reason, "empty version") {
			t.Fatalf("explain hostile version %q: reason %q did not surface a validation-failure diagnostic", hostile, reason)
		}
	}
}
