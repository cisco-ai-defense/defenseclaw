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

func stubWindowsNativeAgentVersion(t *testing.T, fn func(string, string) string) {
	t.Helper()
	previous := windowsNativeAgentVersion
	windowsNativeAgentVersion = fn
	t.Cleanup(func() { windowsNativeAgentVersion = previous })
}

func writeWindowsNativeAgentCandidate(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir native candidate: %v", err)
	}
	if err := os.WriteFile(path, []byte("signed-pe-fixture"), 0o755); err != nil {
		t.Fatalf("write native candidate: %v", err)
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

func TestDiscoverWindowsAgentVersionClaudeNativeInstallWinsOverNPM(t *testing.T) {
	home := t.TempDir()
	native := filepath.Join(home, ".local", "bin", "claude.exe")
	writeWindowsNativeAgentCandidate(t, native)
	writeWindowsAgentPackageJSON(
		t,
		filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"),
		"2.1.272",
	)
	stubWindowsNativeAgentVersion(t, func(connector, candidate string) string {
		if connector != "claudecode" || candidate != native {
			t.Fatalf("unexpected native probe: connector=%q candidate=%q", connector, candidate)
		}
		return "2.1.301"
	})

	if got := discoverWindowsAgentVersion(home, "claudecode"); got != "2.1.301" {
		t.Fatalf("native Claude discovery: got %q, want 2.1.301", got)
	}
}

func TestDiscoverWindowsAgentVersionCodexStandaloneInstall(t *testing.T) {
	home := t.TempDir()
	native := filepath.Join(home, "AppData", "Local", "Programs", "OpenAI", "Codex", "bin", "codex.exe")
	writeWindowsNativeAgentCandidate(t, native)
	stubWindowsNativeAgentVersion(t, func(connector, candidate string) string {
		if connector == "codex" && candidate == native {
			return "0.162.0"
		}
		return ""
	})

	if got := discoverWindowsAgentVersion(home, "codex"); got != "0.162.0" {
		t.Fatalf("standalone Codex discovery: got %q, want 0.162.0", got)
	}
}

func TestDiscoverWindowsAgentVersionCodexDesktopRuntime(t *testing.T) {
	home := t.TempDir()
	native := filepath.Join(
		home,
		"AppData", "Local", "OpenAI", "Codex", "bin",
		"0123456789abcdef0123456789abcdef",
		"codex.exe",
	)
	writeWindowsNativeAgentCandidate(t, native)
	stubWindowsNativeAgentVersion(t, func(connector, candidate string) string {
		if connector == "codex" && candidate == native {
			return "0.163.0"
		}
		return ""
	})

	if got := discoverWindowsAgentVersion(home, "codex"); got != "0.163.0" {
		t.Fatalf("Codex desktop runtime discovery: got %q, want 0.163.0", got)
	}
}

func TestDiscoverWindowsAgentVersionInvalidNativeCandidateBlocksMetadataFallback(t *testing.T) {
	home := t.TempDir()
	native := filepath.Join(home, ".local", "bin", "claude.exe")
	writeWindowsNativeAgentCandidate(t, native)
	writeWindowsAgentPackageJSON(
		t,
		filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"),
		"2.1.301",
	)
	stubWindowsNativeAgentVersion(t, func(string, string) string { return "" })

	if got := discoverWindowsAgentVersion(home, "claudecode"); got != "" {
		t.Fatalf("unverified native candidate fell through to metadata version %q", got)
	}
}

func TestValidWindowsNativeAgentVersion(t *testing.T) {
	cases := map[string]bool{
		"2.1.301":         true,
		"0.163.0-alpha.1": true,
		"0.163.0+build.4": true,
		"0.163":           false,
		"0.163.0-.":       false,
		"codex-cli 0.1.0": false,
		"0.1.0\r\nextra":  false,
	}
	for value, want := range cases {
		if got := validWindowsNativeAgentVersion(value); got != want {
			t.Errorf("validWindowsNativeAgentVersion(%q) = %v, want %v", value, got, want)
		}
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
