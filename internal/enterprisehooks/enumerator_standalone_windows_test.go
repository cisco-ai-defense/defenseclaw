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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	testLocalUserSID = "S-1-5-21-1004336348-1177238915-682003330-1001"
	testEntraUserSID = "S-1-12-1-3570884736-1162376387-1447295907-1452683434"
)

func standaloneEnumeratorConfig(connector string) *config.Config {
	return &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Connector: connector},
	}
}

func secureClientEnumeratorConfig(connector string) *config.Config {
	return &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Guardrail:      config.GuardrailConfig{Connector: connector},
	}
}

// injectWindowsProfileList replaces the ProfileList registry walk with rows
// whose homes are real temporary directories.
func injectWindowsProfileList(t *testing.T, homes map[string]string) {
	t.Helper()
	previousSubkeys, previousPath := windowsProfileListSubkeyReader, windowsProfileImagePathReader
	previousLookup := windowsEnrollmentLookupAccountSID
	t.Cleanup(func() {
		windowsProfileListSubkeyReader, windowsProfileImagePathReader = previousSubkeys, previousPath
		windowsEnrollmentLookupAccountSID = previousLookup
	})
	// The injected SIDs are not real accounts on the runner, and a local SID
	// that LookupAccountSid cannot map is a deleted account (GAP-0430): these
	// tests model existing users. A test that needs another answer stubs the
	// lookup after this call.
	windowsEnrollmentLookupAccountSID = func(string) (string, string, error) { return "user", "HOST", nil }
	names := make([]string, 0, len(homes)+3)
	for sid := range homes {
		names = append(names, sid)
	}
	// Principals every real ProfileList carries.
	names = append(names, "S-1-5-18", "S-1-5-19", "S-1-5-20")
	windowsProfileListSubkeyReader = func() ([]string, error) { return names, nil }
	windowsProfileImagePathReader = func(sid string) (string, error) {
		if home, ok := homes[sid]; ok {
			return home, nil
		}
		return `C:\Windows\ServiceProfiles\` + sid, nil
	}
}

func stubMachineWinGet(t *testing.T, versions map[string]string) {
	t.Helper()
	previous := windowsMachineWinGetPackageVersion
	t.Cleanup(func() { windowsMachineWinGetPackageVersion = previous })
	windowsMachineWinGetPackageVersion = func(packageID string) (string, string) {
		if version, ok := versions[packageID]; ok {
			return version, ""
		}
		return "", "no machine-scope WinGet package " + packageID
	}
}

func codexProfile(t *testing.T, version string) string {
	t.Helper()
	home := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex"), version)
	return home
}

func TestEnumerateWindowsStandaloneAdmitsEntraUsersAndDefersNewRows(t *testing.T) {
	stubMachineWinGet(t, nil)
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: codexProfile(t, "0.140.0"),
		testEntraUserSID: codexProfile(t, "0.141.0"),
	})
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 2 {
		t.Fatalf("targets = %+v, want the local and the Entra ID user", manifest.Targets)
	}
	seen := map[string]bool{}
	for _, target := range manifest.Targets {
		seen[target.SID] = true
		if target.Enabled == nil || !*target.Enabled || !target.Deferred {
			t.Fatalf("standalone new row %s: enabled=%v deferred=%t, want enabled and deferred", target.SID, target.Enabled, target.Deferred)
		}
	}
	if !seen[testLocalUserSID] || !seen[testEntraUserSID] {
		t.Fatalf("targets %+v miss the local or Entra ID user", manifest.Targets)
	}
}

func TestEnumerateWindowsSecureClientKeepsLegacyFilterAndRowState(t *testing.T) {
	stubMachineWinGet(t, map[string]string{"OpenAI.Codex": "0.150.0"})
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: codexProfile(t, "0.140.0"),
		testEntraUserSID: codexProfile(t, "0.141.0"),
	})
	var logged []string
	manifest, err := EnumerateWindows(context.Background(), secureClientEnumeratorConfig("codex"), EnumerateOptions{
		Logger: func(subject, reason string) { logged = append(logged, subject+": "+reason) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].SID != testLocalUserSID {
		t.Fatalf("Secure Client targets = %+v, want only the S-1-5-21 user", manifest.Targets)
	}
	if manifest.Targets[0].Deferred {
		t.Fatal("Secure Client new row must keep Deferred=false")
	}
	if !strings.Contains(strings.Join(logged, "\n"), testEntraUserSID+": not an interactive-user SID (S-1-5-21-…)") {
		t.Fatalf("Secure Client must refuse the Entra ID SID with the historical reason; log:\n%s", strings.Join(logged, "\n"))
	}
}

func TestApplyStandaloneRowStatePreservesKnownRows(t *testing.T) {
	enabled := false
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "codex", AgentVersion: "0.131.0", Enabled: &enabled}
	row := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: codexProfile(t, "0.150.0")}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	if !applyStandaloneRowState(&row, previous, nil) {
		t.Fatal("known row must be emitted")
	}
	if row.AgentVersion != "0.131.0" || row.Enabled == nil || *row.Enabled || row.Deferred {
		t.Fatalf("known row = %+v, want the prior state unchanged", row)
	}
}

func writeNativeClaude(t *testing.T, home string, launcherSize int, versions map[string]int) {
	t.Helper()
	bin := filepath.Join(home, ".local", "bin")
	store := filepath.Join(home, ".local", "share", "claude", "versions")
	for _, directory := range []string{bin, store} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "claude.exe"), make([]byte, launcherSize), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, size := range versions {
		if err := os.WriteFile(filepath.Join(store, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscoverWindowsNativeClaudeVersionMatchesTheLauncher(t *testing.T) {
	home := t.TempDir()
	writeNativeClaude(t, home, 4096, map[string]int{"2.1.283": 4096, "2.1.200": 2048, "2.1.999": 1024, "notes.txt": 4096})
	if version, reason := discoverWindowsNativeClaudeVersion(home); version != "2.1.283" {
		t.Fatalf("native version = %q (%s), want 2.1.283", version, reason)
	}

	unmatched := t.TempDir()
	writeNativeClaude(t, unmatched, 4096, map[string]int{"2.1.200": 2048})
	if version, _ := discoverWindowsNativeClaudeVersion(unmatched); version != "" {
		t.Fatalf("launcher without a matching version entry resolved %q, want empty", version)
	}

	crowded := t.TempDir()
	many := map[string]int{}
	for index := 0; index <= windowsNativeClaudeMaxVersionEntries; index++ {
		many[fmt.Sprintf("2.1.%d", index)] = 1
	}
	writeNativeClaude(t, crowded, 1, many)
	if version, _ := discoverWindowsNativeClaudeVersion(crowded); version != "" {
		t.Fatalf("unbounded versions directory resolved %q, want empty", version)
	}
}

func TestStandaloneDiscoveryCoversNativeClaudeAndMachineWinGet(t *testing.T) {
	stubMachineWinGet(t, map[string]string{"OpenAI.Codex": "0.150.0"})

	native := t.TempDir()
	writeNativeClaude(t, native, 512, map[string]int{"2.1.283": 512})
	if version, reason := standaloneWindowsAgentVersionExplain(native, "claudecode"); version != "2.1.283" {
		t.Fatalf("standalone claudecode discovery = %q (%s), want the native version", version, reason)
	}
	// The Secure Client discovery keeps its historical probe set.
	if version, _ := windowsAgentVersionExplain(native, "claudecode"); version != "" {
		t.Fatalf("Secure Client discovery resolved native Claude %q, want empty", version)
	}

	empty := t.TempDir()
	if version, reason := standaloneWindowsAgentVersionExplain(empty, "codex"); version != "0.150.0" {
		t.Fatalf("standalone codex discovery = %q (%s), want the machine WinGet version", version, reason)
	}
	perUser := codexProfile(t, "0.160.0")
	if version, _ := standaloneWindowsAgentVersionExplain(perUser, "codex"); version != "0.160.0" {
		t.Fatalf("per-user install must take precedence, got %q", version)
	}
	if version, reason := standaloneWindowsAgentVersionExplain(empty, "claudecode"); version != "" || !strings.Contains(reason, "Anthropic.ClaudeCode") {
		t.Fatalf("missing everywhere: version=%q reason=%q", version, reason)
	}
}
