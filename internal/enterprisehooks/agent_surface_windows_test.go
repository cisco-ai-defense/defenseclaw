//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A profile with only the Claude Code extension (here in the folder the
// user's VSCODE_EXTENSIONS names) is enrolled at the extension's engine
// version, one with only Devin Desktop at its bundled Devin CLI's version;
// the Codex app, which has no engine version, is reported; and
// unverified_versions: refuse refuses the extension. The profile is read
// only under its owner's token, so a signed-out owner or a failed
// impersonation finds nothing.
func TestWindowsStandaloneSurfaceOnlyProfile(t *testing.T) {
	home := t.TempDir()
	extension := filepath.Join(home, "relocated", "anthropic.claude-code-2.1.220-win32-x64")
	if err := os.MkdirAll(extension, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extension, "package.json"), []byte(`{"version":"2.1.220"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "AppData", "Local", "Packages", "OpenAI.Codex_test"), 0o755); err != nil {
		t.Fatal(err)
	}
	devin := filepath.Join(home, "AppData", "Local", "Programs", "Devin")
	page := devinDesktopManPage(filepath.Join(devin, "resources", "app"))
	if err := os.MkdirAll(filepath.Dir(page), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{filepath.Join(devin, "Devin.exe"): "MZ", page: ".TH devin 1  \"devin 3000.10.48 (0)\" \n"} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const sid = "S-1-5-21-1-2-3-1001"
	previousReadAs, previousEnvironment := windowsSurfaceReadAs, windowsUserEnvironment
	var readAsErr error
	impersonated := 0
	windowsSurfaceReadAs = func(owner, profileHome string, fn func() error) error {
		if owner != sid || profileHome != home {
			t.Fatalf("read as %s %s, want %s %s", owner, profileHome, sid, home)
		}
		impersonated++
		if readAsErr != nil {
			return readAsErr
		}
		return fn()
	}
	windowsUserEnvironment = func(owner, name string) string {
		if owner == sid && name == "VSCODE_EXTENSIONS" {
			return `%USERPROFILE%\relocated`
		}
		return ""
	}
	t.Cleanup(func() {
		windowsSurfaceReadAs, windowsUserEnvironment = previousReadAs, previousEnvironment
		SetUnverifiedVersionsPolicy(nil)
	})
	var reported []UnprotectedAgent
	rowContext := windowsStandaloneRowContext{sessionActive: true, user: "u", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	row := func(name string) *ManifestTarget {
		return &ManifestTarget{SID: sid, UserHome: home, Connector: name}
	}

	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext, ""); got != "2.1.220" || len(reported) != 0 {
		t.Fatalf("claudecode extension-only version = %q, reported %+v", got, reported)
	}
	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext, "2.1.300"); got != "2.1.220" || len(reported) != 0 {
		t.Fatalf("claudecode CLI plus older extension version = %q, reported %+v", got, reported)
	}
	if got := windowsStandaloneSurfaceVersion(row("devin"), nil, rowContext, ""); got != "3000.10.48" || len(reported) != 0 {
		t.Fatalf("devin Desktop-only version = %q, reported %+v", got, reported)
	}
	if got := windowsStandaloneSurfaceVersion(row("codex"), nil, rowContext, ""); got != "" || len(reported) != 1 ||
		reported[0].Code != UnprotectedCodeSurfaceUnverified || reported[0].Surface != "desktop" || reported[0].Refusal != "" {
		t.Fatalf("codex app-only version = %q, reported %+v", got, reported)
	}
	SetUnverifiedVersionsPolicy(func(string) string { return "refuse" })
	reported = nil
	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext, ""); got != "" || len(reported) != 1 || reported[0].Refusal != RefusalEnforced {
		t.Fatalf("refused claudecode extension version = %q, reported %+v", got, reported)
	}
	// Next to a CLI the refused extension is still reported; it shares the
	// CLI's hooks, and the gateway refuses the calls that name it.
	reported = nil
	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext, "2.1.300"); got != "2.1.300" || len(reported) != 1 || reported[0].Refusal != RefusalEnforced {
		t.Fatalf("refused claudecode extension next to a CLI = %q, reported %+v", got, reported)
	}
	SetUnverifiedVersionsPolicy(nil)

	reported, readAsErr = nil, errors.New("no active session token")
	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext, ""); got != "" || len(reported) != 1 ||
		reported[0].Code != UnprotectedCodeInstallScanIncomplete {
		t.Fatalf("failed impersonation version = %q, reported %+v", got, reported)
	}
	impersonated, rowContext.sessionActive = 0, false
	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext, ""); got != "" || impersonated != 0 {
		t.Fatalf("signed-out version = %q, impersonated %d times", got, impersonated)
	}
}

func TestWindowsEnrolledCLIReportsExplicitlyOldExtension(t *testing.T) {
	home := t.TempDir()
	extension := filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.100-win32-x64")
	if err := os.MkdirAll(extension, 0o755); err != nil {
		t.Fatal(err)
	}
	const sid = "S-1-5-21-1-2-3-1001"
	previous := windowsSurfaceReadAs
	windowsSurfaceReadAs = func(_, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsSurfaceReadAs = previous })
	var reported []UnprotectedAgent
	row := &ManifestTarget{SID: sid, UserHome: home, Connector: "claudecode"}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	if got := windowsStandaloneSurfaceVersion(row, nil, ctx, "2.1.300"); got != "2.1.300" {
		t.Fatalf("CLI row version = %q, want 2.1.300", got)
	}
	if len(reported) != 1 || reported[0].Code != UnprotectedCodeSurfaceUnverified ||
		reported[0].Version != "2.1.100" || reported[0].Refusal != "" {
		t.Fatalf("old extension beside enrolled CLI = %+v, want one non-refusal warning", reported)
	}
}

func TestWindowsExtensionDirectoryOverflowIsIncomplete(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".vscode", "extensions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < windowsSurfaceMaxEntries-1; i++ {
		path := filepath.Join(root, fmt.Sprintf("unrelated-%04d", i))
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "anthropic.claude-code-2.1.220-win32-x64"), 0o755); err != nil {
		t.Fatal(err)
	}
	const sid = "S-1-5-21-1-2-3-1001"
	previousReadAs := windowsSurfaceReadAs
	windowsSurfaceReadAs = func(_, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsSurfaceReadAs = previousReadAs })
	if surfaces, _, err := discoverWindowsAgentSurfaces(sid, home, "claudecode"); err != nil || len(surfaces) != 1 {
		t.Fatalf("exactly %d entries: surfaces=%+v error=%v", windowsSurfaceMaxEntries, surfaces, err)
	}
	if err := os.Mkdir(filepath.Join(root, "one-more"), 0o755); err != nil {
		t.Fatal(err)
	}
	if surfaces, _, err := discoverWindowsAgentSurfaces(sid, home, "claudecode"); err == nil {
		t.Fatalf("overflow produced no incomplete error: %+v", surfaces)
	}
	var reported []UnprotectedAgent
	row := &ManifestTarget{SID: sid, UserHome: home, Connector: "claudecode"}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	_ = windowsStandaloneSurfaceVersion(row, nil, ctx, "2.1.300")
	if len(reported) != 1 || reported[0].Code != UnprotectedCodeInstallScanIncomplete {
		t.Fatalf("overflow must make signed-in coverage incomplete: %+v", reported)
	}
	// An incomplete root cannot enroll its visible extension, but a complete
	// sibling root must still be inspected and can enroll its own surface.
	reported = nil
	if got := windowsStandaloneSurfaceVersion(row, nil, ctx, ""); got != "" || len(reported) != 1 || reported[0].Code != UnprotectedCodeInstallScanIncomplete {
		t.Fatalf("overflow-only row: version=%q reported=%+v", got, reported)
	}
	old := filepath.Join(home, ".cursor", "extensions", "anthropic.claude-code-2.1.100-win32-x64")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	surfaces, _, err := discoverWindowsAgentSurfaces(sid, home, "claudecode")
	oldObserved := false
	for _, surface := range surfaces {
		oldObserved = oldObserved || surface.Path == old
	}
	if err == nil || !oldObserved {
		t.Fatalf("overflow and complete sibling: surfaces=%+v error=%v", surfaces, err)
	}
	reported = nil
	_ = windowsStandaloneSurfaceVersion(row, nil, ctx, "2.1.300")
	var incomplete, oldSurface bool
	for _, agent := range reported {
		incomplete = incomplete || agent.Code == UnprotectedCodeInstallScanIncomplete
		oldSurface = oldSurface || agent.Code == UnprotectedCodeSurfaceUnverified && agent.Version == "2.1.100"
	}
	if !incomplete || !oldSurface {
		t.Fatalf("want overflow and old sibling findings: %+v", reported)
	}
	known := filepath.Join(home, ".cursor", "extensions", "anthropic.claude-code-2.1.220-win32-x64")
	if err := os.Mkdir(known, 0o755); err != nil {
		t.Fatal(err)
	}
	reported = nil
	if got := windowsStandaloneSurfaceVersion(row, nil, ctx, ""); got != "2.1.220" || len(reported) == 0 || reported[0].Code != UnprotectedCodeInstallScanIncomplete {
		t.Fatalf("complete sibling row: version=%q reported=%+v", got, reported)
	}
}

func TestWindowsClaudeDesktopVersionOverflowIsIncomplete(t *testing.T) {
	home := t.TempDir()
	versions := filepath.Join(home, "AppData", "Roaming", "Claude", "claude-code")
	if err := os.MkdirAll(versions, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < windowsSurfaceMaxEntries; i++ {
		if err := os.Mkdir(filepath.Join(versions, fmt.Sprintf("2.1.%04d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const sid = "S-1-5-21-1-2-3-1001"
	previousReadAs := windowsSurfaceReadAs
	windowsSurfaceReadAs = func(_, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsSurfaceReadAs = previousReadAs })
	if observed, complete, err := discoverWindowsAgentSurfaces(sid, home, "claudecode"); err != nil || len(observed) != 1 || len(complete) != 1 {
		t.Fatalf("exactly %d version folders: observed=%+v complete=%+v err=%v", windowsSurfaceMaxEntries, observed, complete, err)
	}
	if err := os.Mkdir(filepath.Join(versions, "9.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	observed, complete, err := discoverWindowsAgentSurfaces(sid, home, "claudecode")
	if err == nil || len(observed) != 1 || len(complete) != 0 {
		t.Fatalf("overflow must keep a partial observation but no complete surface: observed=%+v complete=%+v err=%v", observed, complete, err)
	}
	var reported []UnprotectedAgent
	row := &ManifestTarget{SID: sid, UserHome: home, Connector: "claudecode"}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	if version := windowsStandaloneSurfaceVersion(row, nil, ctx, ""); version != "" || len(reported) != 1 || reported[0].Code != UnprotectedCodeInstallScanIncomplete {
		t.Fatalf("overflow-only row version=%q reported=%+v", version, reported)
	}
}

func TestWindowsCodexAppPackageOverflowIsIncomplete(t *testing.T) {
	home, programFiles := t.TempDir(), t.TempDir()
	app := filepath.Join(home, "AppData", "Local", "Packages", "OpenAI.Codex_test")
	packages := filepath.Join(programFiles, "WindowsApps")
	for _, dir := range []string{app, packages} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < windowsSurfaceMaxEntries; i++ {
		if err := os.Mkdir(filepath.Join(packages, fmt.Sprintf("OpenAI.Codex_1.0.%04d_x64__test", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const sid = "S-1-5-21-1-2-3-1001"
	previousReadAs, previousProgramFiles := windowsSurfaceReadAs, windowsSurfaceTrustedProgramFiles
	windowsSurfaceReadAs = func(_, _ string, fn func() error) error { return fn() }
	windowsSurfaceTrustedProgramFiles = func() (string, error) { return programFiles, nil }
	t.Cleanup(func() {
		windowsSurfaceReadAs, windowsSurfaceTrustedProgramFiles = previousReadAs, previousProgramFiles
	})
	if observed, complete, err := discoverWindowsAgentSurfaces(sid, home, "codex"); err != nil || len(observed) != 1 || len(complete) != 1 {
		t.Fatalf("exactly %d package folders: observed=%+v complete=%+v err=%v", windowsSurfaceMaxEntries, observed, complete, err)
	}
	if err := os.Mkdir(filepath.Join(packages, "OpenAI.Codex_9.0.0_x64__test"), 0o755); err != nil {
		t.Fatal(err)
	}
	observed, complete, err := discoverWindowsAgentSurfaces(sid, home, "codex")
	if err == nil || len(observed) != 1 || len(complete) != 0 {
		t.Fatalf("overflow must keep a partial observation but no complete surface: observed=%+v complete=%+v err=%v", observed, complete, err)
	}
	var reported []UnprotectedAgent
	row := &ManifestTarget{SID: sid, UserHome: home, Connector: "codex"}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	_ = windowsStandaloneSurfaceVersion(row, nil, ctx, "")
	incomplete := false
	for _, agent := range reported {
		incomplete = incomplete || agent.Code == UnprotectedCodeInstallScanIncomplete
	}
	if !incomplete {
		t.Fatalf("overflow-only Codex app did not report incomplete coverage: %+v", reported)
	}
}

// A native claude.exe whose build Claude Code has not recorded yet (it
// writes .local\share\claude\versions on first start) cannot be enrolled,
// and the account is reported with what is missing instead of being left
// without a row and without a reason (GAP-0597).
func TestWindowsStandaloneNativeClaudeWithoutRecordedBuildSaysWhatIsMissing(t *testing.T) {
	stubWindowsSurfaceReadAs(t)
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "claude.exe"), []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	var reported []UnprotectedAgent
	rowContext := windowsStandaloneRowContext{sessionActive: true, user: "ecw1", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	row := ManifestTarget{SID: "S-1-5-21-1000000001-1000000002-1000000003-1101", UserHome: home, Connector: "claudecode"}
	if applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, rowContext) {
		t.Fatal("a launcher without a recorded build was enrolled")
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Reason, filepath.Join(bin, "claude.exe")) ||
		!strings.Contains(reported[0].Reason, filepath.Join(home, ".local", "share", "claude", "versions")) {
		t.Fatalf("reported %+v, want the launcher and the missing versions folder named", reported)
	}
}
