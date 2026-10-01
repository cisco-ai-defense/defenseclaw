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
	"os"
	"path/filepath"
	"testing"
)

// A profile with only the Claude Code extension is enrolled at the
// extension's engine version, one with only Devin Desktop at its bundled
// Devin CLI's version; the Codex app, which has no engine version,
// is reported; and unverified_versions: refuse refuses the extension.
func TestWindowsStandaloneSurfaceOnlyProfile(t *testing.T) {
	home := t.TempDir()
	extension := filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.220-win32-x64")
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
	for path, data := range map[string]string{filepath.Join(devin, "Devin.exe"): "MZ", page: ".TH devin 1  \"devin 3000.4.25 (0)\" \n"} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var reported []UnprotectedAgent
	rowContext := windowsStandaloneRowContext{user: "u", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	row := func(name string) *ManifestTarget {
		return &ManifestTarget{SID: "S-1-5-21-1-2-3-1001", UserHome: home, Connector: name}
	}
	t.Cleanup(func() { SetUnverifiedVersionsPolicy(nil) })

	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext); got != "2.1.220" || len(reported) != 0 {
		t.Fatalf("claudecode extension-only version = %q, reported %+v", got, reported)
	}
	if got := windowsStandaloneSurfaceVersion(row("devin"), nil, rowContext); got != "3000.4.25" || len(reported) != 0 {
		t.Fatalf("devin Desktop-only version = %q, reported %+v", got, reported)
	}
	if got := windowsStandaloneSurfaceVersion(row("codex"), nil, rowContext); got != "" || len(reported) != 1 ||
		reported[0].Code != UnprotectedCodeSurfaceUnverified || reported[0].Surface != "desktop" || reported[0].Refusal != "" {
		t.Fatalf("codex app-only version = %q, reported %+v", got, reported)
	}
	SetUnverifiedVersionsPolicy(func(string) string { return "refuse" })
	reported = nil
	if got := windowsStandaloneSurfaceVersion(row("claudecode"), nil, rowContext); got != "" || len(reported) != 1 || reported[0].Refusal != RefusalEnforced {
		t.Fatalf("refused claudecode extension version = %q, reported %+v", got, reported)
	}
}
