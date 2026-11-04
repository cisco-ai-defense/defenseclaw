//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/codesig"
)

// cowork-1-0-8 GAP-0057: the Windows status names each Claude Desktop data
// folder of an account with the newest engine build in it and whether that
// build's Authenticode signature verifies; a folder without a build is
// listed with none, and a missing folder is not listed.
func TestWindowsClaudeDesktopFoldersNameTheNewestBuildAndItsTrust(t *testing.T) {
	home := t.TempDir()
	write := func(parts ...string) string {
		path := filepath.Join(append([]string{home}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("MZ"), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("AppData", "Roaming", "Claude", "claude-code", "2.1.300", "claude.exe")
	signed := write("AppData", "Roaming", "Claude", "claude-code", "2.1.317", "b1", "claude.exe")
	unsigned := write("AppData", "Local", "Claude-3p", "claude-code", "2.1.317", "claude.exe")
	if err := os.MkdirAll(filepath.Join(home, "AppData", "Local", "Claude-Data", "claude_abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	verify := func(path string, publishers []string) codesig.Result {
		if len(publishers) == 0 {
			t.Fatalf("no publishers for %s", path)
		}
		if strings.EqualFold(path, signed) {
			return codesig.Result{Verified: true, Version: "2.1.317.0"}
		}
		return codesig.Result{Reason: path + " is not signed"}
	}
	folders, err := windowsClaudeDesktopFolders(home, verify)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]ClaudeDesktopFolder{}
	for _, folder := range folders {
		byPath[strings.ToLower(folder.Path)] = folder
	}
	if len(folders) != 3 {
		t.Fatalf("folders = %+v", folders)
	}
	roaming := byPath[strings.ToLower(filepath.Join(home, "AppData", "Roaming", "Claude"))]
	if roaming.Deployment != "1p" || roaming.EngineVersion != "2.1.317" || roaming.Unverified != "" || !strings.EqualFold(roaming.EnginePath, signed) {
		t.Fatalf("Roaming Claude = %+v", roaming)
	}
	thirdParty := byPath[strings.ToLower(filepath.Join(home, "AppData", "Local", "Claude-3p"))]
	if thirdParty.Deployment != "3p" || thirdParty.EngineVersion != "2.1.317" || !strings.Contains(thirdParty.Unverified, unsigned+" is not signed") {
		t.Fatalf("Claude-3p = %+v", thirdParty)
	}
	msix := byPath[strings.ToLower(filepath.Join(home, "AppData", "Local", "Claude-Data", "claude_abc"))]
	if msix.Deployment != "1p" || msix.EngineVersion != "" || msix.Unverified != "" {
		t.Fatalf("Claude-Data = %+v", msix)
	}
}
