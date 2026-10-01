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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// An editor extension is found with its engine version when the vendor
// bundles the CLI at the extension version (Claude Code), with only a host
// version otherwise (Codex), and a host app launcher is never executed.
func TestDiscoverUnixAgentSurfacesReadsExtensionsAndNeverRunsHostApps(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("surface discovery runs only in the per-user worker, never as root")
	}
	origPrefixes, origGOOS := machinePrefixes, unixSurfaceGOOS
	machinePrefixes = func() []string { return nil }
	unixSurfaceGOOS = "linux"
	SetStandaloneUnix(true)
	t.Cleanup(func() { machinePrefixes, unixSurfaceGOOS = origPrefixes, origGOOS; SetStandaloneUnix(false) })
	home := t.TempDir()
	extensions := filepath.Join(home, ".vscode", "extensions")
	writeTestPackage(t, filepath.Join(extensions, "anthropic.claude-code-2.1.219-linux-x64"), "claude-code", "2.1.219")
	writeTestPackage(t, filepath.Join(extensions, "anthropic.claude-code-2.1.220-linux-x64"), "claude-code", "2.1.220")
	writeTestPackage(t, filepath.Join(extensions, "openai.chatgpt-26.5908.31748-linux-x64"), "chatgpt", "26.5908.31748")
	marker := filepath.Join(home, "ran")
	launcher := filepath.Join(home, ".local", "bin", "antigravity")
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\ntouch '"+marker+"'\necho 1.2.3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	claude := DiscoverUnixAgentSurfaces(context.Background(), home, "claudecode", true)
	if len(claude) != 1 || claude[0].Host != "vscode" || claude[0].EngineVersion != "2.1.220" {
		t.Fatalf("claudecode surfaces = %+v", claude)
	}
	codex := DiscoverUnixAgentSurfaces(context.Background(), home, "codex", true)
	if len(codex) != 1 || codex[0].EngineVersion != "" || codex[0].HostVersion != "26.5908.31748" {
		t.Fatalf("codex surfaces = %+v", codex)
	}
	ide := DiscoverUnixAgentSurfaces(context.Background(), home, "antigravity", true)
	if len(ide) != 1 || ide[0].Surface != connector.HostSurfaceDesktop || ide[0].EngineVersion != "" {
		t.Fatalf("antigravity surfaces = %+v", ide)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "antigravity", true); version != "" {
		t.Fatalf("antigravity CLI version = %q from the IDE launcher", version)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a host app launcher was executed")
	}
}

// A Linux user with only Devin Desktop (an unpacked tarball) is enrolled at
// the version the bundled Devin CLI's man page names; nothing is run.
func TestDiscoverUnixDevinDesktopReadsBundledCLIVersion(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("surface discovery runs only in the per-user worker, never as root")
	}
	origGOOS := unixSurfaceGOOS
	unixSurfaceGOOS = "linux"
	t.Cleanup(func() { unixSurfaceGOOS = origGOOS })
	home := t.TempDir()
	page := devinDesktopManPage(filepath.Join(home, "Devin", "resources", "app"))
	if err := os.MkdirAll(filepath.Dir(page), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(page, []byte(".ie \\n(.g .ds Aq \\(aq\n.el .ds Aq '\n.TH devin 1  \"devin 3000.4.25 (fcf7ba39)\" \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	surfaces := DiscoverUnixAgentSurfaces(context.Background(), home, "devin", true)
	if len(surfaces) != 1 || surfaces[0].Host != "devin-desktop" || surfaces[0].EngineVersion != "3000.4.25" {
		t.Fatalf("devin surfaces = %+v", surfaces)
	}
	if got := admitSurfaces("devin", connector.UnverifiedVersionsReport, surfaces).rowVersion(""); got != "3000.4.25" {
		t.Fatalf("Desktop-only row version = %q", got)
	}
}
