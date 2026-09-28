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
	"strings"
	"testing"
)

// Hermes prints its version on stderr when stdout is not a terminal; the
// enumerator reported "no hermes installation found" for an installed agent.
func TestExecUnixAgentVersionFallsBackToStderr(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hermes")
	body := "#!/bin/sh\necho \"Hermes Agent v0.21.5+2581.g74dc4ac (2026.9.24)\" >&2\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, dir, ""); got != "0.21.5+2581.g74dc4ac" {
		t.Fatalf("version = %q", got)
	}
	stdout := filepath.Join(dir, "codex")
	if err := os.WriteFile(stdout, []byte("#!/bin/sh\necho codex-cli 0.157.1\necho noise 9.9.9 >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), stdout, dir, ""); got != "0.157.1" {
		t.Fatalf("stdout version must win: %q", got)
	}
}

// Hermes needs a writable state directory even for --version, and the
// enumerator sees homes read-only; the probe relocates its state into a
// private scratch directory that is removed afterwards.
func TestExecUnixAgentVersionGivesStatefulAgentsAScratchDir(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "scratch-path")
	script := filepath.Join(dir, "hermes")
	body := "#!/bin/sh\n[ -n \"$HERMES_HOME\" ] && touch \"$HERMES_HOME/lock\" || exit 1\necho \"$HERMES_HOME\" > " + marker + "\necho \"Hermes Agent v0.21.5\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, dir, "HERMES_HOME"); got != "0.21.5" {
		t.Fatalf("version = %q", got)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	scratch := strings.TrimSpace(string(data))
	if scratch == "" || strings.HasPrefix(scratch, dir) {
		t.Fatalf("scratch dir = %q", scratch)
	}
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Fatalf("scratch dir %s was not removed", scratch)
	}
}

// OpenHands needs about 11 s to answer --version; its uv tool environment
// names the version without running it.
func TestDiscoverUnixAgentVersionReadsUVToolMetadata(t *testing.T) {
	home := t.TempDir()
	dist := filepath.Join(home, ".local", "share", "uv", "tools", "openhands", "lib", "python3.12", "site-packages", "openhands-1.16.0.dist-info")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(dist), "openhands_sdk-1.21.0.dist-info")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, reason := DiscoverUnixAgentVersion(context.Background(), home, "openhands", false); got != "1.16.0" {
		t.Fatalf("version = %q (%s)", got, reason)
	}
}

// A prerelease that ends in "v" must survive extraction; the root parent
// compared the extracted token with the worker's answer and dropped
// "1.2.0-dev" as "1.2.0-de".
func TestExtractUnixAgentVersionKeepsTrailingV(t *testing.T) {
	for line, want := range map[string]string{
		"opencode 1.2.0-dev":                     "1.2.0-dev",
		"1.2.0-dev":                              "1.2.0-dev",
		"v1.4.2":                                 "1.4.2",
		"amp (v0.9.1-rev)":                       "0.9.1-rev",
		"codex-cli 0.142.0":                      "0.142.0",
		"2.1.187 (Claude Code)":                  "2.1.187",
		"Hermes Agent v0.21.5+2581.g74dc4ac (x)": "0.21.5+2581.g74dc4ac",
		"no version here":                        "",
	} {
		if got := ExtractUnixAgentVersion(line); got != want {
			t.Errorf("ExtractUnixAgentVersion(%q) = %q, want %q", line, got, want)
		}
	}
	if !ValidUnixAgentVersion("1.2.0-dev") || ValidUnixAgentVersion("$(id)") || ValidUnixAgentVersion("v1.2.0") {
		t.Fatal("ValidUnixAgentVersion must accept exactly the metadata version form")
	}
}

func writeTestPackage(t *testing.T, dir, name, version string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"` + name + `","version":"` + version + `"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Agents installed with a Node version manager, a custom npm prefix, pnpm
// or Volta were never found, so no row was written and the per-user
// connector ran with no DefenseClaw hook.
func TestDiscoverUnixAgentVersionFindsVersionManagerInstalls(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("extended discovery runs only in the per-user worker, never as root")
	}
	origPrefixes := machinePrefixes
	machinePrefixes = func() []string { return nil }
	SetStandaloneUnix(true)
	t.Cleanup(func() { machinePrefixes = origPrefixes; SetStandaloneUnix(false) })
	home := t.TempDir()
	// nvm: the newest Node that has the package wins.
	writeTestPackage(t, filepath.Join(home, ".nvm", "versions", "node", "v20.1.0", "lib", "node_modules", "opencode-ai"), "opencode-ai", "0.9.0")
	writeTestPackage(t, filepath.Join(home, ".nvm", "versions", "node", "v22.11.0", "lib", "node_modules", "opencode-ai"), "opencode-ai", "1.2.0-dev")
	// fnm, asdf and mise Node installs.
	writeTestPackage(t, filepath.Join(home, ".local", "share", "fnm", "node-versions", "v22.0.0", "installation", "lib", "node_modules", "@github", "copilot"), "@github/copilot", "1.0.3")
	writeTestPackage(t, filepath.Join(home, ".asdf", "installs", "nodejs", "22.3.0", "lib", "node_modules", "@ampcode", "cli"), "@ampcode/cli", "0.0.170")
	writeTestPackage(t, filepath.Join(home, ".local", "share", "mise", "installs", "node", "22.4.0", "lib", "node_modules", "@openai", "codex"), "@openai/codex", "0.160.0")
	for connector, want := range map[string]string{"opencode": "1.2.0-dev", "copilot": "1.0.3", "amp": "0.0.170", "codex": "0.160.0"} {
		if got, reason := DiscoverUnixAgentVersion(context.Background(), home, connector, false); got != want {
			t.Errorf("%s version = %q (%s), want %q", connector, got, reason, want)
		}
	}

	// A custom npm prefix from ~/.npmrc, pnpm's global store and Volta's
	// per-package image.
	for name, layout := range map[string]func(home string) string{
		"npmrc": func(home string) string {
			if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte("fund=false\nprefix=${HOME}/tools/npm\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, "tools", "npm", "lib", "node_modules", "@github", "copilot")
		},
		"pnpm": func(home string) string {
			return filepath.Join(home, ".local", "share", "pnpm", "global", "5", "node_modules", "@github", "copilot")
		},
		"volta": func(home string) string {
			return filepath.Join(home, ".volta", "tools", "image", "packages", "@github", "copilot", "lib", "node_modules", "@github", "copilot")
		},
	} {
		other := t.TempDir()
		writeTestPackage(t, layout(other), "@github/copilot", "1.0.4")
		if got, reason := DiscoverUnixAgentVersion(context.Background(), other, "copilot", false); got != "1.0.4" {
			t.Errorf("%s layout: copilot version = %q (%s)", name, got, reason)
		}
	}

	// The --version fallback and the worker PATH see the nvm bin dir.
	bin := filepath.Join(home, ".nvm", "versions", "node", "v22.11.0", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "devin"), []byte("#!/bin/sh\necho 'devin 2026.1.2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, reason := DiscoverUnixAgentVersion(context.Background(), home, "devin", true); got != "2026.1.2" {
		t.Fatalf("devin under nvm: %q (%s)", got, reason)
	}
	found := false
	for _, dir := range unixAgentDiscoveryDirs(home) {
		found = found || dir == bin
	}
	if !found {
		t.Fatalf("the nvm bin directory must be searched: %v", unixAgentDiscoveryDirs(home))
	}

	// Outside the standalone worker (the Secure Client guardian runs the
	// installer as root) the search stays the original fixed list and
	// never reads the home.
	SetStandaloneUnix(false)
	want := []string{
		filepath.Join(home, ".local", "bin"), filepath.Join(home, ".npm-global", "bin"), filepath.Join(home, ".bun", "bin"),
		filepath.Join(home, ".opencode", "bin"), filepath.Join(home, "bin"),
	}
	if got := unixAgentDiscoveryDirs(home); strings.Join(got, ":") != strings.Join(want, ":") {
		t.Fatalf("non-standalone search dirs changed: %v", got)
	}
	if got, _ := DiscoverUnixAgentVersion(context.Background(), home, "opencode", false); got != "" {
		t.Fatalf("non-standalone discovery must not search version managers: %q", got)
	}
}

func TestUserNPMRCPrefix(t *testing.T) {
	home := t.TempDir()
	for content, want := range map[string]string{
		"prefix=~/.npm-packages\n":            filepath.Join(home, ".npm-packages"),
		"prefix = \"/opt/team/npm\"\n":        "/opt/team/npm",
		"prefix=$HOME/a\nprefix=${HOME}/b\n":  filepath.Join(home, "b"),
		"prefix=relative/dir\n":               "",
		"prefix=/\n":                          "",
		"registry=https://registry.example\n": "",
	} {
		if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := userNPMRCPrefix(home); got != want {
			t.Errorf("userNPMRCPrefix(%q) = %q, want %q", content, got, want)
		}
	}
}
