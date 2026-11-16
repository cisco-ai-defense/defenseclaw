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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// uninstall --purge kept the per-user install's binaries and the launcher
// links into ~/.defenseclaw, which the purge left dangling. For a folder
// that holds no own install (its .venv and installer state are gone), the
// purge removes managed entries and every DefenseClaw entry in ~/.local/bin,
// keeps saved account originals, and leaves no dangling link;
// the account's own tools stay. A folder with the install's .venv is the
// account's own install and is kept (rel-1-0-6 GAP-0484,
// purge_fresh_own_install_unix_test.go).
func TestPurgeUserStateRemovesPerUserBinariesAndLinks(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	binDir := filepath.Join(home, ".local", "bin")
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, path string) {
		t.Helper()
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(body string) string {
		sum := sha256.Sum256([]byte(body))
		return hex.EncodeToString(sum[:])
	}

	// ~/.defenseclaw as the enrollment leaves it, after the per-user install
	// that put the binaries below went: no config.yaml, .env, audit.db,
	// previous/, .venv or installer/, which mean an install the account made
	// of its own and keep the folder as it is (GAP-0727, GAP-0484).
	write(filepath.Join(dataDir, "hooks", "claude-code-hook.sh"), "#!/bin/bash\n# defenseclaw-managed-hook v5\n", 0o700)
	write(filepath.Join(dataDir, "foreign-hooks-backup", "cursor", "hooks.json"), "{}", 0o600)

	// ~/.local/bin as install.sh leaves it, plus the account's own tools.
	write(filepath.Join(binDir, "defenseclaw-gateway"), "gateway", 0o755)
	write(filepath.Join(binDir, "defenseclaw-acp"), "acp", 0o755)
	// GAP-0571: the hook helpers and the Linux sensor helper go too.
	for _, name := range []string{"defenseclaw-hook-post", "defenseclaw-hook-user", "defenseclaw-sensor-helper"} {
		write(filepath.Join(binDir, name), name, 0o755)
	}
	link(filepath.Join(dataDir, ".venv", "bin", "defenseclaw"), filepath.Join(binDir, "defenseclaw"))
	link(filepath.Join(dataDir, ".venv", "bin", "skill-scanner"), filepath.Join(binDir, "skill-scanner"))
	link("../../.defenseclaw/.venv/bin/mcp-scanner", filepath.Join(binDir, "mcp-scanner"))
	write(filepath.Join(binDir, "uv"), "uv-binary", 0o755)
	write(filepath.Join(binDir, "uvx"), "uvx-updated-by-the-user", 0o755)
	write(filepath.Join(binDir, "defenseclaw-uv.sha256"),
		digest("uv-binary")+"  uv\n"+digest("uvx-binary")+"  uvx\n", 0o644)
	write(filepath.Join(binDir, ".defenseclaw-source-root"), "/src", 0o644)
	write(filepath.Join(binDir, ".defenseclaw-install-custody", "old"), "x", 0o600)
	write(filepath.Join(home, ".defenseclaw-install-custody", "old"), "x", 0o600)
	// The account's own: a pip-installed litellm, a link elsewhere, a tool.
	write(filepath.Join(binDir, "litellm"), "#!/usr/bin/python3\n", 0o755)
	write(filepath.Join(home, "venv", "bin", "mcp-scanner-api"), "#!/bin/sh\n", 0o755)
	link(filepath.Join(home, "venv", "bin", "mcp-scanner-api"), filepath.Join(binDir, "mcp-scanner-api"))
	write(filepath.Join(binDir, "rg"), "ripgrep", 0o755)

	opts := InstallOptions{
		UserHome: home,
		OwnerUID: os.Getuid(),
		OwnerGID: os.Getgid(),
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := PurgeUserState(context.Background(), opts); err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dataDir, "foreign-hooks-backup", "cursor", "hooks.json")); err != nil || string(got) != "{}" {
		t.Fatalf("the saved account hook changed: %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".defenseclaw-install-custody")); !os.IsNotExist(err) {
		t.Fatalf("the legacy custody folder stayed: %v", err)
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
		// No dangling link stays.
		if _, err := os.Stat(filepath.Join(binDir, entry.Name())); err != nil {
			t.Fatalf("%s is left dangling: %v", entry.Name(), err)
		}
	}
	sort.Strings(left)
	if got, want := strings.Join(left, ","), "litellm,mcp-scanner-api,rg,uvx"; got != want {
		t.Fatalf("~/.local/bin holds %s, want %s", got, want)
	}

	// A rerun after ~/.defenseclaw went still removes what the first run
	// could not reach, and a missing ~/.local/bin is not an error.
	write(filepath.Join(binDir, "defenseclaw-gateway"), "gateway", 0o755)
	link(filepath.Join(dataDir, ".venv", "bin", "defenseclaw"), filepath.Join(binDir, "defenseclaw"))
	if _, err := PurgeUserState(context.Background(), opts); err != nil {
		t.Fatalf("rerun PurgeUserState: %v", err)
	}
	for _, name := range []string{"defenseclaw-gateway", "defenseclaw"} {
		if _, err := os.Lstat(filepath.Join(binDir, name)); !os.IsNotExist(err) {
			t.Fatalf("rerun left %s: %v", name, err)
		}
	}
	if err := os.RemoveAll(filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeUserState(context.Background(), opts); err != nil {
		t.Fatalf("PurgeUserState without ~/.local/bin: %v", err)
	}
}

// The purge removed the binaries but left the ~/.local/bin (and ~/.local)
// the per-user install had made, empty (dc-ubuntu-eh). Like the per-user
// uninstall --all --binaries, an emptied ~/.local/bin goes, and ~/.local
// when that leaves it empty; one that still holds anything stays.
func TestRemoveUserBinariesRemovesTheEmptiedLocalBin(t *testing.T) {
	skipIfRoot(t)
	for _, keep := range []string{"", ".local/share/opencode/log"} {
		home := newTestHome(t)
		binDir := filepath.Join(home, ".local", "bin")
		if err := os.MkdirAll(binDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte("gateway"), 0o755); err != nil {
			t.Fatal(err)
		}
		if keep != "" {
			if err := os.MkdirAll(filepath.Join(home, filepath.FromSlash(keep)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := RemoveUserBinaries(home, filepath.Join(home, ".defenseclaw"), os.Getuid()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(binDir); !os.IsNotExist(err) {
			t.Fatalf("keep %q: the emptied ~/.local/bin stayed: %v", keep, err)
		}
		_, err := os.Lstat(filepath.Join(home, ".local"))
		if keep == "" && !os.IsNotExist(err) {
			t.Fatalf("the emptied ~/.local stayed: %v", err)
		}
		if keep != "" && err != nil {
			t.Fatalf("~/.local with other content must stay: %v", err)
		}
	}
}
