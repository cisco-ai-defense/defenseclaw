//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRootOwnedAgentConfigFilesNamesTheVendorFilesRootWrote(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root caller never sees root-owned agent config")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	owned := map[string]bool{}
	for _, rel := range []string{".claude/settings.json", ".codex/config.toml", ".copilot/hooks/defenseclaw.json", ".cursor/hooks.json"} {
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The cursor file stays the account's: the benign twin.
		owned[path] = rel != ".cursor/hooks.json"
	}
	old := agentConfigOwnerUID
	t.Cleanup(func() { agentConfigOwnerUID = old })
	agentConfigOwnerUID = func(info fs.FileInfo) (uint32, bool) {
		for path, root := range owned {
			if known, err := os.Lstat(path); err == nil && os.SameFile(info, known) && root {
				return 0, true
			}
		}
		return uint32(os.Getuid()), true
	}
	got := RootOwnedAgentConfigFiles(filepath.Join(home, ".defenseclaw"))
	want := []string{
		filepath.Join(home, ".claude/settings.json"),
		filepath.Join(home, ".codex/config.toml"),
		filepath.Join(home, ".copilot/hooks/defenseclaw.json"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("root-owned agent config = %v, want %v", got, want)
	}
}

func TestRootOwnedAgentConfigFilesLeavesAnAccountOwnedHomeAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root caller never sees root-owned agent config")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := RootOwnedAgentConfigFiles(filepath.Join(home, ".defenseclaw")); len(got) != 0 {
		t.Fatalf("account-owned agent config listed: %v", got)
	}
}
