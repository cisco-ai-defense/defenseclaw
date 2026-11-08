// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func writeConnectorRuntimeFixture(t *testing.T, dataDir string, names ...string) {
	t.Helper()
	for _, rel := range names {
		path := filepath.Join(dataDir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func connectorRuntimeLeft(t *testing.T, dataDir string) map[string]bool {
	t.Helper()
	left := map[string]bool{}
	_ = filepath.WalkDir(dataDir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			rel, _ := filepath.Rel(dataDir, path)
			left[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	return left
}

// GAP-0916: what one machine-scope connector's managed install wrote for an
// account goes; the other connectors' files, the scripts they share and the
// account's own files stay.
func TestRemoveWindowsConnectorUserRuntimeEntriesTakesOnlyTheConnectorsFiles(t *testing.T) {
	dataDir := t.TempDir()
	all := []string{
		"hooks/.hook-cursor.token", "hooks/.hookcfg.cursor", "hooks/.managed-runtime-cursor-0123abcd.json",
		"hooks/.hook-claudecode.token", "hooks/.hookcfg.claudecode", "hooks/claude-code-hook.sh",
		"hooks/.managed-runtime-claudecode-0123abcd.json",
		"hooks/.hook-codex.token", "hooks/.hookcfg.codex", "hooks/.managed-runtime-codex-0123abcd.json",
		"hooks/.hookcfg", "hooks/.hookcfg.lock", "hooks/_hardening.sh", "hooks/inspect-tool.sh",
		"hooks/user-notes.txt", "hooks/.managed-runtime-cursorish-0123abcd.json", "hook_contract_lock.json", "config.yaml",
	}
	writeConnectorRuntimeFixture(t, dataDir, all...)
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for _, tc := range []struct {
		name    string
		removed []string
	}{
		{"cursor", []string{"hooks/.hook-cursor.token", "hooks/.hookcfg.cursor", "hooks/.managed-runtime-cursor-0123abcd.json"}},
		{"claudecode", []string{"hooks/.hook-claudecode.token", "hooks/.hookcfg.claudecode", "hooks/claude-code-hook.sh", "hooks/.managed-runtime-claudecode-0123abcd.json"}},
		{"codex", []string{"hooks/.hook-codex.token", "hooks/.hookcfg.codex", "hooks/.managed-runtime-codex-0123abcd.json"}},
	} {
		leaves, err := windowsConnectorUserRuntimeLeaves(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), tc.name, leaves); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		left := connectorRuntimeLeft(t, dataDir)
		for _, rel := range tc.removed {
			if left[rel] {
				t.Errorf("%s: %s is still there", tc.name, rel)
			}
			delete(left, rel)
		}
		// A second run finds nothing to do.
		if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), tc.name, leaves); err != nil {
			t.Fatalf("%s again: %v", tc.name, err)
		}
	}
	left := connectorRuntimeLeft(t, dataDir)
	want := []string{"hooks/.hookcfg", "hooks/.hookcfg.lock", "hooks/_hardening.sh", "hooks/inspect-tool.sh",
		"hooks/user-notes.txt", "hooks/.managed-runtime-cursorish-0123abcd.json", "hook_contract_lock.json", "config.yaml"}
	if len(left) != len(want) {
		t.Fatalf("left = %v, want exactly %v", left, want)
	}
	for _, rel := range want {
		if !left[rel] {
			t.Errorf("%s was removed", rel)
		}
	}
}

func TestWindowsConnectorUserRuntimeLeavesAreBounded(t *testing.T) {
	for _, name := range []string{"copilot", "opencode", "hermes", "", "unknown"} {
		if WindowsMachineScopeUserRuntimeConnector(name) {
			t.Errorf("%q is not a machine-scope connector", name)
		}
		if _, err := windowsConnectorUserRuntimeLeaves(name); err == nil {
			t.Errorf("%q has no machine-scope user runtime to remove, but its leaves were returned", name)
		}
	}
	leaves, err := windowsConnectorUserRuntimeLeaves("cursor")
	if err != nil || len(leaves) != 2 {
		t.Fatalf("cursor leaves = %v, %v; want the hook config and the scoped token", leaves, err)
	}
}

func TestRemoveWindowsConnectorUserRuntimeLeavesALinkedHooksFolderAsFound(t *testing.T) {
	dataDir, target := t.TempDir(), t.TempDir()
	writeConnectorRuntimeFixture(t, target, ".hook-cursor.token")
	if err := os.Symlink(target, filepath.Join(dataDir, "hooks")); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	leaves, _ := windowsConnectorUserRuntimeLeaves("cursor")
	if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), "cursor", leaves); err == nil {
		t.Fatal("a linked hooks folder was not refused")
	}
	if _, err := os.Stat(filepath.Join(target, ".hook-cursor.token")); err != nil {
		t.Fatalf("a file behind the link was removed: %v", err)
	}
}
