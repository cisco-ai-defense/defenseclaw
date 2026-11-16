// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"
)

// The Windows PowerShell adapters are the hook assets Setup writes
// (connectorHookAdapters, HookScriptNames); a purge owns each of them, so one
// does not stay behind.
func TestManagedUserStateFileOwnsEveryWrittenWindowsAdapter(t *testing.T) {
	var adapters []string
	for _, names := range connectorHookAdapters {
		adapters = append(adapters, names...)
	}
	if len(adapters) == 0 {
		t.Fatal("no Windows adapters are listed")
	}
	for _, name := range adapters {
		if !ManagedUserStateFile("hooks/" + name) {
			t.Errorf("hooks/%s is written by Setup and is not owned", name)
		}
	}
	// The writer set and the shipped PowerShell assets are the same set.
	entries, err := fs.ReadDir(hookFS, "hooks")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".ps1") && !slices.Contains(adapters, entry.Name()) {
			t.Errorf("hooks/%s is a PowerShell asset no Setup writer lists", entry.Name())
		}
	}
}

// Benign twin: a PowerShell file with no Setup writer is the account own, even
// when a hook script of the same stem exists (a script has an adapter only for
// the connectors that register one).
func TestManagedUserStateFileKeepsPowerShellFilesNoSetupWrites(t *testing.T) {
	var adapters []string
	for _, names := range connectorHookAdapters {
		adapters = append(adapters, names...)
	}
	entries, err := fs.ReadDir(hookFS, "hooks")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		stem, ok := strings.CutSuffix(entry.Name(), ".sh")
		if !ok || slices.Contains(adapters, stem+".ps1") {
			continue
		}
		checked++
		if rel := path.Join("hooks", stem+".ps1"); ManagedUserStateFile(rel) {
			t.Errorf("%s is owned but no Setup writes it", rel)
		}
	}
	if checked == 0 {
		t.Fatal("no hook script without an adapter was checked")
	}
	for _, rel := range []string{
		"hooks/personal.ps1", "hooks/inspect-tool.ps1", "hooks/devin-hook.ps1", "hooks/codex-hook.ps1",
		"hooks/cursor-hook.ps1.bak", "hooks/sub/cursor-hook.ps1", "cursor-hook.ps1", "logs/cursor-hook.ps1",
	} {
		if ManagedUserStateFile(rel) {
			t.Errorf("%s is owned but is not a DefenseClaw hook adapter", rel)
		}
	}
}
