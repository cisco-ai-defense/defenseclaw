// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Review P3 of rel-1-0-10 GAP-1174: the lock beside a removed Kiro file goes
// only when no one holds it. A lock file still there usually belongs to a
// live holder (a release unlinks its own), and unlinking a held one lets a
// second writer lock a new file while the first still writes. An empty lock
// no one holds still goes (GAP-1174).
func TestKiroResidueKeepsALockSomeoneHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), kiroManagedHooksName)
	if err := withFileLock(path, func() error {
		removeKiroFileResidue(path, "/home/u/.defenseclaw/hooks/kiro-hook.sh", false, nil)
		if _, err := os.Lstat(path + ".lock"); err != nil {
			return fmt.Errorf("a held lock was removed: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	removeKiroFileResidue(path, "/home/u/.defenseclaw/hooks/kiro-hook.sh", false, nil)
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("an idle empty lock stayed: %v", err)
	}
}

// Review P3 of rel-1-0-10 GAP-1174: a .bak copy of the defenseclaw agent goes
// only when its hooks run exactly this install's command. A copy whose hook
// runs another data folder's kiro-hook.sh is that install's, and stays.
func TestKiroResidueKeepsABackupCopyOfAnotherInstallsAgent(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, kiroManagedAgentName+".json")
	own := "/home/u/.defenseclaw/hooks/kiro-hook.sh"
	other := "/home/other/.defenseclaw/hooks/kiro-hook.sh"
	copyOf := func(path, command string) {
		t.Helper()
		cfg := map[string]interface{}{"name": kiroManagedAgentName, "hooks": map[string]interface{}{
			"preToolUse": []interface{}{map[string]interface{}{"command": command, "matcher": "*"}},
		}}
		if err := writeJSONObject(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	copyOf(agent+".bak", other)
	copyOf(agent+".bak.1", own)
	before, err := os.ReadFile(agent + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	removeKiroFileResidue(agent, own, true, nil)
	if got, err := os.ReadFile(agent + ".bak"); err != nil || string(got) != string(before) {
		t.Fatalf("the backup copy of another install's agent was removed or changed: %v", err)
	}
	if _, err := os.Lstat(agent + ".bak.1"); !os.IsNotExist(err) {
		t.Fatalf("the backup copy of this install's agent stayed: %v", err)
	}
}
