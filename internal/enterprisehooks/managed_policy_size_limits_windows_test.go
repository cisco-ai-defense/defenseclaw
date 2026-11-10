// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The managed Claude Code policy holds the guarded Windows form of all 29 hook
// events (about 76 KiB), the state record a few lines. Reading the policy under
// the state record's 64 KiB bound made every install, verify and removal of the
// managed policy refuse its own file as an unsafe artifact.
func TestManagedPolicySnapshotUsesThePolicyBoundNotTheStateBound(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, windowsClaudeManagedPolicyFile)
	body := bytes.Repeat([]byte("x"), windowsClaudeManagedStateLimit+12<<10)
	if err := os.WriteFile(policy, body, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotWindowsManagedPolicy(policy)
	if err != nil || !snapshot.existed || !bytes.Equal(snapshot.data, body) {
		t.Fatalf("policy of %d bytes: existed=%v err=%v", len(body), snapshot.existed, err)
	}
	if _, err := snapshotWindowsManagedState(policy); err == nil {
		t.Fatal("a state record over its own bound was accepted")
	}
	huge := bytes.Repeat([]byte("x"), windowsClaudeManagedPolicyLimit+1)
	if err := os.WriteFile(policy, huge, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotWindowsManagedPolicy(policy); err == nil {
		t.Fatal("a policy over its bound was accepted")
	}
}

// The policy a managed Windows install writes, every hook event wrapped by the
// guard, is read under the state record bound too: the installed file is well
// under it. With one wrapper argument to a line it rendered to 105 KB and the
// managed install ended 1603 "guardian did not publish fresh required
// coverage" (GAP-1050).
func TestInstalledWindowsClaudePolicyFitsTheStateBound(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed managed policy: %d bytes, state bound %d", info.Size(), windowsClaudeManagedStateLimit)
	if info.Size() > windowsClaudeManagedStateLimit*7/8 {
		t.Fatalf("installed managed policy is %d bytes, want well under the %d byte state bound", info.Size(), windowsClaudeManagedStateLimit)
	}
	if _, err := snapshotWindowsManagedFileWithLimit(fixture.policyPath, windowsClaudeManagedStateLimit); err != nil {
		t.Fatalf("the policy is refused under the state bound: %v", err)
	}
}
