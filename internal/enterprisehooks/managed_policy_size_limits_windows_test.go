// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
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
