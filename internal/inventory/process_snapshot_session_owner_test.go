// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import "testing"

// rel-1-0-2 GAP-0618: the snapshot says when a process's owner SID is the
// session's signed-in account rather than its own token's, so a process
// started in that session as another account is not taken for the session
// account's.
func TestWindowsSnapshotSaysWhenTheOwnerIsTheSessionAccount(t *testing.T) {
	procs, err := collectWindowsSnapshot(fakeWindowsSnapshotReader{entries: []windowsProcessEntry{
		{PID: 40, Comm: "codex.exe", SessionOwnerID: "S-1-5-21-1-2-3-1001"},
		{PID: 41, Comm: "codex.exe", SessionOwnerID: "S-1-5-21-1-2-3-1001", SessionOwnerFromSession: true},
	}})
	if err != nil || len(procs) != 2 {
		t.Fatalf("snapshot = %+v, %v", procs, err)
	}
	if procs[0].SessionOwnerFromSession || !procs[1].SessionOwnerFromSession {
		t.Fatalf("session owner provenance = %v, %v", procs[0].SessionOwnerFromSession, procs[1].SessionOwnerFromSession)
	}
}
