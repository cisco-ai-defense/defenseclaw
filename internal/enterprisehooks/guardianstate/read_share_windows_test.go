// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package guardianstate

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A reader of a replaced state file must share deletion with the writer.
// Holding a delete-capable handle makes os.Open fail on Windows; the state
// reader should still see the current body through its own shared handle.
func TestReadStateSharesDeletionWithAConcurrentFileHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-guardian.state")
	if err := os.WriteFile(path, []byte(StateReady+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if got := ReadState(path); got != StateReady {
		t.Fatalf("state with concurrent file handle = %q, want %q", got, StateReady)
	}
}

func TestReadStateReadsAnOrdinaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-guardian.state")
	if err := os.WriteFile(path, []byte(StateWaitingForTargets+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(path); got != StateWaitingForTargets {
		t.Fatalf("ordinary state = %q, want %q", got, StateWaitingForTargets)
	}
}
