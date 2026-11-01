// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2065: a small, well-formed file renamed over the marker after its
// checks is not read as the marker. On Windows the owner was read by path
// and os.SameFile of two Lstat results reloads both file IDs by path, so the
// swap went unnoticed there (only the 4 KiB bound stopped the large-file
// case); the checks and the read now use one opened handle.
func TestNativeOTLPTakeBackPendingMarkerSwappedForASmallFileIsNotRead(t *testing.T) {
	dataDir := t.TempDir()
	if err := RecordNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "native-otlp-take-back-pending-codex.json")
	swapped := filepath.Join(dataDir, "swapped")
	if err := os.WriteFile(swapped, []byte(`{"connector":"codex","at":"2026-10-26T00:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nativeOTLPTakeBackPendingBeforeRead
	t.Cleanup(func() { nativeOTLPTakeBackPendingBeforeRead = previous })
	replaced := false
	nativeOTLPTakeBackPendingBeforeRead = func(string) {
		replaced = swapNativeOTLPTakeBackMarkerForTest(t, swapped, path)
	}
	pending := NativeOTLPTakeBackPending(dataDir, "codex")
	if replaced && pending {
		t.Fatal("a small marker renamed over the checked one was read as pending")
	}
	if !replaced && !pending {
		t.Fatal("the checked marker, which could not be replaced, was not read")
	}
}

// swapNativeOTLPTakeBackMarkerForTest renames from over the marker while the
// reader holds it. Windows refuses to replace a file that is open for the
// read (access denied), so the swap the reader guards against cannot happen
// there during the read; it reports false then, and the caller's check that
// a swapped file is not read does not apply.
func swapNativeOTLPTakeBackMarkerForTest(t *testing.T, from, to string) bool {
	t.Helper()
	err := os.Rename(from, to)
	if err == nil {
		return true
	}
	if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
		t.Logf("the marker cannot be replaced while it is read: %v", err)
		return false
	}
	t.Fatal(err)
	return false
}
