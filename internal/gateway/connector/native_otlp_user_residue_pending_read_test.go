// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2021: the SYSTEM guardian reads the take-back-pending marker in a
// directory the account owns every pass. It checked the marker with Lstat and
// then read the path with an unbounded os.ReadFile, so a file swapped in
// after the check (a multi-GB file, a link elsewhere) was read in full. The
// read is now no-follow, bounded and bound to the checked file: a marker
// replaced after the check is not a marker.
func TestNativeOTLPTakeBackPendingMarkerSwappedAfterTheCheckIsNotRead(t *testing.T) {
	dataDir := t.TempDir()
	if err := RecordNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if !NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatal("a marker the take-back wrote is not pending")
	}
	path := filepath.Join(dataDir, "native-otlp-take-back-pending-codex.json")
	large := filepath.Join(dataDir, "large")
	if err := os.WriteFile(large, []byte(`{"connector":"codex","at":"`+strings.Repeat("x", 1<<20)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nativeOTLPTakeBackPendingBeforeRead
	t.Cleanup(func() { nativeOTLPTakeBackPendingBeforeRead = previous })
	nativeOTLPTakeBackPendingBeforeRead = func(string) {
		if err := os.Rename(large, path); err != nil {
			t.Fatal(err)
		}
	}
	if NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatal("a marker replaced after the check by a 1 MiB file was read as pending")
	}
}
