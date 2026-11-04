// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A chmod while a read is in flight changes only the change time; the read
// is repeated and returns the stable content instead of failing.
func TestReadRegularFileBoundedRetriesMetadataOnlyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("KEY=value\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	calls := 0
	data, err := readRegularFileBounded(path, 1024, func() {
		calls++
		if calls == 1 {
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err != nil || string(data) != "KEY=value\n" {
		t.Fatalf("read = %q, %v; want the content after one retry", data, err)
	}
	if calls != 2 {
		t.Fatalf("reads = %d, want 2", calls)
	}
}

func TestReadRegularFileBoundedGivesUpOnPersistentMetadataChurn(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("KEY=value\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	modes := []os.FileMode{0o600, 0o640}
	calls := 0
	_, err := readRegularFileBounded(path, 1024, func() {
		if err := os.Chmod(path, modes[calls%2]); err != nil {
			t.Fatal(err)
		}
		calls++
	})
	if err == nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("err = %v, want a changed-while-reading failure", err)
	}
	if calls != readStabilityMetadataRetries {
		t.Fatalf("reads = %d, want %d", calls, readStabilityMetadataRetries)
	}
}
