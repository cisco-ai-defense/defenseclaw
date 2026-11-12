// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadOptionalManagedRuntimeFileRetriesTransientAbsence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.txt")
	wrote := false
	restore := safefile.SetTransientRetrySleepForTest(func(time.Duration) {
		if wrote {
			return
		}
		wrote = true
		if err := os.WriteFile(path, []byte("published body"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(restore)
	data, exists, err := readStableManagedRuntimeFile(path, "optional runtime", true, 128)
	if err != nil || !exists || string(data) != "published body" || !wrote {
		t.Fatalf("read = %q, exists = %t, err = %v, wrote = %t", data, exists, err, wrote)
	}
}

func TestReadOptionalManagedRuntimeFileReportsGenuineAbsence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	restore := safefile.SetTransientRetrySleepForTest(func(time.Duration) {})
	t.Cleanup(restore)
	data, exists, err := readStableManagedRuntimeFile(path, "optional runtime", true, 128)
	if err != nil || exists || data != nil {
		t.Fatalf("read = %q, exists = %t, err = %v", data, exists, err)
	}
}
