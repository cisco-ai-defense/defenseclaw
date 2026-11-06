//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestAtomicFileAlreadyMatchesRetriesFirstWindowsNameLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	body := []byte("managed\n")
	if err := atomicWriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	parked := path + ".parked"
	if err := os.Rename(path, parked); err != nil {
		t.Fatal(err)
	}
	var restored bool
	var restoreErr error
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
		if !restored {
			restored = true
			restoreErr = os.Rename(parked, path)
		}
	}))
	matched := atomicFileAlreadyMatches(path, body, 0o600)
	if !restored || restoreErr != nil {
		t.Fatalf("retry did not restore the fixture: restored = %v, err = %v", restored, restoreErr)
	}
	if !matched {
		t.Fatal("matching file was treated as changed after a first lookup miss")
	}
}
