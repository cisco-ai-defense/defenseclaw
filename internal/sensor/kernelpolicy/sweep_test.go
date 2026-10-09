// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0047: a state write that its process left mid-way (the helper exits on
// purpose when the manifest changes) leaves safefile's temp file behind; the
// next start removes the old ones, and never a write that may be in flight
// or another file.
func TestStartRemovesTheTempFilesOfInterruptedWrites(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	write := func(name string, age time.Duration) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-age)
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
		return path
	}
	stale := write(".safefile-tetragon-state.json-1911788627", time.Hour)
	staleEmpty := write(".safefile-tetragon-state.json-3021624034", 2*time.Hour)
	inFlight := write(".safefile-tetragon-pause-12345", time.Minute)
	state := write("tetragon-state.json", time.Hour)
	other := write(".tetragon-notes", time.Hour)
	sweepInterruptedWrites(dir, now, nil)
	for _, gone := range []string{stale, staleEmpty} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", filepath.Base(gone), err)
		}
	}
	for _, kept := range []string{inFlight, state, other} {
		if _, err := os.Lstat(kept); err != nil {
			t.Errorf("%s was removed: %v", filepath.Base(kept), err)
		}
	}
}
