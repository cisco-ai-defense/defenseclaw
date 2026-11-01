// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procprobe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-2101: under a /proc mounted subset=pid there is no /proc/stat, so the
// probe had no boot instant and left every StartedAt unset. The instant now
// comes from the clocks there; a directory that is no process table still
// gives the zero time.
func TestBootInstantFromClockUnderSubsetPID(t *testing.T) {
	clock := func() (int64, bool) { return 1_760_000_000, true }
	root := t.TempDir()
	if got := bootInstantFrom(root, clock); !got.IsZero() {
		t.Fatalf("no process table: got %s, want zero", got)
	}
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self", "stat"), []byte("1 (x) S 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := bootInstantFrom(root, clock); !got.Equal(time.Unix(1_760_000_000, 0)) {
		t.Fatalf("subset=pid: got %s", got)
	}
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 0\nbtime 1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := bootInstantFrom(root, clock); !got.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("full /proc: got %s, want btime", got)
	}
}
