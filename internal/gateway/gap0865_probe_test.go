// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !race

package gateway

import (
	"testing"
	"time"
)

// GAP-0865: every call the gateway answers ends in an fsynced journal and
// audit write. On a box whose disk other test binaries keep busy the baseline
// of the real path doubled with every core idle, the CPU probe read quiet, and
// the run failed instead of being inconclusive. The probe now times the disk
// the same way.
func TestGAP0865BoxProbeSeesABusyDisk(t *testing.T) {
	quietCPU := openLoopProbe{share: 1.0, pressure: 0}
	for _, tc := range []struct {
		name    string
		sync    time.Duration
		starved bool
	}{
		{"quiet disk", time.Millisecond, false},
		{"just under the limit", openLoopProbeMaxSync - time.Microsecond, false},
		{"busy disk", 40 * time.Millisecond, true},
		{"at the limit", openLoopProbeMaxSync, true},
	} {
		reading := quietCPU
		reading.sync = tc.sync
		if got := (openLoopProbes{reading}).starved(); got != tc.starved {
			t.Errorf("%s: starved = %v, want %v", tc.name, got, tc.starved)
		}
	}
	// A reading that could not time the disk (0) never marks a box starved.
	if (openLoopProbes{quietCPU}).starved() {
		t.Error("a reading without a disk time was read as starved")
	}
}

// The probe reads the real disk of the test run and answers well under the
// limit on a quiet one; it must at least work (the temp dir is writable).
func TestGAP0865SyncLatencyIsMeasured(t *testing.T) {
	took, ok := openLoopSyncLatency()
	if !ok {
		t.Fatal("the disk probe could not write and sync a file in the temp directory")
	}
	if took <= 0 {
		t.Fatalf("median write+fsync = %v", took)
	}
}
