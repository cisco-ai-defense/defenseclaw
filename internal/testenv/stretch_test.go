// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"testing"
	"time"
)

// A run that got the CPU it asked for reads 1; a run the host starved reads
// the ratio, never more than MaxStretch; a missing CPU reading names nothing.
func TestStretchOfNamesTheShortageOfCPU(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wall, cpu time.Duration
		want      float64
	}{
		{"idle", 150 * time.Millisecond, 148 * time.Millisecond, 1},
		{"coarse clock tick", 150 * time.Millisecond, 135 * time.Millisecond, 1},
		{"half the CPU", 150 * time.Millisecond, 75 * time.Millisecond, 2},
		{"a fifth of the CPU", 150 * time.Millisecond, 30 * time.Millisecond, MaxStretch},
		{"no CPU reading", 150 * time.Millisecond, 0, 1},
		{"no wall time", 0, 10 * time.Millisecond, 1},
	} {
		if got := stretchOf(tc.wall, tc.cpu); got != tc.want {
			t.Errorf("%s: stretchOf(%v, %v) = %v, want %v", tc.name, tc.wall, tc.cpu, got, tc.want)
		}
	}
}

// The measurement runs, advances this process CPU clock, and stays in its
// range; a took inside its bound costs no measurement and one far outside
// MaxStretch times the bound never passes.
func TestStretchMeasuresAndLimitsAreBounded(t *testing.T) {
	before, ok := processCPUTime()
	if !ok {
		t.Fatal("no CPU time for this process")
	}
	got := Stretch()
	if after, _ := processCPUTime(); after <= before {
		t.Errorf("the CPU clock of the process did not advance across the measurement: %v then %v", before, after)
	}
	t.Logf("Stretch() = %.2f", got)
	if got < 1 || got > MaxStretch {
		t.Fatalf("Stretch() = %v, want within [1, %v]", got, MaxStretch)
	}
	if !Within(time.Second, 2*time.Second) {
		t.Error("a took inside its bound did not pass")
	}
	if Within(time.Duration(float64(time.Second)*(MaxStretch+0.5)), time.Second) {
		t.Errorf("a took of %.1fx its bound passed", MaxStretch+0.5)
	}
}
