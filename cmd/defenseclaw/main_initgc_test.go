// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"runtime/debug"
	"runtime/metrics"
	"testing"
)

// gcCyclesBeforeMain is the number of collections that ran while this
// binary's packages initialized; TestMain reads it before anything else.
var gcCyclesBeforeMain uint64

func TestMain(m *testing.M) {
	sample := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(sample)
	gcCyclesBeforeMain = sample[0].Value.Uint64()
	debug.SetGCPercent(100)
	os.Exit(m.Run())
}

// GAP-0050: the one-line install's Windows Claude Code PreToolUse handler
// starts this binary as the launcher guard on every tool call, and it
// initializes the whole CLI first (about 45 MB of package-init allocations).
// With the collector on, six or seven collections ran before main, half the
// guard's start-up CPU. The early packages before initgc allocate under the
// 4 MB first goal, so at most two collections may run before it.
func TestGatewayPackageInitRunsAlmostNoCollections(t *testing.T) {
	if gcCyclesBeforeMain > 2 {
		t.Fatalf("%d garbage collections ran while the gateway's packages initialized, want at most 2", gcCyclesBeforeMain)
	}
}
