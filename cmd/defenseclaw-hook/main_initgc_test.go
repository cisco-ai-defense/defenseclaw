// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime/debug"
	"runtime/metrics"
	"testing"

	"github.com/defenseclaw/defenseclaw/cmd/internal/hookpriority"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// gcCyclesBeforeMain is the number of collections that ran while this
// binary's packages initialized; TestMain reads it before anything else.
var gcCyclesBeforeMain uint64

// recordInitGC reads the collections package init ran and turns the
// collector back on for the tests, as main does.
func recordInitGC() {
	sample := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(sample)
	gcCyclesBeforeMain = sample[0].Value.Uint64()
	debug.SetGCPercent(100)
}

// GAP-0050: every hook and launcher-guard start initializes the whole CLI
// (about 45 MB of package-init allocations). With the collector on, six or
// seven collections ran before main, half the start-up CPU; a 60-way
// parallel read on an 8-processor Windows host starts 120 such processes.
// The early packages before initgc allocate under the 4 MB first goal, so at
// most two collections may run before it.
func TestHookPackageInitRunsAlmostNoCollections(t *testing.T) {
	if gcCyclesBeforeMain > 2 {
		t.Fatalf("%d garbage collections ran while the hook's packages initialized, want at most 2", gcCyclesBeforeMain)
	}
}

// The priority package spells the launcher-guard subcommand out because it
// initializes before the connector package; the two must agree.
func TestHookPriorityKnowsTheLauncherGuardSubcommand(t *testing.T) {
	if hookpriority.LauncherGuardSubcommand != connector.ClaudeCodeLauncherGuardSubcommand {
		t.Fatalf("hookpriority launcher guard %q, connector %q", hookpriority.LauncherGuardSubcommand, connector.ClaudeCodeLauncherGuardSubcommand)
	}
}
