// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// The first start of a PowerShell engine in a fresh Windows runner pays a
// one-time cost (assembly loading, AMSI and Defender scanning of the engine's
// images) that later starts do not. On hosted Windows runners that first start
// outran fixed per-call budgets: TestCopilotAdapterRefusesInvalidEventBinding
// lost its first one to three binding subtests at the 20 s budget each, with
// empty output, while the later ones passed (CI job 122103139666: 20.77 s,
// 20.15 s, 20.03 s); TestWindowsCursorEnterpriseHookCommandPreservesUTF8Stdin
// lost its first case, PlainUTF8, at the 30 s budget (jobs 123937555714 and
// 124163044163: 30.36 s, 30.14 s) while the next two cases passed
// (rel-1-0-6:GAP-0249, GAP-0250). A test that times a PowerShell adapter call
// starts the engine once first (warmPowerShell), so its budget measures the
// adapter and not the engine's first start.
//
// powerShellWarmStartBound bounds that first start. The longest one measured
// on CI was more than 60.9 s (three 20 s budgets expired before a fourth call
// started cleanly, job 122103139666); three minutes leaves about three times
// that. A first start slower than this still fails the test.
const powerShellWarmStartBound = 3 * time.Minute

type powerShellWarmStart struct {
	once sync.Once
	took time.Duration
	out  []byte
	err  error
}

// powerShellWarmStarts holds one first start per engine path for the test
// process.
var powerShellWarmStarts sync.Map

// warmPowerShell starts engine once per test process and fails the test when
// that start does not print the expected word within powerShellWarmStartBound.
func warmPowerShell(t *testing.T, engine string) {
	t.Helper()
	value, _ := powerShellWarmStarts.LoadOrStore(engine, &powerShellWarmStart{})
	warm := value.(*powerShellWarmStart)
	warm.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), powerShellWarmStartBound)
		defer cancel()
		started := time.Now()
		warm.out, warm.err = exec.CommandContext(ctx, engine,
			"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('warm')",
		).CombinedOutput()
		warm.took = time.Since(started)
	})
	if warm.err != nil || string(warm.out) != "warm" {
		t.Fatalf("first start of %s after %v: err=%v output=%q, want %q", engine, warm.took, warm.err, warm.out, "warm")
	}
	t.Logf("first start of %s took %v", engine, warm.took)
}
