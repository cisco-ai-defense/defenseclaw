// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !race

package processutil

import (
	"context"
	"crypto/sha256"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestHookWorkAnswersWhileScansFillTheCPU is rel-1-0-10 GAP-0251 as a
// measurement. A startup rescan that admits many plugins at once (an agent
// update ships new copies of its bundled plugins) keeps scans running for
// minutes; on a small host they filled the CPU and a hook call the gateway
// had to answer within 3.5 s ran past it. This runs four busy scanners per
// CPU through RunTracked, as those admissions do, and times a fixed piece of
// CPU work in this process (the gateway answering a hook) against the same
// work on an idle CPU. With the scanners at the gateway priority the work
// took about five times as long; nicer, it keeps within twice its idle time.
//
// It measures wall-clock time on a whole machine, so it is opt-in
// (DC_SCANNER_PRIORITY_LOAD=1) and built without -race; the priority itself
// is proven in every build by TestScannerRunsBelowTheGatewayPriority.
func TestHookWorkAnswersWhileScansFillTheCPU(t *testing.T) {
	if os.Getenv("DC_SCANNER_PRIORITY_LOAD") != "1" {
		t.Skip("set DC_SCANNER_PRIORITY_LOAD=1 to fill the CPU with scanners and time the hook work")
	}
	block := make([]byte, 1<<20)
	work := func(blocks int) time.Duration {
		started := time.Now()
		sum := sha256.New()
		for range blocks {
			sum.Write(block)
		}
		_ = sum.Sum(nil)
		return time.Since(started)
	}
	median := func(blocks int) time.Duration {
		runs := []time.Duration{work(blocks), work(blocks), work(blocks)}
		slices.Sort(runs)
		return runs[1]
	}
	// About 300 ms of work on an idle CPU.
	blocks := 64
	if took := median(blocks); took > 0 {
		blocks = max(1, int(float64(blocks)*float64(300*time.Millisecond)/float64(took)))
	}
	idle := median(blocks)

	ctx, cancel := context.WithCancel(context.Background())
	var scans sync.WaitGroup
	scanners := 4 * runtime.NumCPU()
	for range scanners {
		scans.Add(1)
		go func() {
			defer scans.Done()
			_ = RunTracked(CommandContext(ctx, "/bin/sh", "-c", "while :; do :; done"))
		}()
	}
	defer func() {
		cancel()
		scans.Wait()
	}()
	// Let every scanner start and fill its CPU.
	time.Sleep(3 * time.Second)
	busy := median(blocks)
	ratio := float64(busy) / float64(idle)
	t.Logf("hook work: %s on an idle CPU, %s beside %d scanners (%.2fx)", idle, busy, scanners, ratio)
	if ratio > 2 {
		t.Fatalf("the hook work took %.2fx its idle time beside %d scanners: the scans take the CPU the gateway needs to answer a hook within its budget", ratio, scanners)
	}
}
