// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Acceptance test of the RKRELAY review (GAP-0356): swap ~/.gemini with an
// agent folder (RENAME_EXCHANGE), hold it for a moment, swap back. The
// guard acted on a later identity check and missed 200 of 200 such swaps;
// it must trip on every one.
func TestGuardTripsOnASwapAndRestore(t *testing.T) {
	for _, hold := range []time.Duration{0, 100 * time.Microsecond, time.Millisecond} {
		missed, n := 0, 200
		for i := 0; i < n; i++ {
			home := t.TempDir()
			gem, evil := filepath.Join(home, ".gemini"), filepath.Join(home, "evil")
			_ = os.Mkdir(gem, 0o755)
			_ = os.Mkdir(evil, 0o755)
			var tripped atomic.Bool
			ctx, cancel := context.WithCancel(context.Background())
			if err := watchGuardedAs(ctx, []string{gem}, func(string) { tripped.Store(true) }, nil); err != nil {
				t.Fatal(err)
			}
			if err := unix.Renameat2(unix.AT_FDCWD, gem, unix.AT_FDCWD, evil, unix.RENAME_EXCHANGE); err != nil {
				cancel()
				t.Skipf("RENAME_EXCHANGE: %v", err)
			}
			if hold > 0 {
				time.Sleep(hold)
			}
			_ = unix.Renameat2(unix.AT_FDCWD, gem, unix.AT_FDCWD, evil, unix.RENAME_EXCHANGE)
			deadline := time.Now().Add(2 * time.Second)
			for !tripped.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !tripped.Load() {
				missed++
			}
			cancel()
		}
		if missed > 0 {
			t.Errorf("swap held %v then swapped back: the guard missed %d of %d", hold, missed, n)
		}
	}
}

// Acceptance test of the RKRELAY review (GAP-0356): rename-into-place in
// HOME and in agent-owned entries below ~/.gemini/config, and a sibling
// created and removed, do not trip the guard.
func TestGuardIgnoresBenignFlows(t *testing.T) {
	home := t.TempDir()
	gem := filepath.Join(home, ".gemini")
	_ = os.MkdirAll(filepath.Join(gem, "config", "projects"), 0o755)
	var tripped atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := watchGuardedAs(ctx, []string{gem}, func(string) { tripped.Store(true) }, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		tmp := filepath.Join(home, ".bash_history.tmp")
		_ = os.WriteFile(tmp, []byte("x"), 0o600)
		_ = os.Rename(tmp, filepath.Join(home, ".bash_history"))
		mt := filepath.Join(gem, "config", "mcp_config.json.tmp")
		_ = os.WriteFile(mt, []byte("{}"), 0o600)
		_ = os.Rename(mt, filepath.Join(gem, "config", "mcp_config.json"))
		_ = os.MkdirAll(filepath.Join(gem, "config", "projects", "p"), 0o755)
		_ = os.RemoveAll(filepath.Join(gem, "config", "projects", "p"))
		_ = os.Mkdir(filepath.Join(home, ".gemini.lock"), 0o755)
		_ = os.Remove(filepath.Join(home, ".gemini.lock"))
	}
	time.Sleep(1500 * time.Millisecond)
	if tripped.Load() {
		t.Error("a benign flow tripped the guard")
	}
}
