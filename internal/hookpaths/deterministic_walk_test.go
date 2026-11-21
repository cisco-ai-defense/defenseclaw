// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// starved runs fn on one processor shared with spinners goroutines that never
// block, the way a hook call runs on a loaded box: each time the scheduler
// takes the processor from fn (a preemption after 10 ms, a system call it
// waits on), fn waits behind every spinner's 10 ms slice. A bound that
// counted wall-clock time sees a slow walk; one that counts entries sees the
// same walk as on an idle box. It returns how long fn took.
func starved(spinners int, fn func()) time.Duration {
	procs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(procs)
	var done atomic.Bool
	var wg sync.WaitGroup
	for range spinners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !done.Load(); n++ {
				_ = n * n
			}
		}()
	}
	runtime.Gosched()
	start := time.Now()
	fn()
	took := time.Since(start)
	done.Store(true)
	wg.Wait()
	return took
}

// TestStateWalksCountEntriesNotTime pins rel-1-0-10:GAP-0339: the identity
// index of the active state ends at its entry bound, never at a deadline, so
// a hard link to a state file the walk reaches is found on a loaded box as on
// an idle one. Before, the walk also stopped after 250 ms; a file it had not
// reached by then was not mapped, so a write through a hard link to it was
// no state write (no block) whenever the box was slow. The cache here holds
// folders up to just inside the entry bound (each one a directory read, so
// the walk runs past one scheduler slice and is preempted), then the file
// the alias names, and the index is built with the processor starved.
func TestStateWalksCountEntriesNotTime(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 0)
	cache := filepath.Join(home, ".defenseclaw", "cache")
	folders := activeStateIndexEntries - len(activeStateFiles) - 64
	for i := range folders {
		if err := os.Mkdir(filepath.Join(cache, fmt.Sprintf("d%04d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// "entry-late" sorts after every folder, so the walk reaches it last.
	late := filepath.Join(cache, "entry-late")
	if err := os.WriteFile(late, []byte("state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(cwd, "late-alias")
	if err := os.Link(late, alias); err != nil {
		t.Fatal(err)
	}
	if _, same := ResolveActiveStateHardlinkTarget(alias, home); !same {
		t.Fatal("the hard link to the last cache entry was not found on an idle box")
	}
	for run := range 3 {
		resetActiveStateIndex(t)
		var same bool
		took := starved(64, func() { _, same = ResolveActiveStateHardlinkTarget(alias, home) })
		if !same {
			t.Fatalf("run %d: the hard link to a state file inside the entry bound was not found on a loaded box (walk took %s)", run, took)
		}
		t.Logf("run %d: starved walk took %s", run, took)
	}
}
