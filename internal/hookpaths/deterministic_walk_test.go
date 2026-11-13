// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// busy keeps every CPU of the box running until the returned stop is called,
// so a bound that counted wall-clock time would see a slow box.
func busy() (stop func()) {
	var done atomic.Bool
	var wg sync.WaitGroup
	for range 2 * runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !done.Load(); n++ {
				_ = n * n
			}
		}()
	}
	return func() { done.Store(true); wg.Wait() }
}

// TestStateWalksCountEntriesNotTime pins GAP-0339: the walks of the active
// state (the identity index, the exact walk of a patch target) end at an
// entry bound, never at a deadline, so the answer for one call is the same on
// a loaded box and an idle one. A call whose hard link to the state is found
// by the walk is found in each of 50 runs under full CPU load, with the index
// rebuilt every time.
func TestStateWalksCountEntriesNotTime(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 64)
	alias := filepath.Join(cwd, "config-alias")
	if err := os.Link(filepath.Join(home, ".defenseclaw", "config.yaml"), alias); err != nil {
		t.Fatal(err)
	}
	defer busy()()
	for run := range 50 {
		resetActiveStateIndex(t)
		if _, same := ResolveActiveStateHardlinkTarget(alias, home); !same {
			t.Fatalf("run %d: the hard link to the state config was not found under load", run)
		}
	}
}
