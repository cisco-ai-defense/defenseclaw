// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

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

// starvedGlob runs fn on one processor shared with spinners goroutines that
// never block, the way a hook call runs on a loaded box: each time the
// scheduler takes the processor from fn, fn waits behind every spinner's
// 10 ms slice. It returns how long fn took.
func starvedGlob(spinners int, fn func()) time.Duration {
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

// TestStateGlobTwinCountsWorkNotTime pins rel-1-0-10:GAP-0339: the expansion
// of a pattern under the DefenseClaw state ends at a work bound (directories
// listed and names examined), never at a deadline, so the same call gets the
// same twin on a loaded box as on an idle one. Before, the expansion also
// stopped after 250 ms and then added nothing, so cp a.txt
// ~/.defenseclaw/*/conf*.yaml wrote the state configs of 64 folders unseen
// whenever the box was slow. The bound covers what rel read on an idle box:
// 64 folders of 2,000 names each (past one scheduler slice of reading) are
// read whole. On Windows the pattern words carry the home with forward
// slashes (a backslash literal is never expanded, statePatternWord) and each
// folder holds 200 names, since NTFS and Defender make 128,000 file creates
// cost minutes there.
func TestStateGlobTwinCountsWorkNotTime(t *testing.T) {
	home, names := t.TempDir(), 2000
	if runtime.GOOS == "windows" {
		home, names = filepath.ToSlash(home), 200
	}
	state := filepath.Join(home, ".defenseclaw")
	for d := range maxStateGlobMatches {
		dir := filepath.Join(state, fmt.Sprintf("d%02d", d))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := range names {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("n%03d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := "cp a.txt " + home + "/.defenseclaw/*/conf*.yaml"
	want, wantOK, _ := stateGlobTwin(command, home, nil)
	if !wantOK {
		t.Fatal("the pattern was not expanded on an idle box")
	}
	for run := range 3 {
		var got string
		var ok bool
		took := starvedGlob(64, func() { got, ok, _ = stateGlobTwin(command, home, nil) })
		if !ok || got != want {
			t.Fatalf("run %d: the twin differs on a loaded box (ok=%t, took %s)", run, ok, took)
		}
		t.Logf("run %d: starved expansion took %s", run, took)
	}
}
