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
)

// TestStateGlobTwinCountsWorkNotTime pins GAP-0339: the expansion of a
// pattern under the DefenseClaw state ends at a work bound (directories
// listed and names examined), never at a deadline: the same call gets the
// same twin in each of 50 runs with every CPU busy, whatever the load.
func TestStateGlobTwinCountsWorkNotTime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the pattern is read under a POSIX home (a Git Bash drive home has its own twin test)")
	}
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		if err := os.WriteFile(filepath.Join(state, fmt.Sprintf("conf%03d.yaml", i)), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := "cp a.txt " + home + "/.defenseclaw/conf*.yaml"
	want, wantOK := stateGlobTwin(command, home, nil)
	if !wantOK {
		t.Fatal("the pattern was not expanded on an idle box")
	}
	var done atomic.Bool
	var wg sync.WaitGroup
	for range min(runtime.NumCPU(), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !done.Load(); n++ {
				_ = n * n
			}
		}()
	}
	defer func() { done.Store(true); wg.Wait() }()
	for run := range 50 {
		if got, ok := stateGlobTwin(command, home, nil); !ok || got != want {
			t.Fatalf("run %d: twin differs under load (ok=%t)", run, ok)
		}
	}
}
