// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGAP1789KnownFolderReadPastAnswerWait pins the mechanism behind
// rel-1-0-10:GAP-1787 and GAP-1789 without load. On Windows every read of the
// state walk first walks the path for a link into a network share
// (networkShareLinkWalk), and a folder the walk already found to be local is
// read once more by stillPlain, which waits for that read at most
// networkShareAnswerWait. Here walkLstat holds that one read of one state
// folder (only the read stillPlain waits for; every other read answers at
// once), so the read is past the wait on every run, as scheduler starvation
// made it on a loaded box.
//
// With a 20 ms wait the hard link to the state file below that folder is not
// in the identity index. Before, that miss read as no state write (an allow,
// GAP-1789); now the target is refused as not proved, as is a multiply linked
// project file, a single-link project write is still allowed, and the index
// whose read did not answer is not kept. With the one-minute wait that
// TestStateWalksCountEntriesNotTime gives its starved runs (GAP-1787), a read
// slower than the default wait is waited for, and the index is the idle index
// entry for entry: that test's result then depends on the walk alone, not on
// how loaded the box is. OverrideNetworkSharesForTest turns the share walk on,
// so the test runs off Windows too.
//
// Where the file system gives no change time (statChangeTime: Windows) the
// index is kept for the hook call only (activeStateIdentities), never across
// calls: there each lookup runs in a hook call of its own and the index read
// is the one that call kept (rel-1-0-10:GAP-2300).
func TestGAP1789KnownFolderReadPastAnswerWait(t *testing.T) {
	resetActiveStateIndex(t)
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	t.Cleanup(restore)
	defaultWait := networkShareAnswerWait
	t.Cleanup(func() { networkShareAnswerWait = defaultWait })

	home, cwd := activeStateIndexFixture(t, 0)
	slow := filepath.Join(home, ".defenseclaw", "cache", "gap1789-slow")
	if err := os.Mkdir(slow, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(slow, "entry")
	alias := filepath.Join(cwd, "entry-alias")
	twin, twinLink := filepath.Join(cwd, "own.txt"), filepath.Join(cwd, "own-twin.txt")
	plain := filepath.Join(cwd, "plain.txt")
	for _, file := range []string{entry, twin, plain} {
		if err := os.WriteFile(file, []byte("data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(entry, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(twin, twinLink); err != nil {
		t.Fatal(err)
	}
	homeInfo, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	_, acrossCalls := statChangeTime(homeInfo)
	// A state folder changed within activeStateViewGuard (or the present
	// filesystem clock tick) is not kept across calls (activeStateSettleLimit,
	// DET111): let the new state settle so the index is kept and can be read.
	time.Sleep(2 * activeStateViewGuard)

	// The held read: a read of the slow folder made by stillPlain while
	// holding is on waits readTakes, or until the test ends.
	var holding atomic.Bool
	var held atomic.Int32
	var readTakes atomic.Int64
	end := make(chan struct{})
	t.Cleanup(func() { close(end) })
	read := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		if holding.Load() && filepath.Base(name) == "gap1789-slow" && readByStillPlain() {
			held.Add(1)
			select {
			case <-end:
			case <-time.After(time.Duration(readTakes.Load())):
			}
		}
		return read(name)
	}
	t.Cleanup(func() { walkLstat = read })

	// callIndexes are the indexes the hook call of the last lookup kept
	// where none is kept across calls.
	var callIndexes map[string][]activeStateIdentity
	state := func(path string) bool {
		resetActiveStateIndex(t)
		if acrossCalls {
			return actionProtectedStatePath(path, &actionStateHome{home: home})
		}
		call, end := beginHookCall()
		defer end()
		if call == nil {
			t.Fatal("no hook call began on the test goroutine")
		}
		got := actionProtectedStatePath(path, &actionStateHome{home: home})
		callIndexes = maps.Clone(call.stateIdentities)
		return got
	}
	indexCount := func() int {
		if acrossCalls {
			return gap1789IndexCount()
		}
		return len(callIndexes)
	}
	indexNames := func() []string {
		t.Helper()
		if acrossCalls {
			return gap1789IndexNames(t)
		}
		if len(callIndexes) != 1 {
			t.Fatalf("%d active state indexes kept for the hook call, want 1", len(callIndexes))
		}
		var names []string
		for _, files := range callIndexes {
			for _, file := range files {
				names = append(names, file.relative)
			}
		}
		return names
	}
	idle := func(when string) []string {
		t.Helper()
		if !state(alias) {
			t.Fatalf("%s: the hard link to a state file was not found", when)
		}
		names := indexNames()
		if state(twin) || state(plain) {
			t.Fatalf("%s: an ordinary project write (a hard link pair of its own, a single-link file) read as a state write", when)
		}
		return names
	}
	// held is the verdict on path with the read of the slow folder held.
	// The walk before it notes the slow folder as local, so the walk of path
	// reads it through stillPlain (a forgotten folder is read directly).
	heldState := func(path string) bool {
		t.Helper()
		idle("before the held read")
		before := held.Load()
		holding.Store(true)
		got := state(path)
		holding.Store(false)
		if held.Load() == before {
			t.Fatalf("%s: the walk did not read the known state folder through stillPlain; the test proves nothing", filepath.Base(path))
		}
		return got
	}
	idleIndex := idle("idle box")
	if !slices.Contains(idleIndex, "cache/gap1789-slow/entry") {
		t.Fatalf("the idle index does not hold the state file below the slow folder: %v", idleIndex)
	}

	// The read is past a 20 ms answer wait.
	networkShareAnswerWait = 20 * time.Millisecond
	readTakes.Store(int64(time.Hour))
	if !heldState(alias) {
		t.Fatal("a hard link to a state file whose folder read was past the answer wait read as no state write (fail open)")
	}
	if n := indexCount(); n != 0 {
		t.Fatalf("%d indexes kept from a walk whose read did not answer", n)
	}
	if !heldState(twinLink) {
		t.Fatal("a multiply linked target was taken as proved free of the state while a read of the state did not answer")
	}
	holding.Store(true)
	if state(plain) {
		t.Fatal("a single-link project write was refused while a read of the state did not answer")
	}
	holding.Store(false)

	// The same read, slower than the default wait, under the one-minute wait
	// of the GAP-1787 starved runs.
	networkShareAnswerWait = time.Minute
	readTakes.Store(int64(defaultWait + 250*time.Millisecond))
	if !heldState(alias) {
		t.Fatal("under the one-minute wait the hard link to a state file was not found while one folder read was slower than the default wait")
	}
	if got := indexNames(); !slices.Equal(got, idleIndex) {
		t.Fatalf("under the one-minute wait the index holds %d files, the idle index %d: %v", len(got), len(idleIndex), got)
	}

	networkShareAnswerWait = defaultWait
	if got := idle("after the state answers again"); !slices.Equal(got, idleIndex) {
		t.Fatalf("after the state answers again the index holds %d files, the idle index %d", len(got), len(idleIndex))
	}
}

// readByStillPlain reports that the walkLstat call being made is the read of
// a known folder by stillPlain (its goroutine), not a direct read of the walk.
func readByStillPlain() bool {
	pcs := make([]uintptr, 16)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, "hookpaths.stillPlain") {
			return true
		}
		if !more {
			return false
		}
	}
}

// gap1789IndexCount is the number of active state indexes kept.
func gap1789IndexCount() int {
	activeStateIndex.Lock()
	defer activeStateIndex.Unlock()
	return len(activeStateIndex.byRoot)
}

// gap1789IndexNames is the relative names of the one active state index
// kept, in walk order.
func gap1789IndexNames(t *testing.T) []string {
	t.Helper()
	activeStateIndex.Lock()
	defer activeStateIndex.Unlock()
	if len(activeStateIndex.byRoot) != 1 {
		t.Fatalf("%d active state indexes kept, want 1", len(activeStateIndex.byRoot))
	}
	var names []string
	for _, index := range activeStateIndex.byRoot {
		for _, file := range index.files {
			names = append(names, file.relative)
		}
	}
	return names
}
