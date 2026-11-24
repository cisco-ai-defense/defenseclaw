// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1805 (RV-1804 follow-ups). Inside a hook call with the call
// memo on (memoReads, the Windows production path), a write is not proved
// free of the state when a local read it needs does not answer within
// networkShareAnswerWait:
//   - the write target's own folder (GAP-1804, now through HookCall: the
//     memo must keep the reason, not only the failed walk);
//   - the home the target is placed against: before, an unanswered home
//     read made every target read as no state, an allow;
//   - the state root a multiply linked target is compared with, reached
//     through the home: before, an unanswered root read was a complete
//     answer, no state file.
//
// An idle call keeps its answers: the hard link to config.yaml is state, an
// ordinary file is not.
func TestGAP1805UnansweredReadsInsideAHookCallAreRefused(t *testing.T) {
	previous := memoReads
	memoReads = true
	t.Cleanup(func() { memoReads = previous })
	resetActiveStateIndex(t)
	resetPlainFolders(t)
	end := make(chan struct{})
	t.Cleanup(func() { close(end) })
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	t.Cleanup(restore)
	defaultWait := networkShareAnswerWait
	t.Cleanup(func() { networkShareAnswerWait = defaultWait })
	home, cwd := activeStateIndexFixture(t, 0)
	alias := filepath.Join(cwd, "cfg-alias")
	if err := os.Link(filepath.Join(home, ".defenseclaw", "config.yaml"), alias); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(cwd, "notes.txt")
	if err := os.WriteFile(plain, []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var hold atomic.Value
	hold.Store("")
	var held atomic.Int32
	read := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		if folder := hold.Load().(string); folder != "" && name == folder && readByStillPlain() {
			held.Add(1)
			select {
			case <-end:
			case <-time.After(time.Hour):
			}
		}
		return read(name)
	}
	t.Cleanup(func() { walkLstat = read })
	// Each target is judged in its own hook call, twice and then through
	// the hard-link resolve: after the first ask, the call memo answers, so
	// it must keep why the walk failed (RV-1804: dropping unanswered from the
	// memo passed every GAP-1804 test). A read that did not answer drops the
	// known folders (stillPlain), so two targets in one call would not both
	// meet the held read.
	type answer struct{ first, again, complete bool }
	judge := func(target string) answer {
		endCall := HookCall()
		defer endCall()
		var got answer
		got.first = actionProtectedStatePath(target, &actionStateHome{home: home})
		got.again = actionProtectedStatePath(target, &actionStateHome{home: home})
		_, _, got.complete = ResolveActiveStateHardlinkTarget(target, home)
		return got
	}
	idle := map[string]answer{"alias": {true, true, true}, "plain": {false, false, true}}
	for _, row := range []struct {
		name   string
		folder string
		want   map[string]answer
	}{
		{"the target's own folder", cwd, map[string]answer{"alias": {true, true, false}, "plain": {true, true, false}}},
		// The home is read through stillPlain only on the walk below it:
		// the state-root resolve a multiply linked target makes, so this
		// row holds both the home (actionStateHome) and the state root
		// (ResolveActiveStateHardlinkTarget) reads.
		{"the home", home, map[string]answer{"alias": {true, true, false}}},
	} {
		for _, target := range []struct{ name, path string }{{"alias", alias}, {"plain", plain}} {
			want, judged := row.want[target.name]
			if !judged {
				continue
			}
			t.Run(row.name+"/"+target.name, func(t *testing.T) {
				// Idle calls first: they answer as rel and make the
				// folders known ones, read again (stillPlain) by the next
				// call's walks (a held read of the row before dropped them).
				networkShareAnswerWait = defaultWait
				resetActiveStateIndex(t)
				for range 2 {
					if got := judge(target.path); got != idle[target.name] {
						t.Fatalf("idle call: %+v, want %+v", got, idle[target.name])
					}
				}
				networkShareAnswerWait = 20 * time.Millisecond
				held.Store(0)
				hold.Store(row.folder)
				got := judge(target.path)
				hold.Store("")
				if held.Load() == 0 {
					t.Fatal("the folder read was never held (vacuous)")
				}
				if got != want {
					t.Errorf("read of %s held: %+v, want %+v", row.name, got, want)
				}
			})
		}
	}
}
