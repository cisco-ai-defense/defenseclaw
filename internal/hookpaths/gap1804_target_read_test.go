// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1804: a write target whose own folder read (stillPlain)
// does not answer within networkShareAnswerWait is not proved free of the
// state: a hard link to config.yaml in it is refused, not read as absent.
// A target on a network share that does not answer keeps its answer: a file
// there cannot be a hard link to the local state.
func TestGAP1804TargetFolderReadPastAnswerWaitIsRefused(t *testing.T) {
	resetActiveStateIndex(t)
	resetPlainFolders(t)
	var shareRoot atomic.Value
	shareRoot.Store("")
	end := make(chan struct{})
	t.Cleanup(func() { close(end) })
	restore := OverrideNetworkSharesForTest(func(path string) string {
		root := shareRoot.Load().(string)
		if root != "" && (path == root || strings.HasPrefix(path, root+string(filepath.Separator))) {
			return root
		}
		return ""
	}, func(string) {
		if shareRoot.Load().(string) != "" {
			<-end
		}
	})
	t.Cleanup(restore)
	defaultWait := networkShareAnswerWait
	t.Cleanup(func() { networkShareAnswerWait = defaultWait })
	home, cwd := activeStateIndexFixture(t, 0)
	alias := filepath.Join(cwd, "cfg-alias")
	if err := os.Link(filepath.Join(home, ".defenseclaw", "config.yaml"), alias); err != nil {
		t.Fatal(err)
	}
	var holding atomic.Bool
	var held atomic.Int32
	read := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		if holding.Load() && name == cwd && readByStillPlain() {
			held.Add(1)
			select {
			case <-end:
			case <-time.After(time.Hour):
			}
		}
		return read(name)
	}
	t.Cleanup(func() { walkLstat = read })
	state := &actionStateHome{home: home}
	if !actionProtectedStatePath(alias, state) {
		t.Fatal("idle: the hard link to config.yaml is not state")
	}
	if _, same, complete := ResolveActiveStateHardlinkTarget(alias, home); !same || !complete {
		t.Fatalf("idle: resolve same=%v complete=%v, want true true", same, complete)
	}

	// The target's own folder read is held past the answer wait.
	networkShareAnswerWait = 20 * time.Millisecond
	holding.Store(true)
	got := actionProtectedStatePath(alias, &actionStateHome{home: home})
	first := held.Load()
	_, same, complete := ResolveActiveStateHardlinkTarget(alias, home)
	holding.Store(false)
	if first == 0 || held.Load() == first {
		t.Fatalf("the target folder read was held %d then %d times, want at least once per check", first, held.Load())
	}
	if !got {
		t.Error("held target folder read: the hard link to config.yaml is not refused (read as absent)")
	}
	if same || complete {
		t.Errorf("held target folder read: resolve same=%v complete=%v, want not complete", same, complete)
	}

	// The same folder as a network share that does not answer: the share
	// keeps its answer (FPR flat for slow shares).
	forgetPlainFolders()
	resetActiveStateIndex(t)
	shareRoot.Store(cwd)
	if actionProtectedStatePath(alias, &actionStateHome{home: home}) {
		t.Error("share target that does not answer: refused, want the answer of rel (not state)")
	}
	if _, same, complete := ResolveActiveStateHardlinkTarget(alias, home); same || !complete {
		t.Errorf("share target that does not answer: resolve same=%v complete=%v, want false true", same, complete)
	}
}
