// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// GAP-0091: on Windows and macOS the staging maps are keyed case folded.
// The fold is injected here, so Linux runs the same rule on a case-sensitive
// volume, the case a folded key names nothing on: every lookup goes through
// stagingKey, and the disk is read through the original path.
func TestClaudeStagingFoldedKeysKeepTheOriginalPath(t *testing.T) {
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	w := claudeWatcher(t, cache)
	w.stagingFold = strings.ToLower
	clock := &stagingTestClock{}
	w.stagingClock = clock.now
	linked := filepath.Join(cache, "Mkt", "Pid1", "1.0.0-x.linking-1")
	writeManifest(t, linked, "pid1")
	if strings.ToLower(linked) == linked {
		t.Fatal("the test path has no upper case to fold")
	}

	if !w.inClaudePluginStaging(linked, 0) {
		t.Fatal("a linking folder being written is not in flight")
	}
	w.deferClaudeStaging(linked, 3)
	w.deferClaudeStaging(strings.ToLower(linked), 3)
	w.stagingMu.Lock()
	entry, ok := w.stagingDeferred[w.stagingKey(strings.ToUpper(linked))]
	entries := len(w.stagingDeferred)
	w.stagingMu.Unlock()
	if !ok || entries != 1 || entry.path != linked {
		t.Fatalf("deferred %d entries, found=%v path=%q; want one under its own spelling", entries, ok, entry.path)
	}

	// The folder is written for longer than the grace; the re-checks prune
	// first-seen times, and a folded key read as gone reset the cap every
	// time, so the folder never settled. It is handed on, under its own
	// spelling, once the cap is reached.
	file := filepath.Join(linked, "big.bin")
	var got []string
	admit := func(path string, _ int) { got = append(got, path) }
	for time.Until(clock.now()) < claudeStagingCap+claudeStagingGrace && len(got) == 0 {
		now := clock.now()
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, now, now); err != nil {
			t.Fatal(err)
		}
		w.recheckClaudeStaging(admit)
		w.stagingMu.Lock()
		_, seen := w.stagingSeen[w.stagingKey(linked)]
		w.stagingMu.Unlock()
		if !seen && len(got) == 0 {
			t.Fatal("the re-check forgot when an existing folder was first seen")
		}
		clock.advance(10 * time.Minute)
	}
	if !slices.Equal(got, []string{linked}) {
		t.Fatalf("handed to admission %v, want [%s] once the cap was reached", got, linked)
	}
	if offset := time.Until(clock.now()); offset < claudeStagingCap || offset > claudeStagingCap+10*time.Minute+time.Second {
		t.Fatalf("settled after %s, want at the %s cap", offset, claudeStagingCap)
	}

	// A folder gone is forgotten through its own path.
	if err := os.RemoveAll(filepath.Join(cache, "Mkt")); err != nil {
		t.Fatal(err)
	}
	w.pruneStagingSeen()
	w.stagingMu.Lock()
	left := len(w.stagingSeen)
	w.stagingMu.Unlock()
	if left != 0 {
		t.Fatalf("first-seen times kept for a folder gone: %d", left)
	}
}

// The memo and registry answers are found by any spelling of a path.
func TestClaudeStagingMemoFoldsCase(t *testing.T) {
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	w := claudeWatcher(t, cache)
	w.stagingFold = strings.ToLower
	staging := filepath.Join(cache, stagingName("github", "", time.Now()))
	mkdirs(t, filepath.Join(staging, "Skills", "Foo"), filepath.Join(staging, "skills", "bar"))
	for _, path := range []string{filepath.Join(staging, "Skills", "Foo"), filepath.Join(staging, "skills", "bar")} {
		if !w.inClaudePluginStaging(path, 0) {
			t.Fatalf("%s is not in flight", path)
		}
	}
	if walks := w.stagingWalks.Load(); walks != 1 {
		t.Fatalf("walked the staging folder %d times, want 1", walks)
	}
	w.stagingMu.Lock()
	_, memo := w.stagingMemo[w.stagingKey(strings.ToUpper(staging))]
	_, registry := w.registryMemo[w.stagingKey(strings.ToUpper(filepath.Dir(cache)))]
	w.stagingMu.Unlock()
	if !memo || !registry {
		t.Fatalf("memo found=%v registry found=%v by another spelling", memo, registry)
	}
}
