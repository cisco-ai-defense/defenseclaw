// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0881: a reload rejected for an asset only the candidate references
// keeps that asset watched, so repairing it rebuilds the generation without
// a config.yaml edit.
func TestConfigManagerWatchesTheRejectedCandidateAssets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	live, candidate := filepath.Join(dir, "pack-a"), filepath.Join(dir, "pack-b")
	for _, pack := range []string{live, candidate} {
		if err := os.Mkdir(pack, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	liveRule, candidateRule := filepath.Join(live, "rule.rego"), filepath.Join(candidate, "rule.rego")
	for _, file := range []string{liveRule, candidateRule} {
		if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan string, 8)
	var rejected atomic.Int32
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			contents, err := os.ReadFile(candidateRule)
			if err != nil {
				return err
			}
			if string(contents) == "bad" {
				rejected.Add(1)
				return errors.New("candidate rule pack is invalid")
			}
			applied <- string(contents)
			return nil
		})
	mgr.assetDirs = func() []string { return []string{live} }
	mgr.candidateAssets = func(*config.Config) ([]string, []string) { return []string{candidate}, nil }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	for len(applied) > 0 {
		<-applied
	}
	// The candidate's own asset is broken; an edit of the live asset makes
	// the watcher reload, and the reload is rejected.
	if err := os.WriteFile(candidateRule, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveRule, []byte("edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for rejected.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("the reload was not rejected")
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Repair only the candidate's asset.
	time.Sleep(300 * time.Millisecond)
	if err := os.WriteFile(candidateRule, []byte("repaired"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-applied:
		if got != "repaired" {
			t.Fatalf("applied %q, want repaired", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("repairing the rejected candidate's asset did not rebuild the generation")
	}
	// The callback sends applied before reload commits its final state.
	// Wait for that reload to return before checking its rejected assets.
	mgr.mu.Lock()
	stillRejected := mgr.rejectedAssets.Load() != nil
	mgr.mu.Unlock()
	if stillRejected {
		t.Fatal("a reload that built still watches the rejected candidate's assets")
	}
	cancel()
	<-done
}

// GAP-0879: an asset folder the watcher cannot watch degrades config health
// with its path and is polled, so its edits are still seen.
func TestAssetFolderThatCannotBeWatchedIsReportedAndPolled(t *testing.T) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	_ = fsw.Close() // every Add fails from now on
	watches := &assetWatches{fsw: fsw, watched: map[string]struct{}{}, failed: map[string]string{}}
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.rego")
	if err := os.WriteFile(rule, []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	watches.sync(map[string]struct{}{dir: {}})
	if got := watches.failedPaths(); !slices.Equal(got, []string{dir}) {
		t.Fatalf("failed watches = %v, want [%s]", got, dir)
	}
	if watches.failedFoldersChanged() {
		t.Fatal("an unchanged folder reported a change")
	}
	if err := os.WriteFile(rule, []byte("package a\nchanged := true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !watches.failedFoldersChanged() {
		t.Fatal("an edit of a folder that cannot be watched was not seen")
	}
	if watches.failedFoldersChanged() {
		t.Fatal("one edit reported twice")
	}

	health := NewSidecarHealth()
	mgr := &ConfigManager{health: health, path: filepath.Join(dir, "config.yaml")}
	mgr.setConfigHealth(StateRunning, "", map[string]interface{}{"path": mgr.path})
	mgr.setAssetWatchFailures(watches.failedPaths())
	health.mu.Lock()
	state, details := health.config.State, health.config.Details
	health.mu.Unlock()
	if state != StateDegraded || !slices.Equal(details["asset_watch_failed"].([]string), []string{dir}) || details["path"] != mgr.path {
		t.Fatalf("config health = %s %v, want degraded naming %s", state, details, dir)
	}
	mgr.setConfigHealth(StateRunning, "", map[string]interface{}{"path": mgr.path})
	health.mu.Lock()
	state = health.config.State
	health.mu.Unlock()
	if state != StateDegraded {
		t.Fatalf("a later reload reported %s while the folder is still not watched", state)
	}
	mgr.setAssetWatchFailures(nil)
	health.mu.Lock()
	state = health.config.State
	health.mu.Unlock()
	if state != StateRunning {
		t.Fatalf("config health = %s after the watch recovered, want running", state)
	}
}

// The polling fallback of a folder that cannot be watched sees a policy
// file replaced with other bytes of the same size, mode and modification
// time.
func TestAssetFolderFingerprintSeesASameSizeEditThatKeepsItsModTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("severity: HIGH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	watches := &assetWatches{failed: map[string]string{dir: assetFolderFingerprint(dir)}}
	if err := os.WriteFile(path, []byte("severity: LOW_\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() {
		t.Fatalf("the replacement changed the file metadata: %v -> %v", before, after)
	}
	if !watches.failedFoldersChanged() {
		t.Fatal("the polling fallback missed a same-size edit that kept the modification time")
	}
	if watches.failedFoldersChanged() {
		t.Fatal("an unchanged folder reported a change")
	}
}
