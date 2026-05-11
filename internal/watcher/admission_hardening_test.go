// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

// TestRescan_NestedFileWriteRetriggersAdmission is the regression for
// finding "Post-admission file changes inside installed
// skills/plugins are not watched". A new direct child directory is
// created, admission runs once, then a nested file is written inside
// that already-admitted directory. The post-admission recursive
// subtree-watch must catch the nested write and the debounce timer
// must re-arm so processPending re-runs admission for the same child.
func TestRescan_NestedFileWriteRetriggersAdmission(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "watched-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var results []AdmissionResult
	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, func(r AdmissionResult) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()

	// Wait for Run to register the watch on skillDir.
	time.Sleep(500 * time.Millisecond)

	skillPath := filepath.Join(skillDir, "watched-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	// Wait for the first admission to land before mutating the
	// already-admitted directory.
	waitForAdmissions(t, &mu, &results, 1, 5*time.Second)

	// Wait long enough for the previous debounce window to fully
	// drain so a second admission isn't merged with the first.
	time.Sleep(time.Duration(cfg.Watch.DebounceMs)*time.Millisecond + 200*time.Millisecond)

	// Nested write inside the admitted directory. Pre-fix this
	// triggered no fsnotify event (root-only watch) and no second
	// admission. Post-fix: addSubtreeWatch registered the subtree at
	// admission time, and the event handler now bumps pending[child]
	// on Write events as well as Create/Rename.
	nestedFile := filepath.Join(skillPath, "post-admit.txt")
	if err := os.WriteFile(nestedFile, []byte("malicious payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Expect a SECOND admission for the same skill within a few
	// debounce windows. Without the recursive watch + Write filter
	// fix, no further admission ever fires for this child.
	waitForAdmissions(t, &mu, &results, 2, 5*time.Second)

	cancel()
	<-errCh

	mu.Lock()
	defer mu.Unlock()
	count := 0
	for _, r := range results {
		if r.Event.Name == "watched-skill" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("expected at least 2 admissions for watched-skill (initial + post-write), got %d (results=%+v)", count, results)
	}
}

// TestResolveTopLevelChild verifies the path-resolution helper that
// remaps nested fsnotify events back to their enclosing top-level
// child directory. This is what makes nested writes feed into the
// existing per-child debounce/admission pipeline.
func TestResolveTopLevelChild(t *testing.T) {
	tmp := t.TempDir()
	skillDir := filepath.Join(tmp, "skills")
	pluginDir := filepath.Join(tmp, "plugins")
	if err := os.MkdirAll(filepath.Join(skillDir, "alpha", "deep", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "beta"), 0o700); err != nil {
		t.Fatal(err)
	}

	w := &InstallWatcher{
		skillDirs:  []string{skillDir},
		pluginDirs: []string{pluginDir},
	}

	tcs := []struct {
		name     string
		evtPath  string
		expected string
	}{
		{
			name:     "direct child file",
			evtPath:  filepath.Join(skillDir, "alpha", "manifest.yaml"),
			expected: filepath.Join(skillDir, "alpha"),
		},
		{
			name:     "deeply nested file",
			evtPath:  filepath.Join(skillDir, "alpha", "deep", "nested", "x.bin"),
			expected: filepath.Join(skillDir, "alpha"),
		},
		{
			name:     "plugin child",
			evtPath:  filepath.Join(pluginDir, "beta", "src", "main.so"),
			expected: filepath.Join(pluginDir, "beta"),
		},
		{
			name:     "watched root itself returns empty",
			evtPath:  skillDir,
			expected: "",
		},
		{
			name:     "outside any root returns empty",
			evtPath:  filepath.Join(tmp, "not-watched", "x"),
			expected: "",
		},
		{
			name:     "hidden top-level child is skipped",
			evtPath:  filepath.Join(skillDir, ".git", "HEAD"),
			expected: "",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := w.resolveTopLevelChild(tc.evtPath)
			gotAbs, _ := filepath.Abs(got)
			expectedAbs, _ := filepath.Abs(tc.expected)
			if tc.expected == "" {
				if got != "" {
					t.Errorf("resolveTopLevelChild(%q) = %q, want \"\"", tc.evtPath, got)
				}
				return
			}
			if gotAbs != expectedAbs {
				t.Errorf("resolveTopLevelChild(%q) = %q, want %q", tc.evtPath, got, tc.expected)
			}
		})
	}
}

// TestStoreBaseline_RejectsScanErrorBaseline is the regression for
// finding "Rescan findings are baselined without admission
// enforcement". Prior to the fix, when no baseline existed for a
// target the rescan path called storeBaseline directly, which ran
// the scanner and persisted its result without consulting the
// admission policy. A target that crashed the scanner (or that the
// policy would have rejected) would silently become the new baseline
// on the next rescan tick, breaking the admission gate.
//
// With the fix, storeBaseline:
//   - bails out early on a non-nil scanner error (the scanner now
//     fails closed on non-zero exit), AND
//   - routes a successful scan result through evaluatePostScanForRescan
//     and refuses to write the baseline when the verdict is
//     rejected/blocked.
//
// We exercise the first branch (scan-error) here because it does
// not require booting a real OPA engine; the second branch is
// covered by TestEvaluateAdmissionFallback_RejectsScanError in the
// policy package, since evaluatePostScanForRescan delegates to the
// same fallback path.
func TestStoreBaseline_RejectsScanErrorBaseline(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	// Point the skill scanner at a binary that exits non-zero so
	// scanner.Scan returns a non-nil error and storeBaseline
	// observes the new fail-closed behaviour.
	bin := filepath.Join(t.TempDir(), "fake-scanner.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho '{\"findings\":[]}'\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Scanners.SkillScanner.Binary = bin

	skillPath := filepath.Join(skillDir, "needs-baseline")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

	evt := InstallEvent{Type: InstallSkill, Name: "needs-baseline", Path: skillPath, Timestamp: time.Now().UTC()}
	snap, err := SnapshotTarget(skillPath)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-fix this would have written a baseline row with an empty
	// scan_id (because scan was treated as success). Post-fix it must
	// log a "baseline-rejected" action and persist nothing.
	w.storeBaseline(context.Background(), evt, snap)

	if _, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path); err == nil {
		t.Fatal("storeBaseline must NOT write a baseline when the scanner fails closed")
	}
	// A "baseline-rejected" audit entry should be present so
	// operators can see why the rescan loop is alerting but the
	// baseline never advances.
	rows, err := w.store.ListEventsByTarget(skillPath, 50)
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, e := range rows {
		if e.Action == "baseline-rejected" {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("expected baseline-rejected audit row for %s, got %d events", skillPath, len(rows))
	}
}

// waitForAdmissions blocks until at least n admissions have landed in
// `dst` or `timeout` elapses. Used by the recursive-watch regression
// to keep the test deterministic without relying on fixed sleeps.
func waitForAdmissions(t *testing.T, mu *sync.Mutex, dst *[]AdmissionResult, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		mu.Lock()
		got := len(*dst)
		mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d admissions; got %d", n, got)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// audit.Store.RecentEvents is package-internal in tests. We pull a
// thin shim through the package boundary by referencing its exported
// surface to keep the test compile self-contained.
var _ = audit.Event{}
