// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// absentRootRun starts a watcher on skillDir and missing, records every
// coverage publication and returns a function that waits for the admission
// of a named skill.
func absentRootRun(t *testing.T, missing string, late string) (*InstallWatcher, func() [][]RootCoverageIssue, func(string)) {
	t.Helper()
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: late, Reason: "pre-approved"})
	admitted := make(chan string, 8)
	w := New(cfg, []string{skillDir, missing}, nil, store, logger, nil, func(r AdmissionResult) { admitted <- r.Event.Name })
	var mu sync.Mutex
	var published [][]RootCoverageIssue
	w.SetRootCoverageHandler(func(issues []RootCoverageIssue) {
		mu.Lock()
		defer mu.Unlock()
		published = append(published, issues)
	})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-errCh })
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-errCh:
		errCh <- err // the cleanup reads it again
		t.Fatalf("watcher stopped with an absent root: %v", err)
	default:
	}
	snapshot := func() [][]RootCoverageIssue {
		mu.Lock()
		defer mu.Unlock()
		return append([][]RootCoverageIssue(nil), published...)
	}
	wait := func(name string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case got := <-admitted:
				if got == name {
					return
				}
			case <-deadline:
				t.Fatalf("skill %s in the late root got no admission", name)
			}
		}
	}
	return w, snapshot, wait
}

func requireNoCoverageIssue(t *testing.T, w *InstallWatcher, published [][]RootCoverageIssue) {
	t.Helper()
	if issues := w.RootCoverageIssues(); len(issues) != 0 {
		t.Fatalf("absent root recorded as a coverage gap (watcher DEGRADED, start never ready): %+v", issues)
	}
	for _, issues := range published {
		if len(issues) != 0 {
			t.Fatalf("absent root published a coverage gap (watcher DEGRADED): %+v", issues)
		}
	}
}

// GAP-1251: in the OpenClaw separate-user layout the configured skill root
// is in the OpenClaw account's home, which the gateway account cannot write.
// A root that does not exist and cannot be created holds nothing to scan: it
// is not a coverage gap (the watcher stays running and start reports ready),
// nothing is created, and the root is watched and admitted once it exists.
func TestWatcherAbsentRootItCannotCreateIsNotACoverageGap(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user: chmod does not bind for root or on Windows")
	}
	home := filepath.Join(testenv.PrivateTempDir(t), "openclaw-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	missing := filepath.Join(home, "skills")

	w, published, wait := absentRootRun(t, missing, "late")
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("watcher created or changed %s: %v", missing, err)
	}
	requireNoCoverageIssue(t, w, published())

	// The OpenClaw account makes its skills folder later.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(missing, "late"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missing, "late", "SKILL.md"), []byte("# late\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait("late")
	requireNoCoverageIssue(t, w, published())
}
