//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
)

type enterpriseHookCaseEventLog struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (log *enterpriseHookCaseEventLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	n, err := log.buf.Write(data)
	if strings.Contains(log.buf.String(), "reconcile reason=startup") {
		log.once.Do(func() { close(log.ready) })
	}
	return n, err
}

// waitFor waits up to timeout for text in the log. The guardian writes the
// reconcile line after the reconcile returns, so a test sees the repair the
// fake reconcile signals before the line that names its reason.
func (log *enterpriseHookCaseEventLog) waitFor(text string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for !strings.Contains(log.String(), text) {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

func (log *enterpriseHookCaseEventLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.buf.String()
}

func TestEnterpriseHookWindowsGuardianRepairsCaseVariantOnEvent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		storedName string
		ownedName  string
		shared     bool
	}{
		{name: "shared config", storedName: "Hooks.JSON", ownedName: "hooks.json", shared: true},
		{name: "scoped token", storedName: ".HOOK-Devin.TOKEN", ownedName: ".hook-devin.token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreEnterpriseHooksLifecycleTestState(t)
			previousReconcile := enterpriseHookWatchReconcileOnce
			previousPlatformWatch := enterpriseHookWatchPlatformWatch
			previousTargetScoped := enterpriseHookWatchTargetScoped
			previousBefore, previousAfter := enterpriseHookBeforeWatchReconcile, enterpriseHookAfterWatchReconcile
			previousManifest := enterpriseHookManifest
			previousInterval, previousDebounce := enterpriseHookWatchInterval, enterpriseHookWatchDebounce
			t.Cleanup(func() {
				enterpriseHookWatchReconcileOnce = previousReconcile
				enterpriseHookWatchPlatformWatch = previousPlatformWatch
				enterpriseHookWatchTargetScoped = previousTargetScoped
				enterpriseHookBeforeWatchReconcile, enterpriseHookAfterWatchReconcile = previousBefore, previousAfter
				enterpriseHookManifest = previousManifest
				enterpriseHookWatchInterval, enterpriseHookWatchDebounce = previousInterval, previousDebounce
			})
			dir := t.TempDir()
			stored := filepath.Join(dir, tc.storedName)
			owned := filepath.Join(dir, tc.ownedName)
			other := filepath.Join(dir, "session.log")
			const original = "original file contents\n"
			for _, path := range []string{stored, other} {
				if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg = &config.Config{DataDir: dir, DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
			enterpriseHookManifest = filepath.Join(dir, "targets.yaml")
			enterpriseHookWatchInterval = time.Minute
			enterpriseHookWatchDebounce = 40 * time.Millisecond
			enterpriseHooksMutationIdentityPreflight = func() error { return nil }
			enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) {}
			enterpriseHookWatchTargetScoped = func() bool { return true }
			enterpriseHookBeforeWatchReconcile = func(io.Writer) {}
			enterpriseHookAfterWatchReconcile = func(context.Context, io.Writer, enterpriseHookReconcileRun) {}
			repaired := make(chan struct{}, 1)
			reconciled := make(chan struct{}, 4)
			row := enterpriseHookReconcileRow{User: "alice", UserHome: dir, Connector: "devin", OK: true}
			enterpriseHookWatchReconcileOnce = func(context.Context) (enterpriseHookReconcileRun, error) {
				run := enterpriseHookReconcileRun{
					Rows: []enterpriseHookReconcileRow{row}, WatchDirs: []string{dir},
					WatchPathOwners: map[string][]string{owned: {enterpriseHookProtectedTargetKey(row)}},
				}
				if tc.shared {
					run.WatchSharedFiles = []string{owned}
				} else {
					run.WatchExclusiveFiles = []string{owned}
				}
				contents, err := os.ReadFile(owned)
				if err != nil {
					return run, err
				}
				if string(contents) != original {
					if err := os.WriteFile(owned, []byte(original), 0o600); err != nil {
						return run, err
					}
					run.Repairs = 1
					select {
					case repaired <- struct{}{}:
					default:
					}
				}
				select {
				case reconciled <- struct{}{}:
				default:
				}
				return run, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			cmd := &cobra.Command{}
			cmd.SetContext(ctx)
			log := &enterpriseHookCaseEventLog{ready: make(chan struct{})}
			cmd.SetErr(log)
			done := make(chan error, 1)
			go func() { done <- runEnterpriseHooksWatch(cmd, nil) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("guardian exit: %v; log: %s", err, log.String())
					}
				case <-time.After(3 * time.Second):
					t.Error("guardian did not stop")
				}
			}()
			select {
			case <-log.ready:
			case <-time.After(4 * time.Second):
				t.Fatalf("guardian did not start: %s", log.String())
			}
			select {
			case <-reconciled:
			default:
				t.Fatal("startup reconcile was not recorded")
			}
			if err := os.WriteFile(other, []byte("unrelated update\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case <-reconciled:
				t.Fatal("an unrelated file scheduled a reconcile")
			case <-time.After(150 * time.Millisecond):
			}
			if err := os.WriteFile(stored, []byte("changed file contents with a different size\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case <-repaired:
			case <-time.After(4 * time.Second):
				t.Fatalf("the owned file was not repaired on its event: %s", log.String())
			}
			contents, err := os.ReadFile(stored)
			if err != nil || string(contents) != original {
				t.Fatalf("file after event repair = %q, %v", contents, err)
			}
			if !log.waitFor("reconcile reason=fsnotify", 4*time.Second) {
				t.Fatalf("repair was not attributed to a file event: %s", log.String())
			}
		})
	}
}

func TestEnterpriseHookWindowsCaseVariantEventRepairsOwnedFiles(t *testing.T) {
	for _, tc := range []struct {
		name       string
		storedName string
		ownedName  string
		shared     bool
	}{
		{name: "shared config", storedName: "Hooks.JSON", ownedName: "hooks.json", shared: true},
		{name: "scoped token", storedName: ".HOOK-Devin.TOKEN", ownedName: ".hook-devin.token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stored := filepath.Join(dir, tc.storedName)
			owned := filepath.Join(dir, tc.ownedName)
			other := filepath.Join(dir, "session.log")
			original := []byte("original file contents\n")
			for _, path := range []string{stored, other} {
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(owned); err != nil {
				t.Fatalf("owned spelling does not resolve the stored file: %v", err)
			}
			exclusive, shared := map[string]struct{}{}, map[string]struct{}{}
			if tc.shared {
				shared[owned] = struct{}{}
			} else {
				exclusive[owned] = struct{}{}
			}
			ownedPaths := enterpriseHookWatchCaseFoldedOwnedPaths(exclusive, shared)
			left := map[string]string{owned: enterprisehooks.OwnedFileFingerprint(owned)}
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				t.Fatal(err)
			}
			defer watcher.Close()
			if err := watcher.Add(dir); err != nil {
				t.Fatal(err)
			}
			await := func(path string) fsnotify.Event {
				t.Helper()
				deadline := time.NewTimer(8 * time.Second)
				defer deadline.Stop()
				for {
					select {
					case event := <-watcher.Events:
						if strings.EqualFold(filepath.Base(event.Name), filepath.Base(path)) && event.Op&fsnotify.Write != 0 {
							return event
						}
					case err := <-watcher.Errors:
						t.Fatalf("filesystem watch: %v", err)
					case <-deadline.C:
						t.Fatalf("no write event for %s", filepath.Base(path))
					}
				}
			}
			classify := func(event fsnotify.Event) bool {
				event.Name = enterpriseHookWatchOwnedPath(event.Name, ownedPaths)
				drop, _ := enterpriseHookWatchEventDropped(time.Now(), time.Time{}, event, false,
					exclusive, shared, left, left, enterprisehooks.OwnedFileFingerprint, true)
				return drop
			}
			if err := os.WriteFile(other, []byte("unrelated update\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if event := await(other); !classify(event) {
				t.Fatal("an unrelated file scheduled a repair")
			}
			if err := os.WriteFile(stored, []byte("changed file contents with a different size\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			event := await(stored)
			if filepath.Base(event.Name) == tc.ownedName {
				t.Fatal("the event did not retain the stored filename spelling")
			}
			if classify(event) {
				t.Fatal("the owned file event did not schedule a repair")
			}
			if err := os.WriteFile(owned, original, 0o600); err != nil {
				t.Fatalf("repair after file event: %v", err)
			}
			contents, err := os.ReadFile(stored)
			if err != nil || string(contents) != string(original) {
				t.Fatalf("the file was not repaired on its event: %v", err)
			}
		})
	}
}
