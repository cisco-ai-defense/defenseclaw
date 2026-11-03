// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/fsnotify/fsnotify"
)

func TestEnterpriseHookWatchSharedPathKeepsHealthyOwnerActive(t *testing.T) {
	home := t.TempDir()
	shared := filepath.Join(home, ".defenseclaw", "hooks", "inspect-tool.sh")
	if err := os.MkdirAll(filepath.Dir(shared), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shared, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	healthy := enterpriseHookReconcileRow{User: "alice", UserHome: home, Connector: "codex", OK: true}
	failing := enterpriseHookReconcileRow{User: "alice", UserHome: home, Connector: "claudecode", Error: "repair pending"}
	owners := map[string][]string{}
	for _, row := range []enterpriseHookReconcileRow{healthy, failing} {
		// The shared ~/.defenseclaw/hooks script comes from the Unix hook
		// installer. Native Windows does not install these connectors through
		// it (requireEnterpriseHookInstaller in internal/enterprisehooks): its
		// home check is the POSIX mode check, which no Windows directory
		// passes. The path-owner rules below are the same on every platform.
		if runtime.GOOS != "windows" {
			own, err := enterprisehooks.WatchOwnedFiles(enterprisehooks.InstallOptions{
				ConnectorName: row.Connector, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
			})
			if err != nil {
				t.Fatalf("%s owned files: %v", row.Connector, err)
			}
			if !slices.Contains(own.ExclusiveWriter, shared) {
				t.Fatalf("%s does not own the shared hook: %v", row.Connector, own.ExclusiveWriter)
			}
		}
		enterpriseHookWatchAddPathOwner(owners, shared, enterpriseHookProtectedTargetKey(row))
	}
	run := enterpriseHookReconcileRun{Rows: []enterpriseHookReconcileRow{healthy, failing}, WatchPathOwners: owners}
	exclusive := map[string]struct{}{shared: {}}
	found, left := map[string]string{}, map[string]string{}
	takeEnterpriseHookOwnedSnapshot(found, exclusive, nil, enterprisehooks.OwnedFileFingerprint)
	if err := os.WriteFile(shared, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	takeEnterpriseHookOwnedSnapshot(left, exclusive, nil, enterprisehooks.OwnedFileFingerprint)
	failedPaths := enterpriseHookWatchFailedOwnedPaths(run)
	if failedPaths[shared] {
		t.Fatal("a healthy owner was marked failed")
	}
	now := time.Now()
	if drop, _ := enterpriseHookWatchEventDropped(now, now.Add(2*time.Second),
		fsnotify.Event{Name: shared, Op: fsnotify.Write}, failedPaths[shared], exclusive, nil,
		found, left, enterprisehooks.OwnedFileFingerprint, true); drop {
		t.Fatal("the shared hook event waited for the other owner's retry")
	}
	run.Rows[0].OK = false
	if !enterpriseHookWatchFailedOwnedPaths(run)[shared] {
		t.Fatal("a file whose owners all failed lost failed-repair tail suppression")
	}
}

func TestEnterpriseHookWatchFailedTargetDoesNotDelayHealthyTokenRepair(t *testing.T) {
	token := filepath.Join(t.TempDir(), ".hook-hermes.token")
	const issued = "issued\n"
	if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
		t.Fatal(err)
	}
	healthy := enterpriseHookReconcileRow{User: "alice", Connector: "hermes", OK: true}
	failing := enterpriseHookReconcileRow{User: "bob", Connector: "hermes", Error: "home unavailable"}
	run := enterpriseHookReconcileRun{
		Rows: []enterpriseHookReconcileRow{failing, healthy}, Failures: 1,
		WatchPathOwners: map[string][]string{token: {enterpriseHookProtectedTargetKey(healthy)}},
	}
	start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	var retries enterpriseHookWatchRetries
	retries.observe("startup", run, nil, start)
	// Advance only the failing target through its retries to the 15 s cap.
	lastRetryAt := start
	for i := 0; i < 5; i++ {
		due, ok := retries.nextDue()
		if !ok {
			t.Fatal("failing target lost its retry")
		}
		retries.observe("retry", run, nil, due)
		lastRetryAt = due
	}
	retryDue, _ := retries.nextDue()
	if retryDue.Sub(start) < 15*time.Second {
		t.Fatalf("failed target retry due in %s, want backoff at the cap", retryDue.Sub(start))
	}

	// The healthy target was checked before the overwrite, but the Write
	// arrived after the pass's snapshot included the damaged token.
	exclusive := map[string]struct{}{token: {}}
	found, left := map[string]string{}, map[string]string{}
	takeEnterpriseHookOwnedSnapshot(found, exclusive, nil, enterprisehooks.OwnedFileFingerprint)
	if err := os.WriteFile(token, []byte("overwritten\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	takeEnterpriseHookOwnedSnapshot(left, exclusive, nil, enterprisehooks.OwnedFileFingerprint)
	failedPaths := enterpriseHookWatchFailedOwnedPaths(run)
	if failedPaths[token] {
		t.Fatal("bob's failure marked alice's token as failed")
	}
	overwriteAt := lastRetryAt.Add(100 * time.Millisecond)
	drop, _ := enterpriseHookWatchEventDropped(overwriteAt, overwriteAt.Add(6*time.Second),
		fsnotify.Event{Name: token, Op: fsnotify.Write}, failedPaths[token], exclusive, nil,
		found, left, enterprisehooks.OwnedFileFingerprint, true)
	if drop {
		t.Fatal("fsnotify event for alice's overwritten token waited for bob's retry")
	}
	repairAt := overwriteAt.Add(enterpriseHookWatchDebounceDelay(overwriteAt, overwriteAt,
		750*time.Millisecond, enterpriseHookWatchDebounceMaxWait))
	if repairAt.Sub(overwriteAt) >= 5*time.Second || !repairAt.Before(retryDue) {
		t.Fatalf("healthy repair scheduled at %s, failed target retry at %s", repairAt, retryDue)
	}
	// Model the affected target's repair when its fsnotify pass runs.
	if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(token)
	if err != nil || string(got) != issued {
		t.Fatalf("healthy target token after repair = %q, %v", got, err)
	}
	retries.observe("fsnotify", run, nil, repairAt)
	if due, _ := retries.nextDue(); !due.Equal(retryDue) {
		t.Fatalf("healthy target's event moved failed target retry from %s to %s", retryDue, due)
	}
}
