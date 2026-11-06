// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestR109G501BSnapshotSpecialEntryIsBounded(t *testing.T) {
	root := t.TempDir()
	dependency := filepath.Join(root, "node_modules", "dependency")
	if err := os.MkdirAll(dependency, 0o700); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dependency, "named-pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}

	// A file can also change into a pipe after the walk has inspected it.
	done := make(chan error, 1)
	go func() { _, err := hashFile(pipe); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("special entry was hashed as a regular file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot file open waited on a special entry")
	}
	doneEndpoints := make(chan struct{}, 1)
	go func() { _ = extractEndpoints(pipe); doneEndpoints <- struct{}{} }()
	select {
	case <-doneEndpoints:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot endpoint read waited on a special entry")
	}

	before, err := snapshotTarget(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pipe); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pipe, []byte("ordinary file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := snapshotTarget(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if before.ContentHash == after.ContentHash {
		t.Fatal("special entry replacement did not change the snapshot")
	}
}

func TestR109G501BSecureClientSpecialEntryKeepsSnapshotScope(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.DeploymentMode = "managed_enterprise"
	cfg.Enterprise.Profile = "secure_client"
	cfg.Watch.RescanContentGated = true
	root, err := os.MkdirTemp("", "g501b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	plugin := filepath.Join(root, "provider")
	if err := os.MkdirAll(plugin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "package.json"), []byte(`{"name":"provider"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{root}, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "provider", Path: plugin, Connector: "openclaw"}
	before, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(plugin, "runtime.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	after, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	baseline := &audit.SnapshotRow{
		ContentHash: before.ContentHash, ScanID: "scan-1", ScannerFingerprint: "scanner-1",
	}
	if rescan, reason := shouldRescan(baseline, after, "scanner-1", true); rescan {
		t.Fatalf("Secure Client rescanned after an ignored entry: %s", reason)
	}
}
