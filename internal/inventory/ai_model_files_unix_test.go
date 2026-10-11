// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDetectModelFilesRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "models", "blocked.gguf")
	if err := unix.Mkdir(filepath.Dir(fifo), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	manifestFIFO := filepath.Join(root, ".ollama", "models", "manifests", "registry.ollama.ai", "library", "blocked", "latest")
	if err := os.MkdirAll(filepath.Dir(manifestFIFO), 0o700); err != nil {
		t.Fatalf("mkdir manifest: %v", err)
	}
	if err := unix.Mkfifo(manifestFIFO, 0o600); err != nil {
		t.Fatalf("mkfifo manifest: %v", err)
	}
	svc := newModelFileTestService(t, t.TempDir(), root, 20, false)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err == nil {
		t.Fatal("special-file manifest did not surface a partial-scan error")
	}
	if files != 0 || len(signals) != 0 {
		t.Fatalf("FIFO was inventoried: files=%d signals=%+v", files, signals)
	}
}

// A package.json that is a FIFO, or a link to a device, is skipped without
// blocking on it or reading it, and a regular manifest beside them is still
// read (GAP-0694: a link to /dev/zero exhausted the host's memory).
func TestPackageManifestScanReadsOnlyRegularFiles(t *testing.T) {
	home := t.TempDir()
	manifest := func(dir string) string {
		path := filepath.Join(home, "work", dir, "package.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := unix.Mkfifo(manifest("a-pipe"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if err := os.Symlink("/dev/zero", manifest("b-device")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, manifest("c-plain"), `{"dependencies":{"ai":"^3.0.0"}}`)
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, DataDir: filepath.Join(home, "data"), HomeDir: home, ScanRoots: []string{home},
		IncludePackageManifests: true, MaxFilesPerScan: 100, MaxFileBytes: 1 << 20,
	}, catalog)
	done := make(chan []AISignal, 1)
	go func() {
		signals, _, _ := svc.detectPackageManifests(context.Background())
		done <- signals
	}()
	select {
	case signals := <-done:
		if len(signals) == 0 {
			t.Fatal("the regular manifest beside the special files was not read")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the manifest scan blocked on a special file")
	}
}
