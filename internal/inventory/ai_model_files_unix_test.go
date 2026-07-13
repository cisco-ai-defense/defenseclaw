// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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
