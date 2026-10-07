// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0132: an upgrade replaces the scanner runtime while a scan still runs
// the installed image (Windows refuses to overwrite a mapped image).
func TestCopyWindowsScannerRuntimeReplacesARunningImage(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "defenseclaw-scanners.exe")
	copyFile := func(from, to string) {
		in, err := os.Open(from)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		out, err := os.Create(to)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		_ = out.Close()
	}
	copyFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), target)
	running := exec.Command(target, "-n", "20", "127.0.0.1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Process.Kill(); _, _ = running.Process.Wait() })
	time.Sleep(500 * time.Millisecond)

	source := filepath.Join(t.TempDir(), "new.exe")
	if err := os.WriteFile(source, []byte("new runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyWindowsScannerRuntime(source, target, root, ""); err != nil {
		t.Fatalf("replace a running scanner runtime: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, []byte("new runtime")) {
		t.Fatalf("installed runtime = %q, %v", got, err)
	}
}
