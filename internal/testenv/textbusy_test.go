// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package testenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestStartWrittenRetriesATextBusyExecutable holds the script's write
// descriptor open, as a fork elsewhere in the process does, so the first
// exec fails with ETXTBSY; StartWritten starts it once the descriptor is
// closed. Any other start error is returned at once.
func TestStartWrittenRetriesATextBusyExecutable(t *testing.T) {
	script := filepath.Join(t.TempDir(), "busy.sh")
	f, err := os.OpenFile(script, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("#!/bin/sh\nexit 0\n"); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(script).Run(); err == nil {
		t.Skip("this kernel runs a file that is open for writing")
	}
	starts := 0
	cmd, err := StartWritten(func() *exec.Cmd {
		if starts++; starts == 3 {
			_ = f.Close()
		}
		return exec.Command(script)
	})
	if err != nil {
		t.Fatalf("StartWritten: %v after %d starts", err, starts)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if starts < 3 {
		t.Fatalf("started after %d tries, want a retry past the busy file", starts)
	}
	if _, err := StartWritten(func() *exec.Cmd { return exec.Command(filepath.Join(t.TempDir(), "missing")) }); err == nil {
		t.Fatal("a missing executable started")
	}
}
