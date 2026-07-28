// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSetupLockSubprocessHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_SETUP_LOCK_TEST_HELPER") != "1" {
		return
	}
	release, err := acquireSetupLock()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("LOCKED")
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestSetupLockIsExclusiveAndReusable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSetupLockSubprocessHelper$")
	cmd.Env = append(os.Environ(), "DEFENSECLAW_SETUP_LOCK_TEST_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatal("setup-lock helper handshake exceeded 15-second deadline")
		}
		t.Fatalf("wait for setup-lock helper: %v", err)
	}
	if strings.TrimSpace(line) != "LOCKED" {
		t.Fatalf("setup-lock helper reported %q", line)
	}
	if release, secondErr := acquireSetupLock(); secondErr == nil {
		_ = release()
		t.Fatal("concurrent acquireSetupLock unexpectedly succeeded")
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatal("setup-lock helper exit exceeded 15-second deadline")
		}
		t.Fatalf("setup-lock helper failed: %v", err)
	}

	release, err := acquireSetupLock()
	if err != nil {
		t.Fatalf("acquire after helper exit: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release setup lock: %v", err)
	}
}
