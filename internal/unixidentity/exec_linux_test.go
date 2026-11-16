//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const parentHelperEnv = "DC_UNIXIDENTITY_PARENT_HELPER"

// parentHelperExit is the status the helper process ends with, as a hook
// ends with os.Exit once its answer is out.
const parentHelperExit = 3

// TestTrustedCommandParentHelper is the helper process of
// TestTrustedCommandDiesWithTheProcessThatStartedIt: it starts a tool that
// stalls (as getent does while NSS does not answer), waits until the tool
// runs, and ends with os.Exit long before the tool's own timeout.
func TestTrustedCommandParentHelper(t *testing.T) {
	pidFile := os.Getenv(parentHelperEnv)
	if pidFile == "" {
		t.Skip("helper process of TestTrustedCommandDiesWithTheProcessThatStartedIt")
	}
	go func() {
		_, _ = runTrustedCommand(context.Background(), "/bin/sh",
			[]string{"-c", `echo $$ > "$0.tmp" && mv "$0.tmp" "$0" && exec sleep 60`, pidFile})
	}()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(pidFile); err == nil {
			os.Exit(parentHelperExit)
		}
	}
	os.Exit(1)
}

// G-small loop 4, finding 3: a managed Linux hook looks its account up with
// getent in the background and ends with os.Exit once the gateway answered.
// A getent that NSS holds must not outlive the hook: it dies with the
// process that started it, well inside runTrustedCommand's own timeout.
func TestTrustedCommandDiesWithTheProcessThatStartedIt(t *testing.T) {
	if os.Getenv(parentHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	pidFile := filepath.Join(t.TempDir(), "tool.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestTrustedCommandParentHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), parentHelperEnv+"="+pidFile)
	var output bytes.Buffer
	helper.Stdout, helper.Stderr = &output, &output
	err := helper.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != parentHelperExit {
		t.Fatalf("helper = %v, want exit %d once its tool ran:\n%s", err, parentHelperExit, output.String())
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		t.Fatalf("tool pid %q: %v", raw, err)
	}
	t.Cleanup(func() {
		if toolRunning(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	for deadline := time.Now().Add(defaultCommandTimeout / 2); toolRunning(pid); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the stalled tool (pid %d) outlived the process that started it", pid)
		}
	}
}

// toolRunning reports whether pid is still the helper's sleep and has not
// exited (a zombie waiting for its new parent's reap has).
func toolRunning(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// pid (comm) state ...
	end := bytes.LastIndexByte(stat, ')')
	start := bytes.IndexByte(stat, '(')
	if start < 0 || end < start || end+2 >= len(stat) {
		return false
	}
	return string(stat[start+1:end]) == "sleep" && stat[end+2] != 'Z' && stat[end+2] != 'X'
}
