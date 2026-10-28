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

package hookexec

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

const systemctlProbeHelperEnv = "DC_HOOKEXEC_SYSTEMCTL_HELPER"

// systemctlProbeHelperStatus is the status the helper ends with, as a hook
// ends with os.Exit once the gateway answered.
const systemctlProbeHelperStatus = 3

// TestSystemctlProbeHelper is the helper process of
// TestGatewayWatchSystemctlDiesWithTheHook: it runs the gateway watch's
// systemd probe against a systemctl that stalls (systemd not answering on
// D-Bus), waits until that systemctl runs, and ends with os.Exit while the
// probe still waits on it.
func TestSystemctlProbeHelper(t *testing.T) {
	stub := os.Getenv(systemctlProbeHelperEnv)
	if stub == "" {
		t.Skip("helper process of TestGatewayWatchSystemctlDiesWithTheHook")
	}
	systemctlPaths = []string{stub}
	go func() { _, _ = systemdGatewayServiceState(context.Background()) }()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(stub + ".pid"); err == nil {
			os.Exit(systemctlProbeHelperStatus)
		}
	}
	os.Exit(1)
}

// G-small: a waiting managed Linux hook polls systemctl about the gateway
// unit in the background. When the gateway answers, the hook ends with
// os.Exit, and the probe's one-second timeout is the hook's own: a systemctl
// stalled on a systemd that does not answer was left running, one more for
// each call. It must die with the hook.
func TestGatewayWatchSystemctlDiesWithTheHook(t *testing.T) {
	if os.Getenv(systemctlProbeHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	stub := filepath.Join(t.TempDir(), "systemctl")
	script := "#!/bin/sh\necho $$ > '" + stub + ".pid.tmp' && /bin/mv '" + stub + ".pid.tmp' '" + stub + ".pid' && exec /bin/sleep 60\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(os.Args[0], "-test.run=^TestSystemctlProbeHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), systemctlProbeHelperEnv+"="+stub)
	var output bytes.Buffer
	helper.Stdout, helper.Stderr = &output, &output
	err := helper.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != systemctlProbeHelperStatus {
		t.Fatalf("helper = %v, want exit %d once its systemctl ran:\n%s", err, systemctlProbeHelperStatus, output.String())
	}
	raw, err := os.ReadFile(stub + ".pid")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		t.Fatalf("systemctl pid %q: %v", raw, err)
	}
	t.Cleanup(func() {
		if stalledSleepRunning(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); stalledSleepRunning(pid); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the stalled systemctl (pid %d) outlived the hook that started it", pid)
		}
	}
}

// stalledSleepRunning reports whether pid is still the stub's sleep and has
// not exited (a zombie waiting for its new parent's reap has).
func stalledSleepRunning(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	end := bytes.LastIndexByte(stat, ')')
	start := bytes.IndexByte(stat, '(')
	if start < 0 || end < start || end+2 >= len(stat) {
		return false
	}
	return string(stat[start+1:end]) == "sleep" && stat[end+2] != 'Z' && stat[end+2] != 'X'
}
