// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package watcher

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The scanner --version probe runs the configured scanner from the gateway,
// so it must own the scanner's whole tree like a scan does. Under a bare
// process group, a helper that started a session of its own and closed its
// streams kept running after the probe returned (GAP-0456 class).
func TestScannerVersionProbeEndsDetachedHelper(t *testing.T) {
	detach := "setsid"
	if _, err := exec.LookPath("setsid"); err != nil {
		if _, err := exec.LookPath("perl"); err != nil {
			t.Skip("neither setsid nor perl is installed")
		}
		detach = `perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; exec @ARGV or die'`
	}
	pidFile := filepath.Join(t.TempDir(), "helper.pid")
	binary := filepath.Join(t.TempDir(), "scanner-fixture")
	pidWrite := `echo $$ > "$1"`
	if runtime.GOOS == "linux" {
		// The child PID namespace still sees the host's /proc mount.
		pidWrite = `read -r p _ < /proc/self/stat; echo "$p" > "$1"`
	}
	script := "#!/bin/sh\npidfile='" + pidFile + "'\n" + detach + ` sh -c '` + pidWrite + `; exec sleep 60' sh "$pidfile" </dev/null >/dev/null 2>&1 &
while [ ! -s "$pidfile" ]; do sleep 0.01; done
echo 'scanner-fixture 1.2.3'
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	if got := (&InstallWatcher{}).probeScannerBinaryVersion(binary); got != "scanner-fixture 1.2.3" {
		t.Fatalf("probeScannerBinaryVersion() = %q", got)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		t.Fatalf("helper pid %q: %v", raw, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	// The helper is no child of this process, so its parent reaps it once
	// it is killed.
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("signal 0 to helper %d: %v", pid, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper %d the scanner started during --version is still running", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
