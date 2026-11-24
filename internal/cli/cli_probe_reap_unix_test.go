// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// reapCLIProbe kills the probe's process group when the test ends and waits
// until it is gone, whatever d.Stop managed (GAP-1056). The daemon starts it
// with Setpgid, so its process group is its PID.
func reapCLIProbe(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		return
	}
	t.Cleanup(func() {
		// d.Stop may have reaped the probe already, and its PID and process
		// group may then belong to another process: signal the group only
		// while the probe still runs (RV-T6A).
		if syscall.Kill(pid, 0) != nil {
			return
		}
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		deadline := time.Now().Add(10 * time.Second)
		for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
	})
}

const gap1056ParentEnv = "DC_TEST_GAP1056_PARENT"

// TestGAP1056ProbeParent is the test process of the GAP-1056 test: it starts
// a probe, says its PID and exits at once, without its cleanups, the way a
// test binary that timed out or was killed goes.
func TestGAP1056ProbeParent(t *testing.T) {
	out := os.Getenv(gap1056ParentEnv)
	if out == "" {
		return
	}
	d := daemon.New(config.DefaultDataPath())
	pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
	if err != nil {
		os.Exit(4)
	}
	waitForCLIProbe(t, d, os.Getenv(cliRestartProbeEnv))
	if err := os.WriteFile(out, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

// GAP-1056: a probe child whose test process is gone exits by itself. Before
// the fix it slept forever with ppid 1 (10 of them held a gate box's heavy
// slot lock for over 3 h after a -race run of this package was cut off).
func TestGAP1056ProbeExitsWhenItsTestProcessIsGone(t *testing.T) {
	gap1056ProbeOutlivesNoParent(t)
}

// RV-T6A: the parent exits as soon as it sees the marker, before the probe
// read its parent. Before the fix the probe read its parent after the
// marker, took ppid 1 for it and never exited.
func TestGAP1056ProbeWhoseParentExitsAtTheMarker(t *testing.T) {
	gap1056ProbeOutlivesNoParent(t, gap1056PauseEnv+"=1")
}

func gap1056ProbeOutlivesNoParent(t *testing.T, env ...string) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "probe.pid")
	log, err := os.Create(filepath.Join(dir, "parent.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP1056ProbeParent$", "-test.count=1")
	cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+filepath.Join(dir, "home"),
		cliRestartProbeEnv+"="+filepath.Join(dir, "probe-running"), gap1056ParentEnv+"="+pidFile)
	cmd.Env = append(cmd.Env, env...)
	// A file, not a pipe: a probe holding the pipe would keep Wait waiting.
	cmd.Stdout, cmd.Stderr = log, log
	runErr := cmd.Run()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		out, _ := os.ReadFile(log.Name())
		t.Fatalf("the test process did not start a probe: %v %v\n%s", runErr, err, out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		t.Fatalf("probe pid %q", b)
	}
	reapCLIProbe(t, pid) // never leaks, red or green
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe %d still runs 10 s after its test process exited (kill 0: %v)", pid, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
