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

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

const cliRestartProbeEnv = "DC_TEST_CLI_RESTART_PROBE"

func TestCLIRestartProcessProbe(t *testing.T) {
	marker := os.Getenv(cliRestartProbeEnv)
	if marker == "" {
		return
	}
	if err := daemon.RegisterCurrentProcess(); err != nil {
		os.Exit(3)
	}
	if err := os.WriteFile(marker, []byte("running\n"), 0o600); err != nil {
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}

// waitForCLIProbe waits until the probe child has written its marker. A -race
// -cover test binary needs seconds just to start on a loaded CI runner, so a
// fixed 5 s budget failed there; wait for the marker or for the child to exit,
// bounded only by the test deadline.
func waitForCLIProbe(t *testing.T, d *daemon.Daemon, marker string) {
	t.Helper()
	limit := time.Now().Add(2 * time.Minute)
	if deadline, ok := t.Deadline(); ok {
		limit = deadline.Add(-30 * time.Second)
	}
	for {
		_, err := os.Stat(marker)
		if err == nil {
			return
		}
		if !os.IsNotExist(err) {
			t.Fatalf("probe marker stat: %v", err)
		}
		if running, _ := d.IsRunning(); !running {
			t.Fatal("probe exited before it created its marker")
		}
		if time.Now().After(limit) {
			t.Fatal("probe marker was not created before the test deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunRestartRefusesUnsafeIdentityBeforeStoppingHealthyGateway(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	marker := filepath.Join(t.TempDir(), "restart-probe-running")
	t.Setenv(cliRestartProbeEnv, marker)

	d := daemon.New(config.DefaultDataPath())
	pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
	if err != nil {
		t.Fatalf("start CLI restart probe: %v", err)
	}
	// Register before any Fatalf so a failed wait never leaks the probe.
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(dataDir, daemon.WatchdogPIDFileName))
		_ = d.Stop(3 * time.Second)
	})
	waitForCLIProbe(t, d, marker)

	watchdogPath := filepath.Join(dataDir, daemon.WatchdogPIDFileName)
	if err := os.WriteFile(watchdogPath, []byte("malformed-watchdog-identity\n"), 0o600); err != nil {
		t.Fatalf("write malformed watchdog identity: %v", err)
	}

	err = runRestart(restartCmd, nil)
	if !errors.Is(err, daemon.ErrUnsafeProcessIdentity) {
		t.Fatalf("runRestart error = %v, want ErrUnsafeProcessIdentity", err)
	}
	if running, currentPID := d.IsRunning(); !running || currentPID != pid {
		t.Fatalf("gateway after refused CLI restart = running %v PID %d, want running PID %d", running, currentPID, pid)
	}
}

func TestRunStartRefusesUnsafeIdentityBeforeAlreadyRunningFastPath(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	marker := filepath.Join(t.TempDir(), "start-probe-running")
	t.Setenv(cliRestartProbeEnv, marker)

	d := daemon.New(config.DefaultDataPath())
	pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
	if err != nil {
		t.Fatalf("start CLI start probe: %v", err)
	}
	// Register before any Fatalf so a failed wait never leaks the probe.
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(dataDir, daemon.WatchdogPIDFileName))
		_ = d.Stop(3 * time.Second)
	})
	waitForCLIProbe(t, d, marker)

	watchdogPath := filepath.Join(dataDir, daemon.WatchdogPIDFileName)
	if err := os.WriteFile(watchdogPath, []byte("malformed-watchdog-identity\n"), 0o600); err != nil {
		t.Fatalf("write malformed watchdog identity: %v", err)
	}

	err = runStart(startCmd, nil)
	if !errors.Is(err, daemon.ErrUnsafeProcessIdentity) {
		t.Fatalf("runStart error = %v, want ErrUnsafeProcessIdentity", err)
	}
	if running, currentPID := d.IsRunning(); !running || currentPID != pid {
		t.Fatalf("gateway after refused CLI start = running %v PID %d, want running PID %d", running, currentPID, pid)
	}
}
