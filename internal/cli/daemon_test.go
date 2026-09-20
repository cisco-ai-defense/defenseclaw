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
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("probe marker stat: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("probe marker was not created: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(dataDir, daemon.WatchdogPIDFileName))
		_ = d.Stop(3 * time.Second)
	})

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
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("probe marker stat: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("probe marker was not created: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(dataDir, daemon.WatchdogPIDFileName))
		_ = d.Stop(3 * time.Second)
	})

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
