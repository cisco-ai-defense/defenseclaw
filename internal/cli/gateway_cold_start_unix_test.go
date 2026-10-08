// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHookColdStartRefusesAfterStopDuringInstallAndAfterAFailure(t *testing.T) {
	dataDir := t.TempDir()
	now := time.Now()
	if err := hookColdStartRefusal(dataDir, now); err != nil {
		t.Fatalf("clean data dir refused a hook start: %v", err)
	}

	markGatewayStopped(dataDir)
	if err := hookColdStartRefusal(dataDir, now); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("after stop = %v, want the stop refusal", err)
	}
	clearGatewayColdStartState(dataDir)
	if err := hookColdStartRefusal(dataDir, now); err != nil {
		t.Fatalf("after start cleared the stop = %v", err)
	}

	lock := filepath.Join(dataDir, installLockName)
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hookColdStartRefusal(dataDir, now); err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatalf("during install = %v, want the install refusal", err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}

	recordHookColdStartFailure(dataDir, startConfigLoadError{err: errors.New("cannot start the gateway: yaml: line 3")})
	if body, err := os.ReadFile(gatewayColdStartFailedPath(dataDir)); err != nil || !strings.Contains(string(body), "config-invalid") {
		t.Fatalf("failure marker = %q, %v; want the config-invalid cause the hooks read (GAP-0409)", body, err)
	}
	if err := hookColdStartRefusal(dataDir, time.Now()); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("right after a failed start = %v, want the backoff refusal", err)
	}
	if err := hookColdStartRefusal(dataDir, time.Now().Add(hookColdStartBackoff+time.Second)); err != nil {
		t.Fatalf("after the backoff window = %v", err)
	}
}

func TestStopRecordsTheStopAndHookStartHonorsIt(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	if err := runStop(stopCmd, nil); err != nil {
		t.Fatalf("stop with nothing running: %v", err)
	}
	if _, err := os.Stat(gatewayStoppedMarkerPath(dataDir)); err != nil {
		t.Fatalf("stop left no marker: %v", err)
	}

	if err := startCmd.Flags().Set(hookColdStartFlag, "true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = startCmd.Flags().Set(hookColdStartFlag, "false") })
	err := runStart(startCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "hook cold start skipped") {
		t.Fatalf("hook start after stop = %v, want it skipped", err)
	}
	if _, statErr := os.Stat(gatewayColdStartFailedPath(dataDir)); !os.IsNotExist(statErr) {
		t.Fatalf("a skipped hook start recorded a failure: %v", statErr)
	}
}

func TestStartLockRunsUnlockedWithoutADataDirectory(t *testing.T) {
	release, err := acquireGatewayStartLock(filepath.Join(t.TempDir(), "missing"), time.Second)
	if err != nil {
		t.Fatalf("missing data dir = %v, want the start to proceed unlocked", err)
	}
	release()
}

// GAP-1229: a hook cold start runs with the hook's locked-down PATH. The
// gateway it starts gets the PATH of the last start from the account's own
// session first, so agent CLIs such as Codex's node launcher still resolve.
func TestHookColdStartRestoresTheRecordedLoginPath(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("PATH", "/opt/node22/bin:relative/bin::/usr/bin")
	recordGatewayLoginPath(dataDir)
	info, err := os.Stat(filepath.Join(dataDir, gatewayLoginPathName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recorded PATH file = %v, %v; want a 0600 file", info, err)
	}

	t.Setenv("PATH", "/home/u/.local/bin:/usr/local/bin:/usr/bin:/bin")
	restoreGatewayLoginPath(dataDir)
	if got, want := os.Getenv("PATH"), "/opt/node22/bin:/usr/bin:/home/u/.local/bin:/usr/local/bin:/bin"; got != want {
		t.Fatalf("cold start PATH = %q, want %q", got, want)
	}

	// Without a record the hook's PATH stays as it is.
	t.Setenv("PATH", "/usr/bin:/bin")
	restoreGatewayLoginPath(t.TempDir())
	if got := os.Getenv("PATH"); got != "/usr/bin:/bin" {
		t.Fatalf("PATH without a record = %q", got)
	}
}

// The watchdog checks the external config used by a per-user gateway.
func TestWatchdogColdStartWithExternalConfig(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	if got := watchdogGatewayConfigPath(dataDir); got != configPath {
		t.Fatalf("watchdog config path = %q, want %q", got, configPath)
	}
}
