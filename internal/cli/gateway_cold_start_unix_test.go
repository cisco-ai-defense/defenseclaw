// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

	lock := filepath.Join(dataDir, ".install.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hookColdStartRefusal(dataDir, now); err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatalf("during install = %v, want the install refusal", err)
	}
	// GAP-0196: an install stops the gateway with the stop marker; the
	// refusal names the install, not an operator stop.
	markGatewayStopped(dataDir)
	if err := hookColdStartRefusal(dataDir, now); err == nil || !strings.Contains(err.Error(), "install") || strings.Contains(err.Error(), "stopped") {
		t.Fatalf("during install with the stop marker = %v, want the install refusal", err)
	}
	clearGatewayColdStartState(dataDir)
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

func TestHookColdStartIgnoresAbandonedInstallLock(t *testing.T) {
	for _, tc := range []struct {
		name, pid string
		age       time.Duration
	}{
		{"dead installer", "99999999", 0},
		// No clock (fix/r104-oss-outage-open identity rule): a pid no
		// installer can have, the reader's own, is a reused pid.
		{"pid reused by the reader", strconv.Itoa(os.Getpid()), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			lock := filepath.Join(dataDir, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.pid != "" {
				if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(tc.pid+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.age != 0 {
				then := time.Now().Add(-tc.age)
				if err := os.Chtimes(lock, then, then); err != nil {
					t.Fatal(err)
				}
			}
			if err := hookColdStartRefusal(dataDir, time.Now()); err != nil {
				t.Fatalf("abandoned lock prevented cold start: %v", err)
			}
		})
	}
}

// An old lock that names no installer pid yet is held: the identity rule
// reads no clock, so the hooks do not start the gateway under it.
func TestHookColdStartHoldsAnOldLockWithoutAnInstallerPid(t *testing.T) {
	dataDir := t.TempDir()
	lock := filepath.Join(dataDir, ".install.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-11 * time.Minute)
	if err := os.Chtimes(lock, then, then); err != nil {
		t.Fatal(err)
	}
	if err := hookColdStartRefusal(dataDir, time.Now()); err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatalf("old lock without an installer pid = %v, want the install refusal", err)
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

// An operator stop must wait for an in-flight watchdog cold start before it
// checks whether there is a gateway to stop or writes the final stop marker.
func TestStopWaitsForWatchdogColdStartLock(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	release, err := acquireGatewayStartLock(dataDir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runStop(stopCmd, nil) }()
	select {
	case err := <-done:
		release()
		t.Fatalf("stop returned while a cold start held the start lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// A cold start that passed its initial marker check can clear a marker
	// written before it finishes. Stop must publish its marker afterward.
	clearGatewayColdStartState(dataDir)
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop after cold start: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not finish after the cold start released its lock")
	}
	if _, err := os.Stat(gatewayStoppedMarkerPath(dataDir)); err != nil {
		t.Fatalf("stop marker after cold start: %v", err)
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

// GAP-0143: every hook that meets a restart starts the gateway. Only the
// first takes the start lock; a start that finds it held (a restart, or
// another hook's start, is bringing the gateway up) ends at once instead of
// waiting in line, so a restart does not leave a dozen start processes.
func TestHookColdStartEndsAtOnceWhileAnotherStartRuns(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	release, err := acquireGatewayStartLock(dataDir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := startCmd.Flags().Set(hookColdStartFlag, "true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = startCmd.Flags().Set(hookColdStartFlag, "false") })
	started := time.Now()
	if err := runStart(startCmd, nil); err != nil {
		t.Fatalf("hook start beside a running start = %v, want it to end quietly", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hook start waited %s for the start lock, want it to end at once", elapsed)
	}
	if _, statErr := os.Stat(gatewayColdStartFailedPath(dataDir)); !os.IsNotExist(statErr) {
		t.Fatalf("a hook start that ended beside another start recorded a failure: %v", statErr)
	}
}

// GAP-2082: an upgrade that stopped between the binary swap and its finish
// (power loss) leaves .install.lock with a dead installer and an
// interrupted-install record beside it. The hooks no longer hold that lock
// (GAP-1024), but neither a hook nor the watchdog may start the half-done
// install: the cold start refuses with the install reason until the next
// installer run finishes or undoes it. Without the record the dead
// installer's lock is abandoned and the start goes ahead (control).
func TestHookColdStartRefusesWhileAnInterruptedInstallWaitsForRecovery(t *testing.T) {
	for _, record := range []string{"", "previous.new", ".repair", ".rollback-hold", ".lifecycle-txn.json"} {
		t.Run("record "+record, func(t *testing.T) {
			dataDir := t.TempDir()
			lock := filepath.Join(dataDir, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte("99999999\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if record != "" {
				if err := os.Mkdir(filepath.Join(dataDir, record), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := hookColdStartRefusal(dataDir, time.Now())
			if record == "" {
				if err != nil {
					t.Fatalf("abandoned lock without a recovery record refused the start: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "install") {
				t.Fatalf("pending recovery %s = %v, want the install refusal", record, err)
			}
			// A record without a lock is not an install: the installer
			// removes the lock last only after it finished the recovery.
			if err := os.RemoveAll(lock); err != nil {
				t.Fatal(err)
			}
			if err := hookColdStartRefusal(dataDir, time.Now()); err != nil {
				t.Fatalf("record %s without a lock refused the start: %v", record, err)
			}
		})
	}
}
