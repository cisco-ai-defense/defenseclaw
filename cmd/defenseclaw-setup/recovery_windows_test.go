// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestPendingRecoveryWaitsForLockedGatewayAndRestoresState(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousServices = serviceState{Gateway: true, Watchdog: true}
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o700); err != nil {
		t.Fatal(err)
	}
	previousMaintenance := []byte("previous maintenance fixture")
	targetMaintenance := []byte("target maintenance fixture")
	if err := os.WriteFile(transaction.MaintenanceBackup, previousMaintenance, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, targetMaintenance, 0o600); err != nil {
		t.Fatal(err)
	}
	transaction.MaintenanceExisted = true
	var err error
	transaction.PreviousMaintenanceSHA256, err = fileSHA256(transaction.MaintenanceBackup)
	if err != nil {
		t.Fatal(err)
	}
	transaction.MaintenanceSHA256, err = fileSHA256(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	writeInstallTree(t, transaction.BackupPath, previous)
	writeRecoveryGatewayFixture(t, transaction.BackupPath, "previous gateway")
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))
	gatewayPath := writeRecoveryGatewayFixture(t, installRoot, "target gateway")
	locked := lockRecoveryGatewayFixture(t, gatewayPath)
	releaseDone := make(chan error, 1)

	phase := setupPhaseQuiescing
	var calls []string
	releaseScheduled := false
	rollback := func(got setupTransaction) error {
		return rollbackSetupTransactionWithRuntime(
			got,
			func(string, string) (serviceState, error) {
				calls = append(calls, "authenticate-stop:gateway+watchdog")
				if !releaseScheduled {
					releaseScheduled = true
					go func() {
						time.Sleep(100 * time.Millisecond)
						releaseDone <- windows.CloseHandle(locked)
					}()
				}
				return serviceState{Gateway: true, Watchdog: true}, nil
			},
			func(path, root string) error {
				calls = append(calls, "verify-release")
				return verifyOwnedRuntimeReleased(path, root)
			},
			func(_ string, _ string, wanted serviceState) (serviceState, error) {
				calls = append(calls, "restore-services")
				if wanted != (serviceState{Gateway: true, Watchdog: true}) {
					t.Fatalf("restored services = %+v", wanted)
				}
				return wanted, nil
			},
		)
	}
	ops := setupRecoveryOps{
		Rollback: rollback,
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return errors.New("unexpected journal transition source")
			}
			calls = append(calls, "journal:"+to)
			phase = to
			return nil
		},
	}
	if err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseQuiescing,
		Transaction:   transaction,
	}, ops); err != nil {
		t.Fatal(err)
	}
	if closeErr := <-releaseDone; closeErr != nil {
		t.Fatalf("release gateway fixture handle: %v", closeErr)
	}
	if phase != setupPhaseComplete {
		t.Fatalf("journal phase = %q", phase)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	assertPathAbsent(t, transaction.BackupPath)
	maintenanceAfter, err := os.ReadFile(maintenancePath)
	if err != nil || string(maintenanceAfter) != string(previousMaintenance) {
		t.Fatalf("restored maintenance = %q, %v", maintenanceAfter, err)
	}
	assertPathAbsent(t, transaction.MaintenanceBackup)
	wantCalls := "authenticate-stop:gateway+watchdog,verify-release,restore-services,journal:complete"
	if got := strings.Join(calls, ","); got != wantCalls {
		t.Fatalf("pending recovery calls = %q, want %q", got, wantCalls)
	}
	before := len(calls)
	if err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseComplete,
		Transaction:   transaction,
	}, ops); err != nil {
		t.Fatal(err)
	}
	if len(calls) != before {
		t.Fatal("complete journal replayed pending recovery effects")
	}
}

func TestCommittedRecoveryWaitsForLockedGatewayBeforeConvergence(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))
	gatewayPath := writeRecoveryGatewayFixture(t, installRoot, "committed gateway")
	locked := lockRecoveryGatewayFixture(t, gatewayPath)
	releaseDone := make(chan error, 1)

	phase := setupPhaseCommitted
	var calls []string
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseCommitted,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Converge: func(got setupTransaction) error {
			return convergeRecoveredCommittedSetupTransactionWithRuntime(
				got,
				func(string, string) (serviceState, error) {
					calls = append(calls, "authenticate-stop:gateway+watchdog")
					go func() {
						time.Sleep(100 * time.Millisecond)
						releaseDone <- windows.CloseHandle(locked)
					}()
					return serviceState{Gateway: true, Watchdog: true}, nil
				},
				func(path, root string) error {
					calls = append(calls, "verify-release")
					return verifyOwnedRuntimeReleased(path, root)
				},
				func(setupTransaction) error {
					calls = append(calls, "converge")
					return probeExecutableRelease(gatewayPath)
				},
			)
		},
		Cleanup: func(setupTransaction) error {
			calls = append(calls, "cleanup")
			return nil
		},
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return errors.New("unexpected journal transition source")
			}
			calls = append(calls, "journal:"+to)
			phase = to
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := <-releaseDone; closeErr != nil {
		t.Fatalf("release gateway fixture handle: %v", closeErr)
	}
	wantCalls := "authenticate-stop:gateway+watchdog,verify-release,converge,journal:converged,cleanup,journal:complete"
	if got := strings.Join(calls, ","); got != wantCalls {
		t.Fatalf("committed recovery calls = %q, want %q", got, wantCalls)
	}
}

func TestWaitForExecutableReleaseRejectsRunningGatewayImageUntilExit(t *testing.T) {
	installRoot, _, _ := testTransactionRoots(t)
	binDir := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(binDir, "defenseclaw-gateway.exe")
	copyExecutable(t, source, gatewayPath)
	ready := filepath.Join(t.TempDir(), "gateway-ready")
	gateway := exec.Command(gatewayPath, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
	gateway.Env = append(os.Environ(),
		"GO_WANT_SETUP_PROCESS_HELPER=1",
		"GO_SETUP_PROCESS_READY="+ready,
	)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = gateway.Process.Kill()
			_, _ = gateway.Process.Wait()
		}
	})
	waitForRecoveryFixture(t, ready)

	if err := waitForExecutableRelease(gatewayPath, 150*time.Millisecond); err == nil ||
		!strings.Contains(err.Error(), "timed out waiting for executable handle release") {
		t.Fatalf("running gateway release proof = %v, want bounded sharing timeout", err)
	}
	if err := gateway.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Process.Wait(); err != nil && !strings.Contains(err.Error(), "signal: killed") {
		t.Fatal(err)
	}
	exited = true
	if err := waitForExecutableRelease(gatewayPath, time.Second); err != nil {
		t.Fatalf("released gateway image remained locked: %v", err)
	}
}

func TestStopOwnedServicesWaitsForAuthenticatedGatewayAndWatchdogExit(t *testing.T) {
	installRoot, dataRoot, _ := testTransactionRoots(t)
	binDir := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(binDir, "defenseclaw-gateway.exe")
	copyExecutable(t, source, gatewayPath)
	t.Setenv("DEFENSECLAW_SETUP_SERVICE_CONTROL_TEST_HELPER", "1")

	type runningFixture struct {
		command *exec.Cmd
		exited  bool
	}
	start := func(name string) *runningFixture {
		t.Helper()
		ready := filepath.Join(t.TempDir(), name+"-ready")
		stop := filepath.Join(t.TempDir(), name+"-stop")
		command := exec.Command(gatewayPath, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
		command.Env = append(os.Environ(),
			"GO_WANT_SETUP_PROCESS_HELPER=1",
			"GO_SETUP_PROCESS_READY="+ready,
			"GO_SETUP_PROCESS_STOP="+stop,
		)
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		fixture := &runningFixture{command: command}
		t.Cleanup(func() {
			if !fixture.exited {
				_ = command.Process.Kill()
				_, _ = command.Process.Wait()
			}
		})
		waitForRecoveryFixture(t, ready)
		switch name {
		case "gateway":
			t.Setenv("DEFENSECLAW_SETUP_TEST_GATEWAY_STOP", stop)
		case "watchdog":
			t.Setenv("DEFENSECLAW_SETUP_TEST_WATCHDOG_STOP", stop)
		default:
			t.Fatalf("unexpected service fixture %q", name)
		}
		imagePath, startIdentity, err := processIdentity(uint32(command.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		state, err := json.Marshal(pidState{
			PID:           command.Process.Pid,
			Executable:    imagePath,
			StartIdentity: startIdentity,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataRoot, name+".pid"), state, 0o600); err != nil {
			t.Fatal(err)
		}
		return fixture
	}
	gateway := start("gateway")
	watchdog := start("watchdog")

	stopped, err := stopOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if stopped != (serviceState{Gateway: true, Watchdog: true}) {
		t.Fatalf("stopped services = %+v", stopped)
	}
	for name, fixture := range map[string]*runningFixture{"gateway": gateway, "watchdog": watchdog} {
		if _, _, err := processIdentity(uint32(fixture.command.Process.Pid)); !errors.Is(err, os.ErrProcessDone) {
			t.Fatalf("%s still owns the installed executable after stop returned: %v", name, err)
		}
		_, _ = fixture.command.Process.Wait()
		fixture.exited = true
	}
	if err := waitForExecutableRelease(gatewayPath, time.Second); err != nil {
		t.Fatalf("stopped service images retained the gateway executable: %v", err)
	}
}

func TestRecoveryRejectsForeignGatewayProcessWithoutMutation(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	writeInstallTree(t, transaction.BackupPath, previous)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	copyExecutable(t, source, gatewayPath)
	ready := filepath.Join(t.TempDir(), "foreign-ready")
	foreign := exec.Command(gatewayPath, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
	foreign.Env = append(os.Environ(),
		"GO_WANT_SETUP_PROCESS_HELPER=1",
		"GO_SETUP_PROCESS_READY="+ready,
	)
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = foreign.Process.Kill()
		_, _ = foreign.Process.Wait()
	})
	waitForRecoveryFixture(t, ready)

	started := false
	err = rollbackSetupTransactionWithRuntime(
		transaction,
		stopOwnedServices,
		verifyOwnedRuntimeReleased,
		func(string, string, serviceState) (serviceState, error) {
			started = true
			return serviceState{}, nil
		},
	)
	if !errors.Is(err, errInstalledProcessRunning) || started {
		t.Fatalf("foreign recovery result = %v, services started=%t", err, started)
	}
	if _, _, processErr := processIdentity(uint32(foreign.Process.Pid)); processErr != nil {
		t.Fatalf("foreign process was stopped: %v", processErr)
	}
	assertInstallVersion(t, installRoot, transaction, transaction.TargetVersion)
	assertInstallVersion(t, transaction.BackupPath, transaction, previous.Version)
}

func writeRecoveryGatewayFixture(t *testing.T, tree, content string) string {
	t.Helper()
	path := filepath.Join(tree, "bin", "defenseclaw-gateway.exe")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lockRecoveryGatewayFixture(t *testing.T, path string) windows.Handle {
	t.Helper()
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

func waitForRecoveryFixture(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("recovery fixture did not become ready: %s", path)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
