// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func TestWatchdogUnlockedLiveProcessRequiresStrongIdentity(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")
	write := func(info watchdogPIDInfo) {
		t.Helper()
		data, err := json.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(pidPath, append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}

	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	write(watchdogPIDInfo{PID: os.Getpid(), Executable: executable, StartIdentity: identity})
	if live, got := watchdogUnlockedLiveProcess(pidPath); !live || got.PID != os.Getpid() {
		t.Fatalf("strong live record = (live=%v, info=%+v)", live, got)
	}

	write(watchdogPIDInfo{PID: os.Getpid()})
	if live, got := watchdogUnlockedLiveProcess(pidPath); live {
		t.Fatalf("legacy liveness-only record treated as strongly owned: %+v", got)
	}
	if verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid()}) {
		t.Fatal("bare numeric PID treated as trusted watchdog identity on Windows")
	}
}

func TestWindowsWatchdogInterruptedAtomicPublicationNeverLeavesEmptyCanonical(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	interrupted := errors.New("simulated interruption before publish")
	watchdogPIDPublicationBeforePublish = func(string) error { return interrupted }
	t.Cleanup(func() { watchdogPIDPublicationBeforePublish = nil })

	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "test-control",
	}
	if holder, err := acquireWatchdogPIDFile(pidPath, info); !errors.Is(err, interrupted) {
		if holder != nil {
			_ = holder.Close()
		}
		t.Fatalf("interrupted acquire error = %v", err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("interrupted first publication created canonical PID file: %v", err)
	}

	prior := []byte(`{"pid":424242,"executable":"stale.exe","start_identity":"stale"}` + "\n")
	if err := safefile.WritePrivate(pidPath, prior); err != nil {
		t.Fatal(err)
	}
	if holder, err := acquireWatchdogPIDFile(pidPath, info); !errors.Is(err, interrupted) {
		if holder != nil {
			_ = holder.Close()
		}
		t.Fatalf("interrupted replacement error = %v", err)
	}
	got, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(prior) || len(got) == 0 {
		t.Fatalf("interrupted replacement changed canonical record: %q", got)
	}
}

func TestWindowsWatchdogAtomicReplacePublishesCompleteLockedRecord(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	prior := []byte(`{"pid":424242,"executable":"stale.exe","start_identity":"stale"}` + "\n")
	if err := safefile.WritePrivate(pidPath, prior); err != nil {
		t.Fatal(err)
	}
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "test-control",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	got, err := readWatchdogPIDInfo(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != info.PID || got.Executable != info.Executable || got.StartIdentity != info.StartIdentity {
		t.Fatalf("published PID record = %+v, want %+v", got, info)
	}
	locked, lockedInfo, err := watchdogIsLocked(pidPath)
	if err != nil || !locked || lockedInfo.PID != info.PID {
		t.Fatalf("atomic record ownership = locked=%v info=%+v err=%v", locked, lockedInfo, err)
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(pidPath), ".safefile-watchdog.pid-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("atomic publication left temp artifacts: %v", temps)
	}
}

func TestWindowsWatchdogExplicitRepairRemovesInvalidAndPreservesSibling(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "watchdog.pid")
	siblingPath := filepath.Join(dir, "unrelated.txt")
	siblingData := []byte("preserve me\n")
	if err := os.WriteFile(siblingPath, siblingData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(pidPath, nil); err != nil {
		t.Fatal(err)
	}
	removed, err := removeStaleWatchdogPIDFile(pidPath)
	if err != nil || !removed {
		t.Fatalf("zero-byte repair = removed=%v err=%v", removed, err)
	}
	gotSibling, err := os.ReadFile(siblingPath)
	if err != nil || string(gotSibling) != string(siblingData) {
		t.Fatalf("unrelated sibling changed: %q err=%v", gotSibling, err)
	}
}

func TestWindowsWatchdogExplicitRepairRefusesReparseAndPreservesTarget(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	outside := filepath.Join(t.TempDir(), "outside.pid")
	outsideData := []byte("unrelated\n")
	if err := os.WriteFile(outside, outsideData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, pidPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if removed, err := removeStaleWatchdogPIDFile(pidPath); err == nil || removed {
		t.Fatalf("reparse repair = removed=%v err=%v", removed, err)
	}
	gotOutside, err := os.ReadFile(outside)
	if err != nil || string(gotOutside) != string(outsideData) {
		t.Fatalf("reparse target changed: %q err=%v", gotOutside, err)
	}
}

func TestWindowsWatchdogExplicitRepairPreservesStrongLiveUnrelatedProcessRecord(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	live := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
	}
	data, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(pidPath, append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	removed, err := removeStaleWatchdogPIDFile(pidPath)
	if err != nil || removed {
		t.Fatalf("live foreign record cleanup = removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("live foreign PID record was removed: %v", err)
	}
}

func TestWindowsWatchdogExplicitRepairRefusesUnsafeDACL(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	if err := safefile.WritePrivate(pidPath, nil); err != nil {
		t.Fatal(err)
	}
	setWatchdogTestUnsafeReadDACL(t, pidPath)
	removed, err := removeStaleWatchdogPIDFile(pidPath)
	if err == nil || removed {
		t.Fatalf("unsafe-DACL repair = removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("unsafe-DACL PID file was removed: %v", err)
	}
}

func TestWindowsWatchdogLifecycleRefusesUntrustedStableOwnershipBeforeCanonicalMutation(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*testing.T, string)
		inspectErr error
	}{
		{
			name: "unsafe DACL",
			setup: func(t *testing.T, dataDir string) {
				ownershipPath := filepath.Join(dataDir, watchdogOwnershipFile)
				if err := safefile.WritePrivate(ownershipPath, []byte(watchdogOwnershipMarker)); err != nil {
					t.Fatal(err)
				}
				setWatchdogTestUnsafeReadDACL(t, ownershipPath)
			},
		},
		{
			name: "reparse point",
			setup: func(t *testing.T, dataDir string) {
				outside := filepath.Join(t.TempDir(), "outside.lock")
				if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(dataDir, watchdogOwnershipFile)); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
		},
		{name: "access denied", inspectErr: windows.ERROR_ACCESS_DENIED},
		{name: "inspection unavailable", inspectErr: windows.ERROR_SHARING_VIOLATION},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dataDir)
			pidPath := filepath.Join(dataDir, watchdogPIDFile)
			canonical := []byte("malformed-but-removable\n")
			if err := safefile.WritePrivate(pidPath, canonical); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, dataDir)
			}

			originalInspector := watchdogOwnershipLockInspector
			if tc.inspectErr != nil {
				watchdogOwnershipLockInspector = func(string) (bool, bool, error) {
					return true, false, tc.inspectErr
				}
			}
			originalStart := watchdogStartBackground
			originalTerminate := watchdogRequestTerminate
			spawned := false
			signalled := false
			watchdogStartBackground = func(*execCommand) error {
				spawned = true
				return errors.New("unexpected child start")
			}
			watchdogRequestTerminate = func(watchdogPIDInfo, *os.Process) error {
				signalled = true
				return errors.New("unexpected process signal")
			}
			t.Cleanup(func() {
				watchdogOwnershipLockInspector = originalInspector
				watchdogStartBackground = originalStart
				watchdogRequestTerminate = originalTerminate
			})

			if err := runWatchdogStart(nil, nil); err == nil {
				t.Fatal("start accepted untrusted stable ownership")
			}
			if err := runWatchdogStop(nil, nil); err == nil {
				t.Fatal("stop accepted untrusted stable ownership")
			}
			if spawned || signalled {
				t.Fatalf("lifecycle crossed fail-closed boundary: spawned=%v signalled=%v", spawned, signalled)
			}
			got, err := os.ReadFile(pidPath)
			if err != nil || string(got) != string(canonical) {
				t.Fatalf("canonical PID changed: got=%q err=%v", got, err)
			}
		})
	}
}

func TestWindowsWatchdogStatusDoesNotRemoveInvalidPIDFile(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(dataDir, "missing-config.yaml"))
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	if err := safefile.WritePrivate(pidPath, nil); err != nil {
		t.Fatal(err)
	}
	if err := runWatchdogStatus(nil, nil); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(pidPath)
	if err != nil {
		t.Fatalf("status removed invalid PID file: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || len(data) != 0 {
		t.Fatalf("status changed invalid PID file: %q err=%v", data, err)
	}
}

func TestWindowsWatchdogStatusReportsEnabledStoppedWithoutCreatingPIDFile(t *testing.T) {
	dataDir := t.TempDir()
	configPath := writeWatchdogEnabledTestConfig(t, dataDir)
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	var statusErr error
	output := captureStdout(t, func() { statusErr = runWatchdogStatus(nil, nil) })
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if !strings.Contains(output, "enabled but not running") ||
		!strings.Contains(output, "defenseclaw-gateway watchdog start") {
		t.Fatalf("enabled/stopped status output = %q", output)
	}
	if _, err := os.Lstat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("read-only status created canonical PID file: %v", err)
	}
}

func TestWindowsWatchdogStatusSurfacesDegradedAsDownstreamWithoutMutation(t *testing.T) {
	dataDir := t.TempDir()
	configPath := writeWatchdogEnabledTestConfig(t, dataDir)
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "degraded-status",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	statePath := filepath.Join(dataDir, watchdogStateFile)
	if err := os.WriteFile(statePath, []byte("degraded"), 0o600); err != nil {
		t.Fatal(err)
	}
	pidBefore, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var statusErr error
	output := captureStdout(t, func() { statusErr = runWatchdogStatus(nil, nil) })
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if !strings.Contains(output, "last known state: degraded") ||
		!strings.Contains(output, "downstream connector") ||
		!strings.Contains(output, "restarting the watchdog is not a repair") {
		t.Fatalf("degraded status output = %q", output)
	}
	pidAfter, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(pidAfter) != string(pidBefore) || string(stateAfter) != string(stateBefore) {
		t.Fatalf("read-only degraded status mutated pid/state: pid=%q state=%q", pidAfter, stateAfter)
	}
}

func TestWindowsWatchdogStatusDoesNotTreatMissingStateAsHealthy(t *testing.T) {
	dataDir := t.TempDir()
	configPath := writeWatchdogEnabledTestConfig(t, dataDir)
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "missing-state-status",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	var statusErr error
	output := captureStdout(t, func() { statusErr = runWatchdogStatus(nil, nil) })
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if !strings.Contains(output, "last known state: unavailable") || strings.Contains(output, "Last known state: healthy") {
		t.Fatalf("missing-state status output = %q", output)
	}
}

func TestWindowsWatchdogConcurrentStartWaitsForAtomicPublication(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "concurrent-start",
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	watchdogPIDPublicationBeforePublish = func(string) error {
		close(entered)
		<-release
		return nil
	}
	t.Cleanup(func() { watchdogPIDPublicationBeforePublish = nil })
	type acquisition struct {
		holder *os.File
		err    error
	}
	acquired := make(chan acquisition, 1)
	go func() {
		holder, err := acquireWatchdogPIDFile(pidPath, info)
		acquired <- acquisition{holder: holder, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first start did not reach atomic publication seam")
	}

	startDone := make(chan error, 1)
	go func() { startDone <- runWatchdogStart(nil, nil) }()
	select {
	case err := <-startDone:
		t.Fatalf("concurrent start returned before canonical publication: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	result := <-acquired
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.holder.Close()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("concurrent start did not converge on published owner: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent start exceeded bounded publication readiness")
	}
	got, err := readWatchdogPIDInfo(pidPath)
	if err != nil || got.ControlName != info.ControlName {
		t.Fatalf("canonical publication = %+v err=%v", got, err)
	}
}

func TestWindowsGatewayRestartInspectionWaitsForAtomicWatchdogPublication(t *testing.T) {
	dataDir := t.TempDir()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "concurrent-restart",
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	watchdogPIDPublicationBeforePublish = func(string) error {
		close(entered)
		<-release
		return nil
	}
	t.Cleanup(func() { watchdogPIDPublicationBeforePublish = nil })
	type acquisition struct {
		holder *os.File
		err    error
	}
	acquired := make(chan acquisition, 1)
	go func() {
		holder, err := acquireWatchdogPIDFile(pidPath, info)
		acquired <- acquisition{holder: holder, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not reach atomic publication seam")
	}

	restartInspection := make(chan error, 1)
	go func() {
		running, err := rotationWatchdogRunning(dataDir)
		if err == nil && !running {
			err = errors.New("restart inspection did not recognize the published watchdog")
		}
		restartInspection <- err
	}()
	select {
	case err := <-restartInspection:
		t.Fatalf("restart inspection returned before canonical publication: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	result := <-acquired
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.holder.Close()
	select {
	case err := <-restartInspection:
		if err != nil {
			t.Fatalf("restart inspection did not converge on published owner: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("restart inspection exceeded bounded publication readiness")
	}
}

func TestWindowsWatchdogAcquireRejectsIncompleteIdentityBeforeOwnershipPublication(t *testing.T) {
	for _, weak := range []watchdogPIDInfo{
		{PID: os.Getpid(), StartIdentity: watchdogProcessStartIdentity(os.Getpid())},
		{PID: os.Getpid(), Executable: mustWatchdogTestExecutable(t)},
	} {
		dataDir := t.TempDir()
		pidPath := filepath.Join(dataDir, watchdogPIDFile)
		if holder, err := acquireWatchdogPIDFile(pidPath, weak); err == nil || holder != nil {
			if holder != nil {
				_ = holder.Close()
			}
			t.Fatalf("weak acquisition = holder=%v err=%v", holder, err)
		}
		for _, path := range []string{pidPath, filepath.Join(dataDir, watchdogOwnershipFile)} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("weak acquisition published %s: %v", path, err)
			}
		}
	}
}

func TestWindowsWaitForWatchdogStartRejectsWeakHeldPublication(t *testing.T) {
	dataDir := t.TempDir()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	weak := []byte(fmt.Sprintf(`{"pid":%d}`+"\n", os.Getpid()))
	if err := safefile.WritePrivate(pidPath, weak); err != nil {
		t.Fatal(err)
	}
	ownershipPath := filepath.Join(dataDir, watchdogOwnershipFile)
	if err := ensureWatchdogOwnershipFile(ownershipPath); err != nil {
		t.Fatal(err)
	}
	holder, exists, err := openPrivateWatchdogFile(
		ownershipPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
	)
	if err != nil || !exists {
		t.Fatalf("open stable ownership: exists=%v err=%v", exists, err)
	}
	defer holder.Close()
	overlapped := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(
		windows.Handle(holder.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.UnlockFileEx(windows.Handle(holder.Fd()), 0, 1, 0, overlapped) }()

	if err := waitForWatchdogStart(pidPath, os.Getpid(), 50*time.Millisecond, 5*time.Millisecond); err == nil ||
		!strings.Contains(err.Error(), "verified process identity") {
		t.Fatalf("weak held publication readiness error = %v", err)
	}
	got, err := os.ReadFile(pidPath)
	if err != nil || string(got) != string(weak) {
		t.Fatalf("readiness mutated weak publication: got=%q err=%v", got, err)
	}
}

func TestWindowsWaitForWatchdogStartDoesNotProbeOwnershipBeforePublication(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), watchdogPIDFile)
	if err := ensureWatchdogOwnershipFile(filepath.Join(filepath.Dir(pidPath), watchdogOwnershipFile)); err != nil {
		t.Fatal(err)
	}
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
	}

	originalProbe := watchdogStartPublicationProbe
	originalInspector := watchdogOwnershipLockInspector
	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	inspected := make(chan struct{}, 1)
	var firstProbe sync.Once
	watchdogStartPublicationProbe = func(path string, expectedPID int) (bool, error) {
		firstProbe.Do(func() {
			close(probeStarted)
			<-releaseProbe
		})
		return watchdogStartPublicationReady(path, expectedPID)
	}
	watchdogOwnershipLockInspector = func(path string) (bool, bool, error) {
		select {
		case inspected <- struct{}{}:
		default:
		}
		return originalInspector(path)
	}
	t.Cleanup(func() {
		watchdogStartPublicationProbe = originalProbe
		watchdogOwnershipLockInspector = originalInspector
	})

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- waitForWatchdogStart(pidPath, info.PID, time.Second, time.Millisecond)
	}()
	<-probeStarted
	select {
	case <-inspected:
		t.Fatal("readiness probed the ownership byte before PID publication")
	default:
	}

	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		close(releaseProbe)
		t.Fatalf("child could not acquire ownership before publishing: %v", err)
	}
	defer holder.Close()
	close(releaseProbe)
	if err := <-waitDone; err != nil {
		t.Fatalf("waitForWatchdogStart: %v", err)
	}
	select {
	case <-inspected:
	default:
		t.Fatal("readiness never verified held ownership after PID publication")
	}
}

func TestWindowsWatchdogForegroundIdentityFailurePublishesNothingAndDoesNotRunLoop(t *testing.T) {
	tests := []struct {
		name        string
		executable  func() (string, error)
		startID     func(int) string
		wantMessage string
	}{
		{
			name: "executable lookup failure",
			executable: func() (string, error) {
				return "", errors.New("injected executable lookup failure")
			},
			startID:     watchdogProcessStartIdentity,
			wantMessage: "resolve executable identity",
		},
		{
			name: "missing process start identity",
			executable: func() (string, error) {
				return mustWatchdogTestExecutable(t), nil
			},
			startID:     func(int) string { return "" },
			wantMessage: "complete executable and process start identity",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dataDir)
			t.Setenv("DEFENSECLAW_CONFIG", writeWatchdogEnabledTestConfig(t, dataDir))

			originalExecutable := watchdogExecutablePath
			originalStartID := watchdogCurrentProcessStartIdentity
			originalLoop := watchdogLoopRunner
			loopCalled := false
			watchdogExecutablePath = tc.executable
			watchdogCurrentProcessStartIdentity = tc.startID
			watchdogLoopRunner = func(
				context.Context,
				string,
				time.Duration,
				int,
				watchdogHealthRequirements,
				*gateway.WebhookDispatcher,
				watchdogRecoveryRecorder,
			) {
				loopCalled = true
			}
			t.Cleanup(func() {
				watchdogExecutablePath = originalExecutable
				watchdogCurrentProcessStartIdentity = originalStartID
				watchdogLoopRunner = originalLoop
			})

			err := runWatchdogForeground(nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("foreground identity failure = %v", err)
			}
			if loopCalled {
				t.Fatal("foreground continued into watchdog loop after identity failure")
			}
			for _, path := range []string{
				filepath.Join(dataDir, watchdogPIDFile),
				filepath.Join(dataDir, watchdogOwnershipFile),
			} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("identity failure published %s: %v", path, err)
				}
			}
		})
	}
}

func writeWatchdogEnabledTestConfig(t *testing.T, dataDir string) string {
	t.Helper()
	configPath := filepath.Join(dataDir, "config.yaml")
	raw := "config_version: 8\ndata_dir: " + strconv.Quote(dataDir) +
		"\ngateway:\n  watchdog:\n    enabled: true\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func setWatchdogTestUnsafeReadDACL(t *testing.T, path string) {
	t.Helper()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(sid *windows.SID, sidType windows.TRUSTEE_TYPE, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  sidType,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		entry(currentUser.User.Sid, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL),
		entry(everyone, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func mustWatchdogTestExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func TestVerifyWatchdogProcess_StartIdentity(t *testing.T) {
	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	executable := mustWatchdogTestExecutable(t)
	if !verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), Executable: executable, StartIdentity: identity}) {
		t.Fatal("verifyWatchdogProcess rejected the matching Windows start identity")
	}
	if verifyWatchdogProcess(
		watchdogPIDInfo{PID: os.Getpid(), Executable: executable, StartIdentity: identity + "-stale"},
	) {
		t.Fatal("verifyWatchdogProcess accepted a stale Windows start identity")
	}
}

func TestWindowsWatchdogLockStateIsAuthoritative(t *testing.T) {
	pidPath := t.TempDir() + `\watchdog.pid`
	if locked, _, err := watchdogIsLocked(pidPath); err != nil || locked {
		t.Fatalf("missing lock state = (locked=%v, err=%v)", locked, err)
	}
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "control",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	locked, got, err := watchdogIsLocked(pidPath)
	if err != nil || !locked {
		_ = holder.Close()
		t.Fatalf("held lock state = (locked=%v, err=%v)", locked, err)
	}
	if got.PID != info.PID || got.StartIdentity != info.StartIdentity || got.ControlName != info.ControlName {
		_ = holder.Close()
		t.Fatalf("locked fingerprint = %+v, want %+v", got, info)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	if locked, _, err := watchdogIsLocked(pidPath); err != nil || locked {
		t.Fatalf("released lock state = (locked=%v, err=%v)", locked, err)
	}
}

func TestWindowsWatchdogObservationRejectsRetainedWriter(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	writer, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := safefile.ProtectFile(pidPath); err != nil {
		t.Fatal(err)
	}
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "legacy-retained-writer",
	}
	if err := writeWatchdogPIDInfo(writer, info); err != nil {
		t.Fatal(err)
	}
	lock := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(
		windows.Handle(writer.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		lock,
	); err != nil {
		t.Fatal(err)
	}
	defer windows.UnlockFileEx(windows.Handle(writer.Fd()), 0, 1, 0, lock) //nolint:errcheck

	locked, got, err := watchdogIsLocked(pidPath)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("mutable locked record = (locked=%v info=%+v err=%v), want sharing violation", locked, got, err)
	}
	if locked || got != (watchdogPIDInfo{}) {
		t.Fatalf("mutable locked record was trusted: locked=%v info=%+v", locked, got)
	}
}

func TestWindowsWatchdogObservationRejectsUnsafeCustody(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "unsafe-custody",
	}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(pidPath, data); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	unsafeACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		pidPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		unsafeACL,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	holder, err := os.Open(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	lock := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(
		windows.Handle(holder.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		lock,
	); err != nil {
		t.Fatal(err)
	}
	defer windows.UnlockFileEx(windows.Handle(holder.Fd()), 0, 1, 0, lock) //nolint:errcheck

	locked, got, err := watchdogIsLocked(pidPath)
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe-custody observation = (locked=%v info=%+v err=%v)", locked, got, err)
	}
	if locked || got != (watchdogPIDInfo{}) {
		t.Fatalf("unsafe-custody locked record was trusted: locked=%v info=%+v", locked, got)
	}
}

func TestWindowsWatchdogObservationAllowsStableReadAndDeniesMutation(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "stable-read-control",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	observer, exists, err := openPrivateWatchdogFile(
		pidPath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
	)
	if err != nil || !exists || observer == nil {
		t.Fatalf("open stable watchdog observation: exists=%v err=%v", exists, err)
	}
	defer observer.Close()
	data, err := io.ReadAll(io.LimitReader(observer, maxWatchdogPIDFileBytes+1))
	if err != nil {
		t.Fatalf("stable read of live watchdog identity: %v", err)
	}
	var got watchdogPIDInfo
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode live watchdog identity: %v", err)
	}
	if got != info {
		t.Fatalf("live watchdog identity = %+v, want %+v", got, info)
	}

	writer, writeErr := os.OpenFile(pidPath, os.O_WRONLY, 0)
	if writeErr == nil {
		_ = writer.Close()
		t.Fatal("stable watchdog observation allowed an in-place writer")
	}
	if !errors.Is(writeErr, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("in-place writer error = %v, want sharing violation", writeErr)
	}

	replacementPath := filepath.Join(filepath.Dir(pidPath), "watchdog-replacement.pid")
	if err := os.WriteFile(replacementPath, []byte(`{"pid":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	from, err := windows.UTF16PtrFromString(replacementPath)
	if err != nil {
		t.Fatal(err)
	}
	to, err := windows.UTF16PtrFromString(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	replaceErr := windows.MoveFileEx(
		from,
		to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
	if replaceErr == nil {
		t.Fatal("stable watchdog observation allowed pathname replacement")
	}
	if !errors.Is(replaceErr, windows.ERROR_SHARING_VIOLATION) &&
		!errors.Is(replaceErr, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("pathname replacement error = %v, want sharing/access denial", replaceErr)
	}
}

func TestWindowsWatchdogOwnershipValidationBindsOpenedObjectToPath(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.pid")
	secondPath := filepath.Join(dir, "second.pid")
	if err := safefile.WritePrivate(firstPath, []byte(`{"pid":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(secondPath, []byte(`{"pid":2}`)); err != nil {
		t.Fatal(err)
	}
	first, exists, err := openPrivateWatchdogFile(
		firstPath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
	)
	if err != nil || !exists || first == nil {
		t.Fatalf("open first private PID object: exists=%v err=%v", exists, err)
	}
	defer first.Close()
	if err := validateWatchdogOwnershipFile(secondPath, first); err == nil ||
		!strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("mismatched ownership path validation error = %v", err)
	}
}

func TestWindowsWatchdogOwnedRemovalLocksThroughExactDelete(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	old := watchdogPIDInfo{
		PID: 111, Executable: "old.exe", StartIdentity: "old", ControlName: "old-control",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}

	replacement := watchdogPIDInfo{
		PID: 222, Executable: "replacement.exe", StartIdentity: "replacement", ControlName: "replacement-control",
	}
	var concurrentAcquireErr error
	watchdogPIDRemovalBeforeDelete = func(string) error {
		var replacementHolder *os.File
		replacementHolder, concurrentAcquireErr = acquireWatchdogPIDFile(pidPath, replacement)
		if replacementHolder != nil {
			_ = replacementHolder.Close()
		}
		return nil
	}
	t.Cleanup(func() { watchdogPIDRemovalBeforeDelete = nil })

	removeWatchdogPIDIfOwned(pidPath, old)
	if concurrentAcquireErr == nil {
		t.Fatal("replacement watchdog acquired ownership during verified deletion")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("verified old PID file still exists: %v", err)
	}

	replacementHolder, err := acquireWatchdogPIDFile(pidPath, replacement)
	if err != nil {
		t.Fatalf("replacement could not acquire ownership after exact deletion: %v", err)
	}
	defer replacementHolder.Close()
	removeWatchdogPIDIfOwned(pidPath, old)
	got, err := readWatchdogPIDInfo(pidPath)
	if err != nil || got.PID != replacement.PID || got.StartIdentity != replacement.StartIdentity {
		t.Fatalf("locked replacement was changed: info=%+v err=%v", got, err)
	}
}

func TestWindowsWatchdogControlEventRequestsGracefulStop(t *testing.T) {
	name, triggered, cleanup, err := watchdogCreateControl()
	if err != nil {
		t.Fatal(err)
	}
	if !validWatchdogControlName(name) {
		cleanup()
		t.Fatalf("control name is not a valid private capability: %q", name)
	}

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	defer proc.Release() //nolint:errcheck -- test process handle.
	if err := watchdogTerminate(watchdogPIDInfo{PID: os.Getpid(), ControlName: name}, proc); err != nil {
		cleanup()
		t.Fatal(err)
	}
	select {
	case <-triggered:
	case <-time.After(2 * time.Second):
		cleanup()
		t.Fatal("named watchdog event was not signaled")
	}
	cleanup()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	if handle, openErr := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, namePtr); openErr == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("watchdog control event remained open after cleanup")
	}
}

func TestWindowsWatchdogControlRejectsForgedName(t *testing.T) {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Release() //nolint:errcheck -- test process handle.
	err = watchdogTerminate(watchdogPIDInfo{PID: os.Getpid(), ControlName: `Local\DefenseClaw-Watchdog-not-hex`}, proc)
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("forged control name error = %v", err)
	}
	if !watchdogProcessAlive(os.Getpid(), proc) {
		t.Fatal("invalid capability path terminated the calling process")
	}
}

func TestWindowsWatchdogWaitConfirmsOriginalProcessExit(t *testing.T) {
	const helperEnv = "DEFENSECLAW_TEST_WATCHDOG_WAIT_EXIT"
	if os.Getenv(helperEnv) == "1" {
		if err := os.WriteFile(os.Getenv("DEFENSECLAW_TEST_WATCHDOG_WAIT_READY"), []byte("ready"), 0o600); err != nil {
			os.Exit(2)
		}
		time.Sleep(150 * time.Millisecond)
		os.Exit(0)
	}

	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=TestWindowsWatchdogWaitConfirmsOriginalProcessExit")
	cmd.Env = append(os.Environ(), helperEnv+"=1", "DEFENSECLAW_TEST_WATCHDOG_WAIT_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	identity := watchdogProcessStartIdentity(cmd.Process.Pid)
	if identity == "" {
		t.Fatal("helper process has no start identity")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not signal readiness")
		}
		time.Sleep(5 * time.Millisecond)
	}
	info := watchdogPIDInfo{PID: cmd.Process.Pid, StartIdentity: identity}
	started := time.Now()
	if !watchdogWaitForExit(cmd.Process, info, 5*time.Second) {
		t.Fatal("original process handle did not become signaled")
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("wait returned before helper exited: %s", elapsed)
	}
	if watchdogProcessAlive(info.PID, cmd.Process) {
		t.Fatal("terminated process with a retained handle was reported alive")
	}
}

func TestWindowsWatchdogExitCodeStillActiveIsNotAlive(t *testing.T) {
	const helperEnv = "DEFENSECLAW_TEST_WATCHDOG_WAIT_EXIT"
	if os.Getenv(helperEnv) == "1" {
		os.Exit(259)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsWatchdogExitCodeStillActiveIsNotAlive$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	if !watchdogWaitForExit(cmd.Process, watchdogPIDInfo{}, 5*time.Second) {
		t.Fatal("exit-code helper did not stop")
	}
	if watchdogProcessAlive(cmd.Process.Pid, cmd.Process) {
		t.Fatal("process that exited with STILL_ACTIVE was reported alive")
	}
}
