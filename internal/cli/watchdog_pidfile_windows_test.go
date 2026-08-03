// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func TestWatchdogUnlockedLiveProcessRequiresStrongIdentity(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	write := func(info watchdogPIDInfo) {
		t.Helper()
		f, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeWatchdogPIDInfo(f, info); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}

	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	write(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity})
	if live, got := watchdogUnlockedLiveProcess(pidPath); !live || got.PID != os.Getpid() {
		t.Fatalf("strong live record = (live=%v, info=%+v)", live, got)
	}

	write(watchdogPIDInfo{PID: os.Getpid()})
	if live, got := watchdogUnlockedLiveProcess(pidPath); live {
		t.Fatalf("legacy liveness-only record treated as strongly owned: %+v", got)
	}
}

func TestVerifyWatchdogProcess_StartIdentity(t *testing.T) {
	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	if !verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity}) {
		t.Fatal("verifyWatchdogProcess rejected the matching Windows start identity")
	}
	if verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity + "-stale"}) {
		t.Fatal("verifyWatchdogProcess accepted a stale Windows start identity")
	}
}

func TestWindowsWatchdogLockStateIsAuthoritative(t *testing.T) {
	pidPath := t.TempDir() + `\watchdog.pid`
	if locked, _, err := watchdogIsLocked(pidPath); err != nil || locked {
		t.Fatalf("missing lock state = (locked=%v, err=%v)", locked, err)
	}
	info := watchdogPIDInfo{PID: os.Getpid(), StartIdentity: watchdogProcessStartIdentity(os.Getpid()), ControlName: "control"}
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

	holder, err := openWatchdogObservationFile(pidPath)
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

func TestWindowsWatchdogOwnershipAllowsStableReadAndDeniesMutation(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "stable-read-control",
	}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	data, err := safefile.ReadRegularFileBounded(pidPath, 16*1024)
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
		t.Fatal("live watchdog ownership handle allowed an in-place writer")
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
		t.Fatal("live watchdog ownership handle allowed pathname replacement")
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
	first, err := openWatchdogOwnershipFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := validateWatchdogOwnershipFile(secondPath, first); err == nil ||
		!strings.Contains(err.Error(), "changed during handoff") {
		t.Fatalf("mismatched ownership path validation error = %v", err)
	}
}

func TestWindowsWatchdogOwnershipOpenRetriesSharingViolation(t *testing.T) {
	attempts := 0
	var sleeps []time.Duration
	file, err := openWatchdogOwnershipFileWithRetry(
		os.DevNull,
		func(path string) (*os.File, error) {
			attempts++
			if path != os.DevNull {
				t.Fatalf("ownership open path = %q, want %q", path, os.DevNull)
			}
			if attempts < 3 {
				return nil, windows.ERROR_SHARING_VIOLATION
			}
			return os.Open(path)
		},
		func(delay time.Duration) {
			sleeps = append(sleeps, delay)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || len(sleeps) != 2 {
		t.Fatalf("ownership handoff = %d attempts and %d sleeps, want 3 and 2", attempts, len(sleeps))
	}
	for _, delay := range sleeps {
		if delay != watchdogOwnershipHandoffRetryDelay {
			t.Fatalf("ownership retry delay = %s, want %s", delay, watchdogOwnershipHandoffRetryDelay)
		}
	}
}

// acquireWatchdogPIDFileWith deliberately releases the lock and closes the
// publication writer before reopening the record read-only, so a competing
// publisher can win that window. The whole safety argument for that window is
// the field-for-field comparison afterwards, which had no coverage: this drives
// a competitor through the injectable open seam and asserts the loser refuses
// to take ownership of a record it did not write.
func TestWindowsWatchdogOwnershipHandoffRefusesCompetingPublisher(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	mine := watchdogPIDInfo{PID: os.Getpid(), StartIdentity: "mine", ControlName: "dc-a"}
	competitor := watchdogPIDInfo{PID: os.Getpid() + 1, StartIdentity: "theirs", ControlName: "dc-b"}

	overwrites := 0
	owner, err := acquireWatchdogPIDFileWith(
		pidPath,
		mine,
		func(path string) (*os.File, error) {
			// Stand in for the racing publisher: replace the record's contents
			// while nobody holds the file, then hand back a real ownership
			// handle so the caller reaches its identity comparison.
			overwrites++
			writer, writeErr := os.OpenFile(path, os.O_RDWR|os.O_TRUNC, 0o600)
			if writeErr != nil {
				return nil, writeErr
			}
			if writeErr := writeWatchdogPIDInfo(writer, competitor); writeErr != nil {
				_ = writer.Close()
				return nil, writeErr
			}
			if writeErr := writer.Close(); writeErr != nil {
				return nil, writeErr
			}
			return openWatchdogOwnershipFile(path)
		},
		func(time.Duration) {},
	)
	if err == nil {
		_ = owner.Close()
		t.Fatal("handoff accepted a record written by another publisher")
	}
	if owner != nil {
		_ = owner.Close()
		t.Fatal("failed handoff returned a non-nil ownership handle")
	}
	if overwrites != 1 {
		t.Fatalf("ownership open called %d times, want 1", overwrites)
	}
	if !strings.Contains(err.Error(), "ownership changed during publication handoff") {
		t.Fatalf("handoff error = %v, want a publication-handoff mismatch", err)
	}

	// The refusal must not strand the lock or the handle: the competitor's
	// record stays readable and writable by the next publisher.
	if _, err := openWatchdogOwnershipFile(pidPath); err != nil {
		t.Fatalf("refused handoff left the PID file unopenable: %v", err)
	}
	reopened, err := os.OpenFile(pidPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("refused handoff left a retained handle on the PID file: %v", err)
	}
	current, err := readWatchdogPIDInfoFile(reopened)
	if err != nil {
		_ = reopened.Close()
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if current != competitor {
		t.Fatalf("record after refused handoff = %+v, want the competitor's %+v", current, competitor)
	}
}

func TestWindowsWatchdogOwnershipOpenSharingRetryIsBounded(t *testing.T) {
	attempts := 0
	sleeps := 0
	_, err := openWatchdogOwnershipFileWithRetry(
		`C:\managed\watchdog.pid`,
		func(string) (*os.File, error) {
			attempts++
			return nil, windows.ERROR_SHARING_VIOLATION
		},
		func(time.Duration) {
			sleeps++
		},
	)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("bounded ownership-open error = %v, want sharing violation", err)
	}
	if attempts != watchdogOwnershipHandoffMaxAttempts {
		t.Fatalf("ownership-open attempts = %d, want %d", attempts, watchdogOwnershipHandoffMaxAttempts)
	}
	if sleeps != watchdogOwnershipHandoffMaxAttempts-1 {
		t.Fatalf("ownership-open sleeps = %d, want %d", sleeps, watchdogOwnershipHandoffMaxAttempts-1)
	}
}

func TestWindowsWatchdogOwnershipLockRetriesTransientObserver(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	attempts := 0
	var sleeps []time.Duration
	overlapped, err := lockWatchdogOwnershipFileWithRetry(
		file,
		func(got *os.File, lock *windows.Overlapped) error {
			attempts++
			if got != file || lock.OffsetHigh != watchdogLockOffsetHigh {
				t.Fatalf("ownership lock arguments = (%p, %#x)", got, lock.OffsetHigh)
			}
			if attempts < 3 {
				return windows.ERROR_LOCK_VIOLATION
			}
			return nil
		},
		func(delay time.Duration) {
			sleeps = append(sleeps, delay)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if overlapped == nil || overlapped.OffsetHigh != watchdogLockOffsetHigh {
		t.Fatalf("ownership lock = %+v", overlapped)
	}
	if attempts != 3 || len(sleeps) != 2 {
		t.Fatalf("ownership lock = %d attempts and %d sleeps, want 3 and 2", attempts, len(sleeps))
	}
}

func TestWindowsWatchdogOwnershipLockRetryIsBounded(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	attempts := 0
	sleeps := 0
	_, err = lockWatchdogOwnershipFileWithRetry(
		file,
		func(*os.File, *windows.Overlapped) error {
			attempts++
			return windows.ERROR_LOCK_VIOLATION
		},
		func(time.Duration) {
			sleeps++
		},
	)
	if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("bounded ownership-lock error = %v, want lock violation", err)
	}
	if attempts != watchdogOwnershipHandoffMaxAttempts {
		t.Fatalf("ownership-lock attempts = %d, want %d", attempts, watchdogOwnershipHandoffMaxAttempts)
	}
	if sleeps != watchdogOwnershipHandoffMaxAttempts-1 {
		t.Fatalf("ownership-lock sleeps = %d, want %d", sleeps, watchdogOwnershipHandoffMaxAttempts-1)
	}
}

func TestWindowsWatchdogOwnedRemovalLocksThroughExactDelete(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	old := watchdogPIDInfo{PID: 111, StartIdentity: "old", ControlName: "old-control"}
	holder, err := acquireWatchdogPIDFile(pidPath, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}

	replacement := watchdogPIDInfo{PID: 222, StartIdentity: "replacement", ControlName: "replacement-control"}
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
