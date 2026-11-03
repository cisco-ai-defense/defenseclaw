//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// windowsUserRuntimeTransactionLocks serialize the complete per-SID managed
// runtime transaction, including any late machine-policy or enrollment
// rollback. Claude, Codex, and Cursor deliberately share .defenseclaw, so the
// directory-creation preimage is only meaningful while this lock is held.
//
// Entries are retained for the process lifetime. The protected manifest bounds
// the number of target SIDs, and retaining entries avoids a reference-count ABA
// race in which a removed lock could be recreated while an older waiter runs.
var windowsUserRuntimeTransactionLocks sync.Map

// windowsUserRuntimeMachineMutexAcquire opens a machine-wide per-SID named
// mutex so separate processes cannot interleave enterprise-hook install,
// reconcile, and removal transactions for the same target. The in-process
// sync.Mutex above is still used for goroutines inside a single process.
// Overridable by tests that cannot access the Windows named-object namespace.
var windowsUserRuntimeMachineMutexAcquire = acquireWindowsUserRuntimeMachineMutex

func lockWindowsUserRuntimeTransaction(rawSID string) (func(), error) {
	target, err := validateWindowsEnterpriseTargetSID(rawSID)
	if err != nil {
		return nil, err
	}
	// Acquire the in-process lock first so that goroutines inside the
	// same process serialize on the sync.Mutex rather than on the
	// machine-wide named mutex, which is recursive per thread. Only one
	// goroutine per process ever waits on the named mutex below.
	lock := windowsUserRuntimeTransactionMutexForSID(target.String())
	lock.Lock()
	release, err := windowsUserRuntimeMachineMutexAcquire(target.String())
	if err != nil {
		lock.Unlock()
		return nil, err
	}
	return func() {
		if release != nil {
			_ = release()
		}
		lock.Unlock()
	}, nil
}

func windowsUserRuntimeTransactionMutex(rawSID string) (*sync.Mutex, error) {
	target, err := validateWindowsEnterpriseTargetSID(rawSID)
	if err != nil {
		return nil, err
	}
	return windowsUserRuntimeTransactionMutexForSID(target.String()), nil
}

func windowsUserRuntimeTransactionMutexForSID(canonicalSID string) *sync.Mutex {
	key := strings.ToUpper(canonicalSID)
	value, _ := windowsUserRuntimeTransactionLocks.LoadOrStore(key, &sync.Mutex{})
	return value.(*sync.Mutex)
}

// windowsUserRuntimeMachineMutexTimeout bounds how long a transaction waits
// for another process (a Guardian tick, an installer step) to finish with the
// same target. Waiting replaces the old fail-fast behaviour, which failed an
// install whenever a Guardian tick overlapped it.
var windowsUserRuntimeMachineMutexTimeout = 90 * time.Second

// windowsUserRuntimeMachineMutexSDDL lets both the LocalSystem Guardian and
// an elevated installer open a mutex the other created.
const windowsUserRuntimeMachineMutexSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

func acquireWindowsUserRuntimeMachineMutex(canonicalSID string) (func() error, error) {
	name, err := windows.UTF16PtrFromString(
		`Global\Cisco.DefenseClaw.EnterpriseHooks.` + strings.ToUpper(canonicalSID),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enterprise hooks: encode machine-wide runtime transaction lock name: %w",
			err,
		)
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsUserRuntimeMachineMutexSDDL)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: build runtime transaction lock descriptor: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	// A mutex belongs to the thread that acquired it, so keep this goroutine
	// on its thread until the release below.
	runtime.LockOSThread()
	handle, err := windows.CreateMutex(attributes, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		runtime.UnlockOSThread()
		return nil, fmt.Errorf(
			"enterprise hooks: acquire machine-wide runtime transaction lock: %w",
			err,
		)
	}
	timeout := uint32(windowsUserRuntimeMachineMutexTimeout / time.Millisecond)
	event, err := windows.WaitForSingleObject(handle, timeout)
	switch {
	case err != nil:
		_ = windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("enterprise hooks: wait for machine-wide runtime transaction lock: %w", err)
	case event == windows.WAIT_OBJECT_0:
	case event == windows.WAIT_ABANDONED:
		// The previous holder exited without releasing. Each transaction
		// re-validates everything it touches, so taking over is safe.
		managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
			"sid":    canonicalSID,
			"reason": "runtime transaction lock was abandoned by a process that exited; taking it over",
		})
	default:
		_ = windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf(
			"enterprise hooks: another DefenseClaw enterprise hook transaction for this target did not finish within %s",
			windowsUserRuntimeMachineMutexTimeout,
		)
	}
	return func() error {
		releaseErr := windows.ReleaseMutex(handle)
		closeErr := windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		if releaseErr != nil {
			return releaseErr
		}
		return closeErr
	}, nil
}
