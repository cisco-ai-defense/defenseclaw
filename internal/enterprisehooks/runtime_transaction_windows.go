//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/winmutex"
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
	// same process serialize on the sync.Mutex (which blocks) rather
	// than fighting the machine-wide named mutex (which fails fast).
	// Only one goroutine per process ever reaches CreateMutex below.
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

func acquireWindowsUserRuntimeMachineMutex(canonicalSID string) (func() error, error) {
	// winmutex holds the mutex on one goroutine locked to its OS thread:
	// only the owning thread can release a Windows mutex, and callers unlock
	// from whatever thread their goroutine has moved to.
	release, err := winmutex.TryAcquire(
		`Global\Cisco.DefenseClaw.EnterpriseHooks.`+strings.ToUpper(canonicalSID), nil,
	)
	if errors.Is(err, winmutex.ErrBusy) {
		return nil, errors.New(
			"enterprise hooks: another DefenseClaw enterprise hook transaction is already in progress for this target",
		)
	}
	if err != nil {
		return nil, fmt.Errorf(
			"enterprise hooks: acquire machine-wide runtime transaction lock: %w",
			err,
		)
	}
	return release, nil
}
