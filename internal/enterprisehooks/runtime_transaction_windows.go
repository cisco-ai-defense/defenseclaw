//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"sync"
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

func lockWindowsUserRuntimeTransaction(rawSID string) (func(), error) {
	lock, err := windowsUserRuntimeTransactionMutex(rawSID)
	if err != nil {
		return nil, err
	}
	lock.Lock()
	return lock.Unlock, nil
}

func windowsUserRuntimeTransactionMutex(rawSID string) (*sync.Mutex, error) {
	target, err := validateWindowsEnterpriseTargetSID(rawSID)
	if err != nil {
		return nil, err
	}
	key := strings.ToUpper(target.String())
	value, _ := windowsUserRuntimeTransactionLocks.LoadOrStore(key, &sync.Mutex{})
	return value.(*sync.Mutex), nil
}
