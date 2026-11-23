//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// enterpriseHookGuardianStateLockWait bounds how long a publication waits for
// another writer's, which takes milliseconds of file writes.
const enterpriseHookGuardianStateLockWait = 2 * time.Minute

var enterpriseHookGuardianStateLocal sync.Mutex

// lockEnterpriseHookGuardianState serializes writeEnterpriseHookGuardianState
// across processes. The guardian service and an administrator's `defenseclaw
// enterprise hooks reconcile` both publish; two writers that read the same
// ledger generation could leave one's release protection record beside the
// other's ledger, which then no longer counted it, and a target failing on
// the next pass lost its protection (GAP-1885). The lock is the reconcile.lock
// the standalone Unix guardian holds, beside the ledger, as an
// administrator-only lock file (enterprisehooks.LockWindowsAdminOnlyFile).
//
// It is a leaf lock: it is taken inside the writer after every target lock
// of the pass is released (Claude managed policy transaction, OpenCode
// ports, connector locks), and nothing else is locked while it is held, so
// it cannot be part of a lock-order cycle with the lifecycle, bundle or
// transaction locks. The local mutex queues goroutines of this process.
//
// A process without an elevated token (not LocalSystem, not an elevated
// administrator) can neither create nor open the lock file, and cannot
// publish either: the protected folder refuses its writes. It takes only
// the local mutex, so the writer fails where it did before (the package's
// tests, which run at Limited on temporary folders, publish that way).
func lockEnterpriseHookGuardianState(authorizationDir string) (func(), error) {
	enterpriseHookGuardianStateLocal.Lock()
	if !windows.GetCurrentProcessToken().IsElevated() {
		return enterpriseHookGuardianStateLocal.Unlock, nil
	}
	unlock, err := enterprisehooks.LockWindowsAdminOnlyFile(
		filepath.Join(authorizationDir, managed.HookGuardianReconcileLockFile),
		"hook guardian state lock",
		enterpriseHookGuardianStateLockWait,
	)
	if err != nil {
		enterpriseHookGuardianStateLocal.Unlock()
		return nil, err
	}
	return func() {
		unlock()
		enterpriseHookGuardianStateLocal.Unlock()
	}, nil
}
