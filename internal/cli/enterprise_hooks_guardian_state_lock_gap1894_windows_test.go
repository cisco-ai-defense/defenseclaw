//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-1894 (review RV-F1885 of GAP-1885): the guardian state
// writer decided whether to take reconcile.lock from
// windows.Token.IsElevated() alone. IsElevated reads a failed elevation
// query as "not elevated", so a LocalSystem guardian or an elevated
// administrator whose query failed took only the in-process mutex, and two
// writers could interleave again (GAP-1885). Only a token known to be
// standard (both queries answered, neither privileged) may skip the file
// lock; an unknown answer or LocalSystem takes it.
func TestGAP1894GuardianStateLockFailsClosedOnUnknownToken(t *testing.T) {
	queryErr := errors.New("GetTokenInformation: access is denied")
	cases := []struct {
		name         string
		facts        enterprisehooks.WindowsTokenAdminFacts
		wantFileLock bool
	}{
		{"elevation query failed", enterprisehooks.WindowsTokenAdminFacts{ElevationErr: queryErr}, true},
		{"both queries failed", enterprisehooks.WindowsTokenAdminFacts{ElevationErr: queryErr, UserErr: queryErr}, true},
		{"user query failed on a token not elevated", enterprisehooks.WindowsTokenAdminFacts{UserErr: queryErr}, true},
		{"LocalSystem whose elevation query failed", enterprisehooks.WindowsTokenAdminFacts{ElevationErr: queryErr, LocalSystem: true}, true},
		{"LocalSystem not reported elevated", enterprisehooks.WindowsTokenAdminFacts{LocalSystem: true}, true},
		{"elevated administrator", enterprisehooks.WindowsTokenAdminFacts{Elevated: true}, true},
		{"standard token known to be limited", enterprisehooks.WindowsTokenAdminFacts{}, false},
	}
	restoreFacts, restoreLock := enterpriseHookGuardianStateTokenFacts, enterpriseHookGuardianStateFileLock
	t.Cleanup(func() {
		enterpriseHookGuardianStateTokenFacts, enterpriseHookGuardianStateFileLock = restoreFacts, restoreLock
	})
	dir := t.TempDir()
	wantPath := filepath.Join(dir, managed.HookGuardianReconcileLockFile)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := tc.facts
			enterpriseHookGuardianStateTokenFacts = func() enterprisehooks.WindowsTokenAdminFacts { return facts }
			var locked, released int
			var gotPath string
			enterpriseHookGuardianStateFileLock = func(path, _ string, _ time.Duration) (func(), error) {
				locked++
				gotPath = path
				return func() { released++ }, nil
			}
			unlock, err := lockEnterpriseHookGuardianState(dir)
			if err != nil {
				t.Fatalf("lockEnterpriseHookGuardianState: %v", err)
			}
			// A failed check must not leave the local mutex held for the
			// next case.
			unlocked := false
			t.Cleanup(func() {
				if !unlocked {
					unlock()
				}
			})
			if got := locked == 1; got != tc.wantFileLock || locked > 1 {
				t.Fatalf("GAP-1894: token %+v took the reconcile.lock file lock %d times, want file lock %v: a writer whose token is not known to be standard must take it", facts, locked, tc.wantFileLock)
			}
			if tc.wantFileLock && gotPath != wantPath {
				t.Fatalf("file lock path = %q, want %q", gotPath, wantPath)
			}
			unlock()
			unlocked = true
			if released != locked {
				t.Fatalf("unlock released the file lock %d times, want %d", released, locked)
			}
			if !enterpriseHookGuardianStateLocal.TryLock() {
				t.Fatal("the local mutex is still held after unlock")
			}
			enterpriseHookGuardianStateLocal.Unlock()
		})
	}

	// A token the queries cannot read whose file lock is refused (a
	// standard user cannot open the administrator-only file) fails the
	// writer with both causes and releases the local mutex.
	t.Run("file lock refused on an unknown token", func(t *testing.T) {
		enterpriseHookGuardianStateTokenFacts = func() enterprisehooks.WindowsTokenAdminFacts {
			return enterprisehooks.WindowsTokenAdminFacts{ElevationErr: queryErr}
		}
		enterpriseHookGuardianStateFileLock = func(string, string, time.Duration) (func(), error) {
			return nil, errors.New("enterprise hooks: open hook guardian state lock: access is denied")
		}
		unlock, err := lockEnterpriseHookGuardianState(dir)
		if err == nil {
			unlock()
			t.Fatal("GAP-1894: a refused file lock on an unknown token must fail the writer")
		}
		if !strings.Contains(err.Error(), "hook guardian state lock") || !strings.Contains(err.Error(), queryErr.Error()) {
			t.Fatalf("error %q should name the lock and the token query failure", err)
		}
		if !enterpriseHookGuardianStateLocal.TryLock() {
			t.Fatal("the local mutex is still held after a refused file lock")
		}
		enterpriseHookGuardianStateLocal.Unlock()
	})
}
