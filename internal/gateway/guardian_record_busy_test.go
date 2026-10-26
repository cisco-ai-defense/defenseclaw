// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

var errTestGuardianRecordBusy = errors.New("the guardian is replacing the record")

// guardianRecordBusyForTest makes the trust check of a guardian record fail
// as busy for the first busy reads, the way Windows answers a read that
// meets the guardian replacing the record (sharing violation), and counts
// the checks.
func guardianRecordBusyForTest(t *testing.T, busy int, failure error) *int {
	t.Helper()
	previousValidate, previousBusy := validateManagedGuardianAuthorization, guardianRecordReadBusy
	t.Cleanup(func() { validateManagedGuardianAuthorization, guardianRecordReadBusy = previousValidate, previousBusy })
	calls := 0
	validateManagedGuardianAuthorization = func(path, label string) error {
		calls++
		if failure != nil {
			return failure
		}
		if calls <= busy {
			return fmt.Errorf("%s: %w", path, errTestGuardianRecordBusy)
		}
		return nil
	}
	guardianRecordReadBusy = func(err error) bool { return errors.Is(err, errTestGuardianRecordBusy) }
	return &calls
}

// GAP-1711: a read of the guardian's authorization ledger that meets the
// guardian replacing it is tried again, so it never drops the ledger. Before,
// one busy read failed the ledger and the gateway refused every per-user
// credential (hooks, session exchanges, OTLP) 401 until its next refresh.
// A real failure (an untrusted ledger) is returned at once.
func TestGuardianAuthorizationLedgerReadRetriesABusyRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorization.json")
	const sid = "S-1-5-21-1000-2000-3000-1017"
	if err := os.WriteFile(path, []byte(`{"protected_targets":[{"sid":"`+sid+`","connector":"opencode","ok":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("busy twice, then read", func(t *testing.T) {
		calls := guardianRecordBusyForTest(t, 2, nil)
		ledger, err := readManagedHookLedger(path)
		if err != nil || len(ledger.Targets) != 1 || *calls != 3 {
			t.Fatalf("a busy read must be tried again: ledger %+v err %v after %d checks", ledger, err, *calls)
		}
	})
	t.Run("stays busy", func(t *testing.T) {
		calls := guardianRecordBusyForTest(t, 1000, nil)
		if _, err := readManagedHookLedger(path); !errors.Is(err, errTestGuardianRecordBusy) || *calls != guardianRecordBusyRetries+1 {
			t.Fatalf("a record that stays busy must fail after %d tries: err %v after %d", guardianRecordBusyRetries+1, err, *calls)
		}
	})
	t.Run("untrusted ledger", func(t *testing.T) {
		calls := guardianRecordBusyForTest(t, 0, errors.New("owner is not SYSTEM"))
		if _, err := readManagedHookLedger(path); err == nil || *calls != 1 {
			t.Fatalf("an untrusted ledger must fail at once: err %v after %d checks", err, *calls)
		}
	})
	t.Run("per-user credential survives a busy ledger read", func(t *testing.T) {
		guardianRecordBusyForTest(t, 1, nil)
		key := strings.Repeat("ab", 32)
		store := newUserScopedCredentialStore(func() string { return filepath.Dir(path) })
		store.loadKey = func(string) (string, error) { return key, nil }
		store.newLedger = func(string) func() (managedHookLedger, uint64, error) {
			return newManagedHookLedgerLoader(path).LoadGeneration
		}
		token, err := connector.UserScopedHookAPIToken(key, "opencode", sid)
		if err != nil {
			t.Fatal(err)
		}
		if identity, ok := store.lookup(connector.UserScopedHookCredential, "opencode", token); !ok || identity != sid {
			t.Fatalf("the account's hook credential must authenticate through a busy ledger read: %q %v", identity, ok)
		}
	})
}

// GAP-1711 review RR3-1/RR3-2: a ledger read that stays busy past its
// retries (the guardian still replacing it) keeps the index of the last good
// read for userScopedCredentialBusyGrace, so one slow replace does not refuse
// every account's per-user credential. After the grace, or on any other
// error (an untrusted ledger), the index is dropped at once, and dropping a
// built index writes one log line with the cause.
func TestUserScopedCredentialIndexSurvivesAStillBusyLedgerBriefly(t *testing.T) {
	const sid = "S-1-5-21-1000-2000-3000-1017"
	key := strings.Repeat("cd", 32)
	token, err := connector.UserScopedHookAPIToken(key, "opencode", sid)
	if err != nil {
		t.Fatal(err)
	}
	previousBusy, previousLog := guardianRecordReadBusy, userScopedCredentialDropLog
	t.Cleanup(func() { guardianRecordReadBusy, userScopedCredentialDropLog = previousBusy, previousLog })
	guardianRecordReadBusy = func(err error) bool { return errors.Is(err, errTestGuardianRecordBusy) }
	var drops []string
	userScopedCredentialDropLog = func(cause string, err error) { drops = append(drops, cause+": "+err.Error()) }
	for _, tc := range []struct {
		name    string
		failure error
		after   time.Duration
		ok      bool
	}{
		{"still busy within the grace", errTestGuardianRecordBusy, userScopedCredentialRefreshInterval, true},
		{"still busy past the grace", errTestGuardianRecordBusy, userScopedCredentialBusyGrace + userScopedCredentialRefreshInterval, false},
		{"untrusted ledger", errors.New("owner is not SYSTEM"), userScopedCredentialRefreshInterval, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drops = nil
			clock := time.Unix(1_800_000_000, 0)
			var ledgerErr error
			generation := uint64(1)
			dir := t.TempDir()
			store := newUserScopedCredentialStore(func() string { return dir })
			store.now = func() time.Time { return clock }
			store.loadKey = func(string) (string, error) { return key, nil }
			store.newLedger = func(string) func() (managedHookLedger, uint64, error) {
				return func() (managedHookLedger, uint64, error) {
					if ledgerErr != nil {
						return managedHookLedger{}, generation, fmt.Errorf("authorization.json: %w", ledgerErr)
					}
					return managedHookLedger{Targets: []managedHookLedgerTarget{{SID: sid, Connector: "opencode", OK: true}}}, generation, nil
				}
			}
			if identity, ok := store.lookup(connector.UserScopedHookCredential, "opencode", token); !ok || identity != sid {
				t.Fatalf("baseline lookup: %q %v", identity, ok)
			}
			ledgerErr = tc.failure
			clock = clock.Add(tc.after)
			_, ok := store.lookup(connector.UserScopedHookCredential, "opencode", token)
			if ok != tc.ok {
				t.Fatalf("lookup after %v of %v: ok=%v, want %v (drops %q)", tc.after, tc.failure, ok, tc.ok, drops)
			}
			if tc.ok && len(drops) != 0 || !tc.ok && (len(drops) != 1 || !strings.HasPrefix(drops[0], "authorization ledger unreadable: ")) {
				t.Fatalf("drop log lines: %q", drops)
			}
		})
	}
}
