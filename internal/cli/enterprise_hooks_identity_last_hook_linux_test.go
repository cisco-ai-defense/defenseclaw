// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// GAP-2024 (RV5-1): after 1.0.3 -> 1.0.4 -> 1.0.5, an account recreated
// during 1.0.4 that 1.0.4 never served kept the earlier holder's entry
// (legacy_holder, no first_seen) and another user's first hook moved the
// homes file's mtime past the new home's birth: the guardian counted the new
// account as the 1.0.3 holder, and the first map bound it to the earlier
// holder's agents entry. The uid's last hook in the agent ledger bounds the
// sighting in the guardian too (as in the gateway, GAP-1947). Control: a
// ledger hook after the home's birth keeps the 1.0.3 holder (GAP-1976).
func TestGuardianBoundsALegacyEntrysSightingByTheUIDsLastHook(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current account:", err)
	}
	uid, err := strconv.Atoi(me.Uid)
	if err != nil || uid <= 0 {
		t.Skip("not run as a non-root account")
	}
	birth, known := enterprisehooks.HomeBirth(me.HomeDir)
	if !known || time.Since(time.Unix(0, birth)) < 3*time.Hour {
		t.Skip("the file system keeps no creation time for the home here, or the home is too young")
	}
	head := `"` + me.Uid + `":{"home":"` + me.HomeDir + `","name":"` + me.Username + `"`
	for _, file := range []struct{ name, body string }{
		{"1.0.4 file, legacy holder 1.0.4 never served", `{"format":{"format":1},` + head + `,"legacy_holder":true}}`},
		{"1.0.3 file", `{` + head + `}}`},
	} {
		age := time.Since(time.Unix(0, birth))
		for _, tc := range []struct {
			name     string
			lastHook int64
			pruned   bool
			window   time.Duration
			pre      bool
		}{
			{"last hook before the home was created", birth - int64(time.Hour), false, 0, false},
			{"last hook after the home was created", time.Now().Add(-time.Minute).UnixNano(), false, 0, true},
			{"no ledger", 0, false, 0, true},
			// GAP-2069: the ledger is read but has no row of the uid, so the
			// holder ran no hook in the row window. A home younger than the
			// window belongs to an account created after that holder; for
			// both the first map and the existing map's join (PreTokenHolder).
			{"pruned ledger, home younger than the row window", 0, true, age + time.Hour, false},
			{"pruned ledger, home older than the row window", 0, true, age - time.Hour, true},
		} {
			t.Run(file.name+": "+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "managed_peer_homes.json")
				if err := os.WriteFile(path, []byte(file.body), 0o600); err != nil {
					t.Fatal(err)
				}
				previous, previousWindow := enterpriseHookAgentLastHooks, inventory.AgentLedgerRowWindow
				t.Cleanup(func() { enterpriseHookAgentLastHooks, inventory.AgentLedgerRowWindow = previous, previousWindow })
				if tc.window > 0 {
					inventory.AgentLedgerRowWindow = tc.window
				}
				enterpriseHookAgentLastHooks = func(dataDir string) map[int]int64 {
					if dataDir != dir {
						t.Errorf("ledger read from %q; want the homes file's data dir %q", dataDir, dir)
					}
					if tc.pruned {
						return map[int]int64{uid + 1: time.Now().UnixNano()}
					}
					if tc.lastHook == 0 {
						return nil
					}
					return map[int]int64{uid: tc.lastHook}
				}
				peer, ok := enterpriseHookResolveGatewayPeers(path, nil)[uid]
				if !ok {
					t.Skip("the account database gives the current account no non-SID incarnation here")
				}
				if peer.PreToken != tc.pre {
					t.Fatalf("PreToken %v, want %v", peer.PreToken, tc.pre)
				}
			})
		}
	}
}

// GAP-2026 (RV5-3): the identity spool's fingerprint includes the local
// account database's stamp, so the records are rewritten at the next tick
// after useradd or userdel, not at the 15-minute interval.
func TestIdentitySpoolFingerprintFollowsTheAccountDatabase(t *testing.T) {
	previous := enterpriseHookLocalAccountsStamp
	t.Cleanup(func() { enterpriseHookLocalAccountsStamp = previous })
	stamp := "1/100/7"
	enterpriseHookLocalAccountsStamp = func() string { return stamp }
	keys := []string{"1001:alice:12", "1002:bob:13"}
	before := enterpriseHookIdentitySpoolFingerprint(keys)
	if again := enterpriseHookIdentitySpoolFingerprint(keys); again != before {
		t.Fatalf("fingerprint %q then %q with nothing changed", before, again)
	}
	stamp = "2/100/8"
	if after := enterpriseHookIdentitySpoolFingerprint(keys); after == before {
		t.Fatalf("fingerprint %q did not change with the account database", after)
	}
}

// GAP-2067 (RV6-1, GAP-2026): the tick decides a pass by the fingerprint
// that carries the local account database's stamp. Inside the interval, a
// useradd or userdel (a new stamp) runs a pass at the next tick; an
// unchanged stamp does not.
func TestIdentitySpoolPassRunsInsideTheIntervalOnlyWhenTheAccountDatabaseChanged(t *testing.T) {
	previous := enterpriseHookLocalAccountsStamp
	state := &enterpriseHookIdentitySpoolState
	state.Lock()
	saved := struct {
		running, failed bool
		last            time.Time
		fingerprint     string
	}{state.running, state.failed, state.last, state.fingerprint}
	state.running, state.failed, state.last, state.fingerprint = false, false, time.Time{}, ""
	state.Unlock()
	t.Cleanup(func() {
		enterpriseHookLocalAccountsStamp = previous
		state.Lock()
		state.running, state.failed, state.last, state.fingerprint = saved.running, saved.failed, saved.last, saved.fingerprint
		state.Unlock()
	})
	stamp := "1/100/7"
	enterpriseHookLocalAccountsStamp = func() string { return stamp }
	dir := t.TempDir()
	keys := func() []string { return []string{"1002:bob:13", "1001:alice:12"} }
	fingerprint, due := enterpriseHookIdentitySpoolPassDue(dir, keys(), time.Now())
	if !due {
		t.Fatal("first tick ran no pass")
	}
	enterpriseHookIdentitySpoolPassDone(fingerprint, nil)
	if _, due := enterpriseHookIdentitySpoolPassDue(dir, keys(), time.Now()); due {
		t.Fatal("a tick inside the interval with nothing changed ran a pass")
	}
	stamp = "2/100/8"
	fingerprint, due = enterpriseHookIdentitySpoolPassDue(dir, keys(), time.Now())
	if !due {
		t.Fatal("a tick after the account database changed ran no pass inside the interval")
	}
	enterpriseHookIdentitySpoolPassDone(fingerprint, nil)
	if _, due := enterpriseHookIdentitySpoolPassDue(dir, keys(), time.Now()); due {
		t.Fatal("the pass for the new stamp did not record it")
	}
}

// GAP-2026 (lead 19:08): the guardian's tick itself, not only its due
// decision, runs a spool pass inside the interval when the local account
// database changed (useradd, userdel) and none when nothing changed.
// Without the stamp in the tick's fingerprint, records were rewritten only
// every 15 minutes, and every bound account was refused for that long
// after each account change.
func TestIdentitySpoolTickRunsAPassInsideTheIntervalOnlyWhenTheAccountDatabaseChanged(t *testing.T) {
	identityCallerTestConfig(t)
	cfg.DataDir = t.TempDir()
	previousStamp, previousWrite := enterpriseHookLocalAccountsStamp, enterpriseHookWriteIdentitySpool
	previousOwner, previousTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck
	state := &enterpriseHookIdentitySpoolState
	state.Lock()
	saved := struct {
		running, failed bool
		last            time.Time
		fingerprint     string
	}{state.running, state.failed, state.last, state.fingerprint}
	state.running, state.failed, state.last, state.fingerprint = false, false, time.Time{}, ""
	state.Unlock()
	t.Cleanup(func() {
		enterpriseHookLocalAccountsStamp, enterpriseHookWriteIdentitySpool = previousStamp, previousWrite
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck = previousOwner, previousTrust
		state.Lock()
		state.running, state.failed, state.last, state.fingerprint = saved.running, saved.failed, saved.last, saved.fingerprint
		state.Unlock()
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	var stampMu sync.Mutex
	stamp := "1/100/7"
	enterpriseHookLocalAccountsStamp = func() string { stampMu.Lock(); defer stampMu.Unlock(); return stamp }
	passes := make(chan struct{}, 4)
	enterpriseHookWriteIdentitySpool = func(context.Context, string, []enterprisehooks.IdentitySpoolAccount, func(string) error,
		func(string, ...any), enterprisehooks.IdentitySpoolWithdraw) error {
		passes <- struct{}{}
		return nil
	}
	tick := func() bool {
		t.Helper()
		startEnterpriseHookIdentitySpool(context.Background(), io.Discard, enterpriseHookReconcileRun{})
		select {
		case <-passes:
		case <-time.After(2 * time.Second):
			return false
		}
		// The pass records its fingerprint when it ends.
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			state.Lock()
			running := state.running
			state.Unlock()
			if !running {
				return true
			}
		}
		t.Fatal("the spool pass did not end")
		return true
	}
	if !tick() {
		t.Fatal("the first tick ran no spool pass")
	}
	if tick() {
		t.Fatal("a tick inside the interval with nothing changed ran a spool pass")
	}
	stampMu.Lock()
	stamp = "2/100/8"
	stampMu.Unlock()
	if !tick() {
		t.Fatal("a tick inside the interval after the local account database changed ran no spool pass (GAP-2026)")
	}
	if tick() {
		t.Fatal("the pass for the new account database did not record its stamp")
	}
}
