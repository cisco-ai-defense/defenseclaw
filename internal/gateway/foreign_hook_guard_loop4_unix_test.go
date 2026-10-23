// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The 1.0.4 guard review loop round 4 (lead directive: outage allow
// redesign, fail closed by class). The hook cannot learn of a revocation the
// gateway failed to write, so an allow must not outlive its proof: it
// passes an outage only while the gateway keeps renewing it, and for at
// most enterprisepolicy.PublishedSessionProofLifetime after that. A denial
// stops the renewal at once; a revocation write that fails closes the
// account, and a denial that could neither revoke nor close is reported
// FAILED with the exact time its last allow ends, and retried until it
// takes.

// foreignHookProofExpired is a moment just past the proof lifetime of an
// allow written now.
const foreignHookProofExpired = enterprisepolicy.PublishedSessionProofLifetime + 2*time.Second

// foreignHookOutageAfter decides a guarded call of identity during a
// gateway outage that began now and has lasted after: nil when it is
// allowed, an error when it is not (a published block denies it).
func foreignHookOutageAfter(server *foreignHookPublishTestServer, identity string, key enterprisepolicy.SessionKey, after time.Duration) error {
	restore := enterprisepolicy.OverridePublishedSessionNowForTest(func() time.Time { return time.Now().Add(after) })
	defer restore()
	got, err := foreignHookOutageCheck(server, identity, key)
	if err == nil && got.Deny {
		return errors.New("denied")
	}
	return err
}

// foreignHookAllowWrites counts the allow records the gateway writes per
// account (exchanges and renewals), writing them for real; while
// refuseDeny or refuseAllow is set, the block records or the allow records
// are refused.
type foreignHookAllowWrites struct {
	mu          sync.Mutex
	allows      map[string]int
	sessions    map[string]int
	refuseDeny  bool
	refuseAllow bool
}

func countForeignHookAllowWrites(t *testing.T) *foreignHookAllowWrites {
	t.Helper()
	writes := &foreignHookAllowWrites{allows: map[string]int{}, sessions: map[string]int{}}
	previous := foreignHookSessionPublish
	foreignHookSessionPublish = func(root, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, now time.Time) error {
		writes.mu.Lock()
		refuse := (decision.Deny && writes.refuseDeny) || (!decision.Deny && writes.refuseAllow)
		if !decision.Deny {
			writes.allows[identity]++
			writes.sessions[foreignHookSessionProofID(identity, key)]++
		}
		writes.mu.Unlock()
		if refuse {
			return errors.New("the account folder takes no change")
		}
		return previous(root, identity, key, decision, recordKey, now)
	}
	t.Cleanup(func() { foreignHookSessionPublish = previous })
	return writes
}

func (w *foreignHookAllowWrites) of(identity string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.allows[identity]
}

func (w *foreignHookAllowWrites) ofSession(identity string, key enterprisepolicy.SessionKey) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sessions[foreignHookSessionProofID(identity, key)]
}

func (w *foreignHookAllowWrites) refuse(deny, allow bool) {
	w.mu.Lock()
	w.refuseDeny, w.refuseAllow = deny, allow
	w.mu.Unlock()
}

// refusedForeignHookSessionClose makes the account's closing fail while
// *refuse is set.
func refusedForeignHookSessionClose(t *testing.T, refuse *bool) {
	t.Helper()
	previous := foreignHookSessionClose
	foreignHookSessionClose = func(root, identity string) error {
		if *refuse {
			return errors.New("the closed mark's folder takes no change")
		}
		return previous(root, identity)
	}
	t.Cleanup(func() { foreignHookSessionClose = previous })
}

// The reviewer's scenario: every revocation write of a block "succeeds" in
// the gateway's view but changes nothing the hook reads (the key stays,
// the block record never lands). The gateway cannot know, so it reports
// nothing; but it stops renewing the session's proof at once, so the
// earlier allow passes no outage past its lifetime (it did for 15 minutes
// before). Another account's proof is still renewed.
func TestForeignHookSessionEarlierAllowEndsWithItsProofWhenTheRevocationIsInvisible(t *testing.T) {
	server := newForeignHookRealPublishTestServer(t)
	writes := countForeignHookAllowWrites(t)
	process := runtime.GOOS + ":b:1:500"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	for _, identity := range []struct{ id, token string }{{server.alice, server.aliceToken}, {server.bob, server.bobToken}} {
		if got := server.call(identity.token, foreignHookTestCall("s-1", process, true)); got.Deny {
			t.Fatalf("%s's clean session start: %+v", identity.id, got)
		}
	}
	if err := foreignHookOutageAfter(server, server.alice, key, 0); err != nil {
		t.Fatalf("a fresh allow passes an outage: %v", err)
	}
	previousKill, previousPublish := foreignHookSessionKill, foreignHookSessionPublish
	foreignHookSessionKill = func(string, string) error { return nil }
	foreignHookSessionPublish = func(root, identity string, k enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, now time.Time) error {
		if decision.Deny {
			return nil
		}
		return previousPublish(root, identity, k, decision, recordKey, now)
	}
	got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process))
	foreignHookSessionKill, foreignHookSessionPublish = previousKill, previousPublish
	if !got.Deny || strings.Contains(got.Reason, "FAILED") {
		t.Fatalf("the block is denied, with nothing the gateway could see failing: %+v", got)
	}
	aliceWrites, bobWrites := writes.of(server.alice), writes.of(server.bob)
	server.api.renewForeignHookSessionProofsOnce()
	if writes.of(server.alice) != aliceWrites {
		t.Fatal("the denied session's proof must not be renewed")
	}
	if writes.of(server.bob) != bobWrites+1 {
		t.Fatalf("bob's proof is renewed: %d writes, want %d", writes.of(server.bob), bobWrites+1)
	}
	for _, after := range []time.Duration{foreignHookProofExpired, 5 * time.Minute, 14 * time.Minute} {
		if err := foreignHookOutageAfter(server, server.alice, key, after); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
			t.Fatalf("alice's earlier allow %s into the outage: %v, want ErrPublishedSessionUnavailable", after, err)
		}
	}
	if err := foreignHookOutageAfter(server, server.bob, key, 0); err != nil {
		t.Fatalf("bob's renewed allow: %v", err)
	}

	// A denial of one call only (a hook found after the session start)
	// records no block, so the private store still allows the session: the
	// denial itself must stop the renewal.
	foreignHookSessionKill = func(string, string) error { return nil }
	foreignHookSessionPublish = func(root, identity string, k enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, now time.Time) error {
		if decision.Deny {
			return nil
		}
		return previousPublish(root, identity, k, decision, recordKey, now)
	}
	callDeny := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": process}, "session_start": false,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}}
	got = server.call(server.bobToken, callDeny)
	foreignHookSessionKill, foreignHookSessionPublish = previousKill, previousPublish
	if !got.Deny {
		t.Fatalf("bob's call with a new hook is denied: %+v", got)
	}
	bobWrites = writes.of(server.bob)
	server.api.renewForeignHookSessionProofsOnce()
	if writes.of(server.bob) != bobWrites {
		t.Fatal("a denied call stops its session's renewal at once")
	}
}

// Every revocation write of a denial that can fail: the key's removal and
// its mark, the block record, the account's closed mark and the save of
// the owed revocation. Whatever fails, the session's proof is not renewed
// and no earlier allow passes an outage past its lifetime. A failed key or
// block record write closes the account, so nothing passes even within
// it. A denial that could neither end the key nor close the account is
// FAILED, to the caller in its reason, with the exact time the account's
// last allow ends; the retry closes the account, and then ends the key and
// opens it again.
func TestForeignHookSessionDenialEscalatesEveryFailedRevocationWrite(t *testing.T) {
	alive := fmt.Errorf("%w: the key folder takes no change", enterprisepolicy.ErrPublishedSessionKeyAlive)
	for _, tc := range []struct {
		name                         string
		killErr                      error
		refuseBlock, refuseClose     bool
		refuseOwedSave               bool
		wantClosed, wantFailed, owed bool
	}{
		{name: "the key's removal and mark are refused", killErr: alive, wantClosed: true, owed: true},
		{name: "the key's removal is refused and its mark is invisible", killErr: errors.New("remove the key: access denied; a revocation mark ends the key"), wantClosed: true},
		{name: "the block record is refused", refuseBlock: true, wantClosed: true},
		{name: "the block record and the closed mark are refused, the key ends", refuseBlock: true, refuseClose: true},
		{name: "the key, the block record and the closed mark are refused", killErr: alive, refuseBlock: true, refuseClose: true, wantFailed: true, owed: true},
		{name: "the key, the closed mark and the owed save are refused", killErr: alive, refuseClose: true, refuseOwedSave: true, wantFailed: true, owed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newForeignHookRealPublishTestServer(t)
			writes := countForeignHookAllowWrites(t)
			process, other := runtime.GOOS+":b:1:500", runtime.GOOS+":b:2:600"
			key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
			// Another agent of alice's, whose allow the denial must end too.
			otherKey := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-2", Process: other}
			for _, call := range []map[string]any{foreignHookTestCall("s-2", other, true), foreignHookTestCall("s-1", process, true)} {
				if got := server.call(server.aliceToken, call); got.Deny {
					t.Fatalf("alice's clean session start: %+v", got)
				}
			}
			dir, _ := enterprisepolicy.PublishedSessionIdentityDir(server.root, server.alice)
			closedMark := filepath.Join(server.root, filepath.Base(dir)+".closed")
			until, err := enterprisepolicy.PublishedSessionAllowWindowEnd(server.root, server.alice)
			if err != nil || until.IsZero() {
				t.Fatalf("alice's allow has an end: %v %v", until, err)
			}
			refuseKill := tc.killErr != nil
			previousKill := foreignHookSessionKill
			foreignHookSessionKill = func(root, identity string) error {
				if refuseKill {
					return tc.killErr
				}
				return previousKill(root, identity)
			}
			refuseClose := tc.refuseClose
			refusedForeignHookSessionClose(t, &refuseClose)
			writes.refuse(tc.refuseBlock, false)
			owedDir := filepath.Join(server.dataDir, foreignHookRevocationsOwedDirName)
			if tc.refuseOwedSave {
				if err := os.WriteFile(owedDir, []byte("not a folder"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process))
			if !got.Deny {
				t.Fatalf("the session start that found the hook is denied: %+v", got)
			}
			failed := strings.Contains(got.Reason, "revocation FAILED")
			if failed != tc.wantFailed {
				t.Fatalf("FAILED in the denial: %v, want %v: %s", failed, tc.wantFailed, got.Reason)
			}
			if tc.wantFailed {
				if !strings.Contains(got.Reason, "until "+until.UTC().Format(time.RFC3339)) || len(got.Findings) == 0 || !strings.Contains(got.Findings[0].Reason, "revocation FAILED") {
					t.Fatalf("a FAILED denial names the exact end of the last allow (%s): %+v", until.UTC().Format(time.RFC3339), got)
				}
			}
			before := writes.of(server.alice)
			server.api.renewForeignHookSessionProofsOnce()
			if writes.of(server.alice) != before {
				t.Fatal("the denied session's proof must not be renewed")
			}
			if _, err := os.Lstat(closedMark); (err == nil) != tc.wantClosed {
				t.Fatalf("the account is closed: %v, want %v", err == nil, tc.wantClosed)
			}
			err = foreignHookOutageAfter(server, server.alice, otherKey, 0)
			if tc.wantFailed != (err == nil) {
				t.Fatalf("within the reported window only a FAILED denial leaves the other agent's earlier allow: %v", err)
			}
			for _, k := range []enterprisepolicy.SessionKey{key, otherKey} {
				if err := foreignHookOutageAfter(server, server.alice, k, foreignHookProofExpired); err == nil {
					t.Fatalf("no allow of %s passes the outage past its proof", k.Session)
				}
			}
			if owed := server.api.foreignHookRevocationOwed(server.api.foreignHookSessionPlaces(server.dataDir), server.alice); owed != tc.owed {
				t.Fatalf("owed: %v, want %v", owed, tc.owed)
			}
			if !tc.owed {
				return
			}

			// The retry until it takes: first the account closes, then the key
			// ends, which opens the account again.
			refuseClose = false
			_ = os.Remove(owedDir)
			server.api.payOwedForeignHookRevocations()
			if _, err := os.Lstat(closedMark); err != nil {
				t.Fatalf("the retry closes the account: %v", err)
			}
			if err := foreignHookOutageAfter(server, server.alice, otherKey, 0); err == nil || !strings.Contains(err.Error(), "closed the account") {
				t.Fatalf("a closed account's earlier allow: %v", err)
			}
			refuseKill = false
			server.api.payOwedForeignHookRevocations()
			if server.keyID(server.alice) != "" || server.api.foreignHookRevocationOwed(server.api.foreignHookSessionPlaces(server.dataDir), server.alice) {
				t.Fatal("the retry ends the key and settles the revocation")
			}
			if _, err := os.Lstat(closedMark); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a revocation that took opens the account: %v", err)
			}
			server.newKey(server.alice)
			if got := server.call(server.aliceToken, foreignHookTestCall("s-3", runtime.GOOS+":b:3:700", true)); got.Deny {
				t.Fatalf("a new clean session: %+v", got)
			}
			if err := foreignHookOutageAfter(server, server.alice, enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-3", Process: runtime.GOOS + ":b:3:700"}, 0); err != nil {
				t.Fatalf("a settled revocation lets a new allow pass an outage again: %v", err)
			}
		})
	}
}

// Every read and write a renewal makes that can fail stops it: the record
// key, the guardian's ledger, the private store, the account's removal
// lock, an owed revocation, a removal after the process started, a session
// the gateway denied, an agent idle too long, and the renewal's own write.
// None of them renews the proof, so none leaves an allow past its
// lifetime. Without a failure the proof is renewed with the current key.
func TestForeignHookSessionProofRenewalStopsWhenAReadOrWriteFails(t *testing.T) {
	// Started before the guardian's removal of the test ledger (mark b:200).
	process := runtime.GOOS + ":b:1:100"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, server *foreignHookPublishTestServer, writes *foreignHookAllowWrites)
		write  bool // the renewal tries its write, which fails
	}{
		{name: "nothing fails"},
		{name: "the record key cannot be read", break_: func(t *testing.T, _ *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			previous := foreignHookSessionKey
			foreignHookSessionKey = func(string, string) (enterprisepolicy.SessionRecordKey, error) {
				return enterprisepolicy.SessionRecordKey{}, errors.New("the key folder cannot be listed")
			}
			t.Cleanup(func() { foreignHookSessionKey = previous })
		}},
		{name: "the guardian's ledger cannot be read", break_: func(t *testing.T, server *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			if err := os.WriteFile(filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile), []byte("not a ledger"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the private store cannot be read", break_: func(t *testing.T, server *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			if err := os.WriteFile(foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "p", process), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the private store lost the session", break_: func(t *testing.T, server *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			if err := os.Remove(foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "s", "s-1")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the account's removal lock cannot be taken", break_: func(t *testing.T, _ *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			previous := foreignHookAccountExchangeLock
			foreignHookAccountExchangeLock = func(context.Context, string, string) (func(), error) {
				return nil, errors.New("the lock file cannot be opened")
			}
			t.Cleanup(func() { foreignHookAccountExchangeLock = previous })
		}},
		{name: "a revocation of the account is owed", break_: func(_ *testing.T, server *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			server.api.oweForeignHookRevocation(server.api.foreignHookSessionPlaces(server.dataDir), server.alice)
		}},
		{name: "the guardian removed a hook after the process started", break_: func(_ *testing.T, server *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			server.guardian(server.alice, "/home/alice/.claude/settings.json")
		}},
		{name: "the session was denied", break_: func(t *testing.T, server *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny {
				t.Fatalf("the block: %+v", got)
			}
		}},
		{name: "the agent made no exchange for too long", break_: func(t *testing.T, _ *foreignHookPublishTestServer, _ *foreignHookAllowWrites) {
			previous := foreignHookSessionProofIdle
			foreignHookSessionProofIdle = 0
			t.Cleanup(func() { foreignHookSessionProofIdle = previous })
		}},
		{name: "the renewal's write fails", write: true, break_: func(_ *testing.T, _ *foreignHookPublishTestServer, writes *foreignHookAllowWrites) {
			writes.refuse(false, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newForeignHookRealPublishTestServer(t)
			writes := countForeignHookAllowWrites(t)
			if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, true)); got.Deny {
				t.Fatalf("alice's clean session start: %+v", got)
			}
			if tc.break_ != nil {
				tc.break_(t, server, writes)
			}
			before := writes.of(server.alice)
			server.api.renewForeignHookSessionProofsOnce()
			renewed := writes.of(server.alice) - before
			if tc.break_ == nil {
				if renewed != 1 {
					t.Fatalf("the proof is renewed once: %d", renewed)
				}
				if err := foreignHookOutageAfter(server, server.alice, key, 0); err != nil {
					t.Fatalf("the renewed proof passes an outage: %v", err)
				}
				return
			}
			if want := map[bool]int{true: 1, false: 0}[tc.write]; renewed != want {
				t.Fatalf("renewal writes: %d, want %d", renewed, want)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, foreignHookProofExpired); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("no allow passes the outage past its proof: %v", err)
			}
		})
	}
}
