// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// These tests write real protected session records with the gateway's own
// publisher and check them as the hook does during an outage
// (CheckPublishedForeignHookSession). They need a uid identity and a record
// folder this account owns, so they run on Linux and macOS.

// newForeignHookRealPublishTestServer is a publish test server whose
// gateway writes real protected records. The account folders are made
// beforehand, owned by this account, so the gateway needs no access-list
// change to write into them.
func newForeignHookRealPublishTestServer(t *testing.T) *foreignHookPublishTestServer {
	t.Helper()
	server := newForeignHookPublishTestServer(t, enterprisepolicy.PublishForeignHookSessionDecision)
	for _, identity := range []string{server.alice, server.bob} {
		dir, ok := enterprisepolicy.PublishedSessionIdentityDir(server.root, identity)
		if !ok {
			t.Fatalf("no record folder for %s", identity)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return server
}

// foreignHookOutageCheck decides a guarded call during a gateway outage
// from identity's protected records, trusting every path (the test cannot
// make root-owned files).
func foreignHookOutageCheck(server *foreignHookPublishTestServer, identity string, key enterprisepolicy.SessionKey) (enterprisepolicy.GuardDecision, error) {
	return enterprisepolicy.CheckPublishedForeignHookSession(server.root, identity, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
}

// Item 4: the kill switch is per account. A block of alice removes alice's
// key only: her earlier allow proves nothing during an outage, while bob's
// key and bob's allow record stay valid.
func TestForeignHookSessionKillIsPerAccount(t *testing.T) {
	server := newForeignHookRealPublishTestServer(t)
	process := runtime.GOOS + ":b:1:500"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	for _, identity := range []struct{ id, token string }{{server.alice, server.aliceToken}, {server.bob, server.bobToken}} {
		if got := server.call(identity.token, foreignHookTestCall("s-1", process, false)); got.Deny {
			t.Fatalf("%s's clean call: %+v", identity.id, got)
		}
		if got, err := foreignHookOutageCheck(server, identity.id, key); err != nil || got.Deny {
			t.Fatalf("%s's allow record during an outage: %+v, %v", identity.id, got, err)
		}
	}
	bobKey := server.keyID(server.bob)

	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-2", process)); !got.Deny {
		t.Fatalf("alice's session start that found a hook: %+v", got)
	}
	if server.keyID(server.alice) != "" {
		t.Fatal("alice's block must remove her key")
	}
	if _, err := foreignHookOutageCheck(server, server.alice, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("alice's earlier allow after her block: %v, want ErrPublishedSessionUnavailable", err)
	}
	if server.keyID(server.bob) != bobKey {
		t.Fatalf("alice's block changed bob's key: %q, want %q", server.keyID(server.bob), bobKey)
	}
	if got, err := foreignHookOutageCheck(server, server.bob, key); err != nil || got.Deny {
		t.Fatalf("bob's allow record after alice's block: %+v, %v", got, err)
	}
	// Alice's block itself denies during an outage, whatever key she has.
	server.newKey(server.alice)
	blocked := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-2", Process: process}
	if got, err := foreignHookOutageCheck(server, server.alice, blocked); err != nil || !got.Deny {
		t.Fatalf("alice's published block during an outage: %+v, %v", got, err)
	}
}

// Item 5: an allow record carries a MAC made with the account's key that
// the exchange read while it held the account's lock; once the guardian
// rotates the key (RotatePublishedSessionKey), the allow proves nothing
// during an outage, and the next exchange's allow carries the new key.
func TestForeignHookSessionAllowRecordDiesWithTheKeyRotation(t *testing.T) {
	server := newForeignHookRealPublishTestServer(t)
	var readID string
	readUnderLock := false
	previousKey := foreignHookSessionKey
	foreignHookSessionKey = func(r, identity string) (enterprisepolicy.SessionRecordKey, error) {
		key, err := previousKey(r, identity)
		readID = key.ID()
		// A removal of the account finds an exchange inside its lock.
		release, drained, lockErr := lockForeignHookAccountRemovalForTest(t, server.dataDir, identity, 20*time.Millisecond)
		if lockErr == nil {
			release()
			readUnderLock = !drained
		}
		return key, err
	}
	process := runtime.GOOS + ":b:1:500"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("a clean call: %+v", got)
	}
	if !readUnderLock || readID == "" || readID != server.keyID(server.alice) {
		t.Fatalf("the record key was read under the account's lock: %v, key %q (current %q)", readUnderLock, readID, server.keyID(server.alice))
	}
	if got, err := foreignHookOutageCheck(server, server.alice, key); err != nil || got.Deny {
		t.Fatalf("the allow record during an outage: %+v, %v", got, err)
	}
	if err := enterprisepolicy.RotatePublishedSessionKey(server.root, server.alice, foreignHookTestTrust); err != nil {
		t.Fatal(err)
	}
	if rotated := server.keyID(server.alice); rotated == "" || rotated == readID {
		t.Fatalf("the rotation left key %q (was %q)", rotated, readID)
	}
	if _, err := foreignHookOutageCheck(server, server.alice, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("the allow after a key rotation: %v, want ErrPublishedSessionUnavailable", err)
	}
	if got, err := foreignHookOutageCheck(server, server.bob, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) || got.Deny {
		t.Fatalf("bob has no record: %+v, %v", got, err)
	}
	readUnderLock = false
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("a clean call after the rotation: %+v", got)
	}
	if !readUnderLock || readID != server.keyID(server.alice) {
		t.Fatalf("the next allow read the new key under the lock: %v, key %q", readUnderLock, readID)
	}
	if got, err := foreignHookOutageCheck(server, server.alice, key); err != nil || got.Deny {
		t.Fatalf("the new allow record during an outage: %+v, %v", got, err)
	}
}
