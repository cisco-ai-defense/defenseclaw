// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The 1.0.4 guard review loop round 2: any doubt blocks. A block whose every
// revocation the operating system refuses must not leave the account an
// allow that passes an outage: the revocation stays owed until it takes.

// refusedForeignHookSessionKill makes every revocation of the protected
// session record key fail the way RevokePublishedSessionKey does when the
// key could be neither removed nor marked revoked, while refuse is set. It
// counts the revocations tried.
func refusedForeignHookSessionKill(t *testing.T, refuse *atomic.Bool, tries *atomic.Int32) {
	t.Helper()
	previous := foreignHookSessionKill
	foreignHookSessionKill = func(root, identity string) error {
		tries.Add(1)
		if refuse.Load() {
			return fmt.Errorf("%w: the key folder takes no change", enterprisepolicy.ErrPublishedSessionKeyAlive)
		}
		return previous(root, identity)
	}
	t.Cleanup(func() { foreignHookSessionKill = previous })
}

// A block whose revocation the operating system refuses leaves the
// revocation owed, saved in the gateway's data directory. Every later
// exchange of the account tries it again first and, while it is still owed,
// publishes its allow without a key (a new session included), also after a
// restart of the gateway. Once the folder takes a change again, the API
// server's retry ends the key and settles the revocation, and the account's
// allows carry its next key again. Another account is untouched.
func TestForeignHookSessionRevocationThatCannotTakeIsOwedUntilItTakes(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	var refuse atomic.Bool
	var tries atomic.Int32
	refusedForeignHookSessionKill(t, &refuse, &tries)
	process, other := runtime.GOOS+":b:1:500", runtime.GOOS+":b:1:600"
	lastKey := func() string {
		t.Helper()
		if len(writes) == 0 {
			t.Fatal("nothing was published")
		}
		return writes[len(writes)-1].keyID
	}
	aliceKey, bobKey := server.keyID(server.alice), server.keyID(server.bob)
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, true)); got.Deny || lastKey() != aliceKey {
		t.Fatalf("a clean session start is allowed under alice's key: %+v %+v", got, writes)
	}

	refuse.Store(true)
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	owedPath := foreignHookRevocationOwedPath(server.dataDir, server.alice)
	if _, err := os.Lstat(owedPath); err != nil {
		t.Fatalf("the refused revocation must be saved as owed: %v", err)
	}
	if server.keyID(server.alice) != aliceKey {
		t.Fatal("the test's refused revocation must leave the key")
	}

	before := tries.Load()
	if got := server.call(server.aliceToken, foreignHookTestCall("s-2", other, true)); got.Deny {
		t.Fatalf("a clean new session is answered allow online: %+v", got)
	}
	if lastKey() != "" {
		t.Fatalf("an allow published while the revocation is owed must carry no key, got %q", lastKey())
	}
	if tries.Load() == before {
		t.Fatal("the account's next exchange must try the owed revocation again first")
	}
	if got := server.call(server.bobToken, foreignHookTestCall("s-1", process, true)); got.Deny || lastKey() != bobKey {
		t.Fatalf("another account keeps its key: %+v %+v", got, writes)
	}

	// A restarted gateway knows only what it saved.
	server.api.foreignHookOwed = foreignHookRevocationsOwed{}
	if got := server.call(server.aliceToken, foreignHookTestCall("s-2", other, false)); got.Deny || lastKey() != "" {
		t.Fatalf("a restarted gateway still owes the revocation: %+v %+v", got, writes)
	}

	// The folder takes a change again: the retry ends the key at once.
	refuse.Store(false)
	server.api.payOwedForeignHookRevocations()
	if server.keyID(server.alice) != "" {
		t.Fatal("the retry must end the key the block could not")
	}
	if _, err := os.Lstat(owedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a revocation that took is settled: %v", err)
	}
	if server.keyID(server.bob) != bobKey {
		t.Fatal("the retry must not touch another account")
	}
	server.newKey(server.alice)
	if got := server.call(server.aliceToken, foreignHookTestCall("s-2", other, false)); got.Deny || lastKey() != server.keyID(server.alice) {
		t.Fatalf("once settled, allows carry the account's key again: %+v %+v", got, writes)
	}
}

// A revocation owed in memory only (its save failed) is owed all the same,
// and the API server's retry loop pays it while it runs and once more when
// it stops.
func TestForeignHookRevocationRetriesRunUntilTheServerStops(t *testing.T) {
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(new([]foreignHookPublished), nil))
	var refuse atomic.Bool
	var tries atomic.Int32
	refusedForeignHookSessionKill(t, &refuse, &tries)
	places := server.api.foreignHookSessionPlaces(server.dataDir)
	// Memory only: the saved file is not there.
	server.api.foreignHookOwed.owed = map[string]string{foreignHookRevocationOwedPath(server.dataDir, server.alice): server.alice}
	if !server.api.foreignHookRevocationOwed(places, server.alice) || server.api.foreignHookRevocationOwed(places, server.bob) {
		t.Fatal("only alice's revocation is owed")
	}

	refuse.Store(true)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.api.retryOwedForeignHookRevocations(ctx, 5*time.Millisecond)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for tries.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if tries.Load() < 2 || server.keyID(server.alice) == "" {
		t.Fatalf("the loop keeps trying a refused revocation (%d tries)", tries.Load())
	}
	refuse.Store(false)
	for server.keyID(server.alice) != "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if server.keyID(server.alice) != "" {
		t.Fatal("the loop must end the key once the folder takes a change")
	}
	stop()
	<-done
	if server.api.foreignHookRevocationOwed(places, server.alice) {
		t.Fatal("a paid revocation is settled")
	}

	// Stopping pays what is owed once more.
	server.newKey(server.alice)
	server.api.oweForeignHookRevocation(places, server.alice)
	ctx, stop = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		defer close(done)
		server.api.retryOwedForeignHookRevocations(ctx, time.Hour)
	}()
	stop()
	<-done
	if server.keyID(server.alice) != "" || server.api.foreignHookRevocationOwed(places, server.alice) {
		t.Fatal("the loop must pay an owed revocation when it stops")
	}
	if server.keyID(server.bob) == "" {
		t.Fatal("bob owes nothing and keeps his key")
	}
}
