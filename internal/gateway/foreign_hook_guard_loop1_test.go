// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The 1.0.4 guard review loop round 1: any doubt blocks. An earlier allow
// must never pass an outage once the gateway decided a block, whichever of
// its revocations the operating system refuses, and an allow must never be
// made with a key a removal rotated to.

// Finding 2: a block whose key unlink the operating system refuses, and
// whose block publication fails too, still leaves no earlier allow of the
// account that passes an outage: the gateway marks the key it could not
// remove revoked, and the hook refuses a marked key. Another account's
// allow is not touched. Once the guardian's next pass made a new key, the
// blocked process stays blocked.
func TestForeignHookSessionEarlierAllowDiesWhenTheUnlinkAndThePublicationFail(t *testing.T) {
	failPublish := false
	server := newForeignHookPublishTestServer(t, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ enterprisepolicy.SessionRecordKey, now time.Time) error {
		if failPublish {
			return errors.New("no space left on device")
		}
		return enterprisepolicy.WritePublishedSessionRecordsForTest(r, identity, key, decision, now)
	})
	process := runtime.GOOS + ":b:1:500"
	sessionKey := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	proves := func(identity string) bool {
		got, err := enterprisepolicy.CheckPublishedForeignHookSession(server.root, identity, sessionKey, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
		return err == nil && !got.Deny
	}
	for _, token := range []string{server.aliceToken, server.bobToken} {
		if got := server.call(token, foreignHookTestCall("s-1", process, true)); got.Deny {
			t.Fatalf("a clean session start is allowed: %+v", got)
		}
	}
	if !proves(server.alice) || !proves(server.bob) {
		t.Fatal("fresh allows must prove the process")
	}
	aliceKey := server.keyID(server.alice)
	restore := enterprisepolicy.OverridePublishedSessionKeyRemoveForTest(func(path string) error {
		return &os.PathError{Op: "remove", Path: path, Err: errors.New("the operating system refused the unlink")}
	})
	t.Cleanup(restore)
	failPublish = true
	// The same session starts again (a compaction or a resume) and the scan
	// finds an unapproved hook.
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	if _, err := os.Lstat(aliceKey); err != nil {
		t.Fatalf("the refused unlink keeps the key file: %v", err)
	}
	if proves(server.alice) {
		t.Fatal("an earlier allow passes an outage although the gateway blocked the session")
	}
	if !proves(server.bob) {
		t.Fatal("another account's allow must not be touched")
	}
	restore()
	failPublish = false
	server.newKey(server.alice)
	if server.keyID(server.alice) == aliceKey {
		t.Fatal("the guardian's pass must replace a key marked revoked")
	}
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false)); !got.Deny {
		t.Fatalf("the blocked process stays blocked: %+v", got)
	}
	if proves(server.alice) {
		t.Fatal("the blocked process must not pass an outage")
	}
}

// Finding 3: an exchange that pauses after it took the account's lock and
// before it read the key, while a removal that gave up waiting for it
// rotates the key, must not answer allow, and must not publish an allow
// under the rotated key: its deadline counts from before it asked for the
// lock, so it has passed by then. Another account is answered as before.
func TestForeignHookSessionAllowDeadlineCountsFromBeforeTheAccountLock(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	const hold = 200 * time.Millisecond
	setForeignHookExchangeHoldForTest(t, hold)
	previousLock := foreignHookAccountExchangeLock
	t.Cleanup(func() { foreignHookAccountExchangeLock = previousLock })
	rotated := ""
	foreignHookAccountExchangeLock = func(ctx context.Context, dataDir, identity string) (func(), error) {
		release, err := previousLock(ctx, dataDir, identity)
		if err == nil && identity == server.alice {
			time.Sleep(hold + 100*time.Millisecond)
			if err := enterprisepolicy.RotatePublishedSessionKey(server.root, identity, foreignHookTestTrust); err != nil {
				t.Error(err)
			}
			rotated = server.keyID(identity)
		}
		return release, err
	}
	process := runtime.GOOS + ":b:1:500"
	got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false))
	if !got.Deny || !strings.Contains(got.Reason, "cannot verify this agent session") {
		t.Fatalf("an exchange whose deadline passed before it read the key must not answer allow: %+v", got)
	}
	if rotated == "" {
		t.Fatal("the removal's rotation must have made a key")
	}
	for _, write := range writes {
		if !write.deny || write.keyID == rotated {
			t.Fatalf("nothing but a denial may be published, and nothing under the rotated key: %+v", writes)
		}
	}
	if got := server.call(server.bobToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("another account is answered as before: %+v", got)
	}
}
