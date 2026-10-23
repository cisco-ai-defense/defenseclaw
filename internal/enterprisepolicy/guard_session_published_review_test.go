// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func publishedSessionTestExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Review P2 (GAP-0352, loop round 2): an answer dated after now proves
// nothing. The clock was ahead when the gateway wrote the allow and was set
// back since: without the bound its age is negative, and the allow would
// outlive the age limit by as long as the clock was ahead. A small step
// back of the clock (publishedSessionClockSkew) still passes, an answer
// older than the limit proves nothing, and the prune drops a future-dated
// record like an expired one. The time is under the MAC, so it cannot be
// changed.
func TestPublishedForeignHookSessionRefusesAFutureDatedAnswer(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	publish := func(at time.Time) {
		t.Helper()
		if err := publishCurrent(root, identity, key, GuardDecision{}, at); err != nil {
			t.Fatal(err)
		}
	}
	check := func() error {
		t.Helper()
		_, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err
	}
	now := time.Now()
	// The record exists first: a publication that creates one prunes the
	// folder by the publication's time.
	publish(now)
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"a month ahead", now.Add(30 * 24 * time.Hour)},
		{"an hour ahead", now.Add(time.Hour)},
		{"just past the skew", now.Add(publishedSessionClockSkew + 10*time.Second)},
		{"older than the limit", now.Add(-publishedSessionMaxAge - time.Minute)},
	} {
		publish(tc.at)
		if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s: the answer must prove nothing: %v", tc.name, err)
		}
	}
	publish(now.Add(publishedSessionClockSkew / 2))
	if err := check(); err != nil {
		t.Fatalf("an answer within the clock skew must prove the process: %v", err)
	}
	ahead := now.Add(48 * time.Hour)
	if err := os.Chtimes(path, ahead, ahead); err != nil {
		t.Fatal(err)
	}
	prunePublishedSessionRecords(filepath.Dir(path), now)
	if publishedSessionTestExists(path) {
		t.Fatal("a future-dated record must be pruned")
	}
}

// Review P2 (GAP-0352, loop round 2): the removal step of every exchange
// (ApplyForeignHookRemovals). The pending mark denies with its own reason, an unreadable ledger denies, a
// removal recorded after the agent process started denies, and a later
// process or another connector is not affected.
func TestApplyForeignHookRemovalsDeniesForARemovalInProgressAndTheLedger(t *testing.T) {
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:b:1:100"}
	now := time.Now()
	for name, err := range map[string]error{
		"a removal in progress":                    ErrForeignHookRemovalPending,
		"a removal in progress with another error": errors.Join(errors.New("the ledger is unreadable"), ErrForeignHookRemovalPending),
	} {
		if got := ApplyForeignHookRemovals(GuardDecision{}, key, nil, err, now); !got.Deny || !strings.Contains(got.Reason, "is removing an unapproved hook") {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	if got := ApplyForeignHookRemovals(GuardDecision{}, key, nil, errors.New("the ledger is unreadable"), now); !got.Deny || !strings.Contains(got.Reason, "cannot verify") {
		t.Fatalf("an unreadable ledger must deny: %+v", got)
	}
	removals := []ForeignHookRemoval{{Identity: "1001", Connector: "copilot", Path: "/home/a/.copilot/hooks/x.json", At: now.UTC().Format(time.RFC3339), Mark: "linux:b:200"}}
	if got := ApplyForeignHookRemovals(GuardDecision{}, key, removals, nil, now); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("a process that started before the removal must be denied: %+v", got)
	}
	for _, other := range []SessionKey{
		{Connector: "copilot", Session: "s-1", Process: "linux:b:1:300"},
		{Connector: "opencode", Session: "s-1", Process: key.Process},
	} {
		if got := ApplyForeignHookRemovals(GuardDecision{}, other, removals, nil, now); got.Deny {
			t.Fatalf("%+v must not be denied: %+v", other, got)
		}
	}
}

// The account's removal lock sits next to the gateway's private session
// store, the folder the gateway has used since 1.0.3 (<data
// dir>/foreign-hook-sessions/<first 20 bytes of the SHA-256 of the
// identity>), so an upgraded gateway keeps its session records.
func TestForeignHookSessionStoreDirIsTheGatewaysStore(t *testing.T) {
	dataDir := t.TempDir()
	for _, identity := range []string{"1001", "S-1-5-21-1111-2222-3333-1001"} {
		digest := sha256.Sum256([]byte(identity))
		want := filepath.Join(dataDir, "foreign-hook-sessions", fmt.Sprintf("%x", digest[:20]))
		if got := ForeignHookSessionStoreDir(dataDir, identity); got != want {
			t.Fatalf("%s: store %s, want %s", identity, got, want)
		}
	}
	if got, want := ForeignHookSessionStoreDir(dataDir, "s-1-5-21-1111-2222-3333-1001"), ForeignHookSessionStoreDir(dataDir, "S-1-5-21-1111-2222-3333-1001"); got != want {
		t.Fatalf("a SID names one store whatever its case: %s %s", got, want)
	}
	gate, lock, ok := ForeignHookAccountLockPaths(dataDir, "1001")
	if store := ForeignHookSessionStoreDir(dataDir, "1001"); !ok || gate != store+".gate" || lock != store+".lock" {
		t.Fatalf("the removal lock must sit next to the store: %s %s %v", gate, lock, ok)
	}
	if _, _, ok := ForeignHookAccountLockPaths("relative", "1001"); ok {
		t.Fatal("no data directory holds no lock")
	}
}
