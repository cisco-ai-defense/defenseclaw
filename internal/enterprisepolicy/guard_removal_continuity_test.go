// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Removal fencing and its ledger still protect an account after the
// outage proof and its public record tree are removed.
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

// The private session store retains the 1.0.3 path so upgrades keep their
// existing block records and put the removal lock next to that store.
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
