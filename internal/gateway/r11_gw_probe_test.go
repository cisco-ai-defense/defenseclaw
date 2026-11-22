// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// R11 probes of POST /api/v1/substrate/relay/task.

package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// The body cannot name another actor: the row and the mark are the token's.
func TestR11TaskEndCannotNameAnotherActor(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = strings.Repeat("ab", 32)
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	body := `{"exit_code":0,"actor_uid":"` + subUID1 + `","atespace":"other","actor":"alice-1","event":"allow","severity":"INFO","batch_id":"forged"}`
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", body); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	marks := strings.Join(f.activity, ",")
	f.mu.Unlock()
	if strings.Contains(marks, SubstrateActivityTaskEnd+":"+subUID1) {
		t.Fatalf("a task end was marked on another actor: %s", marks)
	}
	events, _ := store.ListEvents(50)
	for _, e := range events {
		if strings.Contains(e.Details, "task_end") {
			if strings.Contains(e.Details, "alice-1") || strings.Contains(e.Details, subUID1) || strings.Contains(e.Details, "forged") || !strings.Contains(e.Details, "bob-1") {
				t.Fatalf("forged fields reached the row: %s", e.Details)
			}
		}
	}
	// A large body is refused, not read.
	big := `{"exit_code":1,"cause":"` + strings.Repeat("x", 20<<10) + `"}`
	rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", big)
	t.Logf("R11 20 KiB body: %d", rec.Code)
}

// The agent shares the actor token, so it can post ends first: does the
// relay's real end still reach the audit log?
func TestR11AgentPreemptsTheRealEnd(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = strings.Repeat("ab", 32)
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	for range 3 { // the 3 fake ends the old per-actor cap allowed
		f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", `{"exit_code":0,"duration_ms":1000}`)
	}
	rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", `{"exit_code":124,"stalled":true,"cause":"R11-REAL-END"}`)
	t.Logf("R11 real end after the agent's fakes: %d", rec.Code)
	events, _ := store.ListEvents(100)
	found := false
	for _, e := range events {
		if strings.Contains(e.Details, "R11-REAL-END") {
			found = true
		}
	}
	if !found {
		t.Errorf("R11 FINDING: 3 fake ends posted by the agent (exit 0, INFO) suppress the relay real end (exit 124, HIGH): no audit row for it, and the relay got %d", rec.Code)
	}
}
