// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || windows

package gateway

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// W19 review (loop round 2): a hook's UPN read and its number are one step
// per account. A hook that read the old UPN and paused before its read was
// numbered must not outrank a hook that read the new UPN after it: its
// older UPN would replace the newer one in the row and in inventory.db.
func TestAgentIdentityUPNReadIsNumberedWhereItIsRead(t *testing.T) {
	const oldUPN, newUPN = "dcad-old@dclab.test", "dcad-new@dclab.test"
	agentIdentityTestSetup(t)
	account := newUPNRowFixture(t)
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	previous := sharedAgentIdentities
	recorder := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	sharedAgentIdentities = recorder
	recorder.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
	t.Cleanup(func() { sharedAgentIdentities = previous })

	userID := hookAgentIdentityUser(account.ctx).ID
	if userID == "" {
		t.Fatal("the fixture's hook context names no account")
	}
	paused, resume := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	hook := func(id string) {
		if id == userID && first.CompareAndSwap(false, true) {
			close(paused)
			<-resume
		}
	}
	agentIdentityUPNReadHook.Store(&hook)
	t.Cleanup(func() { agentIdentityUPNReadHook.Store(nil) })
	resumed := false
	t.Cleanup(func() {
		if !resumed {
			close(resume)
		}
	})

	resolve := func() <-chan agentIdentityFacts {
		out := make(chan agentIdentityFacts, 1)
		go func() { out <- resolveHookAgentIdentity(account.ctx, agentHookRequest{ConnectorName: "codex"}) }()
		return out
	}
	account.publish(oldUPN, false)
	olderOut := resolve()
	select {
	case <-paused: // the older hook read oldUPN and has no number yet
	case <-time.After(10 * time.Second):
		t.Fatal("the older hook never read the UPN")
	}
	account.publish(newUPN, false)
	newerOut := resolve()
	// The newer hook waits for the older one's number. Without that it
	// would finish here, read first and numbered first.
	var newer agentIdentityFacts
	newerDone := false
	select {
	case newer = <-newerOut:
		newerDone = true
	case <-time.After(300 * time.Millisecond):
	}
	resumed = true
	close(resume)
	older := <-olderOut
	if !newerDone {
		newer = <-newerOut
	}
	if older.UserUPN != oldUPN || newer.UserUPN != newUPN || older.ID == "" || older.ID != newer.ID {
		t.Fatalf("older hook read %q (%s), newer %q (%s); want %q then %q for one identity",
			older.UserUPN, older.ID, newer.UserUPN, newer.ID, oldUPN, newUPN)
	}
	if older.UPNRead >= newer.UPNRead {
		t.Fatalf("older read numbered %d, newer %d; the newer read must have the larger number", older.UPNRead, newer.UPNRead)
	}
	recorder.observe(newer, "sess-newer", true)
	recorder.observe(older, "sess-older", true)
	row := listedAgentIdentityRows(t)[older.ID]
	if row == nil || row["upn"] != newUPN {
		t.Fatalf("row %v; want upn %q", row, newUPN)
	}
	if err := recorder.flush(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.ListAgentIdentities(context.Background(), inventory.AgentIdentityFilter{})
	if err != nil || len(stored) != 1 || stored[0].UPN != newUPN {
		t.Fatalf("stored rows %+v, err %v; want UPN %q", stored, err, newUPN)
	}
}
