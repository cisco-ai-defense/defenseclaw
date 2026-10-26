// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strconv"
	"testing"
	"time"
)

// GAP-0422, reopened by FC-BLK-167-ER on a machine-policy host: the local
// account was no guardian target, so no identity record ever proved the home
// of the account the hooks saw first. The account is deleted and created
// again under the same name, uid and home path. Its new home was created
// after the gateway first saw the uid, so the administrator's first view
// (root's holder_proof, before any record or hook of the new account) lists
// none of the earlier holder's rows, and once the guardian's record proves
// the new home the new account derives its own agent identity, which it
// keeps across a restart.
func TestRecreatedAccountWithoutAProvenFirstHomeIsToldApart(t *testing.T) {
	f := newRecreatedAccountFixture(t)
	f.guardian("")
	old := f.hook("s-old")
	f.mu.Lock()
	f.now = f.now.Add(time.Minute)
	created := f.now.UnixNano()
	f.mu.Unlock()
	newHome := "home:2049:2000:" + strconv.FormatInt(created, 10)
	f.guardian("")
	rows := f.view(viewOf("alice", strconv.Itoa(f.uid)+":"+newHome))
	if _, listed := rows[old.ID]; listed {
		t.Fatalf("first view of the recreated account lists the earlier holder's row %s (%v)", old.ID, listedIDs(rows))
	}
	f.guardian(newHome)
	recreated := f.hook("s-new")
	if recreated.ID == old.ID {
		t.Fatalf("the recreated account derived the earlier holder's agent identity %s", old.ID)
	}
	f.start()
	if got := f.hook("s-new-2").ID; got != recreated.ID {
		t.Fatalf("after a restart the recreated account's agent identity is %s, want %s", got, recreated.ID)
	}
}

// The account the hooks saw first, whose home existed before then, keeps
// its agent identity when the guardian's record first proves that home,
// also when the record comes long after its first hook; root's view lists
// its rows.
func TestFirstProvenHomeOlderThanTheFirstHookKeepsTheAgentIdentity(t *testing.T) {
	f := newRecreatedAccountFixture(t)
	home := "home:2049:1000:" + strconv.FormatInt(f.now.Add(-24*time.Hour).UnixNano(), 10)
	f.guardian("")
	before := f.hook("s-1")
	rows := f.view(viewOf("alice", strconv.Itoa(f.uid)+":"+home))
	if _, listed := rows[before.ID]; !listed {
		t.Fatalf("root's view of the same account does not list its row %s (%v)", before.ID, listedIDs(rows))
	}
	f.guardian(home)
	if got := f.hook("s-2").ID; got != before.ID {
		t.Fatalf("the first proven home moved the agent identity to %s, want %s", got, before.ID)
	}
	if _, changed := agentIdentityHolderHistory(f.id); changed {
		t.Fatal("the first proven home recorded a holder change")
	}
}
