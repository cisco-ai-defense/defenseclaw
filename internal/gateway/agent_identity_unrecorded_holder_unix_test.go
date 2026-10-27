// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
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

// GAP-1876 (FC-BLK-167-ER on ee6ebae3a1): on an AD-joined host the gateway
// service cannot resolve a bare name itself (sssd.conf is root's, so whether
// a directory account shares the name is unknown and the name is refused,
// GAP-1131), and a uid filter selected every row of the uid. Right after
// userdel -r and useradd -u, root's first view by name and by uid lists none
// of the earlier holder's rows; after the guardian's pass the uid view
// without a proof does not either. The same account's own view lists its
// row, and the recreated account's new agent identity is listed.
func TestRecreatedAccountFirstViewByUnresolvedNameAndByUID(t *testing.T) {
	f := newRecreatedAccountFixture(t)
	profileExplainAccount = func(string) (string, string, error) {
		return "", "", errors.New("whether a directory account shares the name is unknown")
	}
	uid := strconv.Itoa(f.uid)
	oldHome := "home:66308:251958246:" + strconv.FormatInt(f.now.Add(-time.Minute).UnixNano(), 10)
	f.guardian("")
	old := f.hook("s-old")
	f.guardian(oldHome)
	if got := f.hook("s-old-2").ID; got != old.ID {
		t.Fatalf("the first proven home moved the agent identity to %s, want %s", got, old.ID)
	}
	for _, user := range []string{"alice", uid} {
		if _, listed := f.view(viewOf(user, uid+":"+oldHome))[old.ID]; !listed {
			t.Fatalf("the account's own view %q does not list its row %s", user, old.ID)
		}
	}
	f.mu.Lock()
	f.now = f.now.Add(2 * time.Minute)
	created := f.now.UnixNano()
	f.mu.Unlock()
	newHome := "home:66308:84679938:" + strconv.FormatInt(created, 10)
	for _, user := range []string{"alice", uid} {
		if rows := f.view(viewOf(user, uid+":"+newHome)); len(rows) != 0 {
			t.Fatalf("first view %q of the recreated account lists %v; want none of the earlier holder's rows (%s)", user, listedIDs(rows), old.ID)
		}
	}
	f.guardian(newHome)
	if _, listed := f.view(viewOf(uid, ""))[old.ID]; listed {
		t.Fatalf("the uid view after the guardian's pass lists the earlier holder's row %s", old.ID)
	}
	recreated := f.hook("s-new")
	rows := f.view(viewOf(uid, ""))
	if _, listed := rows[recreated.ID]; !listed || recreated.ID == old.ID {
		t.Fatalf("uid view %v; want the recreated account's own agent %s", listedIDs(rows), recreated.ID)
	}
	if _, listed := rows[old.ID]; listed {
		t.Fatalf("uid view lists the earlier holder's row %s next to the new one", old.ID)
	}
}

// GAP-1867, the upgrade variant of GAP-0422: a 1.0.4 gateway served the
// local account A (its homes file keeps the uid with no first_seen and, on a
// machine-policy host, no home proof). A is deleted and B created under the
// same name, uid and home path before B's first hook on 1.0.5. The upgraded
// gateway takes the homes file's last write as the time the uid was seen,
// so B's newer home is another account's: root's first view lists none of
// A's rows and B's first hook derives its own agent identity. A home older
// than that write keeps the agent identity, and the view lists its row.
func TestUpgradedGatewayTellsARecreatedAccountFromTheOneTheOldBuildServed(t *testing.T) {
	for _, recreated := range []bool{true, false} {
		f := newRecreatedAccountFixture(t)
		const oldRow = "agt-00000000001867a1"
		saved := time.Unix(3_000_000, 0)
		body := `{"format":{"format":1},"` + f.id + `":{"home":"` + f.home + `","name":"alice","base_incarnation":"files","incarnation":"files"}}`
		if err := os.WriteFile(f.store, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(f.store, saved, saved); err != nil {
			t.Fatal(err)
		}
		f.start()
		if err := f.inv.UpsertAgentIdentities(context.Background(), []inventory.AgentIdentityRecord{{AgentID: oldRow, UserID: f.id,
			UserName: "alice", Connector: "codex", UserIncarnation: "files", FirstSeen: saved.Add(-time.Hour), LastSeen: saved}}); err != nil {
			t.Fatal(err)
		}
		birth := saved.Add(-24 * time.Hour)
		if recreated {
			birth = saved.Add(time.Hour)
		}
		home := "home:2049:3000:" + strconv.FormatInt(birth.UnixNano(), 10)
		rows := f.view(viewOf("alice", strconv.Itoa(f.uid)+":"+home))
		if _, listed := rows[oldRow]; listed == recreated {
			t.Fatalf("recreated=%v: first view lists=%v the row the 1.0.4 gateway recorded (%v)", recreated, listed, listedIDs(rows))
		}
		f.guardian(home)
		facts := f.hook("s-1867")
		if fresh := facts.UserIncarnation != "files"; fresh != recreated {
			t.Fatalf("recreated=%v: first hook on the upgraded gateway has account token %q", recreated, facts.UserIncarnation)
		}
	}
}
