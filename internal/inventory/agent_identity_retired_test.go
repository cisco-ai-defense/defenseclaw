// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
)

// A prune keeps aside, out of the listing, the records the gateway's 1.0.3
// assignment bridge links an agents entry by: the record 1.0.3 wrote for a
// qualified account, and another domain's namesake of it. Other records go.
func TestPruneKeepsLegacyAgentRecordsAsideForTheAssignmentBridge(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	machine := agentidentity.MachineHash("0123456789abcdef0123456789abcdef")
	record := func(uid, account string, legacy bool, seen time.Time) AgentIdentityRecord {
		in := agentidentity.Inputs{MachineHash: machine, UserID: uid, Connector: "codex", InstallFP: "/home/alice/.codex", Account: account}
		id := agentidentity.AgentID(in)
		if legacy {
			id = agentidentity.LegacyAgentID(in)
		}
		return AgentIdentityRecord{AgentID: id, UserID: uid, UserName: account, Connector: in.Connector,
			InstallFP: in.InstallFP, MachineHash: machine, FirstSeen: seen, LastSeen: seen}
	}
	old, now := time.Now().Add(-200*24*time.Hour), time.Now()
	legacy := record("70001", "alice@corp.example", true, old)
	namesake := record("70001", "alice@lab.example", false, old)
	unrelated := record("70002", "bob@corp.example", false, old)
	bare := record("70003", "carol", false, old)
	fresh := record("70001", "alice@corp.example", false, now)
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{legacy, namesake, unrelated, bare, fresh}); err != nil {
		t.Fatal(err)
	}
	if removed, err := st.PruneAgentIdentities(ctx, now.Add(-90*24*time.Hour)); err != nil || removed != 4 {
		t.Fatalf("prune removed %d, err %v; want the 4 stale records", removed, err)
	}
	ids := func(filter AgentIdentityFilter) []string {
		t.Helper()
		rows, _, err := st.ListAgentIdentities(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, rec := range rows {
			out = append(out, rec.AgentID)
		}
		slices.Sort(out)
		return out
	}
	if got := ids(AgentIdentityFilter{}); !slices.Equal(got, []string{fresh.AgentID}) {
		t.Errorf("listing after the prune = %v, want only the fresh record %s", got, fresh.AgentID)
	}
	want := []string{legacy.AgentID, namesake.AgentID, fresh.AgentID}
	slices.Sort(want)
	if got := ids(AgentIdentityFilter{Retired: true}); !slices.Equal(got, want) {
		t.Errorf("records the bridge reads = %v, want the legacy record, its namesake and the fresh one %v", got, want)
	}
	// A later prune keeps them; a namesake seen only after the legacy
	// record was set aside is kept too.
	late := record("70001", "alice@dev.example", false, old)
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{late}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PruneAgentIdentities(ctx, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	want = append(want, late.AgentID)
	slices.Sort(want)
	if got := ids(AgentIdentityFilter{Retired: true}); !slices.Equal(got, want) {
		t.Errorf("after a second prune the bridge reads %v, want %v", got, want)
	}
	if got := ids(AgentIdentityFilter{Retired: true, AgentIDs: []string{legacy.AgentID}}); !slices.Equal(got, []string{legacy.AgentID}) {
		t.Errorf("the legacy record by id = %v", got)
	}
}

// T4 combination of w3-g3-ident (the retired union) and w2b-g-ident (v7
// account domains): the bridge's listing keeps a live row's domains, and a
// retired 1.0.3 record, which has none, lists with none.
func TestRetiredListingKeepsTheLiveRowsAccountDomains(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	machine := agentidentity.MachineHash("0123456789abcdef0123456789abcdef")
	in := agentidentity.Inputs{MachineHash: machine, UserID: "70001", Connector: "codex", InstallFP: "/home/alice/.codex", Account: "alice@corp.example"}
	old, now := time.Now().Add(-200*24*time.Hour), time.Now()
	legacy := AgentIdentityRecord{AgentID: agentidentity.LegacyAgentID(in), UserID: in.UserID, UserName: in.Account, Connector: in.Connector,
		InstallFP: in.InstallFP, MachineHash: machine, FirstSeen: old, LastSeen: old}
	fresh := AgentIdentityRecord{AgentID: agentidentity.AgentID(in), UserID: in.UserID, UserName: in.Account, Connector: in.Connector,
		InstallFP: in.InstallFP, MachineHash: machine, FirstSeen: now, LastSeen: now, UserDomain: "corp.example", UserIncarnation: "sid:S-1-5-21-7-7-7-1001"}
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{legacy, fresh}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PruneAgentIdentities(ctx, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{Retired: true})
	if err != nil {
		t.Fatal(err)
	}
	domains, incarnations := map[string]string{}, map[string]string{}
	for _, rec := range rows {
		domains[rec.AgentID] = rec.UserDomain
		incarnations[rec.AgentID] = rec.UserIncarnation
	}
	if len(domains) != 2 || domains[fresh.AgentID] != "corp.example" || domains[legacy.AgentID] != "" {
		t.Fatalf("retired listing domains = %v, want the fresh row with corp.example and the legacy one with none", domains)
	}
	// T5 integration (g3-ident's retired union with w2b-g-ident's
	// user_incarnation column): the live row keeps its incarnation, the
	// retired one has none.
	if incarnations[fresh.AgentID] != fresh.UserIncarnation || incarnations[legacy.AgentID] != "" {
		t.Fatalf("retired listing incarnations = %v, want the fresh row's and none for the legacy one", incarnations)
	}
}
