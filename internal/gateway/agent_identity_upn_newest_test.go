// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || windows

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// upnRowFixture is one directory account on this OS (a managed uid on Linux
// and macOS, a SID on Windows) whose guardian record the test rewrites.
type upnRowFixture struct {
	// ctx is a hook request context verified as the account.
	ctx context.Context
	// publish writes the guardian's record of the account: its UPN, marked
	// kept or verified, and runs the hook path's directory lookup.
	publish func(upn string, kept bool)
}

// W19 review (continuation 5): an agent identity row lists the UPN of the
// newest sighting only. Hooks read the UPN before they reach the recorder,
// so overlapping hooks can arrive in either order, also around a failed or
// a successful write: a newer sighting replaces the UPN, an older one never
// puts its UPN back, and a sighting of a UPN the guardian marked kept
// leaves the row without one until a newer pass verifies it again, on every
// OS.
func TestAgentIdentityRowUPNIsTheNewestSighting(t *testing.T) {
	const oldUPN, newUPN = "dcad-old@dclab.test", "dcad-new@dclab.test"
	// Steps: "read <name> <upn> [kept]" publishes a guardian record and
	// reads a hook's identity facts; "observe <name>" records them; "take",
	// "restore" are a write that fails; "flush" is one that succeeds.
	type step struct {
		op, name, upn string
		kept          bool
	}
	read := func(name, upn string, kept bool) step { return step{op: "read", name: name, upn: upn, kept: kept} }
	observe := func(name string) step { return step{op: "observe", name: name} }
	take, restore, flush := step{op: "take"}, step{op: "restore"}, step{op: "flush"}
	for _, tc := range []struct {
		name  string
		steps []step
		want  string // the UPN the row lists, "" none
	}{
		{"a newer sighting replaces the UPN", []step{
			read("a", oldUPN, false), observe("a"), read("b", newUPN, false), observe("b")}, newUPN},
		{"an older read arrives after a newer one", []step{
			read("a", oldUPN, false), read("b", newUPN, false), observe("b"), observe("a")}, newUPN},
		{"an older read arrives while a write fails", []step{
			read("a", oldUPN, false), read("b", newUPN, false), observe("b"), take, observe("a"), restore}, newUPN},
		{"an older read arrives after a write", []step{
			read("a", oldUPN, false), read("b", newUPN, false), observe("b"), flush, observe("a")}, newUPN},
		{"the guardian marks the UPN kept", []step{
			read("a", newUPN, false), observe("a"), read("b", newUPN, true), observe("b")}, ""},
		{"an older verified read arrives after the kept mark", []step{
			read("a", newUPN, false), read("b", newUPN, true), observe("b"), observe("a")}, ""},
		{"an older verified read arrives after the kept mark is written", []step{
			read("a", newUPN, false), read("b", newUPN, true), observe("b"), flush, observe("a")}, ""},
		{"a kept UPN verified again", []step{
			read("a", newUPN, false), read("b", newUPN, true), read("c", newUPN, false),
			observe("a"), observe("b"), observe("c")}, newUPN},
		{"an older kept read arrives after a newer verification", []step{
			read("a", oldUPN, true), read("b", newUPN, false), observe("b"), flush, observe("a")}, newUPN},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

			reads := map[string]agentIdentityFacts{}
			var failed []inventory.AgentIdentityRecord
			id := ""
			for _, s := range tc.steps {
				switch s.op {
				case "read":
					account.publish(s.upn, s.kept)
					facts := resolveHookAgentIdentity(account.ctx, agentHookRequest{ConnectorName: "codex"})
					if facts.ID == "" || (id != "" && facts.ID != id) {
						t.Fatalf("read %s: agent identity %q, want one identity", s.name, facts.ID)
					}
					id, reads[s.name] = facts.ID, facts
				case "observe":
					recorder.observe(reads[s.name], "sess-"+s.name, true)
				case "take":
					failed, _, _ = recorder.take()
				case "restore":
					recorder.restore(failed, nil, nil)
				case "flush":
					if err := recorder.flush(context.Background(), store); err != nil {
						t.Fatal(err)
					}
				}
			}
			row := listedAgentIdentityRows(t)[id]
			if row == nil {
				t.Fatal("no agent identity row")
			}
			if got, named := row["upn"]; (tc.want == "" && named) || (tc.want != "" && got != tc.want) {
				t.Fatalf("row lists upn %v; want %q", got, tc.want)
			}
			if err := recorder.flush(context.Background(), store); err != nil {
				t.Fatal(err)
			}
			stored, _, err := store.ListAgentIdentities(context.Background(), inventory.AgentIdentityFilter{})
			if err != nil || len(stored) != 1 || stored[0].UPN != tc.want || stored[0].UPNUnavailable != (tc.want == "") {
				t.Fatalf("stored rows %+v, err %v; want UPN %q", stored, err, tc.want)
			}
		})
	}
}
