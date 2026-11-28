// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestEarlierRunAlwaysApprovalIsListedAndRevocableGAP0387GAP0492: an
// approve --always given on an earlier run (since deleted) answers a new run
// of the same person and profile (GAP-0387). The new run must show it in
// approvals --standing, and revoke on the new run must take it back
// (GAP-0492), so the next request asks again. Before the fix, the list was
// empty and revoke answered 404 while the host stayed open for this and
// every later run (the CLOSE-AUTH fold review, RV-CAF P2).
func TestEarlierRunAlwaysApprovalIsListedAndRevocableGAP0387GAP0492(t *testing.T) {
	const earlierUID = "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4d"
	store := asks.NewMemory()
	fake := ateapifake.New()
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks, c.Policies = asksDirect{store}, fake })
	store.OnRevoke = func(ctx context.Context, in asks.RevokeRequest) (bool, error) {
		return registry.RemoveApproved(ctx, f.regs, in.Atespace, in.UID, in.Host, in.CallerID, in.Admin)
	}
	ctx := context.Background()
	earlier := registry.Registration{Atespace: "eng-web", Name: "alice-0", UID: earlierUID, Connector: "claudecode", Profile: "eng",
		Person: ownerOf(alice)}
	if err := f.regs.Put(ctx, earlier); err != nil {
		t.Fatal(err)
	}
	f.live["eng-web/alice-0"] = identity.LiveActor{UID: earlierUID, State: identity.ActorRunning}
	callout := func(actor string) map[string]any {
		t.Helper()
		body := `{"actor":{"atespace":"eng-web","name":"` + actor + `"},"host":"example.com","rule":"ask_hosts:example.com","summary":"GET example.com"}`
		rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout, body, "X-DefenseClaw-Client", "substrate-extproc")
		var got map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("callout ask for %s: %d %s", actor, rec.Code, rec.Body)
		}
		return got
	}
	// alice approves always on the earlier run, then that run is deleted.
	id, _ := callout("alice-0")["id"].(string)
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/asks/"+id, "p-alice", `{"decision":"approve","always":true}`); rec.Code != http.StatusOK {
		t.Fatalf("approve always %d %s", rec.Code, rec.Body)
	}
	earlier.Deleted = true
	if err := f.regs.Put(ctx, earlier); err != nil {
		t.Fatal(err)
	}
	delete(f.live, "eng-web/alice-0")

	// The new run of the same person and profile gets through on it.
	if got := callout("alice-1"); got["state"] != asks.StateApproved {
		t.Fatalf("the new run is not answered by the earlier always approval (GAP-0387): %v", got)
	}
	// It is listed on the new run, so the person can see what keeps it open.
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/approvals", "p-alice", "")
	var listed struct {
		Approvals []map[string]any `json:"approvals"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &listed) != nil {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	if len(listed.Approvals) != 1 || listed.Approvals[0]["actor"] != "alice-1" || listed.Approvals[0]["host"] != "example.com" ||
		listed.Approvals[0]["ask_id"] != id {
		t.Errorf("standing approvals %v, want the earlier run's approval listed on alice-1", listed.Approvals)
	}
	// bob cannot take it back; alice can, on the new run.
	if code := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/approvals/eng-web/alice-1/example.com", "p-bob", "").Code; code != http.StatusNotFound {
		t.Fatalf("bob revokes alice's approval: %d", code)
	}
	if code := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/approvals/eng-web/alice-1/example.com", "p-alice", "").Code; code != http.StatusOK {
		t.Fatalf("alice revokes the approval that keeps alice-1 open: %d, want 200", code)
	}
	if got := callout("alice-1"); got["state"] != asks.StatePending {
		t.Fatalf("the request after the revoke did not ask again: %v", got)
	}
	all, err := store.List(ctx, asks.ListRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.ID == id && a.State != asks.StateRevoked {
			t.Fatalf("the earlier run's always approval after the revoke: state %q, want revoked", a.State)
		}
	}
}
