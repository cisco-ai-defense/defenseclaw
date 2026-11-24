// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestSubstrateStandingApprovalsListAndRevokeGAP0492: an `approve --always`
// approval is listed (agent, host, scope, who approved it, when) to its
// person only, to an administrator with all=1, and its person takes it back
// with DELETE approvals/ATESPACE/NAME/HOST: the host leaves the
// registration (so the controller's policy) and the callout asks again.
// Before the fix neither route existed: nothing listed the approval, and
// nothing but deleting the agent ended it (J10 ask-always steps 3 and 6).
func TestSubstrateStandingApprovalsListAndRevokeGAP0492(t *testing.T) {
	store := asks.NewMemory()
	fake := ateapifake.New()
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks, c.Policies = asksDirect{store}, fake })
	// The leader's hooks, as substrate serve sets them.
	store.OnApprove = func(ctx context.Context, a asks.Ask) error {
		if a.Host == "" || !asks.HostWide(a.Rule) {
			return nil
		}
		reg, _, err := f.regs.Get(ctx, a.Atespace, a.UID)
		if err != nil {
			return err
		}
		if !slices.Contains(reg.Approved, a.Host) {
			reg.Approved = append(reg.Approved, a.Host)
		}
		return f.regs.Put(ctx, reg)
	}
	store.OnRevoke = func(ctx context.Context, in asks.RevokeRequest) (bool, error) {
		return registry.RemoveApproved(ctx, f.regs, in.Atespace, in.UID, in.Host, in.CallerID, in.Admin)
	}
	ctx := context.Background()
	callout := func() map[string]any {
		t.Helper()
		body := `{"actor":{"atespace":"eng-web","name":"alice-1"},"host":"example.com","rule":"ask_hosts:example.com","summary":"GET example.com"}`
		rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout, body, "X-DefenseClaw-Client", "substrate-extproc")
		var got map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("callout ask %d %s", rec.Code, rec.Body)
		}
		return got
	}
	list := func(token, query string) []map[string]any {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/approvals"+query, token, "")
		var got struct {
			Approvals []map[string]any `json:"approvals"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("list approvals as %s: %d %s", token, rec.Code, rec.Body)
		}
		return got.Approvals
	}
	revoke := func(token string) int {
		t.Helper()
		return f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/approvals/eng-web/alice-1/example.com", token, "").Code
	}
	approvedHosts := func() []string {
		t.Helper()
		reg, _, err := f.regs.Get(ctx, "eng-web", subUID1)
		if err != nil {
			t.Fatal(err)
		}
		return reg.Approved
	}

	// alice approves always.
	id, _ := callout()["id"].(string)
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/asks/"+id, "p-alice", `{"decision":"approve","always":true}`); rec.Code != http.StatusOK {
		t.Fatalf("approve always %d %s", rec.Code, rec.Body)
	}
	if got := callout(); got["state"] != asks.StateApproved {
		t.Fatalf("the request after approve always: %v", got)
	}

	// Listed for alice, with who and when; not for bob.
	mine := list("p-alice", "")
	if len(mine) != 1 {
		t.Fatalf("alice's standing approvals: %v", mine)
	}
	a := mine[0]
	if a["atespace"] != "eng-web" || a["actor"] != "alice-1" || a["host"] != "example.com" || a["scope"] != "host" ||
		a["approved_by"] != "you" || a["approved_at"] == nil || a["ask_id"] != id {
		t.Fatalf("alice's standing approval: %v", a)
	}
	if got := list("p-bob", ""); len(got) != 0 {
		t.Fatalf("bob sees alice's approvals: %v", got)
	}
	if got := list("p-bob", "?all=1"); len(got) != 0 {
		t.Fatalf("bob's all=1 (not an administrator) sees alice's approvals: %v", got)
	}
	if got := list("p-admin", "?all=1"); len(got) != 1 || got[0]["approved_by"] != "owner" || got[0]["owner"] != alice.Principal {
		t.Fatalf("the administrator's all=1 view: %v", got)
	}

	// bob cannot take it back; alice can, once.
	if code := revoke("p-bob"); code != http.StatusNotFound {
		t.Fatalf("bob revokes alice's approval: %d", code)
	}
	if code := revoke("p-alice"); code != http.StatusOK {
		t.Fatalf("alice revokes: %d", code)
	}
	if hosts := approvedHosts(); slices.Contains(hosts, "example.com") {
		t.Fatalf("the revoked host is still in the registration (and so the policy): %v", hosts)
	}
	if got := callout(); got["state"] != asks.StatePending {
		t.Fatalf("the request after the revoke did not ask again: %v", got)
	}
	if got := list("p-alice", ""); len(got) != 0 {
		t.Fatalf("a revoked approval is still listed: %v", got)
	}
	if code := revoke("p-alice"); code != http.StatusNotFound {
		t.Fatalf("a second revoke: %d", code)
	}
	ds, _ := store.Decisions(ctx, asks.ListRequest{OwnerID: ownerOf(alice).ID()})
	if !slices.ContainsFunc(ds, func(d asks.Decision) bool { return d.Verdict == asks.StateRevoked && d.Tool == "example.com" }) {
		t.Fatalf("the revoke is not in alice's decisions: %v", ds)
	}
}
