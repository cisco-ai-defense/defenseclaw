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
)

// TestSubstrateCalloutAskOnceLetsOneRequestGAP0484: `substrate approve ID`
// without --always lets exactly one request through, the held one or the
// agent's retry after its hold ended, and the next request asks again. It
// is never a standing approval: the host does not join the registration
// (so not the policy), and the approved ask answers no later request.
// Before the fix every later request to the host was answered "approved
// earlier for this actor" for as long as the actor lived (live: 200 at
// +1 s, +9 s, +1 min, +2.5 min, +4 min, with no new ask). --always keeps
// answering approved and joins the registration.
func TestSubstrateCalloutAskOnceLetsOneRequestGAP0484(t *testing.T) {
	store := asks.NewMemory()
	fake := ateapifake.New()
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks, c.Policies = asksDirect{store}, fake })
	// The leader's hook, as substrate serve sets it: a host-wide approval
	// adds the host to the actor's registration.
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
	ctx := context.Background()
	post := func(askID string) map[string]any {
		t.Helper()
		body := `{"actor":{"atespace":"eng-web","name":"alice-1"},"host":"example.com","rule":"ask_hosts:example.com","summary":"GET example.com"`
		if askID != "" {
			body += `,"ask_id":"` + askID + `"`
		}
		rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout, body+"}", "X-DefenseClaw-Client", "substrate-extproc")
		var got map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("callout ask %d %s", rec.Code, rec.Body)
		}
		return got
	}
	approve := func(id any, always bool) {
		t.Helper()
		if _, err := store.Resolve(ctx, asks.ResolveRequest{ID: id.(string), Decision: "approve", Always: always, CallerID: ownerOf(alice).ID()}); err != nil {
			t.Fatal(err)
		}
	}
	pending := func(what string, got map[string]any) string {
		t.Helper()
		id, _ := got["id"].(string)
		if got["state"] != asks.StatePending || id == "" {
			t.Fatalf("%s: want a new pending ask, got %v", what, got)
		}
		return id
	}
	approvedHosts := func() []string {
		t.Helper()
		reg, _, err := f.regs.Get(ctx, "eng-web", subUID1)
		if err != nil {
			t.Fatal(err)
		}
		return reg.Approved
	}

	// The held request reads its ask, approved once: it goes through.
	first := pending("the first request", post(""))
	approve(first, false)
	if got := post(first); got["state"] != asks.StateApproved {
		t.Fatalf("the held request after approve once: %v", got)
	}
	// The next request asks again, and so does the one after it (the same
	// open question): no standing approval.
	second := pending("the request after a once approval was used", post(""))
	if second == first {
		t.Fatalf("the used once approval's ask %s was offered again", first)
	}
	if again := pending("the next request", post("")); again != second {
		t.Fatalf("a second open ask %s for the same question %s", again, second)
	}
	if hosts := approvedHosts(); slices.Contains(hosts, "example.com") {
		t.Fatalf("approve once added the host to the registration (a standing approval): %v", hosts)
	}

	// The held request was refused as pending before the answer: the
	// agent's retry takes the once approval, and only that retry does.
	approve(second, false)
	if got := post(""); got["state"] != asks.StateApproved {
		t.Fatalf("the retry after approve once: %v", got)
	}
	third := pending("the request after the retry", post(""))

	// Two requests held on one ask: one goes through, the other asks again.
	approve(third, false)
	if got := post(third); got["state"] != asks.StateApproved {
		t.Fatalf("the first held request: %v", got)
	}
	fourth := pending("the second held request on a used once approval", post(third))

	// Always: every later request goes through, and the host joins the
	// registration for the controller to keep in the policy.
	approve(fourth, true)
	for i := range 3 {
		if got := post(""); got["state"] != asks.StateApproved {
			t.Fatalf("request %d after approve always: %v", i, got)
		}
	}
	if hosts := approvedHosts(); !slices.Contains(hosts, "example.com") {
		t.Fatalf("approve always did not add the host to the registration: %v", hosts)
	}
}
