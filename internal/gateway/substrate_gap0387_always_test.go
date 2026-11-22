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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0387: approve --always keeps the approval for later runs of the same
// person and profile. Before, Always was only recorded: a second --task run
// (a new actor) raised a new ask for the same host and was refused again.
func TestGAP0387AlwaysApprovalCoversLaterRunsOfThePersonAndProfile(t *testing.T) {
	store := asks.NewMemory()
	queue := func(string) SubstrateUnattendedAsk {
		return SubstrateUnattendedAsk{Queue: true, Timeout: 5 * time.Minute}
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks = asksDirect{store}; c.UnattendedAsk = queue })
	ctx := context.Background()
	// Later runs: bob again on profile eng, bob on another profile, alice on eng.
	for i, r := range []registry.Registration{
		{Atespace: "eng-web", Name: "bob-2", UID: "00000000-0000-4000-8000-0000000000b2", Connector: "claudecode", Profile: "eng", Person: ownerOf(bob), Unattended: true},
		{Atespace: "eng-web", Name: "bob-3", UID: "00000000-0000-4000-8000-0000000000b3", Connector: "claudecode", Profile: "ops", Person: ownerOf(bob), Unattended: true},
		{Atespace: "eng-web", Name: "alice-2", UID: "00000000-0000-4000-8000-0000000000a2", Connector: "claudecode", Profile: "eng", Person: ownerOf(alice), Unattended: true},
	} {
		if err := f.regs.Put(ctx, r); err != nil {
			t.Fatal(i, err)
		}
		f.live[r.Atespace+"/"+r.Name] = identity.LiveActor{UID: r.UID, State: identity.ActorRunning}
	}
	ask := func(name, body string) map[string]any {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout,
			`{"actor":{"atespace":"eng-web","name":"`+name+`"},`+body+`}`, "X-DefenseClaw-Client", "substrate-extproc")
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("ask %s: %d %s", name, rec.Code, rec.Body)
		}
		return got
	}
	approve := func(id string, always bool) {
		t.Helper()
		if _, err := store.Resolve(ctx, asks.ResolveRequest{ID: id, Decision: "approve", Always: always, CallerID: ownerOf(bob).ID()}); err != nil {
			t.Fatal(err)
		}
	}
	host := `"host":"example.com","rule":"ask_hosts:example.com"`
	// The first run's ask, approved once (no --always): the next run asks again.
	first := ask("bob-1", host)
	if first["state"] != asks.StatePending {
		t.Fatalf("first ask: %v", first)
	}
	approve(first["id"].(string), false)
	if got := ask("bob-2", host); got["state"] != asks.StatePending {
		t.Fatalf("a once-approval covered another run: %v", got)
	}
	// Approved with --always: bob's later run on the same profile is not asked.
	pending := store.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending asks: %v", pending)
	}
	list, _ := store.List(ctx, asks.ListRequest{All: true, Actor: "bob-2"})
	approve(list[0].ID, true)
	if err := f.regs.Put(ctx, registry.Registration{Atespace: "eng-web", Name: "bob-4", UID: "00000000-0000-4000-8000-0000000000b4",
		Connector: "codex", Profile: "eng", Person: ownerOf(bob), Unattended: true}); err != nil {
		t.Fatal(err)
	}
	f.live["eng-web/bob-4"] = identity.LiveActor{UID: "00000000-0000-4000-8000-0000000000b4", State: identity.ActorRunning}
	if got := ask("bob-4", host); got["state"] != asks.StateApproved {
		t.Fatalf("--always did not cover bob's later run on the same profile: %v", got)
	}
	// Not another profile, not another person, not another host, and a
	// url_rules ask is not answered by a host-wide approval.
	if got := ask("bob-3", host); got["state"] != asks.StatePending {
		t.Fatalf("--always covered another profile: %v", got)
	}
	if got := ask("alice-2", host); got["state"] != asks.StatePending {
		t.Fatalf("--always covered another person: %v", got)
	}
	if got := ask("bob-4", `"host":"other.example.com","rule":"ask_hosts:other.example.com"`); got["state"] != asks.StatePending {
		t.Fatalf("--always covered another host: %v", got)
	}
	if got := ask("bob-4", `"host":"example.com","rule":"url_rules:upload POST"`); got["state"] != asks.StatePending {
		t.Fatalf("a host-wide --always answered a url_rules ask: %v", got)
	}
}
