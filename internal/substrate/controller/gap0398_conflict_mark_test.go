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

package controller_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// GAP-0398: policy_conflict lived only in the controller's memory and log.
// The controller now marks it on the actor's registration on the leader,
// which the gateway's list, status, policy explain and doctor read, and
// clears the mark when an admin resets the conflict or the policy is
// DefenseClaw's again. A write back keeps what the gateway wrote since.
func TestPolicyConflictIsMarkedOnTheRegistration(t *testing.T) {
	store := &leaderStore{m: map[string]registry.Registration{}}
	resets := &memResets{cms: map[string]*setup.ConfigMap{}}
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		o.Registry = &controller.LeaderRegistry{Store: store}
		o.Resets, o.Namespace = resets, "defenseclaw-system"
	})
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "")
	uid := a.GetMetadata().GetUid()
	key := "eng-web/" + uid
	if err := store.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: uid,
		Person: registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "sub-alice"}, Profile: "eng",
		Connector: "claudecode", Template: "eng-web/claude", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// markOf reads the stored record as the gateway gets it (JSON).
	markOf := func() map[string]any {
		t.Helper()
		store.mu.Lock()
		raw, _ := json.Marshal(store.m[key])
		store.mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		pc, _ := m["policy_conflict"].(map[string]any)
		return pc
	}
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	full := r.api.Policy(ref)
	if full == nil {
		t.Fatal("no policy")
	}
	if pc := markOf(); pc != nil {
		t.Fatalf("marked before any conflict: %v", pc)
	}
	wide := []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"*"}}}}
	conflict := func() {
		t.Helper()
		before := len(r.sink.Events(controller.EventPolicyConflict))
		for range 3 {
			r.clk.Add(time.Minute)
			_ = r.api.ForeignSetPolicy(ref, wide)
			r.pass()
		}
		if len(r.sink.Events(controller.EventPolicyConflict)) != before+1 {
			t.Fatal("no conflict")
		}
	}
	conflict()
	pc := markOf()
	if pc == nil || pc["reverts"] != float64(3) || pc["since"] == "" {
		t.Fatalf("conflict mark = %v, want 3 reverts and a time", pc)
	}

	// A conflict that ends because another writer put DefenseClaw's policy
	// back clears the mark.
	r.clk.Add(time.Minute)
	_ = r.api.ForeignSetPolicy(ref, full.GetRules())
	r.pass()
	if len(r.sink.Events(controller.EventConflictCleared)) != 1 {
		t.Fatal("the conflict did not end")
	}
	if pc := markOf(); pc != nil {
		t.Fatalf("the conflict ended but the mark stayed: %v", pc)
	}

	// A second conflict, cleared by an admin reset. The gateway writes an
	// approval meanwhile; the clear must keep it.
	conflict()
	if markOf() == nil {
		t.Fatal("second conflict not marked")
	}
	store.mu.Lock()
	rec := store.m[key]
	rec.Approved = []string{"registry.example.test"}
	store.m[key] = rec
	store.mu.Unlock()
	if err := controller.RequestReset(context.Background(), resets, "defenseclaw-system",
		controller.ResetRequest{Atespace: "eng-web", Actor: "alice-1", By: "admin@example.com", Reason: "GitOps fixed"}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if pc := markOf(); pc != nil {
		t.Fatalf("an admin reset left the mark: %v", pc)
	}
	store.mu.Lock()
	approved := store.m[key].Approved
	store.mu.Unlock()
	if !slices.Contains(approved, "registry.example.test") {
		t.Fatalf("clearing the mark dropped the gateway's approval: %v", approved)
	}
}
