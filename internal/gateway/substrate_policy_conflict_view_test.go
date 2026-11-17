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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// conflictPolicies is the control API's egress policy reader for policy
// explain: the deny-only policy of an actor in policy_conflict.
type conflictPolicies struct{}

func (conflictPolicies) GetActorEgressPolicy(context.Context, *ateapi.ObjectRef) (*ateapi.EgressPolicy, error) {
	return &ateapi.EgressPolicy{Metadata: &ateapi.ResourceMetadata{Version: 4}}, nil
}

// GAP-0398: the controller's policy_conflict mark on the registration is
// shown by the routes the launcher's list, status and policy explain read,
// to the owner and to an administrator, with the reset that clears it.
func TestSubstratePolicyConflictIsShown(t *testing.T) {
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Policies = conflictPolicies{} })
	ctx := context.Background()
	reg, ok, err := f.regs.Get(ctx, "eng-web", subUID1)
	if err != nil || !ok {
		t.Fatalf("alice-1 registration: %v %v", ok, err)
	}
	// The mark as the controller writes it over the leader RPC (JSON).
	raw, _ := json.Marshal(reg)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["policy_conflict"] = map[string]any{"since": "2026-11-17T15:40:00Z", "reverts": 3}
	raw, _ = json.Marshal(m)
	var marked registry.Registration
	if err := json.Unmarshal(raw, &marked); err != nil {
		t.Fatal(err)
	}
	if err := f.regs.Put(ctx, marked); err != nil {
		t.Fatal(err)
	}

	conflictOf := func(t *testing.T, v map[string]any) map[string]any {
		t.Helper()
		pc, _ := v["policy_conflict"].(map[string]any)
		return pc
	}
	wantConflict := func(t *testing.T, where string, v map[string]any) {
		t.Helper()
		pc := conflictOf(t, v)
		if pc == nil || pc["reverts"] != float64(3) || pc["since"] != "2026-11-17T15:40:00Z" ||
			!strings.Contains(pc["fix"].(string), "defenseclaw substrate policy reset eng-web/alice-1") {
			t.Fatalf("%s: policy_conflict = %v (in %v)", where, pc, v)
		}
	}
	list := func(t *testing.T, tok, query string) map[string]map[string]any {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors"+query, tok, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body)
		}
		var out struct {
			Actors []map[string]any `json:"actors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		by := map[string]map[string]any{}
		for _, a := range out.Actors {
			by[a["name"].(string)] = a
		}
		return by
	}

	// list (the owner) and list --all (an administrator).
	wantConflict(t, "owner list", list(t, "p-alice", "")["alice-1"])
	all := list(t, "p-admin", "?all=1")
	wantConflict(t, "admin list --all", all["alice-1"])
	if pc := conflictOf(t, all["bob-1"]); pc != nil {
		t.Fatalf("bob-1 is not in conflict: %v", pc)
	}

	// status NAME reads the actor.
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-1", "p-alice", "")
	var one map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &one) != nil {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	wantConflict(t, "get", one)

	// policy explain says the policy in force is deny-only, and why.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/policy/explain?actor=eng-web/alice-1", "p-alice", "")
	var ex map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ex) != nil {
		t.Fatalf("explain: %d %s", rec.Code, rec.Body)
	}
	wantConflict(t, "explain", ex)
	if eg, _ := ex["egress"].(map[string]any); eg["policy"] != "deny-only (policy_conflict)" {
		t.Fatalf("explain egress = %v", ex["egress"])
	}
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/policy/explain?actor=eng-web/bob-1", "p-bob", "")
	ex = nil
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ex) != nil {
		t.Fatalf("explain bob: %d %s", rec.Code, rec.Body)
	}
	if _, has := ex["policy_conflict"]; has {
		t.Fatalf("bob-1 explain shows a conflict: %v", ex)
	}
	if eg, _ := ex["egress"].(map[string]any); eg["policy"] != "in force" {
		t.Fatalf("bob-1 explain egress = %v", ex["egress"])
	}
}
