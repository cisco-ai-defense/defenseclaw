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

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0640: a person who signed in with an email the issuer did not verify
// is the lower-assurance principal; policy explain (one agent and the
// default-profile form) and the agent's hook audit row say so. A verified
// sign-in carries no mark.
func TestSubstrateUnverifiedEmailIsMarkedLowerAssurance(t *testing.T) {
	unv := alice
	unv.Subject, unv.EmailUnverified = "kc-unverified-sub", true
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = fakePeople{"p-alice": alice, "p-bob": bob, "p-unv": unv}
	})
	ctx := context.Background()
	reg, ok, err := f.regs.Get(ctx, "eng-web", subUID1)
	if err != nil || !ok {
		t.Fatalf("alice-1 registration: %v %v", ok, err)
	}
	var explainAs func(t *testing.T, tok, query string) map[string]any
	explain := func(t *testing.T, query string) map[string]any {
		t.Helper()
		return explainAs(t, "p-alice", query)
	}
	explainAs = func(t *testing.T, tok, query string) map[string]any {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/policy/explain"+query, tok, "")
		var out map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("explain %s: %d %s", query, rec.Code, rec.Body)
		}
		return out
	}
	hookRow := func(reg registry.Registration) map[string]string {
		key, err := sandboxreg.SubstrateKey(reg.Atespace, reg.UID)
		if err != nil {
			t.Fatal(err)
		}
		c := withSubstrateActor(context.Background(), verifiedSubstrateActor(reg.Atespace, reg.Name, reg.UID, "actor/"+reg.Atespace+"/"+reg.Name, key))
		return substrateHookAuditExtra(context.WithValue(c, substrateRegistrationKey{}, reg))
	}

	// A verified sign-in: no mark anywhere.
	if ex := explain(t, "?actor=eng-web/alice-1"); ex["assurance"] != nil {
		t.Fatalf("verified person marked: %v", ex)
	}
	if row := hookRow(reg); row["substrate_person_assurance"] != "" {
		t.Fatalf("verified person's audit row marked: %v", row)
	}

	reg.Person.EmailUnverified = true
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	ex := explain(t, "?actor=eng-web/alice-1")
	if ex["assurance"] != "lower" || ex["assurance_reason"] != registry.AssuranceEmailUnverified || ex["assurance_note"] == nil {
		t.Fatalf("explain: want lower assurance (email_unverified), got %v", ex)
	}
	// The default-profile form names the caller's own sign-in.
	if ex := explainAs(t, "p-unv", ""); ex["assurance"] != "lower" || ex["assurance_reason"] != registry.AssuranceEmailUnverified {
		t.Fatalf("default-profile explain of an unverified caller: %v", ex)
	}
	if ex := explainAs(t, "p-alice", ""); ex["assurance"] != nil {
		t.Fatalf("default-profile explain marks a verified caller: %v", ex)
	}
	if row := hookRow(reg); row["substrate_person_assurance"] != registry.AssuranceEmailUnverified {
		t.Fatalf("audit row: want substrate_person_assurance=email_unverified, got %v", row)
	}
}
