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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// carryPolicies is an egress policy reader whose policy carries one
// credential URI (none when uri is "").
type carryPolicies struct{ uri *string }

func (p carryPolicies) GetActorEgressPolicy(context.Context, *ateapi.ObjectRef) (*ateapi.EgressPolicy, error) {
	r := &ateapi.HttpsRule{Hostnames: []string{"gitlab.com"}}
	if *p.uri != "" {
		r.Effects = &ateapi.HttpRuleEffects{ReplaceHeaders: []*ateapi.CredentialHeader{{Header: "Authorization", CredentialUri: *p.uri}}}
	}
	return &ateapi.EgressPolicy{Rules: []*ateapi.EgressRule{{Https: r}}}, nil
}

// TestB1SecretListStatesS6a: list says, for each of the caller's own
// bindings, its kind and template and one status: set, waiting on admin
// (with the ask), denied, ask expired (the ask is gone or expired), expired,
// or not covered (the template was narrowed); only a usable one names the
// caller's agents. test --agent says whether that agent's policy carries it.
func TestB1SecretListStatesS6a(t *testing.T) {
	uri := ""
	bf := newBindingFixture(t, func(c *SubstrateConfig) { c.Policies = carryPolicies{uri: &uri} })
	if code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	_, out := bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v2"}`)
	labAsk, _ := out["ask_id"].(string)
	_, out = bf.add(t, "p-alice", `{"name":"gl-den","template":"gitlab","host":"git.den.example","value":"v3"}`)
	denAsk, _ := out["ask_id"].(string)
	if code, out := bf.decide(t, "p-admin", denAsk, "deny"); code != http.StatusOK {
		t.Fatalf("deny: %d %v", code, out)
	}
	alice, now := render.PersonKey("alice"), time.Now()
	if err := bf.store.Update(t.Context(), func(d *secretbind.Doc) error {
		d.Bindings = append(d.Bindings,
			secretbind.Binding{ID: "b-00000000d1", Name: "gl-gone", Owner: alice, Template: "gitlab", Hosts: []string{"git.gone.example"},
				State: secretbind.Waiting, AskID: "A-gone", Created: now},
			secretbind.Binding{ID: "b-00000000d2", Name: "gl-old", Owner: alice, Template: "gitlab", Hosts: []string{"gitlab.com"},
				State: secretbind.Active, Expires: now.Add(-time.Hour), Created: now.Add(-48 * time.Hour)},
			secretbind.Binding{ID: "b-00000000d3", Name: "gl-narrow", Owner: alice, Template: "gitlab", Hosts: []string{"git.narrow.example"},
				State: secretbind.Active, Created: now})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secrets?mine=1", "p-alice", "")
	var list struct {
		Secrets []map[string]any `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	got := map[string]map[string]any{}
	for _, s := range list.Secrets {
		got[s["name"].(string)] = s
	}
	for name, want := range map[string][2]string{
		"gl-work":   {"set", ""},
		"gl-lab":    {"waiting on admin", "secret_binding_outside_templates"},
		"gl-den":    {"denied", "secret_binding_denied"},
		"gl-gone":   {"ask expired", "secret_binding_ask_expired"},
		"gl-old":    {"expired", "secret_expired"},
		"gl-narrow": {"not covered", "secret_binding_not_covered"},
	} {
		s := got[name]
		reason, _ := s["reason"].(string)
		if s == nil || s["status"] != want[0] || reason != want[1] || s["kind"] != "template" || s["template"] != "gitlab" {
			t.Errorf("%s: %v, want %v", name, s, want)
		}
		agents, _ := s["agents"].([]any)
		if usable := want[0] == "set"; usable != slices.Contains(agents, any("alice-1")) {
			t.Errorf("%s agents %v", name, agents)
		}
	}
	if got["gl-lab"]["ask_id"] != labAsk || got["gl-old"]["expires"] == nil {
		t.Errorf("ask id / expires: %v %v", got["gl-lab"], got["gl-old"])
	}

	test := func(name string) map[string]any {
		t.Helper()
		rec := bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/secrets/"+name+"/test", "p-alice", `{"agent":"eng-web/alice-1"}`)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		ag, _ := out["agent"].(map[string]any)
		if rec.Code != http.StatusOK || ag == nil {
			t.Fatalf("test %s: %d %s", name, rec.Code, rec.Body.String())
		}
		return ag
	}
	tpl, _ := secretbind.Find(secretbind.Catalog(bf.api.substrateState().cfg.SecretTemplates), "gitlab")
	ss := config.SubstrateSelfServiceSecretsConfig{}
	uri = substrateSecretFor(secretbind.SecretFor(tpl, ss.EffectiveProvider(), ss.EffectiveNamespace(), bf.binding(t, "alice", "gl-work"), false), "alice")
	if ag := test("gl-work"); ag["in_policy"] != true || ag["actor"] != "eng-web/alice-1" {
		t.Errorf("carried: %v", ag)
	}
	uri = ""
	if ag := test("gl-work"); ag["in_policy"] != false || ag["reason"] != "secret_not_in_policy" {
		t.Errorf("not carried: %v", ag)
	}
	if ag := test("gl-lab"); ag["in_policy"] != false || ag["reason"] != "secret_binding_outside_templates" {
		t.Errorf("waiting: %v", ag)
	}
}
