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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// approveOnOpen is an ask store where an administrator approves every
// binding ask the moment it opens: before the binding is written.
type approveOnOpen struct{ SubstrateAskStore }

func (s approveOnOpen) OpenAsk(ctx context.Context, a asks.Ask) (asks.Ask, error) {
	got, err := s.SubstrateAskStore.OpenAsk(ctx, a)
	if err == nil && got.Kind == asks.KindSecretBinding {
		_, err = s.Resolve(ctx, asks.ResolveRequest{ID: got.ID, Decision: "approve", CallerID: "root", Admin: true})
	}
	return got, err
}

func (bf *bindingFixture) listed(t *testing.T, tok string) map[string]map[string]any {
	t.Helper()
	rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secrets?mine=1", tok, "")
	var list struct {
		Secrets []map[string]any `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	out := map[string]map[string]any{}
	for _, s := range list.Secrets {
		out[s["name"].(string)] = s
	}
	return out
}

// TestRV4F2ApprovalBeforeBindingWriteApplies: an ask approved before its
// binding is written still makes the binding active.
func TestRV4F2ApprovalBeforeBindingWriteApplies(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) { c.Asks = approveOnOpen{c.Asks} })
	code, out := bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v"}`)
	if code != http.StatusCreated || out["status"] != "set" {
		t.Errorf("add answered %d %v, want 201 set", code, out)
	}
	if b := bf.binding(t, "alice", "gl-lab"); b.State != secretbind.Active {
		t.Fatalf("binding %s after an early approval, want active", b.State)
	}
	if s := bf.listed(t, "p-alice")["gl-lab"]; s["status"] != "set" {
		t.Errorf("list: %v", s)
	}
}

// TestRV4F2FailedBindingWriteOnDecide: when the binding write on approve
// fails, list says "approved, not applied", and the administrator's second
// approve applies it.
func TestRV4F2FailedBindingWriteOnDecide(t *testing.T) {
	bf := newBindingFixture(t, nil)
	_, out := bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v"}`)
	id, _ := out["ask_id"].(string)
	bf.cm.mu.Lock()
	bf.cm.failPut = true
	bf.cm.mu.Unlock()
	if code, out := bf.decide(t, "p-admin", id, "approve"); code != http.StatusBadGateway {
		t.Fatalf("approve with a failing store: %d %v", code, out)
	}
	bf.cm.mu.Lock()
	bf.cm.failPut = false
	bf.cm.mu.Unlock()
	if s := bf.listed(t, "p-alice")["gl-lab"]; s["status"] != "approved, not applied" || s["reason"] != "secret_binding_not_applied" {
		t.Errorf("list after the failed write: %v", s)
	}
	if code, out := bf.decide(t, "p-admin", id, "deny"); code != http.StatusConflict {
		t.Errorf("a different second answer: %d %v, want 409", code, out)
	}
	if code, out := bf.decide(t, "p-admin", id, "approve"); code != http.StatusOK || out["state"] != asks.StateApproved {
		t.Fatalf("second approve: %d %v", code, out)
	}
	if b := bf.binding(t, "alice", "gl-lab"); b.State != secretbind.Active {
		t.Fatalf("binding %s after the second approve, want active", b.State)
	}
	if code, _ := bf.decide(t, "p-admin", id, "approve"); code != http.StatusOK {
		t.Errorf("a third approve is not harmless: %d", code)
	}
	if code, _ := bf.decide(t, "p-alice", id, "approve"); code == http.StatusOK {
		t.Errorf("the owner re-applied their own binding ask")
	}
}

// TestRV4F3ValuesOnlyListsBindingsLocked: under values_only list and test
// say a binding is locked, name no agents and keep it out of the policy.
func TestRV4F3ValuesOnlyListsBindingsLocked(t *testing.T) {
	live := config.SubstrateSelfServiceSecretsConfig{Mode: config.SelfServiceBindings}
	uri := "ate-secret://anything"
	bf := newBindingFixture(t, func(sc *SubstrateConfig) {
		tmpl := sc.SecretTemplates
		sc.Policies = carryPolicies{uri: &uri}
		sc.LiveSelfService = func() (config.SubstrateSelfServiceSecretsConfig, []config.SubstrateSecretTemplate) { return live, tmpl }
	})
	if code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	live.Mode = config.SelfServiceValuesOnly
	s := bf.listed(t, "p-alice")["gl-work"]
	agents, _ := s["agents"].([]any)
	if s["status"] != "locked" || s["reason"] != "secret_bindings_locked" || len(agents) != 0 {
		t.Errorf("list under values_only: %v", s)
	}
	rec := bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/secrets/gl-work/test", "p-alice", `{"agent":"eng-web/alice-1"}`)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	ag, _ := out["agent"].(map[string]any)
	if rec.Code != http.StatusOK || ag["in_policy"] != false || ag["reason"] != "secret_bindings_locked" {
		t.Errorf("test under values_only: %d %s", rec.Code, rec.Body.String())
	}
}

// TestRV4F8SecretTestOtherPersonAgent: a person who names another person's
// agent gets actor_not_found; an administrator who does so is answered and
// an admin_read row names the agent.
func TestRV4F8SecretTestOtherPersonAgent(t *testing.T) {
	bf := newBindingFixture(t, nil)
	store, logger := testStoreAndLogger(t)
	bf.api.store, bf.api.logger = store, logger
	rec := bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/secrets/github-push/test", "p-alice", `{"agent":"eng-web/bob-1"}`)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "actor_not_found") {
		t.Fatalf("alice named bob's agent: %d %s", rec.Code, rec.Body.String())
	}
	rec = bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/secrets/github-push/test", "p-admin", `{"agent":"eng-web/bob-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin test: %d %s", rec.Code, rec.Body.String())
	}
	events, err := store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if strings.Contains(e.Details, `"event":"admin_read"`) && strings.Contains(e.Details, `"actor":"eng-web/bob-1"`) &&
			strings.Contains(e.Details, `"view":"secret test"`) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d admin_read rows for the admin's secret test of bob's agent, want 1", n)
	}
}

// TestRV4F11AdminValueCap: an administrator's per_person value is capped at
// the stored-value limit too (the proxy's header limit), like a binding's.
func TestRV4F11AdminValueCap(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) {
		c.Secrets = append(c.Secrets, config.SubstrateSecret{Name: "npm-token", Source: "ate-secret://k8s.io/default/dc-people/{person}-npm/token",
			Scope: "per_person", Inject: config.SubstrateSecretInject{Hosts: []string{"registry.npmjs.org"}, Header: "Authorization"}, Profiles: []string{"eng"}})
	})
	big := strings.Repeat("a", secretbind.MaxStoredValue+1)
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/npm-token", "p-alice", `{"value":"`+big+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a value over the header limit: %d %s", rec.Code, rec.Body.String())
	}
	ok := strings.Repeat("a", secretbind.MaxStoredValue)
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/npm-token", "p-alice", `{"value":"`+ok+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("a value at the limit: %d %s", rec.Code, rec.Body.String())
	}
}
