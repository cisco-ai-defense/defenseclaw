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
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

func (bf *bindingFixture) askNamed(t *testing.T, id string) asks.Ask {
	t.Helper()
	list, err := bf.asks.List(context.Background(), asks.ListRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("ask %s not found", id)
	return asks.Ask{}
}

const hardOutsideAdd = `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v"}`

// TestRV4F4RmDeniesThePendingAsk: removing a waiting binding denies its ask,
// so the queue of the administrators no longer shows it (RV4 F4).
func TestRV4F4RmDeniesThePendingAsk(t *testing.T) {
	bf := newBindingFixture(t, nil)
	code, out := bf.add(t, "p-alice", hardOutsideAdd)
	id, _ := out["ask_id"].(string)
	if code != http.StatusAccepted || id == "" {
		t.Fatalf("add: %d %v", code, out)
	}
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-lab", "p-alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("rm: %d", rec.Code)
	}
	if s := bf.askNamed(t, id).State; s != asks.StateDenied {
		t.Errorf("ask is %q after rm of its binding, want denied", s)
	}
}

// TestRV4F4DecideOnGoneBinding: an approval of an ask whose binding is gone
// (rm's deny of it did not land) moves nothing: no binding comes back. The
// answer stands and is recorded (GAP-0903, GAP-0908).
func TestRV4F4DecideOnGoneBinding(t *testing.T) {
	bf := newBindingFixture(t, nil)
	_, out := bf.add(t, "p-alice", hardOutsideAdd)
	id, _ := out["ask_id"].(string)
	owner := render.PersonKey("alice")
	if err := bf.store.Update(context.Background(), func(d *secretbind.Doc) error {
		d.Bindings = slicesDeleteBinding(d.Bindings, owner, "gl-lab")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	code, out := bf.decide(t, "p-admin", id, "approve")
	if code != http.StatusOK {
		t.Fatalf("approve on a gone binding: %d %v, want 200", code, out)
	}
	if n := len(bf.store.ForOwner(owner)); n != 0 {
		t.Errorf("approve on a gone binding left %d bindings, want none", n)
	}
}

// TestRV4F6RejectedAddOpensNoAsk: a person at the limit opens no ask and
// writes no value on a retry (RV4 F6).
func TestRV4F6RejectedAddOpensNoAsk(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) { c.SelfService.MaxPerPerson = 1 })
	if code, _ := bf.add(t, "p-alice", hardOutsideAdd); code != http.StatusAccepted {
		t.Fatalf("first add: %d", code)
	}
	before, _ := bf.asks.List(context.Background(), asks.ListRequest{All: true})
	for i := 0; i < 5; i++ {
		code, out := bf.add(t, "p-alice", `{"name":"gl-two","template":"gitlab","host":"git2.lab.example","value":"w"}`)
		if code != http.StatusConflict || out["error"] != "secret_binding_limit" && out["reason"] != "secret_binding_limit" {
			t.Fatalf("over the limit: %d %v, want 409 secret_binding_limit", code, out)
		}
	}
	after, _ := bf.asks.List(context.Background(), asks.ListRequest{All: true})
	if len(after) != len(before) {
		t.Errorf("rejected adds opened %d asks", len(after)-len(before))
	}
}

// TestRV4F5ExpiredAskStaysListed pins the behaviour of an expired binding
// ask: nothing moves the binding, list says so, and rm then add works again.
func TestRV4F5ExpiredAskStaysListed(t *testing.T) {
	bf := newBindingFixture(t, nil)
	_, out := bf.add(t, "p-alice", hardOutsideAdd)
	id, _ := out["ask_id"].(string)
	bf.asks.CloseActor(bf.askNamed(t, id).UID, "actor_deleted", "test")
	if s := bf.listed(t, "p-alice")["gl-lab"]; s["status"] != "ask expired" {
		t.Fatalf("list: %v", s)
	}
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-lab", "p-alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("rm: %d", rec.Code)
	}
	if code, _ := bf.add(t, "p-alice", hardOutsideAdd); code != http.StatusAccepted {
		t.Errorf("re-add after rm: %d", code)
	}
}

// TestRV3P43TemplateFormChangeIsFlagged: an admin moves a template from
// bearer to basic after a value was stored; list flags the binding until
// the value is set again (RV3 P4-3).
func TestRV3P43TemplateFormChangeIsFlagged(t *testing.T) {
	live := config.SubstrateSelfServiceSecretsConfig{Mode: config.SelfServiceBindings}
	tmpl := []config.SubstrateSecretTemplate{{Name: "gitlab", Hosts: []string{"gitlab.com"}, Form: "bearer"}}
	bf := newBindingFixture(t, func(sc *SubstrateConfig) {
		sc.LiveSelfService = func() (config.SubstrateSelfServiceSecretsConfig, []config.SubstrateSecretTemplate) { return live, tmpl }
	})
	if code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	if s := bf.listed(t, "p-alice")["gl-work"]; s["status"] != "set" {
		t.Fatalf("before the edit: %v", s)
	}
	tmpl = []config.SubstrateSecretTemplate{{Name: "gitlab", Hosts: []string{"gitlab.com"}, Form: "basic", BasicUser: "oauth2"}}
	if s := bf.listed(t, "p-alice")["gl-work"]; s["status"] != "template changed" || s["reason"] != "secret_binding_form_changed" {
		t.Fatalf("after the edit: %v", s)
	}
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/gl-work", "p-alice", `{"value":"v2"}`); rec.Code != http.StatusOK {
		t.Fatalf("set: %d", rec.Code)
	}
	if s := bf.listed(t, "p-alice")["gl-work"]; s["status"] != "set" {
		t.Errorf("after the value was set again: %v", s)
	}
}
