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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

func (bf *bindingFixture) binding(t *testing.T, owner, name string) secretbind.Binding {
	t.Helper()
	for _, b := range bf.store.ForOwner(render.PersonKey(owner)) {
		if b.Name == name {
			return b
		}
	}
	t.Fatalf("no binding %s of %s", name, owner)
	return secretbind.Binding{}
}

func (bf *bindingFixture) decide(t *testing.T, tok, id, decision string) (int, map[string]any) {
	t.Helper()
	rec := bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/asks/"+id, tok, `{"decision":"`+decision+`"}`)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (bf *bindingFixture) audited(op audit.SubstrateSecretOperation, name string) bool {
	for _, ev := range bf.audits {
		if ev.Operation == op && ev.Name == name && !ev.Failed {
			return true
		}
	}
	return false
}

// TestB1BindingOutsideAsksAdmin: a host outside every template opens an
// administrator ask (ask_id in the 202); only an administrator answers it;
// approve makes the binding active, deny makes it denied, each audited.
func TestB1BindingOutsideAsksAdmin(t *testing.T) {
	bf := newBindingFixture(t, nil)
	code, out := bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v1"}`)
	id, _ := out["ask_id"].(string)
	if code != http.StatusAccepted || id == "" {
		t.Fatalf("outside add: %d %v", code, out)
	}
	list, _ := bf.asks.List(t.Context(), asks.ListRequest{All: true})
	if len(list) != 1 || list[0].Kind != asks.KindSecretBinding || list[0].Host != "git.lab.example" || list[0].Tool != "gl-lab" ||
		list[0].Expires.Sub(list[0].Created) != 72*time.Hour {
		t.Fatalf("ask %+v", list)
	}
	if b := bf.binding(t, "alice", "gl-lab"); b.AskID != id || b.State != secretbind.Waiting || list[0].BindingID() != b.ID {
		t.Fatalf("binding %+v ask %s", b, id)
	}
	if code, out := bf.decide(t, "p-alice", id, "approve"); code != http.StatusForbidden || out["reason"] != "ask_admin_only" {
		t.Fatalf("alice approves her own binding ask: %d %v", code, out)
	}
	if code, out := bf.decide(t, "p-admin", id, "approve"); code != http.StatusOK || out["state"] != "approved" {
		t.Fatalf("admin approve: %d %v", code, out)
	}
	if b := bf.binding(t, "alice", "gl-lab"); b.State != secretbind.Active || !bf.audited(audit.SubstrateSecretBindingApproved, "gl-lab") {
		t.Fatalf("after approve: %+v audits %+v", b, bf.audits)
	}

	_, out = bf.add(t, "p-alice", `{"name":"gl-other","template":"gitlab","host":"git.other.example","value":"v2"}`)
	id, _ = out["ask_id"].(string)
	if code, _ := bf.decide(t, "p-admin", id, "deny"); code != http.StatusOK {
		t.Fatalf("admin deny: %d", code)
	}
	if b := bf.binding(t, "alice", "gl-other"); b.State != secretbind.Denied || !bf.audited(audit.SubstrateSecretBindingDenied, "gl-other") {
		t.Fatalf("after deny: %+v", b)
	}
	// A binding inside a template opens no ask.
	if _, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v3"}`); out["ask_id"] != nil {
		t.Fatalf("inside add asked: %v", out)
	}
	if list, _ := bf.asks.List(t.Context(), asks.ListRequest{All: true}); len(list) != 2 {
		t.Fatalf("asks %d, want 2", len(list))
	}
}

// TestB1BindingOutsideRefuseAndNoAsks: outside_templates: refuse refuses
// the host up front; with no ask store the add fails; neither stores a value.
func TestB1BindingOutsideRefuseAndNoAsks(t *testing.T) {
	for _, c := range []struct {
		name   string
		edit   func(*SubstrateConfig)
		code   int
		reason string
	}{
		{"refuse", func(sc *SubstrateConfig) { sc.SelfService.OutsideTemplates = "refuse" }, 403, "secret_binding_outside_refused"},
		{"no ask store", func(sc *SubstrateConfig) { sc.Asks = nil }, 503, "secret_store_unavailable"},
	} {
		bf := newBindingFixture(t, c.edit)
		if code, out := bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v"}`); code != c.code || out["reason"] != c.reason {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
		if len(bf.values.m) != 0 || len(bf.store.ForOwner(render.PersonKey("alice"))) != 0 {
			t.Errorf("%s: stored %v", c.name, bf.values.m)
		}
		// Inside a template still works.
		if code, _ := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v"}`); code != http.StatusCreated {
			t.Errorf("%s: inside add %d", c.name, code)
		}
	}
}

// TestB1BindingModeIsLive: the gateway follows the live self-service
// config (mode, templates) without a restart, but keeps the boot
// namespace for values.
func TestB1BindingModeIsLive(t *testing.T) {
	live := config.SubstrateSelfServiceSecretsConfig{Mode: config.SelfServiceValuesOnly, Namespace: "elsewhere"}
	var tmpl []config.SubstrateSecretTemplate
	bf := newBindingFixture(t, func(sc *SubstrateConfig) {
		tmpl = sc.SecretTemplates
		sc.LiveSelfService = func() (config.SubstrateSelfServiceSecretsConfig, []config.SubstrateSecretTemplate) {
			return live, tmpl
		}
	})
	if code, out := bf.add(t, "p-alice", `{"name":"a","template":"gitlab","host":"gitlab.com","value":"v"}`); code != 403 || out["reason"] != "secret_bindings_locked" {
		t.Fatalf("live values_only: %d %v", code, out)
	}
	live.Mode = config.SelfServiceBindings
	if code, out := bf.add(t, "p-alice", `{"name":"a","template":"gitlab","host":"gitlab.com","value":"v"}`); code != http.StatusCreated {
		t.Fatalf("live bindings: %d %v", code, out)
	}
	b := bf.binding(t, "alice", "a")
	if _, ok := bf.values.m["defenseclaw-user-secrets/"+secretbind.ValueSecretName(render.PersonKey("alice"))+"/"+b.ID]; !ok {
		t.Fatalf("value not in the boot namespace: %v", bf.values.m)
	}
	live.Mode = config.SelfServiceOff
	if code, out := bf.add(t, "p-alice", `{"name":"b","template":"gitlab","host":"gitlab.com","value":"v"}`); code != 404 || out["reason"] != "secret_bindings_off" {
		t.Fatalf("live off: %d %v", code, out)
	}
}
