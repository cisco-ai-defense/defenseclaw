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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// memBindings is the binding ConfigMap; failPut makes every write fail.
type memBindings struct {
	mu      sync.Mutex
	raw     []byte
	ver     int
	failPut bool
}

func (m *memBindings) Get(context.Context) ([]byte, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.raw...), strconv.Itoa(m.ver), m.raw != nil, nil
}

func (m *memBindings) Put(_ context.Context, raw []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return errors.New("configmap write refused")
	}
	m.raw, m.ver = append([]byte(nil), raw...), m.ver+1
	return nil
}

type bindingFixture struct {
	*substrateFixture
	values *memSecrets
	cm     *memBindings
	store  *secretbind.Store
	asks   *asks.Store
	audits []audit.SubstrateSecretChangeEvent
}

func newBindingFixture(t *testing.T, edit func(*SubstrateConfig)) *bindingFixture {
	t.Helper()
	bf := &bindingFixture{values: &memSecrets{m: map[string][]byte{}}, cm: &memBindings{}, asks: asks.NewMemory()}
	bf.store = secretbind.New(bf.cm)
	bf.substrateFixture = newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.SecretStore = bf.values
		c.Bindings = bf.store
		c.Asks = asksDirect{bf.asks}
		c.SecretAudit = func(_ context.Context, ev audit.SubstrateSecretChangeEvent) { bf.audits = append(bf.audits, ev) }
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
		c.Secrets = []config.SubstrateSecret{
			{Name: "github-push", Source: "ate-secret://k8s.io/default/dc-secrets/github/token",
				Inject: config.SubstrateSecretInject{Hosts: []string{"github.com"}, Header: "Authorization"}, Profiles: []string{"eng"}},
		}
		c.SecretTemplates = []config.SubstrateSecretTemplate{
			{Name: "gitlab", Hosts: []string{"*.corp.example", "gitlab.com"}},
			{Name: "generic-bearer"},
			{Name: "ops-only", Hosts: []string{"ops.example.com"}, Profiles: []string{"ops"}},
		}
		if edit != nil {
			edit(c)
		}
	})
	return bf
}

func (bf *bindingFixture) add(t *testing.T, tok, body string) (int, map[string]any) {
	t.Helper()
	rec := bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/secrets", tok, body)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestB1BindingAdd(t *testing.T) {
	bf := newBindingFixture(t, nil)
	alice := render.PersonKey("alice")
	vname := "defenseclaw-user-secrets/" + secretbind.ValueSecretName(alice) + "/"

	code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"Git.Corp.Example","value":"glpat-1"}`)
	if code != http.StatusCreated || out["status"] != "set" || out["host"] != "git.corp.example" {
		t.Fatalf("add inside template: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if string(bf.values.m[vname+id]) != basicForm("oauth2", "glpat-1") {
		t.Fatalf("value not under %s%s: %v", vname, id, bf.values.m)
	}
	if bs := bf.store.ForOwner(alice); len(bs) != 1 || bs[0].State != secretbind.Active {
		t.Fatalf("store after add: %+v", bs)
	}
	if strings.Contains(string(bf.cm.raw), "glpat-1") {
		t.Fatal("value written into the binding ConfigMap")
	}

	code, out = bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"glpat-2"}`)
	if code != http.StatusAccepted || out["reason"] != "secret_binding_outside_templates" || out["status"] != "waiting on admin" {
		t.Fatalf("add outside template: %d %v", code, out)
	}
	for _, b := range bf.store.ForOwner(alice) {
		if b.Name == "gl-lab" && b.State != secretbind.Waiting {
			t.Fatalf("outside binding state %s", b.State)
		}
	}

	for _, c := range []struct {
		name, body string
		code       int
		reason     string
	}{
		{"name taken vs admin", `{"name":"github-push","template":"gitlab","host":"gitlab.com","value":"v"}`, 409, "secret_name_taken"},
		{"name taken vs own", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v"}`, 409, "secret_name_taken"},
		{"echo host", `{"name":"e1","template":"generic-bearer","host":"httpbin.org","value":"v"}`, 403, "secret_echo_host"},
		// RV3 P2-1: request bins sit two labels under a listed entry.
		{"echo host two labels deep", `{"name":"e3","template":"generic-bearer","host":"eo123.m.pipedream.net","value":"v"}`, 403, "secret_echo_host"},
		{"echo wildcard two labels deep", `{"name":"e4","template":"generic-bearer","host":"*.free.beeceptor.com","value":"v"}`, 403, "secret_echo_host"},
		{"echo host, allow_echo without the admin switch", `{"name":"e2","template":"generic-bearer","host":"httpbin.org","value":"v","allow_echo":true}`, 403, "secret_echo_host"},
		{"unknown template", `{"name":"x1","template":"nope","host":"gitlab.com","value":"v"}`, 400, "secret_template_unknown"},
		{"template of another profile", `{"name":"x2","template":"ops-only","host":"ops.example.com","value":"v"}`, 400, "secret_template_unknown"},
		{"any host", `{"name":"x3","template":"gitlab","host":"*","value":"v"}`, 400, "invalid_pattern"},
		{"empty value", `{"name":"x4","template":"gitlab","host":"gitlab.com","value":""}`, 400, "value_required"},
		{"user on a bearer template", `{"name":"x6","template":"generic-bearer","host":"api.example.com","value":"v","user":"me"}`, 400, "secret_invalid"},
		{"expiry past 400 days", `{"name":"x5","template":"gitlab","host":"gitlab.com","value":"v","expires":"2099-01-01T00:00:00Z"}`, 400, "secret_invalid"},
	} {
		if code, out := bf.add(t, "p-alice", c.body); code != c.code || out["reason"] != c.reason {
			t.Errorf("%s: %d %v, want %d %s", c.name, code, out, c.code, c.reason)
		}
	}
	// Bob may reuse alice's name: names are per person.
	if code, out := bf.add(t, "p-bob", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"b"}`); code != http.StatusCreated {
		t.Fatalf("bob same name: %d %v", code, out)
	}
	if len(bf.values.m) != 3 {
		t.Fatalf("a refused add left a value behind: %v", bf.values.m)
	}
	var added int
	for _, ev := range bf.audits {
		if ev.Operation == audit.SubstrateSecretBindingAdded && !ev.Failed {
			added++
		}
	}
	if added != 3 {
		t.Fatalf("binding_added audit records %d, want 3: %+v", added, bf.audits)
	}
}

func TestB1BindingAddLimitAndRollback(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) { c.SelfService.MaxPerPerson = 1 })
	if code, out := bf.add(t, "p-alice", `{"name":"a","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("first add: %d %v", code, out)
	}
	if code, out := bf.add(t, "p-alice", `{"name":"b","template":"gitlab","host":"gitlab.com","value":"v2"}`); code != http.StatusConflict || out["reason"] != "secret_binding_limit" {
		t.Fatalf("over the limit: %d %v", code, out)
	}
	if len(bf.values.m) != 1 {
		t.Fatalf("value of the refused binding not removed: %v", bf.values.m)
	}
	bf.cm.failPut = true
	if code, out := bf.add(t, "p-bob", `{"name":"c","template":"gitlab","host":"gitlab.com","value":"v3"}`); code != http.StatusBadGateway || out["reason"] != "secret_not_stored" {
		t.Fatalf("store write fails: %d %v", code, out)
	}
	if len(bf.values.m) != 1 {
		t.Fatalf("value kept after the binding write failed: %v", bf.values.m)
	}
	last := bf.audits[len(bf.audits)-1]
	if last.Operation != audit.SubstrateSecretBindingAdded || !last.Failed {
		t.Fatalf("failed add audit: %+v", last)
	}
}

func TestB1BindingModes(t *testing.T) {
	for _, c := range []struct {
		mode        string
		addCode     int
		addReason   string
		templatesOK bool
	}{
		{config.SelfServiceOff, 404, "secret_bindings_off", false},
		{config.SelfServiceValuesOnly, 403, "secret_bindings_locked", true},
	} {
		bf := newBindingFixture(t, func(sc *SubstrateConfig) { sc.SelfService.Mode = c.mode })
		if code, out := bf.add(t, "p-alice", `{"name":"a","template":"gitlab","host":"gitlab.com","value":"v"}`); code != c.addCode || out["reason"] != c.addReason {
			t.Errorf("%s add: %d %v", c.mode, code, out)
		}
		rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secret-templates", "p-alice", "")
		if (rec.Code == 200) != c.templatesOK {
			t.Errorf("%s templates: %d", c.mode, rec.Code)
		}
		if len(bf.values.m) != 0 {
			t.Errorf("%s: value stored %v", c.mode, bf.values.m)
		}
	}
	// No store at all (an old chart) reads as off.
	bf := newBindingFixture(t, func(sc *SubstrateConfig) { sc.Bindings = nil })
	if code, out := bf.add(t, "p-alice", `{"name":"a","template":"gitlab","host":"gitlab.com","value":"v"}`); code != 404 || out["reason"] != "secret_bindings_off" {
		t.Fatalf("no store: %d %v", code, out)
	}
}

func TestB1BindingTemplatesByProfile(t *testing.T) {
	bf := newBindingFixture(t, nil)
	names := func(tok string) string {
		rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secret-templates", tok, "")
		var out struct {
			Templates []secretbind.Template `json:"templates"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		var n []string
		for _, tp := range out.Templates {
			n = append(n, tp.Name)
		}
		return strings.Join(n, ",")
	}
	if got := names("p-alice"); got != "gitlab,generic-bearer" {
		t.Fatalf("alice (eng-web) sees %q", got)
	}
	if got := names("p-admin"); got != "gitlab,generic-bearer,ops-only" {
		t.Fatalf("admin sees %q", got)
	}
}

// An own binding is a secret its owner can list, set, test and remove,
// and no other person can see or touch.
func TestB1BindingOwnSetListRemove(t *testing.T) {
	bf := newBindingFixture(t, nil)
	alice := render.PersonKey("alice")
	_, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`)
	id, _ := out["id"].(string)
	key := "defenseclaw-user-secrets/" + secretbind.ValueSecretName(alice) + "/" + id

	mine := func(tok string) []map[string]any {
		rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secrets?mine=1", tok, "")
		var o struct {
			Secrets []map[string]any `json:"secrets"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &o)
		return o.Secrets
	}
	if got := mine("p-alice"); len(got) != 1 || got[0]["name"] != "gl-work" || got[0]["status"] != "set" {
		t.Fatalf("alice mine: %v", got)
	}
	if got := mine("p-bob"); len(got) != 0 {
		t.Fatalf("bob sees alice's binding: %v", got)
	}
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/gl-work", "p-alice", `{"value":"v2"}`); rec.Code != 200 || string(bf.values.m[key]) != basicForm("oauth2", "v2") {
		t.Fatalf("set own binding: %d %s %v", rec.Code, rec.Body, bf.values.m)
	}
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/gl-work", "p-bob", `{"value":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("bob set alice's binding: %d %s", rec.Code, rec.Body)
	}
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-work", "p-bob", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("bob rm alice's binding: %d %s", rec.Code, rec.Body)
	}
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-work", "p-alice", ""); rec.Code != 200 {
		t.Fatalf("rm own binding: %d %s", rec.Code, rec.Body)
	}
	if _, ok := bf.values.m[key]; ok || len(bf.store.ForOwner(alice)) != 0 {
		t.Fatalf("rm left value %v or binding %+v", bf.values.m, bf.store.ForOwner(alice))
	}
}

func basicForm(user, token string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
}

// TestB1BindingBasicStoredForm: a basic-form binding stores
// base64(user:token) on add and on every later set, so the header
// Substrate injects ("Basic " + value) stays valid after a re-set. The CLI
// sends only the plain token.
func TestB1BindingBasicStoredForm(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) {
		c.SecretTemplates = append(c.SecretTemplates, config.SubstrateSecretTemplate{Name: "generic-basic"})
	})
	alice := render.PersonKey("alice")
	key := func(id string) string {
		return "defenseclaw-user-secrets/" + secretbind.ValueSecretName(alice) + "/" + id
	}
	set := func(name, value string) {
		t.Helper()
		if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/"+name, "p-alice", `{"value":"`+value+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("set %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	add := func(body string) string {
		t.Helper()
		code, out := bf.add(t, "p-alice", body)
		if code != http.StatusCreated && code != http.StatusAccepted { // generic-basic has no hosts: waiting
			t.Fatalf("add %s: %d %v", body, code, out)
		}
		id, _ := out["id"].(string)
		return id
	}

	// Template user (gitlab: oauth2).
	gl := add(`{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"glpat-1"}`)
	if got := string(bf.values.m[key(gl)]); got != basicForm("oauth2", "glpat-1") {
		t.Fatalf("gitlab add stored %q", got)
	}
	set("gl-work", "glpat-2")
	if got := string(bf.values.m[key(gl)]); got != basicForm("oauth2", "glpat-2") {
		t.Fatalf("gitlab re-set stored %q, want base64(oauth2:glpat-2)", got)
	}
	tl, _ := secretbind.Find(secretbind.Catalog([]config.SubstrateSecretTemplate{{Name: "gitlab"}}), "gitlab")
	if p := tl.Prefix(); p != "Basic " {
		t.Fatalf("gitlab prefix %q", p)
	}

	// generic-basic takes the user at add and keeps it on the binding.
	gb := add(`{"name":"nexus","template":"generic-basic","host":"nexus.corp.example","value":"tok-1","user":"svc-ci"}`)
	set("nexus", "tok-2")
	if got := string(bf.values.m[key(gb)]); got != basicForm("svc-ci", "tok-2") {
		t.Fatalf("generic-basic re-set stored %q, want base64(svc-ci:tok-2)", got)
	}
	if !strings.Contains(string(bf.cm.raw), `"basic_user":"svc-ci"`) || strings.Contains(string(bf.cm.raw), "tok-") {
		t.Fatalf("binding ConfigMap: %s", bf.cm.raw)
	}

	// A bearer binding stores the token as given.
	br := add(`{"name":"api","template":"generic-bearer","host":"api.corp.example","value":"b-1"}`)
	set("api", "b-2")
	if got := string(bf.values.m[key(br)]); got != "b-2" {
		t.Fatalf("bearer re-set stored %q", got)
	}

	for _, c := range []struct{ name, body string }{
		{"generic-basic without a user", `{"name":"g1","template":"generic-basic","host":"a.corp.example","value":"v"}`},
		{"user with a colon", `{"name":"g2","template":"generic-basic","host":"a.corp.example","value":"v","user":"a:b"}`},
		{"user with a space", `{"name":"g3","template":"generic-basic","host":"a.corp.example","value":"v","user":"a b"}`},
	} {
		if code, out := bf.add(t, "p-alice", c.body); code != http.StatusBadRequest || out["reason"] != "secret_invalid" {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if len(bf.values.m) != 3 {
		t.Fatalf("a refused add left a value behind: %v", bf.values.m)
	}
}
