// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// B1 S7: GET secrets?agent=NAME answers the usable secrets that reach the
// caller's agent NAME, each with the registry file it feeds at start. A
// binding added or removed shows on the next call, so the next run's
// files follow it with no template rebuild.
func TestB1S7SecretsForAgentRegistries(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) {
		c.SecretTemplates = append(c.SecretTemplates,
			config.SubstrateSecretTemplate{Name: "npm", Hosts: []string{"npm.corp.example"}},
			config.SubstrateSecretTemplate{Name: "pypi", Hosts: []string{"pypi.corp.example"}})
	})
	forAgent := func(agent string) (int, map[string]map[string]any) {
		t.Helper()
		rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secrets?agent="+agent, "p-alice", "")
		var list struct {
			Secrets []map[string]any `json:"secrets"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &list)
		out := map[string]map[string]any{}
		for _, s := range list.Secrets {
			out[s["name"].(string)] = s
		}
		return rec.Code, out
	}
	for _, body := range []string{
		`{"name":"npm-corp","template":"npm","host":"npm.corp.example","value":"v1"}`,
		`{"name":"py-corp","template":"pypi","host":"pypi.corp.example","value":"v2"}`,
		`{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v3"}`,
		`{"name":"gl-wait","template":"gitlab","host":"git.wait.example","value":"v4"}`,
	} {
		if code, out := bf.add(t, "p-alice", body); code != http.StatusCreated && code != http.StatusAccepted {
			t.Fatalf("add %s: %d %v", body, code, out)
		}
	}
	code, got := forAgent("alice-1")
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if got["npm-corp"]["registry"] != "npm" || got["py-corp"]["registry"] != "pypi" || got["gl-work"] == nil || got["gl-work"]["registry"] != nil {
		t.Errorf("registries: %v", got)
	}
	// Only what reaches the agent: not a waiting binding, not an admin
	// secret with no value.
	if got["gl-wait"] != nil || got["github-push"] != nil {
		t.Errorf("unusable secrets listed for the agent: %v", got)
	}
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/py-corp", "p-alice", ""); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("rm: %d %s", rec.Code, rec.Body.String())
	}
	if _, got = forAgent("alice-1"); got["py-corp"] != nil || got["npm-corp"] == nil {
		t.Errorf("after rm: %v", got)
	}
	if code, _ := forAgent("nobody-9"); code != http.StatusNotFound {
		t.Errorf("unknown agent: %d", code)
	}
}

// B1 S7: an administrator's entry in the Authorization header feeds the
// npmrc, as the template build's rule did (GAP-0529); its placeholder is
// passed, never a value. Another header feeds nothing.
func TestB1S7AdminSecretRegistry(t *testing.T) {
	for _, tc := range []struct {
		header, ph, want string
	}{{"authorization", "DC_SECRET_NPM", "npm"}, {"X-Api-Key", "", ""}} {
		v := map[string]any{}
		sec := config.SubstrateSecret{Name: "a"}
		sec.Inject.Header, sec.Inject.Placeholder = tc.header, tc.ph
		addSubstrateSecretRegistry(v, substrateSecretEntry{sec: sec}, nil)
		if r, _ := v["registry"].(string); r != tc.want || (tc.ph != "" && v["placeholder"] != tc.ph) {
			t.Errorf("%s: %v", tc.header, v)
		}
	}
}

// RV3 P4-3 (S7): the doctor flags a binding whose template form changed
// since its value was stored, and a new set clears it.
func TestB1S7BindingFormDoctor(t *testing.T) {
	bf := newBindingFixture(t, nil)
	if code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	if b := bf.binding(t, "alice", "gl-work"); b.StoredForm != "basic:oauth2" {
		t.Fatalf("form %q", b.StoredForm)
	}
	tpls := bf.api.substrateState().cfg.SecretTemplates
	if c := SubstrateSecretBindingFormCheck(bf.store, tpls); c.Status != "pass" {
		t.Fatalf("before: %+v", c)
	}
	i := slices.IndexFunc(tpls, func(t config.SubstrateSecretTemplate) bool { return t.Name == "gitlab" })
	tpls[i].BasicUser = "x-other"
	if c := SubstrateSecretBindingFormCheck(bf.store, tpls); c.Status != "warn" || !strings.Contains(c.Detail, "gl-work (gitlab: basic:oauth2 -> basic:x-other)") {
		t.Fatalf("after the edit: %+v", c)
	}
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/gl-work", "p-alice", `{"value":"v2"}`); rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	if c := SubstrateSecretBindingFormCheck(bf.store, tpls); c.Status != "pass" {
		t.Errorf("after set: %+v", c)
	}
	if c := SubstrateSecretBindingFormCheck(nil, nil); c.Status != "pass" {
		t.Errorf("off: %+v", c)
	}
}
