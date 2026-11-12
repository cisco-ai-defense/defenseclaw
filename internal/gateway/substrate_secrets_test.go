// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

type memSecrets struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memSecrets) Set(_ context.Context, ns, name, key string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ns+"/"+name+"/"+key] = v
	return nil
}

func (s *memSecrets) Remove(_ context.Context, ns, name, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, ns+"/"+name+"/"+key)
	return nil
}

func (s *memSecrets) Exists(_ context.Context, ns, name, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m[ns+"/"+name+"/"+key]) > 0, nil
}

// PLAN 7.2: names only, never a value; a person sets only their own
// per_person value; a shared secret is an administrator's.
func TestSubstrateSecretsAPI(t *testing.T) {
	store := &memSecrets{m: map[string][]byte{}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.SecretStore = store
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
		c.Secrets = []config.SubstrateSecret{
			{Name: "npm-token", Source: "ate-secret://k8s.io/default/dc-people/{person}-npm/token", Scope: "per_person",
				Inject: config.SubstrateSecretInject{Hosts: []string{"registry.npmjs.org"}, Header: "Authorization"}, Profiles: []string{"eng*"}},
			{Name: "github-push", Source: "ate-secret://k8s.io/default/dc-secrets/github/token",
				Inject: config.SubstrateSecretInject{Hosts: []string{"github.com"}, Header: "Authorization"}, Profiles: []string{"eng"}},
			{Name: "vault-thing", Source: "ate-secret://vault.example/kv/team/x", Scope: "per_person",
				Inject: config.SubstrateSecretInject{Hosts: []string{"api.example.com"}, Header: "Authorization"}, Profiles: []string{"eng"}},
			{Name: "ops-only", Source: "ate-secret://k8s.io/default/dc-secrets/ops/token",
				Inject: config.SubstrateSecretInject{Hosts: []string{"ops.example.com"}, Header: "Authorization"}, Profiles: []string{"ops"}},
		}
	})
	list := func(tok, q string) []map[string]any {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/secrets"+q, tok, "")
		var out struct {
			Secrets []map[string]any `json:"secrets"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Secrets
	}
	if got := list("p-alice", ""); len(got) != 3 {
		t.Fatalf("alice sees %v", got)
	}
	if got := list("p-alice", "?mine=1"); len(got) != 0 {
		t.Fatalf("mine before set %v", got)
	}
	rec := f.do(t, f.admin, http.MethodPut, "/api/v1/substrate/secrets/npm-token", "p-alice", `{"value":"npm_value_123"}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "npm_value_123") {
		t.Fatalf("set %d %s", rec.Code, rec.Body)
	}
	key := "dc-people/" + render.PersonKey("alice") + "-npm/token"
	if string(store.m[key]) != "npm_value_123" {
		t.Fatalf("stored under %v", store.m)
	}
	if got := list("p-alice", "?mine=1"); len(got) != 1 || got[0]["status"] != "set" {
		t.Fatalf("mine after set %v", got)
	}
	// bob's value is his own: alice's is not set for him.
	for _, s := range list("p-bob", "") {
		if s["name"] == "npm-token" && s["status"] != "not set" {
			t.Fatalf("bob sees alice's value as set: %v", s)
		}
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/secrets/npm-token/test", "p-alice", `{}`); !strings.Contains(rec.Body.String(), `"set"`) ||
		strings.Contains(rec.Body.String(), "npm_value_123") {
		t.Fatalf("test %s", rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPut, "/api/v1/substrate/secrets/github-push", "p-alice", `{"value":"x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("person sets a shared secret: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPut, "/api/v1/substrate/secrets/github-push", "p-admin", `{"value":"ghp_x"}`); rec.Code != 200 {
		t.Fatalf("admin sets a shared secret: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPut, "/api/v1/substrate/secrets/vault-thing", "p-alice", `{"value":"x"}`); rec.Code != http.StatusConflict {
		t.Fatalf("vault source %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPut, "/api/v1/substrate/secrets/ops-only", "p-alice", `{"value":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("another profile's secret %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/secrets/npm-token", "p-alice", ""); rec.Code != 200 || len(store.m[key]) != 0 {
		t.Fatalf("remove %d %v", rec.Code, store.m)
	}
	// The value never appears in any answer.
	for _, s := range list("p-admin", "") {
		raw, _ := json.Marshal(s)
		if strings.Contains(string(raw), "ghp_x") {
			t.Fatalf("value in the list: %s", raw)
		}
	}
}
