// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// notOwnedSecrets is a store whose Secret exists but is not DefenseClaw's.
type notOwnedSecrets struct{ memSecrets }

func (s *notOwnedSecrets) Set(context.Context, string, string, string, []byte) error {
	return fmt.Errorf("secret dc-people/x: %w", ErrSubstrateSecretNotOwned)
}

func (s *notOwnedSecrets) Remove(context.Context, string, string, string) error {
	return fmt.Errorf("secret dc-people/x: %w", ErrSubstrateSecretNotOwned)
}

// GAP-0183: a Secret of the source's name that DefenseClaw did not create
// is not changed, and the answer says so (409), not a store outage (502).
func TestGAP0183SecretNotOwnedIsAConflict(t *testing.T) {
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.SecretStore = &notOwnedSecrets{memSecrets{m: map[string][]byte{}}}
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
		c.Secrets = []config.SubstrateSecret{{Name: "npm-token", Source: "ate-secret://k8s.io/default/dc-people/{person}-npm/token", Scope: "per_person",
			Inject: config.SubstrateSecretInject{Hosts: []string{"registry.npmjs.org"}, Header: "Authorization"}, Profiles: []string{"eng*"}}}
	})
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		rec := f.do(t, f.admin, m, "/api/v1/substrate/secrets/npm-token", "p-alice", `{"value":"npm_value_123"}`)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "secret_not_managed_by_defenseclaw") || strings.Contains(rec.Body.String(), "npm_value_123") {
			t.Fatalf("%s: %d %s", m, rec.Code, rec.Body)
		}
	}
}
