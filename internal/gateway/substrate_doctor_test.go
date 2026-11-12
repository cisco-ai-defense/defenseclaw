// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// GAP-0040: a VPC endpoint makes the provider host resolve to private
// addresses; the check names the ones to list.
func TestSubstrateUpstreamCheck(t *testing.T) {
	providers := DefaultSubstrateLLMProviders(t.TempDir(), "us-east-1")
	lookup := func(private map[string][]string) SubstrateResolver {
		return func(_ context.Context, host string) ([]string, error) {
			if a, ok := private[host]; ok {
				return a, nil
			}
			if host == "generativelanguage.googleapis.com" {
				return nil, errors.New("no such host")
			}
			return []string{"203.0.113.10"}, nil
		}
	}
	vpce := map[string][]string{"bedrock-runtime.us-east-1.amazonaws.com": {"10.0.4.17", "10.0.5.23"}}
	c := SubstrateUpstreamCheck(context.Background(), providers, nil, lookup(vpce))
	if c.Status != "fail" || !strings.Contains(c.Fix, "10.0.4.17, 10.0.5.23") || !strings.Contains(c.Detail, "bedrock") {
		t.Fatalf("vpc endpoint %+v", c)
	}
	c = SubstrateUpstreamCheck(context.Background(), providers, []string{"10.0.4.17", "10.0.5.23"}, lookup(vpce))
	if c.Status != "warn" { // gemini does not resolve in this fake
		t.Fatalf("allowed endpoint %+v", c)
	}
	delete(providers, "gemini")
	if c := SubstrateUpstreamCheck(context.Background(), providers, nil, lookup(nil)); c.Status != "pass" {
		t.Fatalf("public %+v", c)
	}
}

func TestSubstrateDoctorAndInfoRoutes(t *testing.T) {
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Doctor = func(context.Context) []SubstrateCheck { return []SubstrateCheck{{ID: "x", Status: "pass"}} }
		c.Info = map[string]any{"sign_in": "oidc", "issuer": "https://idp.example", "client_id": "defenseclaw-launcher"}
	})
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/doctor", "p-alice", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("person doctor %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/doctor", "p-admin", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"x"`) {
		t.Fatalf("admin doctor %d %s", rec.Code, rec.Body)
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "defenseclaw-launcher") || !strings.Contains(rec.Body.String(), `"attach":false`) {
		t.Fatalf("info %d %s", rec.Code, rec.Body)
	}
}
