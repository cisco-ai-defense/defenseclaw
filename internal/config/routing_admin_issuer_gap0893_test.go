// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

// GAP-0893: with no identity.oidc issuer, an install that is not managed
// signs people in with Kubernetes credentials, so the Kubernetes issuer is
// the primary person issuer (and counts toward the two-issuer warning).
func TestGAP0893KubeIssuerIsPrimary(t *testing.T) {
	const ciA, ciB = "https://ci-a.example", "https://ci-b.example"
	cfg := &Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: ciA}, {Issuer: ciB}}
	if got := cfg.PersonIssuers(); !slices.Equal(got, []string{SubstrateKubeIssuer, ciA, ciB}) {
		t.Fatalf("OSS, no oidc: issuers %v", got)
	}
	cfg.Routing.Admin = &RoutingAdminConfig{Rules: []RoutingAdminRule{{ID: "r1", Match: RoutingAdminMatch{Users: []string{"alice"}}}}}
	if w := cfg.RoutingAdminIssuerWarnings(); len(w) != 1 || !strings.Contains(w[0], "primary issuer "+SubstrateKubeIssuer) {
		t.Fatalf("warning names the primary issuer: %v", w)
	}
	cfg.DeploymentMode = "managed_enterprise"
	if got := cfg.PersonIssuers(); !slices.Equal(got, []string{ciA, ciB}) {
		t.Fatalf("managed: issuers %v", got)
	}
	cfg.DeploymentMode = ""
	cfg.Substrate.Identity.OIDC.Issuer = "https://idp.example"
	if got := cfg.PersonIssuers(); !slices.Equal(got, []string{"https://idp.example", ciA, ciB}) {
		t.Fatalf("oidc: issuers %v", got)
	}
}

// GAP-0895: a qualified entry whose issuer is not trusted exactly as
// written names no one: config load warns.
func TestGAP0895UnknownIssuerWarns(t *testing.T) {
	const idp = "https://idp-b.example"
	cfg := &Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.OIDC.Issuer = idp
	cfg.Routing.Admin = &RoutingAdminConfig{
		Rules: []RoutingAdminRule{{ID: "r1", Match: RoutingAdminMatch{Users: []string{
			idp + "#alice", idp + "/#slash", "https://IDP-b.example#case"}}}},
		Budgets: []RoutingBudget{{ID: "b1", Scope: "user", Subject: "https://idp-x.example#bob"}},
	}
	w := cfg.RoutingAdminIssuerWarnings()
	if len(w) != 3 {
		t.Fatalf("warnings %v", w)
	}
	for i := range w {
		if !strings.Contains(w[i], "routing_admin_unknown_issuer") {
			t.Errorf("warning %d: %s", i, w[i])
		}
	}
	if !strings.Contains(w[0], idp+"/") || !strings.Contains(w[1], "IDP-b") || !strings.Contains(w[2], "budget b1") {
		t.Fatalf("warnings %v", w)
	}
	// The scheme is case-sensitive, as in the Python mirror: HTTPS:// is a
	// bare name.
	if _, _, ok := SplitQualifiedUser("HTTPS://idp-b.example#alice"); ok {
		t.Fatal("HTTPS:// split as qualified")
	}
}
