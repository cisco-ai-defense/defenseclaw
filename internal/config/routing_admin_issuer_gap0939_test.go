// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

// GAP-0939: with the Kubernetes sign-in off (identity.kube_sign_in false
// or the gateway's --no-kube-sign-in), no one signs in as a Kubernetes
// person, so kubernetes is not a trusted issuer: with no OIDC issuer and
// one workload issuer, that workload issuer is the only one.
func TestGAP0939KubeSignInOffDropsKubeIssuer(t *testing.T) {
	defer TurnOffKubeSignIn(false)
	const ci = "https://ci.example"
	cfg := &Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: ci}}
	cfg.Routing.Admin = &RoutingAdminConfig{Rules: []RoutingAdminRule{{ID: "r1", Match: RoutingAdminMatch{Users: []string{"alice"}}}}}
	if !cfg.SubstrateKubeSignIn() || !slices.Equal(cfg.PersonIssuers(), []string{SubstrateKubeIssuer, ci}) {
		t.Fatalf("sign-in on: %v %v", cfg.SubstrateKubeSignIn(), cfg.PersonIssuers())
	}
	if w := cfg.RoutingAdminIssuerWarnings(); len(w) != 1 || !strings.Contains(w[0], "primary issuer "+SubstrateKubeIssuer) {
		t.Fatalf("sign-in on: warnings %v", w)
	}
	off := false
	cfg.Substrate.Identity.KubeSignIn = &off
	if cfg.SubstrateKubeSignIn() || !slices.Equal(cfg.PersonIssuers(), []string{ci}) {
		t.Fatalf("kube_sign_in false: %v %v", cfg.SubstrateKubeSignIn(), cfg.PersonIssuers())
	}
	if w := cfg.RoutingAdminIssuerWarnings(); len(w) != 0 {
		t.Fatalf("kube_sign_in false: one issuer, no warning: %v", w)
	}
	on := true
	cfg.Substrate.Identity.KubeSignIn = &on
	if !slices.Equal(cfg.PersonIssuers(), []string{SubstrateKubeIssuer, ci}) {
		t.Fatalf("kube_sign_in true: %v", cfg.PersonIssuers())
	}
	// The flag: process-wide, so a reloaded configuration keeps it.
	TurnOffKubeSignIn(true)
	reloaded := *cfg
	if reloaded.SubstrateKubeSignIn() || !slices.Equal(reloaded.PersonIssuers(), []string{ci}) {
		t.Fatalf("--no-kube-sign-in: %v %v", reloaded.SubstrateKubeSignIn(), reloaded.PersonIssuers())
	}
	TurnOffKubeSignIn(false)
	// OIDC and managed installs never sign in with Kubernetes credentials.
	cfg.Substrate.Identity.KubeSignIn = nil
	cfg.DeploymentMode = "managed_enterprise"
	if cfg.SubstrateKubeSignIn() {
		t.Fatal("managed: kube sign-in on")
	}
	cfg.DeploymentMode = ""
	cfg.Substrate.Identity.OIDC.Issuer = "https://idp.example"
	if cfg.SubstrateKubeSignIn() {
		t.Fatal("oidc: kube sign-in on")
	}
}

// GAP-0939: substrate.identity.kube_sign_in is in the schema (a boolean)
// and loads.
func TestGAP0939KubeSignInLoads(t *testing.T) {
	for raw, want := range map[string]bool{"false": false, "true": true} {
		doc := []byte("config_version: 9\nsubstrate:\n  identity: {kube_sign_in: " + raw + "}\n")
		if err := ValidateV8SchemaBytes("kube.yaml", doc); err != nil {
			t.Fatalf("schema: kube_sign_in %s: %v", raw, err)
		}
		cfg, err := LoadRuntimeV8FromBytes("kube.yaml", doc)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Substrate.Identity.KubeSignIn; got == nil || *got != want {
			t.Fatalf("kube_sign_in: %s loaded as %v", raw, got)
		}
	}
	if err := ValidateV8SchemaBytes("kube.yaml", []byte("config_version: 9\nsubstrate: {identity: {kube_sign_in: off-ish}}\n")); err == nil {
		t.Fatal("schema accepted a string kube_sign_in")
	}
}
