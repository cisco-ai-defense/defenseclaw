// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0939 (RV6 K2): an OSS cluster with no OIDC issuer, one workload
// issuer, and the Kubernetes sign-in off. No one signs in as a Kubernetes
// person, so the workload issuer is the only trusted one and a bare users
// entry names the workload alice, as before GAP-0893. With the sign-in on,
// the Kubernetes alice is the one it names.
func TestGAP0939KubeSignInOffWorkloadMatchesBareName(t *testing.T) {
	defer config.UnpinKubeSignIn()
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.WorkloadOIDC = []config.SubstrateWorkloadOIDCConfig{{Issuer: gap0792IdpA}}
	kube := registry.Person{Kind: "user", Issuer: identity.KubeIssuer, Subject: "alice"}
	ci := registry.Person{Kind: "user", Issuer: gap0792IdpA, Subject: "alice"}
	bare := config.ProfileMatch{Users: []string{"alice"}}
	if got := gap0792Match(bare, ci, cfg.PersonIssuers()); got != engine.No {
		t.Fatalf("sign-in on: workload alice vs users:[alice]: %v", got)
	}
	if got := gap0792Match(bare, kube, cfg.PersonIssuers()); got != engine.Yes {
		t.Fatalf("sign-in on: kube alice vs users:[alice]: %v", got)
	}
	off := false
	cfg.Substrate.Identity.KubeSignIn = &off
	if got := gap0792Match(bare, ci, cfg.PersonIssuers()); got != engine.Yes {
		t.Fatalf("kube_sign_in false: workload alice vs users:[alice]: %v (issuers %v)", got, cfg.PersonIssuers())
	}
	cfg.Substrate.Identity.KubeSignIn = nil
	config.PinKubeSignIn(false) // the gateway booted with --no-kube-sign-in
	if got := gap0792Match(bare, ci, cfg.PersonIssuers()); got != engine.Yes {
		t.Fatalf("--no-kube-sign-in: workload alice vs users:[alice]: %v (issuers %v)", got, cfg.PersonIssuers())
	}
}

// GAP-0968: the gateway booted with the Kubernetes sign-in on, then a live
// reload sets kube_sign_in false. The verifiers are still the boot ones, so
// kube alice can still sign in: users:[alice] keeps naming her, not the
// workload alice, until a restart.
func TestGAP0968LiveKubeSignInEditKeepsBootIssuers(t *testing.T) {
	defer config.UnpinKubeSignIn()
	config.PinKubeSignIn(true) // booted with the sign-in on
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.WorkloadOIDC = []config.SubstrateWorkloadOIDCConfig{{Issuer: gap0792IdpA}}
	off := false
	cfg.Substrate.Identity.KubeSignIn = &off // the live reload
	kube := registry.Person{Kind: "user", Issuer: identity.KubeIssuer, Subject: "alice"}
	ci := registry.Person{Kind: "user", Issuer: gap0792IdpA, Subject: "alice"}
	bare := config.ProfileMatch{Users: []string{"alice"}}
	if got := gap0792Match(bare, kube, cfg.PersonIssuers()); got != engine.Yes {
		t.Fatalf("kube alice vs users:[alice] after a live edit: %v (issuers %v)", got, cfg.PersonIssuers())
	}
	if got := gap0792Match(bare, ci, cfg.PersonIssuers()); got != engine.No {
		t.Fatalf("workload alice vs users:[alice] after a live edit: %v (issuers %v)", got, cfg.PersonIssuers())
	}
}
