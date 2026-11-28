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

// GAP-0893 (PROBE-K): an OSS cluster with no identity.oidc issuer signs
// people in with Kubernetes credentials. With two workload issuers, a bare
// users entry still names the Kubernetes-signed-in alice, not the
// workload alice.
func TestGAP0893KubePersonMatchesBareName(t *testing.T) {
	if config.SubstrateKubeIssuer != identity.KubeIssuer {
		t.Fatalf("config.SubstrateKubeIssuer %q != identity.KubeIssuer %q", config.SubstrateKubeIssuer, identity.KubeIssuer)
	}
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.WorkloadOIDC = []config.SubstrateWorkloadOIDCConfig{{Issuer: gap0792IdpA}, {Issuer: gap0792IdpB}}
	issuers := cfg.PersonIssuers()
	kube := registry.Person{Kind: "user", Issuer: identity.KubeIssuer, Subject: "alice"}
	ci := registry.Person{Kind: "user", Issuer: gap0792IdpA, Subject: "alice"}
	bare := config.ProfileMatch{Users: []string{"alice"}}
	if got := gap0792Match(bare, kube, issuers); got != engine.Yes {
		t.Fatalf("kube alice vs users:[alice]: %v", got)
	}
	if got := gap0792Match(bare, ci, issuers); got != engine.No {
		t.Fatalf("workload alice vs users:[alice]: %v", got)
	}
}
