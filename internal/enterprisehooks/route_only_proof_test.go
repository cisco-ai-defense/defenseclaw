// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1975: the proof the guardian records for a route-only render it read
// back names that exact render (endpoint, flags, route credential) and never
// carries the credential; no render and an underivable one have none.
func TestRouteOnlyProofBindsTheExactRender(t *testing.T) {
	if RouteOnlyProof(nil) != "" {
		t.Fatal("no render has a proof")
	}
	if RouteOnlyProof(&connector.RouteOnlySetup{Unavailable: "no epoch"}) != "" {
		t.Fatal("a render whose credential cannot be derived has a proof")
	}
	base := connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-secret-token", Custody: true}
	proof := RouteOnlyProof(&base)
	if !strings.HasPrefix(proof, routeOnlyProofPrefix) || len(proof) != len(routeOnlyProofPrefix)+64 {
		t.Fatalf("proof = %q", proof)
	}
	if strings.Contains(proof, base.Token) {
		t.Fatal("the proof carries the route credential")
	}
	again := base
	if RouteOnlyProof(&again) != proof {
		t.Fatal("the same render has another proof")
	}
	for name, change := range map[string]func(*connector.RouteOnlySetup){
		"endpoint":   func(r *connector.RouteOnlySetup) { r.BaseURL = "http://127.0.0.1:18971/r/codex" },
		"credential": func(r *connector.RouteOnlySetup) { r.Token = "dcr1-rotated-epoch" },
		"bedrock":    func(r *connector.RouteOnlySetup) { r.Bedrock = true },
		"signing":    func(r *connector.RouteOnlySetup) { r.GatewaySigning = true },
		"custody":    func(r *connector.RouteOnlySetup) { r.Custody = false },
	} {
		other := base
		change(&other)
		if RouteOnlyProof(&other) == proof {
			t.Errorf("%s: another render has the same proof", name)
		}
	}
}
