// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10 GAP-0568: a managed host with no enrolled route render says so
// instead of reporting route-only ready while nothing is routed.
func TestRouteOnlyReadinessReportsNoEnrolledRender(t *testing.T) {
	cfg := readinessConfig(config.RoutingUpstreamConfig{BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages})
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	var signers bedrockSigners
	if !cfg.StandaloneEnterprise() {
		t.Skip("fixture is not a standalone managed config on this platform")
	}
	count := 0
	enrolled := func(string) (int, bool) { return count, true }
	r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, enrolled))
	if r.Ready || r.EnrolledUsers == nil || *r.EnrolledUsers != 0 || !strings.Contains(r.Problem, "no enrolled account") {
		t.Fatalf("zero renders: %+v", r)
	}
	count = 2
	r = onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, enrolled))
	if !r.Ready || *r.EnrolledUsers != 2 || r.Problem != "" {
		t.Fatalf("two renders: %+v", r)
	}
	r = onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, func(string) (int, bool) { return 0, false }))
	if !r.Ready || r.EnrolledUsers != nil {
		t.Fatalf("an unbuilt index changes nothing: %+v", r)
	}
}
