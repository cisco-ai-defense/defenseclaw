// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestRouteOnlySetupForRendersGatewaySigning(t *testing.T) {
	dir := isolateAWSEnv(t)
	if err := os.WriteFile(filepath.Join(dir, "credentials"), []byte("[dc-route]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = profile-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(b *config.RoutingBedrockAuthConfig) *config.Config {
		cfg := &config.Config{DataDir: t.TempDir()}
		cfg.Guardrail.Connector = "claudecode"
		cfg.Routing = config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierRules, RouteOnly: config.RoutingRouteOnlyConfig{
			Connectors: []string{"claudecode"},
			Upstreams:  map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", API: config.RoutingAPIInvoke, Bedrock: b}},
		}}
		return cfg
	}
	for name, tc := range map[string]struct {
		block            *config.RoutingBedrockAuthConfig
		rendered, signed bool
	}{
		"profile":         {&config.RoutingBedrockAuthConfig{Auth: "profile", Profile: "dc-route"}, true, true},
		"iam credentials": {&config.RoutingBedrockAuthConfig{Auth: "iam_credentials", AccessKeyEnv: "A_K", SecretKeyEnv: "S_K"}, true, true},
		"bearer":          {&config.RoutingBedrockAuthConfig{Auth: "passthrough"}, true, false},
		"missing profile": {&config.RoutingBedrockAuthConfig{Auth: "profile", Profile: "nope"}, false, false},
		"region mismatch": {&config.RoutingBedrockAuthConfig{Auth: "profile", Profile: "dc-route", Region: "eu-west-1"}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			route := routeOnlySetupFor(build(tc.block), "claudecode", "127.0.0.1:18970")
			if (route != nil) != tc.rendered {
				t.Fatalf("rendered = %v, want %v", route != nil, tc.rendered)
			}
			if route != nil && (!route.Bedrock || route.GatewaySigning != tc.signed) {
				t.Fatalf("route = %+v, want Bedrock and GatewaySigning %v", route, tc.signed)
			}
		})
	}
}
