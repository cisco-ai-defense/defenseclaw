// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Native Windows OpenClaw (DESIGN-REVIEW-1 P2-12): no guardrail proxy binds
// for it, no provider probe runs, and setup hands it only the scoped plugin
// credential. Linux and macOS keep the proxy and the gateway token.
func TestOpenClawNativeModeTopologyFollowsTheHookMode(t *testing.T) {
	for _, tc := range []struct {
		goos  string
		proxy bool
	}{{"linux", true}, {"darwin", true}, {"windows", false}} {
		t.Run(tc.goos, func(t *testing.T) {
			t.Cleanup(connector.PinOpenClawHooksGOOSForTest(tc.goos))
			conn := connector.NewOpenClawConnector()
			gc := &config.GuardrailConfig{}
			if got := proxyShouldBindForConnector(conn, gc); got != tc.proxy {
				t.Fatalf("proxyShouldBindForConnector = %v, want %v", got, tc.proxy)
			}
			if got := shouldRunProviderProbeForConnector(conn, gc); got != tc.proxy {
				t.Fatalf("shouldRunProviderProbeForConnector = %v, want %v", got, tc.proxy)
			}
			cfg := &config.Config{Guardrail: config.GuardrailConfig{Connector: "openclaw"}}
			cfg.Claw.Mode = "openclaw"
			if got := proxyShouldBindForConfiguredConnector(cfg); got != tc.proxy {
				t.Fatalf("proxyShouldBindForConfiguredConnector = %v, want %v", got, tc.proxy)
			}
			tokens, err := connectorSetupTokensFor(t.TempDir(), conn, "gateway-master", false)
			if err != nil {
				t.Fatalf("connectorSetupTokensFor: %v", err)
			}
			if !tokens.hookTokenScoped || tokens.hookToken == "" || tokens.hookToken == "gateway-master" {
				t.Fatalf("hook token = %+v, want the connector-scoped plugin credential", tokens)
			}
			wantConnector := tokens.hookToken
			if tc.proxy {
				wantConnector = "gateway-master"
			}
			if tokens.connectorToken != wantConnector {
				t.Fatalf("connector token = %q, want %q", tokens.connectorToken, wantConnector)
			}
			mode := connectorModeFor("openclaw", "action")
			wantMode, wantSurface := "observability", "agent_lifecycle_hooks"
			if tc.proxy {
				wantMode, wantSurface = "guardrail", "llm_proxy_and_plugin_hooks"
			}
			if mode["mode"] != wantMode || mode["proxy_intercept"] != tc.proxy || mode["enforcement_surface"] != wantSurface {
				t.Fatalf("connectorModeFor(openclaw) = %v, want mode %s, proxy_intercept %v, surface %s", mode, wantMode, tc.proxy, wantSurface)
			}
			managedCfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
			if got := lifecycleManagerForConnector(managedCfg, conn); got != "gateway" {
				t.Fatalf("managed lifecycle manager = %q, want gateway (the hook guardian never takes OpenClaw)", got)
			}
		})
	}
}

// The plugin proves the listener with its scoped credential, so the API
// listener proof is keyed on hooks/.hook-openclaw.token (P1-2).
func TestOpenClawPluginProofTokenIsTheScopedCredential(t *testing.T) {
	dataDir := t.TempDir()
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	if got := api.openClawPluginProofToken(); got != "" {
		t.Fatalf("proof token with no credential = %q, want empty", got)
	}
	token, err := connector.EnsureHookAPIToken(dataDir, "openclaw")
	if err != nil {
		t.Fatalf("EnsureHookAPIToken: %v", err)
	}
	if got := api.openClawPluginProofToken(); got != token {
		t.Fatalf("proof token = %q, want the scoped plugin credential", got)
	}
	if got := (&APIServer{}).openClawPluginProofToken(); got != "" {
		t.Fatalf("proof token with no data dir = %q, want empty", got)
	}
}
