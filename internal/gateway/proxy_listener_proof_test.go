// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0594 review N2: the guardrail port answers the OpenClaw listener proof
// on a per-user install, and a Secure Client gateway serves none, as on the
// API port.
func TestGuardrailProxyListenerProofRefusesSecureClient(t *testing.T) {
	keyID := connector.UserScopedCredentialKeyID(gatewayTokenProofTestToken)
	for name, tc := range map[string]struct {
		cfg  func() *config.Config
		want int
	}{
		"per-user": {cfg: func() *config.Config { return &config.Config{} }, want: http.StatusNoContent},
		"Secure Client": {cfg: func() *config.Config {
			cfg := &config.Config{}
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileSecureClient
			return cfg
		}, want: http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			proxy := &GuardrailProxy{gatewayToken: gatewayTokenProofTestToken}
			generation := &Generation{N: 1, Config: tc.cfg()}
			srv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxy.handleListenerProof(w, r.WithContext(withPinnedGeneration(r.Context(), generation)))
			}))
			if resp := gatewayTokenProofRequest(t, srv.URL, "openclaw", keyID); resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
