// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// id.GAP-1264: with human approval enabled at the level block_at already
// blocks and no guardrail profiles, status and verify warn that approval
// cannot ask, as config validate and profile-explain do. /health lists the
// warning to root on the hook socket, /status to the gateway credential.
func TestStandaloneHealthWarnsOfInertApprovalWithoutProfiles(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.HILT = config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	api.setGuardrailProfiles(nil)
	get := func(handler http.HandlerFunc, ctx context.Context) string {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		return response.Body.String()
	}
	root := withManagedHookPeer(context.Background(), managedHookPeer{UID: 0})
	for name, body := range map[string]string{
		"/health as root": get(api.handleHealth, root),
		"/status":         get(api.handleStatus, context.Background()),
	} {
		if !strings.Contains(body, `"profile_warnings"`) || !strings.Contains(body, "human approval at HIGH cannot ask") {
			t.Fatalf("%s lacks the inert approval warning: %s", name, body)
		}
	}
}
