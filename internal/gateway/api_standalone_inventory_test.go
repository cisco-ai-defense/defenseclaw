// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1142: on a managed standalone deployment (no OpenClaw gateway) /skills
// failed with 502 "gateway: not connected" and /mcps answered an empty list.
// The OpenClaw-backed inventory routes now say what to use instead.
func TestOpenClawInventoryRoutesRefuseOnStandaloneEnterprise(t *testing.T) {
	standalone := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	api := &APIServer{scannerCfg: standalone}
	for route, handle := range map[string]http.HandlerFunc{
		"/skills":        api.handleSkills,
		"/mcps":          api.handleMCPs,
		"/tools/catalog": api.handleToolsCatalog,
	} {
		response := httptest.NewRecorder()
		handle(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != http.StatusNotImplemented || !strings.Contains(response.Body.String(), "AI Discovery") {
			t.Fatalf("%s = %d %s, want 501 naming AI Discovery", route, response.Code, response.Body.String())
		}
	}
	// A per-user gateway keeps the old answer.
	response := httptest.NewRecorder()
	(&APIServer{scannerCfg: &config.Config{}}).handleMCPs(response, httptest.NewRequest(http.MethodGet, "/mcps", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("per-user /mcps = %d, want 200", response.Code)
	}
}
