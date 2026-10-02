// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// healthInspection decodes /health the way the Linux and macOS lifecycle
// does (enterpriseunix readInspection).
type healthInspection struct {
	Inspection *struct {
		Local     string `json:"local"`
		AIDefense string `json:"ai_defense"`
	} `json:"inspection"`
}

func getHealthInspection(t *testing.T, api *APIServer) healthInspection {
	t.Helper()
	response := httptest.NewRecorder()
	api.handleHealth(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("/health = %d", response.Code)
	}
	var body healthInspection
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// TestHealthPublishesTheStandaloneInspectionPosture: status and verify on
// Linux and macOS read inspection.local and inspection.ai_defense from
// /health; without them a healthy deployment reported "unknown" for both.
func TestHealthPublishesTheStandaloneInspectionPosture(t *testing.T) {
	// packaging/mdm/contract/lifecycle-result.schema.json
	localValues := map[string]bool{"active": true, "disabled": true, "unknown": true}
	aiDefensePattern := regexp.MustCompile(`^(|disabled|ok|unknown|unavailable(:[A-Za-z0-9_.-]+)?)$`)
	for _, test := range []struct {
		name          string
		aiDefense     bool
		state         SubsystemState
		details       map[string]interface{}
		wantLocal     string
		wantAIDefense string
	}{
		{"local engine only", false, StateRunning, nil, "active", "disabled"},
		{"guardrail failed", false, StateError, nil, "unknown", "disabled"},
		{"ai defense ok", true, StateRunning, map[string]interface{}{"ai_defense_available": true}, "active", "ok"},
		{"ai defense key rejected", true, StateRunning, map[string]interface{}{
			"ai_defense_available": false, "ai_defense_error": "ai_defense: the API key was rejected (HTTP 401)",
		}, "active", "unavailable:auth_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{DeploymentMode: "managed_enterprise"}
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Enterprise.Inspection.AIDefense.Enabled = test.aiDefense
			health := NewSidecarHealth()
			health.SetGuardrail(test.state, "", test.details)
			body := getHealthInspection(t, &APIServer{health: health, scannerCfg: cfg})
			if body.Inspection == nil {
				t.Fatal("/health has no inspection object")
			}
			if body.Inspection.Local != test.wantLocal || body.Inspection.AIDefense != test.wantAIDefense {
				t.Fatalf("inspection = %+v, want local=%s ai_defense=%s", *body.Inspection, test.wantLocal, test.wantAIDefense)
			}
			if !localValues[body.Inspection.Local] || !aiDefensePattern.MatchString(body.Inspection.AIDefense) {
				t.Fatalf("inspection %+v is outside the lifecycle result contract", *body.Inspection)
			}
		})
	}
}

// TestHealthOmitsInspectionOutsideTheStandaloneProfile keeps the /health
// body of per-user and Secure Client gateways unchanged.
func TestHealthOmitsInspectionOutsideTheStandaloneProfile(t *testing.T) {
	secureClient := &config.Config{DeploymentMode: "managed_enterprise"}
	for name, cfg := range map[string]*config.Config{"per-user": {}, "secure client": secureClient} {
		health := NewSidecarHealth()
		health.SetGuardrail(StateRunning, "", nil)
		if body := getHealthInspection(t, &APIServer{health: health, scannerCfg: cfg}); body.Inspection != nil {
			t.Fatalf("%s /health published inspection %+v", name, *body.Inspection)
		}
	}
}
