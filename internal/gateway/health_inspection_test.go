// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// healthInspection decodes /health the way the Linux and macOS lifecycle
// does (enterpriseunix readGatewayPosture).
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

// The profile warnings name configured groups and DOMAIN\user selectors.
// /health needs no credential, so it gives any caller but root on the hook
// socket only their number; the authenticated /status and root on the hook
// socket get the warnings themselves (GAP-1268).
func TestHealthWithholdsProfileAssignmentSelectors(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	api.setGuardrailProfiles(&guardrailProfileSet{base: cfg, assignments: []config.ProfileAssignment{{
		Profile: "strict", Match: config.ProfileMatch{Users: []string{`DCLAB\alice`}, Connectors: []string{"claudcode"}},
	}}})
	t.Cleanup(func() { api.setGuardrailProfiles(nil) })
	get := func(handler http.HandlerFunc, path string, ctx context.Context) string {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
		return response.Body.String()
	}
	health := get(api.handleHealth, "/health", context.Background())
	var counts struct {
		Assignment int `json:"profile_assignment_warning_count"`
		Profile    int `json:"profile_warning_count"`
	}
	if err := json.Unmarshal([]byte(health), &counts); err != nil || strings.Contains(health, "claudcode") ||
		strings.Contains(health, "alice") || counts.Assignment == 0 || counts.Profile == 0 {
		t.Fatalf("/health without a credential = %s (error %v)", health, err)
	}
	root := withManagedHookPeer(context.Background(), managedHookPeer{UID: 0})
	for path, body := range map[string]string{
		"/status":         get(api.handleStatus, "/status", context.Background()),
		"/health as root": get(api.handleHealth, "/health", root),
	} {
		var warnings struct {
			Assignment []string `json:"profile_assignment_warnings"`
			Profile    []string `json:"profile_warnings"`
		}
		if err := json.Unmarshal([]byte(body), &warnings); err != nil || len(warnings.Assignment) != counts.Assignment ||
			len(warnings.Profile) != counts.Profile || !strings.Contains(strings.Join(warnings.Assignment, "\n"), "claudcode") {
			t.Fatalf("%s warnings = %+v, error %v", path, warnings, err)
		}
	}
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
		{"ai defense key not yet used", true, StateRunning, map[string]interface{}{
			"ai_defense_available": true, "ai_defense_verified": false,
		}, "active", "unknown"},
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

// TestHealthReportsFailingDirectoryLookups pins GAP-0216: the standalone
// /health carries how many accounts fail to resolve since when, so status and
// verify can warn, and carries neither the reason nor an account.
func TestHealthReportsFailingDirectoryLookups(t *testing.T) {
	previous := directoryCacheHealth
	t.Cleanup(func() { directoryCacheHealth = previous })
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	api := &APIServer{health: NewSidecarHealth(), scannerCfg: cfg}
	directory := func() (map[string]any, string) {
		response := httptest.NewRecorder()
		api.handleHealth(response, httptest.NewRequest(http.MethodGet, "/health", nil))
		var body struct {
			Directory map[string]any `json:"directory"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Directory, response.Body.String()
	}
	directoryCacheHealth = func() identityCacheHealth { return identityCacheHealth{} }
	if got, _ := directory(); got != nil {
		t.Fatalf("/health published a directory object %v while no lookup fails", got)
	}
	directoryCacheHealth = func() identityCacheHealth {
		return identityCacheHealth{Failing: 2, Stale: 1, Since: time.Date(2026, 10, 7, 0, 5, 54, 0, time.UTC), LastError: "groups of dcad-frank@dclab.test: getent timed out"}
	}
	got, raw := directory()
	if got["failing"] != float64(2) || got["stale"] != float64(1) || got["since"] != "2026-10-07T00:05:54Z" || strings.Contains(raw, "dcad-frank") {
		t.Fatalf("directory = %v (%d bytes of /health), want the counts and the time, no account", got, len(raw))
	}
}
