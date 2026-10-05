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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func standaloneConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		DataDir:        dir,
		ConfigFilePath: filepath.Join(dir, "etc", "config.yaml"),
		DeploymentMode: string(config.DeploymentModeManagedEnterprise),
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Enabled: true},
	}
}

func TestStandaloneInspectorWithoutAIDefenseIsLocalOnly(t *testing.T) {
	s := &Sidecar{cfg: standaloneConfig(t), health: NewSidecarHealth()}
	if inspector := s.pickInspector(context.Background()); inspector != nil {
		t.Fatalf("standalone without ai_defense must not build a remote inspector, got %T", inspector)
	}
	if available, detail := s.inspectionAvailability(); !available || detail != "" {
		t.Fatalf("local-only standalone inspection must be available: available=%v detail=%q", available, detail)
	}
}

func TestStandaloneMultiConnectorBootNeedsNoCloudProvider(t *testing.T) {
	s := &Sidecar{cfg: standaloneConfig(t), health: NewSidecarHealth()}
	detail, conn := waitForGuardrailDetail(t, s)
	if detail["inspection_available"] != true {
		t.Fatalf("standalone local inspection must be reported available: %+v", detail)
	}
	if !conn.credsSet {
		t.Fatal("standalone boot must register the connector for hook evaluation")
	}
}

// waitForGuardrailDetail runs the managed multi-connector guardrail until it
// publishes inspection_available and returns that health detail and the
// connector it booted.
func waitForGuardrailDetail(t *testing.T, s *Sidecar) (map[string]interface{}, *hookBootStubConnector) {
	t.Helper()
	resetConnectorRuleCategories(t)
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.runManagedEnterpriseMultiHookGuardrail(ctx, reg, []connector.Connector{conn}, "gateway-token", "127.0.0.1:0", "127.0.0.1:0", "master")
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("managed guardrail did not stop")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := s.health.Snapshot().Guardrail
		if snapshot.State == StateError {
			t.Fatalf("managed guardrail boot failed: %v", snapshot.LastError)
		}
		if _, ok := snapshot.Details["inspection_available"].(bool); ok {
			return snapshot.Details, conn
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("managed guardrail never published inspection_available")
	return nil, nil
}

func TestStandaloneHealthReportsAMissingAIDefenseCredential(t *testing.T) {
	cfg := standaloneConfig(t)
	cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	cfg.CiscoAIDefense.APIKeyEnv = "CISCO_AI_DEFENSE_API_KEY"
	t.Setenv("CISCO_AI_DEFENSE_API_KEY", "must-not-be-used")
	if _, err := newStandaloneCiscoInspectClient(cfg); !errors.Is(err, managed.ErrNoServiceCredential) {
		t.Fatalf("missing protected credential error = %v, want ErrNoServiceCredential (the env key must never be used)", err)
	}
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	// Boot builds the inspector before the guardrail publishes health; the
	// protected credential does not exist, so AI Defense is degraded.
	if inspector := s.pickInspector(context.Background()); inspector != nil {
		t.Fatalf("missing credential must not yield an inspector, got %T", inspector)
	}
	if available, _ := s.inspectionAvailability(); available {
		t.Fatal("a configured but missing AI Defense credential must be reported")
	}
	detail, _ := waitForGuardrailDetail(t, s)
	if available, _ := detail["inspection_available"].(bool); !available {
		t.Fatalf("the local engine still inspects, so inspection_available must stay true: %+v", detail)
	}
	if _, ok := detail["inspection_error"]; ok {
		t.Fatalf("inspection_error describes the Secure Client remote-only posture, not a standalone AI Defense outage: %+v", detail)
	}
	if available, ok := detail["ai_defense_available"].(bool); !ok || available {
		t.Fatalf("an enabled AI Defense without its credential must report ai_defense_available=false: %+v", detail)
	}
	reason, _ := detail["ai_defense_error"].(string)
	if !strings.HasPrefix(reason, "ai_defense: ") || !strings.Contains(reason, "ai-defense-api-key") {
		t.Fatalf("ai_defense_error must carry the credential failure, got %q", reason)
	}
}

func TestStandaloneAIDefenseHealthDetail(t *testing.T) {
	enabled := standaloneConfig(t)
	enabled.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	for _, test := range []struct {
		name      string
		cfg       *config.Config
		probe     error
		probed    bool
		wantKeys  bool
		available bool
		reason    string
	}{
		{name: "secure client", cfg: &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}, probe: errors.New("provider down"), probed: true},
		{name: "unmanaged", cfg: &config.Config{DeploymentMode: string(config.DeploymentModeUnmanagedBYOD)}, probe: errors.New("no key"), probed: true},
		{name: "standalone local only", cfg: standaloneConfig(t), probed: true},
		{name: "standalone healthy", cfg: enabled, probed: true, wantKeys: true, available: true},
		{name: "standalone degraded", cfg: enabled, probe: errors.New("credential missing"), probed: true, wantKeys: true, reason: "ai_defense: credential missing"},
		{name: "standalone not probed", cfg: enabled, wantKeys: true, reason: "ai_defense: client not initialized"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &Sidecar{cfg: test.cfg, health: NewSidecarHealth()}
			if test.probed {
				s.setInspectionAvailability(test.probe)
			}
			detail := map[string]interface{}{}
			s.addStandaloneAIDefenseHealth(detail)
			if !test.wantKeys {
				if len(detail) != 0 {
					t.Fatalf("detail = %+v, want untouched", detail)
				}
				return
			}
			if got, ok := detail["ai_defense_available"].(bool); !ok || got != test.available {
				t.Fatalf("ai_defense_available = %v, want %v", detail["ai_defense_available"], test.available)
			}
			if got, _ := detail["ai_defense_error"].(string); got != test.reason {
				t.Fatalf("ai_defense_error = %q, want %q", got, test.reason)
			}
		})
	}
}

func TestStandaloneEgressTransportHonorsTheEnterpriseProxy(t *testing.T) {
	cfg := standaloneConfig(t)
	cfg.Enterprise.Network = config.EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}
	transport, err := standaloneEgressTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat": "http://proxy.corp:3128",
		"https://aid.internal.corp/api/v1/inspect/chat":                           "",
	} {
		req, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := transport.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		if (got == nil && want != "") || (got != nil && got.String() != want) {
			t.Fatalf("proxy(%s) = %v, want %q", target, got, want)
		}
	}
	cfg.Enterprise.Network.HTTPSProxy = "http://user:secret@proxy.corp:3128"
	if _, err := standaloneEgressTransport(cfg); err == nil {
		t.Fatal("a proxy URL with credentials must be refused")
	}
}

// TestStandaloneAIDefenseHealthFollowsRequestOutcomes covers a client that
// was built but cannot work: a revoked key or an unreachable endpoint must
// show on /health until a request succeeds again.
func TestStandaloneAIDefenseHealthFollowsRequestOutcomes(t *testing.T) {
	cfg := standaloneConfig(t)
	cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}

	var status atomic.Int32
	status.Store(http.StatusUnauthorized)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := int(status.Load())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(`{"is_safe":true,"action":"Allow"}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"invalid API key"}`))
	}))
	defer server.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	unreachableURL := closed.URL
	closed.Close()

	client := func(endpoint string) *CiscoInspectClient {
		t.Helper()
		c := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{APIKey: "stored-key", Endpoint: endpoint, TimeoutMs: 2000}, "")
		if c == nil {
			t.Fatal("the AI Defense client was not built")
		}
		return c
	}
	health := func() (bool, string) {
		t.Helper()
		detail := map[string]interface{}{}
		s.addStandaloneAIDefenseHealth(detail)
		available, ok := detail["ai_defense_available"].(bool)
		if !ok {
			t.Fatalf("ai_defense_available missing: %+v", detail)
		}
		reason, _ := detail["ai_defense_error"].(string)
		return available, reason
	}
	messages := []ChatMessage{{Role: "user", Content: "hello"}}
	inspect := func(c *CiscoInspectClient, ctx context.Context) *ScanVerdict {
		t.Helper()
		return c.Inspect(ctx, messages)
	}

	c := client(server.URL)
	s.adoptStandaloneInspector(c)
	if available, reason := health(); !available || reason != "" {
		t.Fatalf("a freshly built client must start available: available=%t reason=%q", available, reason)
	}
	if verdict := inspect(c, context.Background()); verdict != nil {
		t.Fatalf("HTTP 401 produced a verdict: %+v", verdict)
	}
	if available, reason := health(); available || !strings.HasPrefix(reason, "ai_defense: ") || !strings.Contains(reason, "API key was rejected (HTTP 401)") {
		t.Fatalf("HTTP 401: available=%t reason=%q, want a rejected-key error", available, reason)
	}

	// The key works again: the next verdict clears the error.
	status.Store(http.StatusOK)
	if verdict := inspect(c, context.Background()); verdict == nil || verdict.Action != "allow" {
		t.Fatalf("recovered request verdict = %+v, want allow", verdict)
	}
	if available, reason := health(); !available || reason != "" {
		t.Fatalf("a successful request must clear the error: available=%t reason=%q", available, reason)
	}

	// A request the caller abandoned says nothing about the service.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if verdict := inspect(c, canceled); verdict != nil {
		t.Fatalf("a canceled request produced a verdict: %+v", verdict)
	}
	if available, reason := health(); !available || reason != "" {
		t.Fatalf("a canceled request changed the reported state: available=%t reason=%q", available, reason)
	}

	// An unreachable endpoint or proxy.
	down := client(unreachableURL)
	s.adoptStandaloneInspector(down)
	inspect(down, context.Background())
	if available, reason := health(); available || !strings.Contains(reason, "endpoint or egress proxy unreachable") {
		t.Fatalf("unreachable endpoint: available=%t reason=%q", available, reason)
	}

	// A reload replaces the client; a late failure of the old one must not
	// overwrite the new one's state.
	current := client(server.URL)
	s.adoptStandaloneInspector(current)
	if verdict := inspect(current, context.Background()); verdict == nil {
		t.Fatal("the rebuilt client did not inspect")
	}
	inspect(down, context.Background())
	if available, reason := health(); !available || reason != "" {
		t.Fatalf("a replaced client overwrote /health: available=%t reason=%q", available, reason)
	}
}

func TestOpensourceCiscoInspectClientReportsNothing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	c := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{APIKey: "k", Endpoint: server.URL}, "")
	if c.availabilityCallback() != nil {
		t.Fatal("an opensource client must not carry an availability observer")
	}
	if verdict := c.Inspect(context.Background(), []ChatMessage{{Role: "user", Content: "hello"}}); verdict != nil {
		t.Fatalf("HTTP 401 produced a verdict: %+v", verdict)
	}
}
