// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// #1320: `enterprise secret check` proves the key before the first prompt
// with one request that carries no content, and reports the codes
// inspection.ai_defense reports.
func TestProbeAIDefenseReportsTheHealthCodesAndSendsNoContent(t *testing.T) {
	const key = "stored-key-CHECK-MARKER"
	contract := lifecycleAIDefenseValues(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	unreachableURL := closed.URL
	closed.Close()
	for _, test := range []struct {
		name   string
		status int
		delay  time.Duration
		down   bool
		want   string
	}{
		{name: "accepted", status: http.StatusOK, want: "ok"},
		{name: "401", status: http.StatusUnauthorized, want: "unavailable:auth_failed"},
		{name: "403", status: http.StatusForbidden, want: "unavailable:auth_failed"},
		{name: "407", status: http.StatusProxyAuthRequired, want: "unavailable:proxy_auth_required"},
		{name: "500", status: http.StatusInternalServerError, want: "unavailable:error"},
		{name: "timeout", status: http.StatusOK, delay: 2 * time.Second, want: "unavailable:unreachable"},
		{name: "unreachable", down: true, want: "unavailable:unreachable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := unreachableURL
			var body string
			if !test.down {
				release := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ := io.ReadAll(r.Body)
					body = string(raw)
					if r.Header.Get("X-Cisco-AI-Defense-API-Key") != key {
						t.Errorf("the request did not carry the stored key")
					}
					if test.delay > 0 {
						select {
						case <-time.After(test.delay):
						case <-release:
						}
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(test.status)
					_, _ = w.Write([]byte(`{"is_safe":true,"action":"Allow"}`))
				}))
				t.Cleanup(server.Close)
				t.Cleanup(func() { close(release) })
				endpoint = server.URL
			}
			c := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{APIKey: key, Endpoint: endpoint, TimeoutMs: 200}, "")
			if c == nil {
				t.Fatal("the AI Defense client was not built")
			}
			got := probeAIDefense(context.Background(), c)
			if got != test.want {
				t.Fatalf("check = %q, want %q", got, test.want)
			}
			if !contract[got] {
				t.Fatalf("check %q is not a value of inspection.ai_defense in the contract", got)
			}
			if !test.down && !strings.Contains(body, `"content":"."`) {
				t.Fatalf("the check sent more than the probe message: %s", body)
			}
		})
	}
}

// A check needs the standalone profile; AI Defense off is "disabled"; a
// missing protected credential is credential_unavailable, and the
// environment key is never used instead.
func TestCheckStandaloneAIDefenseOnTheConfig(t *testing.T) {
	if _, err := CheckStandaloneAIDefense(context.Background(), &config.Config{}); err == nil {
		t.Fatal("a config that is not a standalone deployment must be refused")
	}
	cfg := standaloneConfig(t)
	if got, err := CheckStandaloneAIDefense(context.Background(), cfg); err != nil || got != "disabled" {
		t.Fatalf("ai_defense off = %q, %v", got, err)
	}
	cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	cfg.CiscoAIDefense.APIKeyEnv = "CISCO_AI_DEFENSE_API_KEY"
	t.Setenv("CISCO_AI_DEFENSE_API_KEY", "must-not-be-used")
	if got, err := CheckStandaloneAIDefense(context.Background(), cfg); err != nil || got != "unavailable:credential_unavailable" {
		t.Fatalf("missing credential = %q, %v", got, err)
	}
}
