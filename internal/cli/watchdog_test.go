// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func intPtr(v int) *int { return &v }

func TestProbeHealth(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}

	t.Run("unreachable", func(t *testing.T) {
		got := probeHealth(client, "http://127.0.0.1:1/health", watchdogHealthRequirements{})
		if got.state != stateDown {
			t.Fatalf("unreachable: got %v want stateDown", got.state)
		}
	})

	cases := []struct {
		name         string
		status       int
		body         string
		requirements watchdogHealthRequirements
		want         watchdogState
	}{
		{
			name:         "gateway running only",
			status:       http.StatusOK,
			body:         `{"gateway":{"state":"running"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true},
			want:         stateHealthy,
		},
		{
			name:         "gateway and guardrail running",
			status:       http.StatusOK,
			body:         `{"gateway":{"state":"running"},"guardrail":{"state":"running"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true, requireGuardrail: true},
			want:         stateHealthy,
		},
		{
			name:         "guardrail error",
			status:       http.StatusOK,
			body:         `{"gateway":{"state":"running"},"guardrail":{"state":"error"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true, requireGuardrail: true},
			want:         stateDegraded,
		},
		{
			name:         "gateway starting",
			status:       http.StatusOK,
			body:         `{"gateway":{"state":"starting"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true},
			want:         stateDown,
		},
		{
			name:         "empty gateway state",
			status:       http.StatusOK,
			body:         `{}`,
			requirements: watchdogHealthRequirements{requireFleet: true},
			want:         stateDown,
		},
		{
			name:         "invalid json",
			status:       http.StatusOK,
			body:         `not json`,
			requirements: watchdogHealthRequirements{requireFleet: true},
			want:         stateDown,
		},
		{
			name:         "http 500",
			status:       http.StatusInternalServerError,
			body:         `{"gateway":{"state":"running"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true},
			want:         stateDown,
		},
		{
			name:         "gateway null",
			status:       http.StatusOK,
			body:         `{"gateway":null}`,
			requirements: watchdogHealthRequirements{requireFleet: true},
			want:         stateDown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				if tc.body != "" {
					_, _ = w.Write([]byte(tc.body))
				}
			}))
			defer srv.Close()

			got := probeHealth(client, srv.URL+"/health", tc.requirements)
			if got.state != tc.want {
				t.Fatalf("got %s want %s", got.state, tc.want)
			}
		})
	}
}

func TestWatchdogHealthRequirementsFromConfig(t *testing.T) {
	t.Run("hook-only multi connector", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Guardrail.Enabled = true
		cfg.Guardrail.Connector = ""
		cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
			"codex":      {},
			"claudecode": {},
		}
		cfg.Claw.Mode = ""
		cfg.Gateway.Host = "127.0.0.1"
		cfg.Gateway.FleetMode = "auto"
		cfg.Gateway.Watcher.Enabled = true

		got := watchdogHealthRequirementsFromConfig(cfg)
		if got.requireFleet {
			t.Fatal("hook-only loopback topology must not require the fleet gateway")
		}
		if !got.requireGuardrail || !got.requireWatcher {
			t.Fatalf("required protection flags = %+v", got)
		}
		if want := []string{"claudecode", "codex"}; !reflect.DeepEqual(got.connectors, want) {
			t.Fatalf("connectors = %v, want %v", got.connectors, want)
		}
	})

	t.Run("fleet topology", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Guardrail.Connector = "openclaw"
		cfg.Guardrail.Connectors = nil
		cfg.Gateway.FleetMode = "auto"
		if got := watchdogHealthRequirementsFromConfig(cfg); !got.requireFleet {
			t.Fatal("OpenClaw topology must require the fleet gateway")
		}
	})

	t.Run("explicit fleet on for hook connector", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Guardrail.Connector = "codex"
		cfg.Guardrail.Connectors = nil
		cfg.Gateway.Host = "127.0.0.1"
		cfg.Gateway.FleetMode = "enabled"
		if got := watchdogHealthRequirementsFromConfig(cfg); !got.requireFleet {
			t.Fatal("explicit fleet enable must remain required")
		}
	})
}

func TestProbeHealthTopologyMatrix(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}
	hookRequirements := watchdogHealthRequirements{
		requireGuardrail: true,
		requireWatcher:   true,
		connectors:       []string{"claudecode", "codex"},
	}
	cases := []struct {
		name         string
		body         string
		requirements watchdogHealthRequirements
		want         watchdogState
		wantSeverity string
	}{
		{
			name: "hook-only regression fleet and optional services disabled",
			body: `{
				"gateway":{"state":"disabled"},
				"watcher":{"state":"running"},
				"guardrail":{"state":"running"},
				"telemetry":{"state":"disabled"},
				"sinks":{"state":"disabled"},
				"connectors":[{"name":"codex","state":"running"},{"name":"claudecode","state":"running"}]
			}`,
			requirements: hookRequirements,
			want:         stateHealthy,
		},
		{
			name: "hook-only required connector down",
			body: `{
				"gateway":{"state":"disabled"},
				"watcher":{"state":"running"},
				"guardrail":{"state":"running"},
				"connectors":[{"name":"codex","state":"running"},{"name":"claudecode","state":"error"}]
			}`,
			requirements: hookRequirements,
			want:         stateDegraded,
			wantSeverity: "HIGH",
		},
		{
			name: "hook-only required watcher down",
			body: `{
				"gateway":{"state":"disabled"},
				"watcher":{"state":"error"},
				"guardrail":{"state":"running"},
				"connectors":[{"name":"codex","state":"running"},{"name":"claudecode","state":"running"}]
			}`,
			requirements: hookRequirements,
			want:         stateDegraded,
			wantSeverity: "HIGH",
		},
		{
			name:         "required fleet disabled",
			body:         `{"gateway":{"state":"disabled"},"guardrail":{"state":"running"},"connector":{"name":"openclaw","state":"running"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true, requireGuardrail: true, connectors: []string{"openclaw"}},
			want:         stateDown,
			wantSeverity: "CRITICAL",
		},
		{
			name:         "required fleet and guardrail running",
			body:         `{"gateway":{"state":"running"},"guardrail":{"state":"running"},"connector":{"name":"openclaw","state":"running"}}`,
			requirements: watchdogHealthRequirements{requireFleet: true, requireGuardrail: true, connectors: []string{"openclaw"}},
			want:         stateHealthy,
		},
		{
			name:         "legacy singular connector",
			body:         `{"gateway":{"state":"disabled"},"guardrail":{"state":"running"},"connector":{"name":"codex","state":"running"}}`,
			requirements: watchdogHealthRequirements{requireGuardrail: true, connectors: []string{"codex"}},
			want:         stateHealthy,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got := probeHealth(client, srv.URL, tc.requirements)
			if got.state != tc.want {
				t.Fatalf("state = %s, want %s (details=%q)", got.state, tc.want, got.details)
			}
			if got.severity != tc.wantSeverity {
				t.Fatalf("severity = %q, want %q", got.severity, tc.wantSeverity)
			}
			if got.state == stateHealthy && strings.Contains(strings.ToLower(got.notification), "unprotected") {
				t.Fatalf("healthy hook topology produced false outage text: %q", got.notification)
			}
		})
	}
}

func TestWatchdogStateTransitions(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	var healthy atomic.Bool
	healthy.Store(true)

	var downProbes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if healthy.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
			return
		}
		downProbes.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	go func() {
		time.Sleep(25 * time.Millisecond)
		healthy.Store(false)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, 2, watchdogHealthRequirements{requireFleet: true}, nil, nil)

	if n := downProbes.Load(); n < 2 {
		t.Fatalf("expected at least %d probes while server returned errors after flip, got %d", 2, n)
	}
}

func TestWatchdogHealthURL(t *testing.T) {
	t.Run("defaults to loopback", func(t *testing.T) {
		cfg := config.DefaultConfig()
		got := watchdogHealthURL(cfg)
		want := "http://127.0.0.1:18970/health"
		if got != want {
			t.Fatalf("watchdogHealthURL() = %q, want %q", got, want)
		}
	})

	t.Run("uses api bind when configured", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Gateway.APIBind = "10.0.0.8"
		cfg.Gateway.APIPort = 19001
		got := watchdogHealthURL(cfg)
		want := "http://10.0.0.8:19001/health"
		if got != want {
			t.Fatalf("watchdogHealthURL() = %q, want %q", got, want)
		}
	})

	t.Run("uses guardrail host in standalone mode", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.OpenShell.Mode = "standalone"
		cfg.Guardrail.Host = "192.168.65.2"
		got := watchdogHealthURL(cfg)
		want := "http://192.168.65.2:18970/health"
		if got != want {
			t.Fatalf("watchdogHealthURL() = %q, want %q", got, want)
		}
	})
}

func TestWatchdogWebhookDispatchOnStateChange(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	os.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	defer os.Unsetenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST")

	var mu sync.Mutex
	var received []map[string]interface{}

	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			mu.Lock()
			received = append(received, body)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	webhooks := gateway.NewWebhookDispatcher([]config.WebhookConfig{
		{
			URL:             webhookSrv.URL,
			Type:            "generic",
			Enabled:         true,
			CooldownSeconds: intPtr(0), // disable cooldown for fast test loop
		},
	})
	defer webhooks.Close()

	var healthy atomic.Bool
	healthy.Store(true)

	healthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if healthy.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer healthSrv.Close()

	go func() {
		time.Sleep(25 * time.Millisecond)
		healthy.Store(false)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	runWatchdogLoop(ctx, healthSrv.URL+"/health", 10*time.Millisecond, 2, watchdogHealthRequirements{requireFleet: true}, webhooks, nil)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := len(received)
	mu.Unlock()
	if count != 1 {
		t.Fatalf("expected exactly 1 webhook event for gateway-down, got %d", count)
	}

	mu.Lock()
	first := received[0]
	mu.Unlock()
	evt, ok := first["event"].(map[string]interface{})
	if !ok {
		t.Fatal("webhook payload missing event field")
	}
	if evt["action"] != "gateway-down" {
		t.Errorf("expected action=gateway-down, got %v", evt["action"])
	}
	if evt["severity"] != "CRITICAL" {
		t.Errorf("expected severity=CRITICAL, got %v", evt["severity"])
	}
}

func TestWatchdogHookOnlyDoesNotDispatchFalseOutage(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")

	var received atomic.Int32
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	webhooks := gateway.NewWebhookDispatcher([]config.WebhookConfig{{
		URL:             webhookSrv.URL,
		Type:            "generic",
		Enabled:         true,
		CooldownSeconds: intPtr(0),
	}})
	defer webhooks.Close()

	healthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"gateway":{"state":"disabled"},
			"watcher":{"state":"running"},
			"guardrail":{"state":"running"},
			"telemetry":{"state":"disabled"},
			"sinks":{"state":"disabled"},
			"connectors":[{"name":"codex","state":"running"},{"name":"claudecode","state":"running"}]
		}`))
	}))
	defer healthSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	runWatchdogLoop(ctx, healthSrv.URL, 10*time.Millisecond, 2, watchdogHealthRequirements{
		requireGuardrail: true,
		requireWatcher:   true,
		connectors:       []string{"codex", "claudecode"},
	}, webhooks, nil)

	time.Sleep(30 * time.Millisecond)
	if got := received.Load(); got != 0 {
		t.Fatalf("healthy hook-only topology dispatched %d false outage event(s)", got)
	}
}

func TestWatchdogDispatchesOneOutageAndOneRecovery(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")

	var mu sync.Mutex
	var actions []string
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Event struct {
				Action string `json:"action"`
			} `json:"event"`
		}
		if json.NewDecoder(r.Body).Decode(&payload) == nil {
			mu.Lock()
			actions = append(actions, payload.Event.Action)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	webhooks := gateway.NewWebhookDispatcher([]config.WebhookConfig{{
		URL:             webhookSrv.URL,
		Type:            "generic",
		Enabled:         true,
		CooldownSeconds: intPtr(0),
	}})

	var probes atomic.Int32
	healthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := probes.Add(1)
		if n == 3 || n == 4 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
	}))
	defer healthSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Millisecond)
	defer cancel()
	runWatchdogLoop(ctx, healthSrv.URL, 10*time.Millisecond, 2, watchdogHealthRequirements{requireFleet: true}, webhooks, nil)
	// Dispatch is asynchronous. Close deterministically drains every accepted
	// delivery, avoiding a scheduler-dependent sleep before the assertion.
	webhooks.Close()

	mu.Lock()
	defer mu.Unlock()
	want := []string{string(audit.ActionGatewayDown), string(audit.ActionGatewayRecovered)}
	// WebhookDispatcher intentionally delivers endpoints asynchronously; pin
	// exactly-once transition delivery without imposing goroutine completion
	// order on the receiver.
	sort.Strings(actions)
	sort.Strings(want)
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("health transition actions = %v, want %v", actions, want)
	}
}

func TestDispatchHealthEventNilWebhooks(t *testing.T) {
	dispatchHealthEvent(nil, "gateway-down", "CRITICAL", "test")
}

func TestWatchdogStatePersistenceAndRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", tmpDir)

	saveWatchdogState(tmpDir, stateDown)
	got := loadWatchdogState(tmpDir)
	if got != stateDown {
		t.Fatalf("expected stateDown after save/load, got %s", got)
	}

	// Simulate a new watchdog starting after gateway was down, with gateway
	// now healthy. The loop should detect recovery on the first healthy probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, 2, watchdogHealthRequirements{requireFleet: true}, nil, nil)

	restored := loadWatchdogState(tmpDir)
	if restored != stateHealthy {
		t.Fatalf("expected stateHealthy after recovery, got %s", restored)
	}
}
