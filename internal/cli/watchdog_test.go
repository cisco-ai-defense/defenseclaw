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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestProbeHealth(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}

	t.Run("unreachable", func(t *testing.T) {
		got := probeHealth(client, "http://127.0.0.1:1/health")
		if got != stateDown {
			t.Fatalf("unreachable: got %v want stateDown", got)
		}
	})

	cases := []struct {
		name   string
		status int
		body   string
		want   watchdogState
	}{
		{
			name:   "gateway running only",
			status: http.StatusOK,
			body:   `{"gateway":{"state":"running"}}`,
			want:   stateHealthy,
		},
		{
			name:   "gateway and guardrail running",
			status: http.StatusOK,
			body:   `{"gateway":{"state":"running"},"guardrail":{"state":"running"}}`,
			want:   stateHealthy,
		},
		{
			name:   "guardrail error",
			status: http.StatusOK,
			body:   `{"gateway":{"state":"running"},"guardrail":{"state":"error"}}`,
			want:   stateDegraded,
		},
		{
			name:   "gateway starting",
			status: http.StatusOK,
			body:   `{"gateway":{"state":"starting"}}`,
			want:   stateDown,
		},
		{
			name:   "empty gateway state",
			status: http.StatusOK,
			body:   `{}`,
			want:   stateDown,
		},
		{
			name:   "invalid json",
			status: http.StatusOK,
			body:   `not json`,
			want:   stateDown,
		},
		{
			name:   "http 500",
			status: http.StatusInternalServerError,
			body:   `{"gateway":{"state":"running"}}`,
			want:   stateDown,
		},
		{
			name:   "gateway null",
			status: http.StatusOK,
			body:   `{"gateway":null}`,
			want:   stateDown,
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

			got := probeHealth(client, srv.URL+"/health")
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestWatchdogStateTransitions(t *testing.T) {
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

	runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, 2)

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
