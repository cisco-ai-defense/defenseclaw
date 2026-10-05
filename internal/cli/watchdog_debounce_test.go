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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1642: degraded probes no longer count toward "protection down", so one
// slow probe after a degraded run does not report the gateway unreachable.
func TestWatchdogDegradedProbesDoNotCountTowardDown(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if probes.Add(1) == 5 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"guardrail":{"state":"starting"}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for probes.Load() < 8 {
			time.Sleep(2 * time.Millisecond)
		}
		cancel()
	}()
	runWatchdogLoop(ctx, srv.URL+"/health", 5*time.Millisecond, 2, watchdogHealthRequirements{requireGuardrail: true}, nil, nil)

	state, err := readWatchdogState(config.DefaultDataPath())
	if err != nil || state != stateDegraded {
		t.Fatalf("watchdog state = %s (err %v), want degraded", state, err)
	}
}

// GAP-1847: a watchdog that starts with an earlier run's "down" state and
// finds the gateway reachable but degraded records degraded, not down.
func TestWatchdogDownStateMovesToDegradedWhenGatewayAnswers(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	dataDir := config.DefaultDataPath()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, watchdogStateFile), []byte("down"), 0o600); err != nil {
		t.Fatal(err)
	}
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		_, _ = w.Write([]byte(`{"guardrail":{"state":"starting"}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for probes.Load() < 4 {
			time.Sleep(2 * time.Millisecond)
		}
		cancel()
	}()
	runWatchdogLoop(ctx, srv.URL+"/health", 5*time.Millisecond, 2, watchdogHealthRequirements{requireGuardrail: true}, nil, nil)

	state, err := readWatchdogState(dataDir)
	if err != nil || state != stateDegraded {
		t.Fatalf("watchdog state = %s (err %v), want degraded", state, err)
	}
}
