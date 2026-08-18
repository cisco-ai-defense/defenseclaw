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

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func TestHandleAIUsageDisabled(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage", nil)
	w := httptest.NewRecorder()

	api.handleAIUsage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled response missing: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"lookup_model_provenance_online":false`) {
		t.Fatalf("disabled response missing online provenance state: %s", w.Body.String())
	}
}

func TestHandleAIUsageReportsRuntimeModelProvenanceOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
			service := inventory.NewContinuousDiscoveryServiceWithOptions(
				inventory.AIDiscoveryOptions{
					Enabled:                     true,
					LookupModelProvenanceOnline: enabled,
				},
				nil,
			)
			api.SetAIDiscoveryService(service)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage", nil)
			w := httptest.NewRecorder()
			api.handleAIUsage(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			var payload struct {
				LookupModelProvenanceOnline bool `json:"lookup_model_provenance_online"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.LookupModelProvenanceOnline != enabled {
				t.Fatalf(
					"lookup_model_provenance_online = %t, want %t; body=%s",
					payload.LookupModelProvenanceOnline, enabled, w.Body.String(),
				)
			}
		})
	}
}

func TestAPIServerAIDiscoveryLeasePinsOneService(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	first := &inventory.ContinuousDiscoveryService{}
	second := &inventory.ContinuousDiscoveryService{}
	api.SetAIDiscoveryService(first)

	got, release := api.leaseAIDiscovery()
	if got != first {
		release()
		t.Fatalf("leased service = %p, want first %p", got, first)
	}
	if api.aiDiscoveryMu.TryLock() {
		api.aiDiscoveryMu.Unlock()
		release()
		t.Fatal("discovery writer lock succeeded while handler lease was active")
	}
	release()
	if !api.aiDiscoveryMu.TryLock() {
		t.Fatal("discovery writer lock remained blocked after handler lease release")
	}
	api.aiDiscoveryMu.Unlock()

	api.SetAIDiscoveryService(second)
	got, release = api.leaseAIDiscovery()
	defer release()
	if got != second {
		t.Fatalf("leased service after swap = %p, want second %p", got, second)
	}
}

func TestAPIServerAIDiscoveryConcurrentSwapAndUsage(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	services := []*inventory.ContinuousDiscoveryService{{}, {}}
	api.SetAIDiscoveryService(services[0])

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			api.SetAIDiscoveryService(services[i%len(services)])
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage", nil)
			w := httptest.NewRecorder()
			api.handleAIUsage(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("iteration %d: status = %d, want 200", i, w.Code)
				return
			}
		}
	}()
	wg.Wait()
}

func TestHandleAIUsageDiscoveryRejectsRawPath(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	service := inventory.NewContinuousDiscoveryServiceWithOptions(
		inventory.AIDiscoveryOptions{Enabled: true, DataDir: t.TempDir()},
		nil,
	)
	t.Cleanup(func() {
		if closed, err := service.CloseIfNeverStarted(); err != nil || !closed {
			t.Errorf("close prepared AI discovery service = (%t, %v), want (true, nil)", closed, err)
		}
	})
	api.SetAIDiscoveryService(service)
	body := `{
	  "summary": {"scan_id":"scan-1"},
	  "signals": [{"category":"ai_cli","state":"new","basenames":["/tmp/raw"]}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai-usage/discovery", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.handleAIUsageDiscovery(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestHandleAIUsageRedactsStoredRawPaths(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	rawPath := filepath.Join(home, ".raw-ai", "config.json")
	if err := os.MkdirAll(filepath.Dir(rawPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(rawPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	svc := inventory.NewContinuousDiscoveryServiceWithOptions(
		inventory.AIDiscoveryOptions{
			Enabled:                 true,
			Mode:                    "enhanced",
			DataDir:                 filepath.Join(tmp, "data"),
			HomeDir:                 home,
			ScanRoots:               []string{home},
			IncludeShellHistory:     false,
			IncludePackageManifests: false,
			IncludeEnvVarNames:      false,
			IncludeNetworkDomains:   false,
			StoreRawLocalPaths:      true,
		},
		[]inventory.AISignature{{
			ID:          "raw-ai-config",
			Name:        "Raw AI",
			Vendor:      "Example",
			Category:    inventory.SignalWorkspaceArtifact,
			ConfigPaths: []string{"~/.raw-ai/config.json"},
		}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 2*time.Second)
	report, err := svc.ScanNow(scanCtx)
	scanCancel()
	if err != nil {
		t.Fatalf("ScanNow: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("discovery service did not stop")
	}
	var sawRaw bool
	for _, sig := range report.Signals {
		for _, ev := range sig.Evidence {
			if ev.RawPath == rawPath {
				sawRaw = true
			}
		}
	}
	if !sawRaw {
		t.Fatalf("test setup did not retain raw path in local report: %+v", report.Signals)
	}

	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.SetAIDiscoveryService(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage", nil)
	w := httptest.NewRecorder()

	api.handleAIUsage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), rawPath) || strings.Contains(w.Body.String(), `"raw_path"`) {
		t.Fatalf("usage API leaked raw path with redaction enabled: %s", w.Body.String())
	}
}
