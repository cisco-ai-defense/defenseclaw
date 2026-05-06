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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
}

func TestHandleAIUsageDiscoveryRejectsRawPath(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.SetAIDiscoveryService(inventory.NewContinuousDiscoveryServiceWithOptions(
		inventory.AIDiscoveryOptions{Enabled: true, DataDir: t.TempDir(), EmitOTel: false},
		nil,
		nil,
		nil,
	))
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
			DisableRedaction:        false,
			EmitOTel:                false,
		},
		[]inventory.AISignature{{
			ID:          "raw-ai-config",
			Name:        "Raw AI",
			Vendor:      "Example",
			Category:    inventory.SignalWorkspaceArtifact,
			ConfigPaths: []string{"~/.raw-ai/config.json"},
		}},
		nil,
		nil,
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
