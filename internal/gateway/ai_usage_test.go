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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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

// A managed computer whose config leaves AI discovery off answers the IDE
// plugin view with the reason and the administrator config key, not a bare
// enabled:false (GAP-0611).
func TestIDEPluginsWithDiscoveryOffSayWhyOnAManagedComputer(t *testing.T) {
	withManagedEnterprise(t, true)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	w := httptest.NewRecorder()
	api.handleAIUsageIDEPlugins(w, httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage/ide-plugins", nil))
	var body struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Enabled ||
		!strings.Contains(body.Reason, "ai_discovery.enabled: true") || strings.Contains(body.Reason, "agent discovery enable") {
		t.Fatalf("answer = %s (%v), want enabled false with the managed config hint", w.Body.String(), err)
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
	// Windows also scans machine-wide Visual Studio extensions; keep the
	// scan off the runner's own installation.
	t.Setenv("ProgramFiles", tmp)
	t.Setenv("ProgramFiles(x86)", tmp)
	home := filepath.Join(tmp, "home")
	rawPath := filepath.Join(home, ".raw-ai", "config.json")
	if err := os.MkdirAll(filepath.Dir(rawPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(rawPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	extensions := filepath.Join(home, ".vscode", "extensions")
	if err := os.MkdirAll(extensions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extensions, "extensions.json"), []byte(`[{"identifier":{"id":"example.raw-ai"},"version":"1.0.0","relativeLocation":"example.raw-ai-1.0.0"},{"identifier":{"id":"example.other"},"version":"2.0.0"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cursorExtensions := filepath.Join(home, ".cursor", "extensions")
	if err := os.MkdirAll(cursorExtensions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cursorExtensions, "extensions.json"), []byte(`[{"identifier":{"id":"example.other"},"version":"2.0.0"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := inventory.NewContinuousDiscoveryServiceWithOptions(
		inventory.AIDiscoveryOptions{
			Enabled:                 true,
			Mode:                    "enhanced",
			ProcessInterval:         50 * time.Millisecond,
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
			ID:           "raw-ai-config",
			Name:         "Raw AI",
			Vendor:       "Example",
			Category:     inventory.SignalWorkspaceArtifact,
			ConfigPaths:  []string{"~/.raw-ai/config.json"},
			ExtensionIDs: []string{"example.raw-ai"},
		}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	// A hang guard, not a latency budget: a full scan on a loaded Windows
	// runner still reads the account's real AppData.
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 30*time.Second)
	report, err := svc.ScanNow(scanCtx)
	scanCancel()
	if err != nil {
		t.Fatalf("ScanNow: %v", err)
	}
	// The process tick replaces the general snapshot while keeping the
	// full scan's IDE inventory. The endpoint must name the latter.
	deadline := time.Now().Add(10 * time.Second)
	for svc.Snapshot().Summary.ScanID == report.Summary.ScanID && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if svc.Snapshot().Summary.ScanID == report.Summary.ScanID {
		t.Fatal("process tick did not replace the general snapshot")
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

	// The IDE plugin list pages through the full inventory, filters to AI
	// plugins on request, counts the filtered rows (GAP-0096), keeps only the
	// installations holding an AI plugin under ai_only (GAP-0104), and
	// carries paths only as hashes.
	w = httptest.NewRecorder()
	api.handleAIUsageIDEPlugins(w, httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage/ide-plugins?limit=1", nil))
	var page struct {
		ScanID        string                       `json:"scan_id"`
		Total         int                          `json:"total"`
		NextCursor    string                       `json:"next_cursor"`
		Counts        inventory.IDEInventoryCounts `json:"counts"`
		Installations []inventory.IDEInstallation  `json:"installations"`
		Plugins       []inventory.IDEPlugin        `json:"plugins"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != http.StatusOK {
		t.Fatalf("ide-plugins = %d %s", w.Code, w.Body.String())
	}
	if page.ScanID != report.Summary.ScanID || page.Total != 3 || page.Counts.Total != 3 || page.Counts.Installations != 2 || len(page.Installations) != 2 || page.NextCursor != "1" || len(page.Plugins) != 1 || strings.Contains(w.Body.String(), home) {
		t.Fatalf("ide-plugins page = %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	api.handleAIUsageIDEPlugins(w, httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage/ide-plugins?ai_only=true", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Total != 1 || page.Counts.Total != 1 || page.Counts.AI != 1 || page.Counts.Installations != 1 || len(page.Installations) != 1 || page.Installations[0].Product != "vscode" || page.Plugins[0].PluginID != "example.raw-ai" || !page.Plugins[0].IsAI {
		t.Fatalf("ai_only = %s", w.Body.String())
	}
}

// GAP-0051/GAP-0079: --ide vscode selects VS Code, not its forks; a bare
// account name selects DOMAIN\name rows and a DOMAIN\name filter selects
// bare-name rows; a Windows transcript keeps its backslashes in the install
// hint.
func TestIDEPluginFiltersAndInstallHintKeepWindowsSpelling(t *testing.T) {
	if ideFilterMatches("vscode", "vscode", "cursor") || !ideFilterMatches("vscode", "vscode", "vscode") ||
		!ideFilterMatches("jetbrains", "jetbrains", "pycharm") {
		t.Fatal("ide filter must match products, and families only when the family is not a product")
	}
	if !useridentity.AccountFilterMatches("dcad-alice", "S-1-5-21-1", `DCLAB\dcad-alice`) || useridentity.AccountFilterMatches("bob", "S-1-5-21-1", `DCLAB\dcad-alice`) {
		t.Fatal("user filter must accept the account name without its domain")
	}
	if !useridentity.AccountFilterMatches(`DCLAB\dcad-alice`, "S-1-5-21-1", "dcad-alice") || useridentity.AccountFilterMatches("bob", "S-1-5-21-1", "dcad-alice") {
		t.Fatal("user filter must accept the account name with its domain")
	}
	hint := claimedInstallHint(map[string]interface{}{"transcript_path": `C:\Users\dcad-alice\altcfg\projects\p\s.jsonl`})
	if hint != `C:\Users\dcad-alice\altcfg` {
		t.Fatalf("install hint = %q", hint)
	}
}

func TestSecureClientDiscoveryRejectsIDEInventoryMember(t *testing.T) {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	service := inventory.NewContinuousDiscoveryServiceWithOptions(
		inventory.AIDiscoveryOptions{Enabled: true, DataDir: t.TempDir(), SecureClient: true}, nil)
	t.Cleanup(func() { _, _ = service.CloseIfNeverStarted() })
	api.SetAIDiscoveryService(service)
	body := `{"summary":{"scan_id":"scan-1"},"signals":[],"ide_inventory":{"scope":"all","installations":[],"plugins":[]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai-usage/discovery", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.handleAIUsageDiscovery(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid JSON body") {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}
