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

package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAISignatures_ContainsRequiredSurfaces(t *testing.T) {
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		seen[sig.ID] = true
	}
	for _, id := range []string{"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot", "ai-sdks"} {
		if !seen[id] {
			t.Fatalf("signature %q missing", id)
		}
	}
}

func TestContinuousDiscoveryDetectsEnhancedSignalsWithoutRawEvidence(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	workspace := filepath.Join(tmp, "workspace")
	dataDir := filepath.Join(tmp, "data")
	mustWrite(t, filepath.Join(home, ".shadowai", "config.json"), "{}")
	mustWrite(t, filepath.Join(home, ".zsh_history"), "openai chat --model test\n")
	mustWrite(t, filepath.Join(workspace, "package.json"), `{"dependencies":{"openai":"latest"}}`)
	t.Setenv("OPENAI_API_KEY", "not-emitted")

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:                 true,
		Mode:                    "enhanced",
		ScanRoots:               []string{workspace},
		IncludeShellHistory:     true,
		IncludePackageManifests: true,
		IncludeEnvVarNames:      true,
		IncludeNetworkDomains:   true,
		DataDir:                 dataDir,
		HomeDir:                 home,
		EmitOTel:                false,
		MaxFilesPerScan:         20,
		MaxFileBytes:            64 * 1024,
	}, []AISignature{testAISignature()}, nil, nil)

	report, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if report.Summary.ActiveSignals < 4 {
		t.Fatalf("ActiveSignals = %d, want at least 4; report=%+v", report.Summary.ActiveSignals, report.Signals)
	}
	if report.Summary.NewSignals < 4 {
		t.Fatalf("NewSignals = %d, want at least 4", report.Summary.NewSignals)
	}
	raw, _ := json.Marshal(report)
	wire := string(raw)
	if strings.Contains(wire, tmp) {
		t.Fatalf("sanitized report leaked raw temp path: %s", wire)
	}
	if strings.Contains(wire, "openai chat") || strings.Contains(wire, "not-emitted") {
		t.Fatalf("sanitized report leaked history command or env value: %s", wire)
	}
}

func TestContinuousDiscoveryFullScanEmitsGone(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	dataDir := filepath.Join(tmp, "data")
	cfgPath := filepath.Join(home, ".shadowai", "config.json")
	mustWrite(t, cfgPath, "{}")
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:  true,
		Mode:     "enhanced",
		DataDir:  dataDir,
		HomeDir:  home,
		EmitOTel: false,
	}, []AISignature{testAISignature()}, nil, nil)

	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first runScan: %v", err)
	}
	if first.Summary.NewSignals != 1 {
		t.Fatalf("first NewSignals = %d, want 1", first.Summary.NewSignals)
	}
	if err := os.Remove(cfgPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("second runScan: %v", err)
	}
	if second.Summary.GoneSignals != 1 {
		t.Fatalf("GoneSignals = %d, want 1", second.Summary.GoneSignals)
	}
	if len(second.Signals) != 1 || second.Signals[0].State != AIStateGone {
		t.Fatalf("gone signal missing: %+v", second.Signals)
	}
}

func TestContinuousDiscoveryDetectsLoopbackEndpointWithoutRawURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	tmp := t.TempDir()
	sig := testAISignature()
	sig.LocalEndpoints = []string{server.URL + "/v1/models"}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:               true,
		Mode:                  "enhanced",
		IncludeNetworkDomains: true,
		DataDir:               filepath.Join(tmp, "data"),
		HomeDir:               filepath.Join(tmp, "home"),
		EmitOTel:              false,
		MaxFilesPerScan:       20,
		MaxFileBytes:          64 * 1024,
	}, []AISignature{sig}, nil, nil)

	report, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	var found bool
	for _, sig := range report.Signals {
		if sig.Category == SignalLocalAIEndpoint {
			found = true
		}
	}
	if !found {
		t.Fatalf("local endpoint signal missing: %+v", report.Signals)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), server.URL) {
		t.Fatalf("sanitized report leaked raw local endpoint URL: %s", raw)
	}
}

func TestProcessNameMatchesShortNamesExactly(t *testing.T) {
	if processNameMatches("quicklookd", "q") {
		t.Fatal("short process name matched by substring")
	}
	if !processNameMatches("q", "q") {
		t.Fatal("short process name did not match exactly")
	}
	if !processNameMatches("helper-claude", "claude") {
		t.Fatal("long process name should allow substring matching")
	}
}

func TestValidateSanitizedAIDiscoveryReportRejectsRawPath(t *testing.T) {
	err := ValidateSanitizedAIDiscoveryReport(AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-1"},
		Signals: []AISignal{{
			Category:  SignalAICLI,
			State:     AIStateNew,
			Basenames: []string{"/Users/alice/.codex/config.toml"},
		}},
	})
	if err == nil {
		t.Fatal("expected raw path rejection")
	}
}

func testAISignature() AISignature {
	return AISignature{
		ID:              "shadowai",
		Name:            "ShadowAI",
		Vendor:          "Example",
		Category:        SignalAICLI,
		Confidence:      0.9,
		ConfigPaths:     []string{"~/.shadowai/config.json"},
		PackageNames:    []string{"openai"},
		EnvVarNames:     []string{"OPENAI_API_KEY"},
		HistoryPatterns: []string{"openai"},
		DomainPatterns:  []string{"api.openai.com"},
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
