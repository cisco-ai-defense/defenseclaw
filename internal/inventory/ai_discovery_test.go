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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

func TestLoadAISignaturesWithManagedPackAndDisabledIDs(t *testing.T) {
	tmp := t.TempDir()
	packDir := filepath.Join(tmp, "signature-packs")
	mustWrite(t, filepath.Join(packDir, "custom.json"), `{
  "version": 1,
  "signatures": [{
    "id": "custom-ai",
    "name": "Custom AI",
    "vendor": "Example",
    "category": "ai_cli",
    "confidence": 0.7,
    "binary_names": ["custom-ai"]
  }]
}`)

	sigs, err := LoadAISignaturesWithOptions(AISignatureLoadOptions{
		DataDir:              tmp,
		DisabledSignatureIDs: []string{"codex"},
	})
	if err != nil {
		t.Fatalf("LoadAISignaturesWithOptions: %v", err)
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		seen[sig.ID] = true
	}
	if !seen["custom-ai"] {
		t.Fatalf("custom pack signature missing")
	}
	if seen["codex"] {
		t.Fatalf("disabled built-in signature still present")
	}
}

func TestLoadAISignaturesWithOptionsRejectsDuplicatePackID(t *testing.T) {
	tmp := t.TempDir()
	mustWrite(t, filepath.Join(tmp, "signature-packs", "dup.json"), `{
  "version": 1,
  "signatures": [{
    "id": "codex",
    "name": "Codex Duplicate",
    "vendor": "Example",
    "category": "ai_cli",
    "confidence": 0.7
  }]
}`)

	_, err := LoadAISignaturesWithOptions(AISignatureLoadOptions{DataDir: tmp})
	if err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestLoadAISignaturesWorkspacePackRequiresOptIn(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	mustWrite(t, filepath.Join(workspace, ".defenseclaw", "ai-signatures.json"), `{
  "version": 1,
  "signatures": [{
    "id": "workspace-ai",
    "name": "Workspace AI",
    "vendor": "Example",
    "category": "workspace_artifact",
    "confidence": 0.6,
    "config_paths": [".workspace-ai"]
  }]
}`)

	without, err := LoadAISignaturesWithOptions(AISignatureLoadOptions{ScanRoots: []string{workspace}})
	if err != nil {
		t.Fatalf("without workspace opt-in: %v", err)
	}
	for _, sig := range without {
		if sig.ID == "workspace-ai" {
			t.Fatalf("workspace signature loaded without opt-in")
		}
	}
	with, err := LoadAISignaturesWithOptions(AISignatureLoadOptions{
		ScanRoots:                []string{workspace},
		AllowWorkspaceSignatures: true,
	})
	if err != nil {
		t.Fatalf("with workspace opt-in: %v", err)
	}
	var found bool
	for _, sig := range with {
		found = found || sig.ID == "workspace-ai"
	}
	if !found {
		t.Fatalf("workspace signature not loaded with opt-in")
	}
}

func TestNewContinuousDiscoveryServiceUsesConfiguredSignaturePacks(t *testing.T) {
	tmp := t.TempDir()
	mustWrite(t, filepath.Join(tmp, "signature-packs", "custom.json"), `{
  "version": 1,
  "signatures": [{
    "id": "custom-sidecar-ai",
    "name": "Custom Sidecar AI",
    "vendor": "Example",
    "category": "ai_cli",
    "confidence": 0.8
  }]
}`)
	cfg := &config.Config{
		DataDir: tmp,
		AIDiscovery: config.AIDiscoveryConfig{
			Enabled: true,
		},
	}
	svc, err := NewContinuousDiscoveryService(cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewContinuousDiscoveryService: %v", err)
	}
	if svc == nil {
		t.Fatal("service nil")
	}
	var found bool
	for _, sig := range svc.catalog {
		found = found || sig.ID == "custom-sidecar-ai"
	}
	if !found {
		t.Fatalf("configured signature pack not loaded into service catalog")
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

func TestContinuousDiscoveryLoadsConfiguredConfidencePolicy(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "confidence.yaml")
	mustWrite(t, policyPath, `
detectors:
  package_manifest:
    identity_lr: 7
    presence_lr: 11
`)

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:              true,
		DataDir:              filepath.Join(tmp, "data"),
		HomeDir:              filepath.Join(tmp, "home"),
		ConfidencePolicyPath: policyPath,
		EmitOTel:             false,
	}, nil, nil, nil)

	policy := svc.ConfidenceParams().Policy
	if got := policy.Detectors["package_manifest"].IdentityLR; got != 7 {
		t.Fatalf("package_manifest identity_lr = %v, want override 7", got)
	}
	if got := policy.Detectors["process"].IdentityLR; got <= 0 {
		t.Fatalf("process detector should fall back to embedded default, got %v", got)
	}
}

func TestMatchManifestEntryRequiresParsedDependencyForComponent(t *testing.T) {
	svc := &ContinuousDiscoveryService{
		catalog: []AISignature{{
			ID:           "vercel-ai",
			Name:         "AI SDKs",
			Vendor:       "Multiple",
			Category:     SignalPackageDependency,
			PackageNames: []string{"ai"},
			Components: []AISignatureComponent{{
				Ecosystem: "npm",
				Name:      "ai",
				Framework: "Vercel AI SDK",
				Vendor:    "Vercel",
			}},
		}},
	}
	entry := pkgManifestEntry{
		path:      "/workspace/package.json",
		basename:  "package.json",
		body:      `{"name":"rainbow-ai","scripts":{"postinstall":"echo ai"}}`,
		bodyLower: `{"name":"rainbow-ai","scripts":{"postinstall":"echo ai"}}`,
		pathHash:  hashPath("/workspace/package.json"),
		wsHash:    hashPath("/workspace"),
		ecosystem: "npm",
	}

	if got := svc.matchManifestEntry(entry, nil); len(got) != 0 {
		t.Fatalf("substring-only component match produced %d signals: %+v", len(got), got)
	}

	entry.parsedComponents = map[string]map[string]string{"npm": {"ai": "4.0.0"}}
	got := svc.matchManifestEntry(entry, map[string]map[string]string{"npm": {"ai": "4.0.0"}})
	if len(got) != 1 {
		t.Fatalf("parsed dependency match produced %d signals, want 1: %+v", len(got), got)
	}
	if got[0].Component == nil || got[0].Component.Name != "ai" || got[0].Component.Version != "4.0.0" {
		t.Fatalf("resolved component mismatch: %+v", got[0].Component)
	}
	if got[0].Product != "Vercel AI SDK" || got[0].Vendor != "Vercel" {
		t.Fatalf("component framework/vendor not applied: product=%q vendor=%q", got[0].Product, got[0].Vendor)
	}
	if len(got[0].Evidence) != 1 || got[0].Evidence[0].MatchKind != MatchKindExact {
		t.Fatalf("component evidence should be exact: %+v", got[0].Evidence)
	}
}

// TestContinuousDiscoveryShellHistoryFingerprintIsStable pins the M-2
// invariant: appending more shell commands to the same history file
// must not change the fingerprint of an existing signal. The previous
// implementation hashed the full history tail into the evidence ID, so
// every additional command shifted the fingerprint and downstream
// dedup / "since-last-seen" alerting broke. Identity is now derived
// from (signature, pattern, history file) only.
func TestContinuousDiscoveryShellHistoryFingerprintIsStable(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	dataDir := filepath.Join(tmp, "data")
	historyPath := filepath.Join(home, ".zsh_history")
	mustWrite(t, historyPath, "openai chat --model gpt-4\n")

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:             true,
		Mode:                "enhanced",
		IncludeShellHistory: true,
		DataDir:             dataDir,
		HomeDir:             home,
		EmitOTel:            false,
		MaxFilesPerScan:     20,
		MaxFileBytes:        64 * 1024,
	}, []AISignature{testAISignature()}, nil, nil)

	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first runScan: %v", err)
	}
	var firstFP string
	for _, sig := range first.Signals {
		if sig.Detector == "shell_history" {
			firstFP = sig.Fingerprint
			break
		}
	}
	if firstFP == "" {
		t.Fatalf("first scan produced no shell_history signal: %+v", first.Signals)
	}

	// Append unrelated commands — these must NOT change the fingerprint
	// because the detection identity is independent of churn in the
	// surrounding history.
	for i := 0; i < 25; i++ {
		f, err := os.OpenFile(historyPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open history: %v", err)
		}
		if _, err := f.WriteString("ls -la /tmp\n"); err != nil {
			t.Fatalf("write history: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close history: %v", err)
		}
	}
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("second runScan: %v", err)
	}
	var secondFP string
	for _, sig := range second.Signals {
		if sig.Detector == "shell_history" {
			secondFP = sig.Fingerprint
			break
		}
	}
	if secondFP == "" {
		t.Fatalf("second scan produced no shell_history signal: %+v", second.Signals)
	}
	if firstFP != secondFP {
		t.Fatalf("shell_history fingerprint churned across scans: first=%s second=%s", firstFP, secondFP)
	}
	// And the second scan must NOT report it as a fresh detection.
	if second.Summary.NewSignals != 0 {
		t.Fatalf("second scan reported NewSignals=%d, want 0 (history churn must not look like a new detection)", second.Summary.NewSignals)
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

// TestDetectLocalEndpoints_PrefersHEADToAvoidTriggeringInference pins
// M-3 part 1: when the local AI server accepts HEAD on a metadata path,
// detectLocalEndpoints MUST NOT issue a GET. A GET against a custom /
// misconfigured pack endpoint could trigger inference, billing, or PII
// logging on the local server.
func TestDetectLocalEndpoints_PrefersHEADToAvoidTriggeringInference(t *testing.T) {
	var sawGet bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			sawGet = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
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

	if _, err := svc.runScan(context.Background(), true, "test"); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if sawGet {
		t.Fatalf("detectLocalEndpoints issued a GET when HEAD was accepted; this can trigger inference on the local server")
	}
}

// TestDetectLocalEndpoints_FallsBackToGETWhenHEADUnsupported pins M-3
// part 2: when HEAD returns 405, detectLocalEndpoints falls back to GET
// — but only on a path that's been explicitly cleared as
// metadata-only (here, /v1/models from safeLocalEndpointPaths).
func TestDetectLocalEndpoints_FallsBackToGETWhenHEADUnsupported(t *testing.T) {
	var sawGet bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			sawGet = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
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
	if !sawGet {
		t.Fatal("detectLocalEndpoints did not fall back to GET when HEAD returned 405")
	}
	var found bool
	for _, sig := range report.Signals {
		if sig.Category == SignalLocalAIEndpoint {
			found = true
		}
	}
	if !found {
		t.Fatalf("local endpoint signal missing after HEAD->GET fallback: %+v", report.Signals)
	}
}

// TestDetectLocalEndpoints_SkipsPathsOutsideAllowList pins M-3 part 3:
// an operator-supplied signature pack that declares a custom path
// (e.g. /v1/chat/completions) MUST be silently skipped. We only probe
// vendor-cleared metadata paths to prevent surprise inference triggers,
// even if the path happens to live on a loopback host.
func TestDetectLocalEndpoints_SkipsPathsOutsideAllowList(t *testing.T) {
	var probed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tmp := t.TempDir()
	sig := testAISignature()
	sig.LocalEndpoints = []string{
		server.URL + "/v1/chat/completions", // NOT in safeLocalEndpointPaths
		server.URL + "/admin/restart",       // NOT in safeLocalEndpointPaths
	}
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

	if _, err := svc.runScan(context.Background(), true, "test"); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if probed {
		t.Fatal("detectLocalEndpoints probed a path outside the safe allow-list")
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

// TestIngestExternalReport_ForcesExternalSourceAttribution pins M-5:
// a malicious CLI cannot forge sidecar-attributed signals by sending
// summary.source = "sidecar" / signals[].source = "sidecar". External
// reports are force-attributed to AISourceExternal before any
// telemetry / audit fanout runs.
func TestIngestExternalReport_ForcesExternalSourceAttribution(t *testing.T) {
	tmp := t.TempDir()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:  true,
		Mode:     "enhanced",
		DataDir:  filepath.Join(tmp, "data"),
		HomeDir:  filepath.Join(tmp, "home"),
		EmitOTel: false,
	}, []AISignature{testAISignature()}, nil, nil)

	// CLI is sending us a forged report claiming the sidecar produced it.
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID: "scan-forged",
			Source: "sidecar", // attacker claim
		},
		Signals: []AISignal{{
			Fingerprint: "fp-1",
			SignatureID: "shadowai",
			Category:    SignalAICLI,
			State:       AIStateSeen,
			Detector:    "config_path",
			Source:      "sidecar", // attacker claim
		}},
	}
	if err := svc.IngestExternalReport(context.Background(), &report); err != nil {
		t.Fatalf("IngestExternalReport: %v", err)
	}
	// IngestExternalReport rewrites the source fields in place — that's
	// the contract callers (and downstream telemetry) rely on.
	if report.Summary.Source != AISourceExternal {
		t.Errorf("summary.source = %q, want %q (CLI MUST NOT be able to forge sidecar attribution)", report.Summary.Source, AISourceExternal)
	}
	if got := report.Signals[0].Source; got != AISourceExternal {
		t.Errorf("signal.source = %q, want %q", got, AISourceExternal)
	}
}

// TestRunScan_NonFullTickShipsFullInventoryConsistentWithSummary
// pins the Bug A fix: on a process-only ticker tick, the API
// payload must still expose every active fingerprint (so the
// summary.active_signals count and len(report.Signals) agree).
//
// Pre-fix, classifyAndPersist built `out` from `signals` (this
// tick only) while `current` (the merged inventory) carried the
// full state. summary.ActiveSignals tracked `current` but the
// API/CLI iterated `out`, producing a 4-vs-755 mismatch the
// operator saw as "header says 755 active, table only renders
// 4 rows".
func TestRunScan_NonFullTickShipsFullInventoryConsistentWithSummary(t *testing.T) {
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

	// 1) Full scan: detect the config-path signal so it lands in
	//    the persisted inventory.
	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first runScan: %v", err)
	}
	if first.Summary.ActiveSignals != 1 || len(first.Signals) != 1 {
		t.Fatalf("full-scan baseline drifted: active=%d signals=%d", first.Summary.ActiveSignals, len(first.Signals))
	}
	configFP := first.Signals[0].Fingerprint

	// 2) Non-full tick: process detector runs but finds no
	//    matching processes (no binary named "shadowai" running
	//    in the test process tree). Pre-fix, len(report.Signals)
	//    would be 0 even though summary.ActiveSignals stayed at
	//    1 from the merged map.
	second, err := svc.runScan(context.Background(), false, "process_tick")
	if err != nil {
		t.Fatalf("non-full runScan: %v", err)
	}
	if second.Summary.ActiveSignals != len(second.Signals) {
		t.Fatalf("Bug A regression: non-full tick summary.active_signals=%d but len(report.Signals)=%d (must match)",
			second.Summary.ActiveSignals, len(second.Signals))
	}
	// The carried-forward config signal must be present and
	// state=seen so OTel/events emitters (which trigger on
	// new/changed/gone) don't replay lifecycle events on every
	// 5s tick.
	var foundCarried bool
	for _, sig := range second.Signals {
		if sig.Fingerprint != configFP {
			continue
		}
		foundCarried = true
		if sig.State != AIStateSeen {
			t.Fatalf("carried-forward signal must be state=seen on non-full tick to avoid OTel replay; got %q", sig.State)
		}
	}
	if !foundCarried {
		t.Fatalf("carried-forward fingerprint %q missing from non-full tick payload", configFP)
	}
	// summary.NewSignals/ChangedSignals must also stay zero --
	// the non-full tick didn't actually re-detect the config
	// signal, so it shouldn't be re-classified as new/changed.
	if second.Summary.NewSignals != 0 || second.Summary.ChangedSignals != 0 {
		t.Fatalf("non-full tick must not re-fire lifecycle classification: new=%d changed=%d",
			second.Summary.NewSignals, second.Summary.ChangedSignals)
	}
}

// TestEnrichSignalsWithComponentConfidence pins the Bug B fix:
// `/api/v1/ai-usage` and `/api/v1/ai-usage/scan` must stamp the
// per-component identity / presence scores on each signal so
// `defenseclaw agent usage --detail` can render the same
// confidence numbers `/api/v1/ai-usage/components` returns
// without a second round-trip.
//
// This test exercises the engine wiring directly (the gateway
// handlers are thin shims over EnrichSignalsWithComponentConfidence)
// and asserts:
//   - Signals with a Component block get IdentityScore/Band +
//     PresenceScore/Band populated.
//   - Signals without a Component block stay zero (so omitempty
//     hides them on the wire and legacy CLIs don't see noise).
//   - Bands fall in the documented enum so the CLI's case-style
//     formatter never sees an unknown value.
func TestEnrichSignalsWithComponentConfidence(t *testing.T) {
	now := time.Now()
	signals := []AISignal{
		{
			Fingerprint: "fp-with-component",
			Product:     "Vercel AI SDK",
			Vendor:      "Vercel",
			Detector:    "package_dependency",
			Category:    SignalPackageDependency,
			State:       AIStateSeen,
			LastSeen:    now,
			Component: &AIComponent{
				Ecosystem: "npm",
				Name:      "ai",
				Version:   "3.0.0",
			},
			Evidence: []AIEvidence{{
				Type:      "package_dependency",
				MatchKind: MatchKindExact,
				Quality:   0.9,
			}},
		},
		{
			Fingerprint: "fp-process-no-component",
			Product:     "Claude Code",
			Vendor:      "Anthropic",
			Detector:    "process",
			Category:    SignalActiveProcess,
			State:       AIStateSeen,
			LastSeen:    now,
		},
	}
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("load default policy: %v", err)
	}
	params := ConfidenceParams{Policy: policy}
	EnrichSignalsWithComponentConfidence(signals, params)

	withComp := signals[0]
	if withComp.IdentityScore <= 0 || withComp.IdentityScore > 1 {
		t.Fatalf("IdentityScore out of (0,1]: got %v", withComp.IdentityScore)
	}
	if withComp.PresenceScore < 0 || withComp.PresenceScore > 1 {
		t.Fatalf("PresenceScore out of [0,1]: got %v", withComp.PresenceScore)
	}
	if withComp.IdentityBand == "" || withComp.PresenceBand == "" {
		t.Fatalf("bands must populate when scores are present: identity=%q presence=%q",
			withComp.IdentityBand, withComp.PresenceBand)
	}
	allowedBands := map[string]bool{
		"very_high": true, "high": true, "medium": true, "low": true, "very_low": true,
	}
	if !allowedBands[withComp.IdentityBand] {
		t.Fatalf("IdentityBand %q outside enum", withComp.IdentityBand)
	}
	if !allowedBands[withComp.PresenceBand] {
		t.Fatalf("PresenceBand %q outside enum", withComp.PresenceBand)
	}

	// Per-product enrichment: signals without a component now
	// score via their (vendor, product) key so the API / CLI /
	// TUI can show confidence on Claude Code / Cursor / Codex
	// rows the same way they do for SDK rows. The legacy
	// behavior (zero on the wire) was the bug, not the goal --
	// operators wanted to know "how sure are you this Anthropic
	// process is Claude Code?", and the engine has always had
	// the math to answer.
	noComp := signals[1]
	if noComp.IdentityScore <= 0 || noComp.IdentityScore > 1 {
		t.Fatalf("Claude Code (no component) IdentityScore out of (0,1]: got %v", noComp.IdentityScore)
	}
	if noComp.PresenceScore < 0 || noComp.PresenceScore > 1 {
		t.Fatalf("Claude Code (no component) PresenceScore out of [0,1]: got %v", noComp.PresenceScore)
	}
	if noComp.IdentityBand == "" || noComp.PresenceBand == "" {
		t.Fatalf("Claude Code (no component) must get bands too: identity=%q presence=%q",
			noComp.IdentityBand, noComp.PresenceBand)
	}
	if !allowedBands[noComp.IdentityBand] {
		t.Fatalf("IdentityBand %q outside enum", noComp.IdentityBand)
	}
	if !allowedBands[noComp.PresenceBand] {
		t.Fatalf("PresenceBand %q outside enum", noComp.PresenceBand)
	}

	// Empty input must not panic / mutate (defensive: API
	// handlers call this on every request, including for
	// totally-empty snapshots while the discovery loop is
	// initialising).
	EnrichSignalsWithComponentConfidence(nil, params)
	EnrichSignalsWithComponentConfidence([]AISignal{}, params)
}

func TestEnrichSignalsWithComponentConfidence_ProductRollup(t *testing.T) {
	// Real-world Claude Code shape: independently surfaced by
	// 7 detectors (binary, process, mcp, config, shell_history,
	// provider_history, application), all sharing
	// (vendor=Anthropic, product=Claude Code), none carrying a
	// Component block. After enrichment EVERY row must carry
	// the same score because they all map to one product
	// rollup -- if downstream renderers see drift between rows
	// of the same product, the dedup-after-first-row logic in
	// the CLI / TUI prints inconsistent numbers.
	now := time.Now()
	mk := func(fp, det, cat string) AISignal {
		return AISignal{
			Fingerprint: fp,
			Vendor:      "Anthropic",
			Product:     "Claude Code",
			Detector:    det,
			Category:    cat,
			State:       AIStateSeen,
			LastSeen:    now,
			Confidence:  0.9,
		}
	}
	signals := []AISignal{
		mk("fp-bin", "binary", SignalAICLI),
		mk("fp-proc", "process", SignalActiveProcess),
		mk("fp-mcp", "mcp", "mcp_server"),
		mk("fp-cfg", "config", "supported_app"),
		mk("fp-sh", "shell_history", "shell_history"),
		// A different product from the same vendor MUST get
		// its own score (vendor is part of the key but so is
		// product; collapsing them would be a bug).
		{
			Fingerprint: "fp-cd-proc",
			Vendor:      "Anthropic",
			Product:     "Claude Desktop",
			Detector:    "process",
			Category:    SignalActiveProcess,
			State:       AIStateSeen,
			LastSeen:    now,
			Confidence:  0.9,
		},
		// Catch-all signal with empty product MUST stay
		// un-enriched (engine has no stable identity to score
		// against, omitempty hides it on the wire).
		{
			Fingerprint: "fp-empty",
			Vendor:      "Anthropic",
			Product:     "",
			Detector:    "process",
			State:       AIStateSeen,
			LastSeen:    now,
		},
	}
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	EnrichSignalsWithComponentConfidence(signals, ConfidenceParams{Policy: policy})

	// Every Claude Code row MUST carry the same score (one
	// engine call per product, stamped on all members).
	wantIdentity := signals[0].IdentityScore
	wantPresence := signals[0].PresenceScore
	if wantIdentity <= 0 || wantPresence <= 0 {
		t.Fatalf("Claude Code rollup must produce non-zero scores; got id=%v pr=%v",
			wantIdentity, wantPresence)
	}
	for i := 1; i < 5; i++ {
		if signals[i].IdentityScore != wantIdentity {
			t.Fatalf("Claude Code rows must share identity (got [0]=%v vs [%d]=%v)",
				wantIdentity, i, signals[i].IdentityScore)
		}
		if signals[i].PresenceScore != wantPresence {
			t.Fatalf("Claude Code rows must share presence (got [0]=%v vs [%d]=%v)",
				wantPresence, i, signals[i].PresenceScore)
		}
	}

	// Claude Desktop is a DIFFERENT product (same vendor) and
	// MUST score independently. We don't pin an exact value
	// (the engine math may evolve) -- we just assert that the
	// score lands AND is independent of the Claude Code score.
	cd := signals[5]
	if cd.IdentityScore <= 0 || cd.PresenceScore <= 0 {
		t.Fatalf("Claude Desktop must get its own non-zero score; got %+v", cd)
	}
	if cd.IdentityBand == "" || cd.PresenceBand == "" {
		t.Fatalf("Claude Desktop must get bands; got id=%q pr=%q",
			cd.IdentityBand, cd.PresenceBand)
	}

	// Empty product → no enrichment, omitempty hides it.
	empty := signals[6]
	if empty.IdentityScore != 0 || empty.IdentityBand != "" ||
		empty.PresenceScore != 0 || empty.PresenceBand != "" {
		t.Fatalf("signal with empty product MUST stay un-enriched; got %+v", empty)
	}
}

func TestEnrichSignalsWithComponentConfidence_DoesNotDoubleScoreComponent(t *testing.T) {
	// A signal that has BOTH a component AND a (vendor, product)
	// pair must score via the COMPONENT path only -- otherwise
	// the LR sum gets contributed twice and inflates the score.
	// Pin the component-only score, then add a parallel
	// product-keyed signal for a different product, and assert
	// the component score is unchanged.
	now := time.Now()
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	params := ConfidenceParams{Policy: policy}

	componentOnly := []AISignal{{
		Fingerprint: "fp-sdk",
		Product:     "Vercel AI SDK",
		Vendor:      "Vercel",
		Detector:    "package_dependency",
		Category:    SignalPackageDependency,
		State:       AIStateSeen,
		LastSeen:    now,
		Component:   &AIComponent{Ecosystem: "npm", Name: "ai", Version: "3.0.0"},
		Evidence:    []AIEvidence{{Type: "package_dependency", Quality: 0.9}},
	}}
	EnrichSignalsWithComponentConfidence(componentOnly, params)
	pinnedID := componentOnly[0].IdentityScore

	mixed := []AISignal{
		{
			Fingerprint: "fp-sdk",
			Product:     "Vercel AI SDK",
			Vendor:      "Vercel",
			Detector:    "package_dependency",
			Category:    SignalPackageDependency,
			State:       AIStateSeen,
			LastSeen:    now,
			Component:   &AIComponent{Ecosystem: "npm", Name: "ai", Version: "3.0.0"},
			Evidence:    []AIEvidence{{Type: "package_dependency", Quality: 0.9}},
		},
		{
			Fingerprint: "fp-cli",
			Product:     "Claude Code",
			Vendor:      "Anthropic",
			Detector:    "binary",
			Category:    SignalAICLI,
			State:       AIStateSeen,
			LastSeen:    now,
			Confidence:  0.9,
		},
	}
	EnrichSignalsWithComponentConfidence(mixed, params)
	if mixed[0].IdentityScore != pinnedID {
		t.Fatalf("component score MUST be invariant when product groups are added; pinned=%v got=%v",
			pinnedID, mixed[0].IdentityScore)
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

// TestResolveComponent_FallbackHonorsEcosystemHint pins the
// catalog-layer half of Fix A: when the caller passes a real
// ecosystem hint (because the manifest filename told us so),
// the second-pass ecosystem-agnostic fallback MUST stay off.
// Otherwise short package names like `ai` (npm) match against
// any ecosystem and we attribute a Cargo.toml hit to "Vercel
// AI SDK".
func TestResolveComponent_FallbackHonorsEcosystemHint(t *testing.T) {
	sig := AISignature{
		ID: "test",
		Components: []AISignatureComponent{
			{Ecosystem: "npm", Name: "ai", Framework: "Vercel AI SDK", Vendor: "Vercel"},
			{Ecosystem: "cargo", Name: "async-openai", Framework: "async-openai", Vendor: "OpenAI community"},
		},
	}
	if got := sig.resolveComponent("ai", "cargo"); got != nil {
		t.Fatalf("ecosystem hint cargo should NOT match npm-only `ai` component; got %+v", got)
	}
	if got := sig.resolveComponent("ai", "npm"); got == nil || got.Name != "ai" {
		t.Fatalf("npm hint must resolve npm `ai` component; got %+v", got)
	}
	if got := sig.resolveComponent("async-openai", "cargo"); got == nil || got.Name != "async-openai" {
		t.Fatalf("cargo hint must resolve cargo `async-openai` component; got %+v", got)
	}
	// When the caller can't determine the ecosystem (legacy
	// callers or scan paths that don't have a filename hint),
	// the agnostic fallback SHOULD still fire for sufficiently
	// long package names so packs that omit per-ecosystem
	// listings keep working.
	longNameSig := AISignature{
		ID: "test-long",
		Components: []AISignatureComponent{
			{Ecosystem: "npm", Name: "openai", Framework: "OpenAI TS", Vendor: "OpenAI"},
		},
	}
	if got := longNameSig.resolveComponent("openai", ""); got == nil || got.Name != "openai" {
		t.Fatalf("empty-ecosystem fallback must still match longer names; got %+v", got)
	}
	// But for SHORT names (≤3 chars) the fallback must stay off
	// even with no ecosystem hint -- this is what kills the
	// Dockerfile / docker-compose.yml false positives where
	// `lockparse.Ecosystem` returns "" and the body always
	// contains the substring "ai" via words like "main", "args",
	// "RUN apt install", etc.
	if got := sig.resolveComponent("ai", ""); got != nil {
		t.Fatalf("empty-ecosystem fallback MUST NOT match short names; got %+v", got)
	}
}

// TestProjectRootForManifest_WalksPastDependencyCacheSegments pins
// the Fix B helper that collapses transitive `node_modules/<dep>/
// package.json` records into one project-root wsHash.
func TestProjectRootForManifest_WalksPastDependencyCacheSegments(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{
			name: "node_modules nested two levels deep",
			path: "/u/me/proj/node_modules/foo/node_modules/bar/package.json",
			want: "/u/me/proj",
		},
		{
			name: "python site-packages collapses to project owning venv",
			path: "/u/me/proj/.venv/lib/python3.12/site-packages/openai/pyproject.toml",
			want: "/u/me/proj",
		},
		{
			name: "go vendor tree",
			path: "/u/me/proj/vendor/github.com/foo/bar/go.mod",
			want: "/u/me/proj",
		},
		{
			name: "cargo two-segment cache",
			path: "/u/me/.cargo/registry/src/index.crates.io-XXX/serde-1/Cargo.toml",
			want: "/u/me",
		},
		{
			name: "yarn two-segment cache",
			path: "/u/me/proj/.yarn/cache/foo-1.2.3/package.json",
			want: "/u/me/proj",
		},
		{
			name: "no cache segment falls back to manifest dir",
			path: "/u/me/proj/sub/package.json",
			want: "/u/me/proj/sub",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := projectRootForManifest(tc.path)
			if got != tc.want {
				t.Fatalf("projectRootForManifest(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestDetectPackageManifests_CrossEcosystemLeakRejected pins Fix A:
// an npm-only package name like `ai` substring-matches the body of
// a Cargo.toml file (which contains words like `mainly`, `available`
// etc.), but the catalog declares `ai` only as an npm component.
// Pre-fix the matcher fell through to a catch-all emit that
// attributed the Cargo.toml hit to "Vercel AI SDK". Post-fix the
// emit is suppressed: a component-bearing signature must resolve
// to a component for THIS ecosystem to fire.
func TestDetectPackageManifests_CrossEcosystemLeakRejected(t *testing.T) {
	tmp := t.TempDir()
	cargoToml := filepath.Join(tmp, "rustproj", "Cargo.toml")
	mustWrite(t, cargoToml, `[package]
name = "rustproj"
version = "0.1.0"

[dependencies]
serde = "1"
# This file MUST NOT match the npm "ai" package signature
# even though it contains the substring "ai" in words like
# "mainly" and "available".
mainly_for_demo = "0.1"
`)
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:         true,
		Mode:            "enhanced",
		DataDir:         filepath.Join(tmp, "data"),
		HomeDir:         tmp,
		ScanRoots:       []string{tmp},
		MaxFilesPerScan: 100,
		MaxFileBytes:    1 << 20,
		EmitOTel:        false,
	}, catalog, nil, nil)
	signals, _, err := svc.detectPackageManifests()
	if err != nil {
		t.Fatalf("detectPackageManifests: %v", err)
	}
	for _, sig := range signals {
		if strings.EqualFold(sig.Product, "Vercel AI SDK") {
			t.Fatalf("Fix A regression: Cargo.toml leaked into npm-only Vercel AI SDK signal: %+v", sig)
		}
		// More general guard: any component-bearing signal MUST
		// have an ecosystem matching the manifest it cites.
		if sig.Component == nil {
			continue
		}
		eco := strings.ToLower(sig.Component.Ecosystem)
		for _, bn := range sig.Basenames {
			switch strings.ToLower(bn) {
			case "cargo.toml", "cargo.lock":
				if eco != "cargo" {
					t.Fatalf("ecosystem leak: component=%s/%s emitted with %s evidence",
						sig.Component.Ecosystem, sig.Component.Name, bn)
				}
			case "pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock":
				if eco != "pypi" {
					t.Fatalf("ecosystem leak: component=%s/%s emitted with %s evidence",
						sig.Component.Ecosystem, sig.Component.Name, bn)
				}
			case "go.mod", "go.sum":
				if eco != "go" {
					t.Fatalf("ecosystem leak: component=%s/%s emitted with %s evidence",
						sig.Component.Ecosystem, sig.Component.Name, bn)
				}
			case "build.gradle.kts", "build.gradle", "pom.xml":
				if eco != "maven" {
					t.Fatalf("ecosystem leak: component=%s/%s emitted with %s evidence",
						sig.Component.Ecosystem, sig.Component.Name, bn)
				}
			}
		}
	}
}

// TestDetectPackageManifests_CollapsesTransitiveNodeModules pins Fix B:
// 50 transitive `node_modules/<dep>/package.json` files in one
// project that all depend on the npm `ai` package must collapse
// to ONE signal whose Evidence list carries every contributing
// manifest, not 50 near-identical signals with distinct fingerprints.
func TestDetectPackageManifests_CollapsesTransitiveNodeModules(t *testing.T) {
	tmp := t.TempDir()
	projRoot := filepath.Join(tmp, "myapp")
	// Top-level package.json declares `ai`.
	mustWrite(t, filepath.Join(projRoot, "package.json"), `{
  "name": "myapp",
  "dependencies": { "ai": "^3.0.0" }
}`)
	// 50 transitive deps in node_modules each ALSO declare a
	// dependency on `ai` in their own package.json. Pre-fix this
	// produced 51 signals (top-level + 50 transitive). Post-fix:
	// 1 signal with all 51 paths in Evidence.
	for i := 0; i < 50; i++ {
		dir := filepath.Join(projRoot, "node_modules", "transit"+strings.Repeat("x", i+1))
		mustWrite(t, filepath.Join(dir, "package.json"), `{
  "name": "transit",
  "dependencies": { "ai": "^3.0.0" }
}`)
	}
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:         true,
		Mode:            "enhanced",
		DataDir:         filepath.Join(tmp, "data"),
		HomeDir:         tmp,
		ScanRoots:       []string{tmp},
		MaxFilesPerScan: 1000,
		MaxFileBytes:    1 << 20,
		EmitOTel:        false,
	}, catalog, nil, nil)
	signals, _, err := svc.detectPackageManifests()
	if err != nil {
		t.Fatalf("detectPackageManifests: %v", err)
	}
	var aiSignals []AISignal
	for _, sig := range signals {
		if sig.Component != nil && strings.EqualFold(sig.Component.Name, "ai") &&
			strings.EqualFold(sig.Component.Ecosystem, "npm") {
			aiSignals = append(aiSignals, sig)
		}
	}
	if len(aiSignals) != 1 {
		t.Fatalf("Fix B regression: expected exactly 1 collapsed signal for ai (npm), got %d", len(aiSignals))
	}
	collapsed := aiSignals[0]
	// All 51 manifests must show up in PathHashes / Basenames
	// so the operator can still trace which files matched.
	if len(collapsed.PathHashes) != 51 {
		t.Fatalf("Fix B: collapsed signal missing path evidence: got %d unique paths, want 51",
			len(collapsed.PathHashes))
	}
	if len(collapsed.Basenames) == 0 || collapsed.Basenames[0] != "package.json" {
		t.Fatalf("Fix B: collapsed signal missing basename evidence: %+v", collapsed.Basenames)
	}
	// Fingerprint MUST be deterministic across reruns -- otherwise
	// the inventory store treats each scan as a brand-new signal
	// and lifecycle (`new` / `seen` / `gone`) tracking breaks.
	signals2, _, err := svc.detectPackageManifests()
	if err != nil {
		t.Fatalf("detectPackageManifests rerun: %v", err)
	}
	for _, sig := range signals2 {
		if sig.Component != nil && strings.EqualFold(sig.Component.Name, "ai") &&
			strings.EqualFold(sig.Component.Ecosystem, "npm") {
			if sig.Fingerprint != collapsed.Fingerprint {
				t.Fatalf("Fix B regression: fingerprint not deterministic across scans: %q vs %q",
					sig.Fingerprint, collapsed.Fingerprint)
			}
			break
		}
	}
}
