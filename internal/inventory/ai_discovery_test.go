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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func cleanupPreparedDiscoveryService(t *testing.T, svc *ContinuousDiscoveryService) {
	t.Helper()
	t.Cleanup(func() {
		if closed, err := svc.CloseIfNeverStarted(); err != nil || !closed {
			t.Errorf("close prepared AI discovery service = (%t, %v), want (true, nil)", closed, err)
		}
	})
}

func TestContinuousDiscoveryServiceRunClosesInventoryStoreAcrossRestarts(t *testing.T) {
	dataDir := t.TempDir()
	homeDir := t.TempDir()

	for restart := 0; restart < 3; restart++ {
		svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
			DataDir:         dataDir,
			HomeDir:         homeDir,
			ScanRoots:       []string{homeDir},
			ScanInterval:    time.Hour,
			ProcessInterval: time.Hour,
		}, nil)
		store := svc.InventoryStore()
		if store == nil {
			t.Fatalf("restart %d: inventory store was not opened", restart)
		}
		if _, err := store.SchemaVersion(); err != nil {
			t.Fatalf("restart %d: inventory store unusable before Run: %v", restart, err)
		}
		if open := store.db.Stats().OpenConnections; open == 0 {
			t.Fatalf("restart %d: inventory store did not retain an open pool before Run", restart)
		}

		startupComplete := make(chan struct{}, 1)
		svc.AddReportObserver(func(context.Context, AIDiscoveryReport) {
			select {
			case startupComplete <- struct{}{}:
			default:
			}
		})
		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- svc.Run(ctx) }()
		select {
		case <-startupComplete:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("restart %d: startup scan did not complete", restart)
		}
		cancel()
		var runErr error
		select {
		case runErr = <-runDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("restart %d: Run did not stop after cancellation", restart)
		}
		if err := runErr; !errors.Is(err, context.Canceled) {
			t.Fatalf("restart %d: Run error = %v, want context.Canceled", restart, err)
		}
		if open := store.db.Stats().OpenConnections; open != 0 {
			t.Fatalf("restart %d: inventory DB retained %d open connections after Run", restart, open)
		}
		if _, err := store.SchemaVersion(); err == nil {
			t.Fatalf("restart %d: inventory DB still accepted queries after Run", restart)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("restart %d: repeated Close was not idempotent: %v", restart, err)
		}
	}
}

func TestContinuousDiscoveryServiceCloseIfNeverStartedAndClaimRun(t *testing.T) {
	newService := func(dataDir string) (*ContinuousDiscoveryService, *InventoryStore) {
		t.Helper()
		svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
			DataDir:         dataDir,
			HomeDir:         t.TempDir(),
			ScanRoots:       []string{t.TempDir()},
			ScanInterval:    time.Hour,
			ProcessInterval: time.Hour,
		}, nil)
		store := svc.InventoryStore()
		if store == nil {
			t.Fatal("inventory store was not opened")
		}
		if _, err := store.SchemaVersion(); err != nil {
			t.Fatalf("inventory store unusable before lifecycle transition: %v", err)
		}
		return svc, store
	}

	dataDir := t.TempDir()
	prepared, preparedStore := newService(dataDir)
	closed, err := prepared.CloseIfNeverStarted()
	if err != nil || !closed {
		t.Fatalf("CloseIfNeverStarted() = (%v, %v), want (true, nil)", closed, err)
	}
	if open := preparedStore.db.Stats().OpenConnections; open != 0 {
		t.Fatalf("prepared service retained %d open connections", open)
	}
	if err := prepared.Run(context.Background()); err == nil {
		t.Fatal("closed prepared service unexpectedly started")
	}

	claimed, claimedStore := newService(dataDir)
	runner, ok := claimed.ClaimRun()
	if !ok || runner == nil {
		t.Fatal("ClaimRun did not reserve prepared service")
	}
	if closed, err := claimed.CloseIfNeverStarted(); err != nil || closed {
		t.Fatalf("claimed CloseIfNeverStarted() = (%v, %v), want (false, nil)", closed, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("claimed runner error = %v, want context.Canceled", err)
	}
	if open := claimedStore.db.Stats().OpenConnections; open != 0 {
		t.Fatalf("claimed service retained %d open connections after Run", open)
	}
}

func TestLoadAISignatures_ContainsRequiredSurfaces(t *testing.T) {
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		seen[sig.ID] = true
	}
	for _, id := range []string{"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent", "ai-sdks", "lemonade"} {
		if !seen[id] {
			t.Fatalf("signature %q missing", id)
		}
	}
}

func TestLoadAISignatures_CoversRequestedProductCatalog(t *testing.T) {
	type requiredProduct struct {
		label     string
		id        string
		connector string
	}
	required := []requiredProduct{
		{label: "Cursor", id: "cursor", connector: "cursor"},
		{label: "GitHub Copilot CLI", id: "copilot", connector: "copilot"},
		{label: "ChatGPT Desktop", id: "chatgpt-desktop"},
		{label: "Claude Code", id: "claudecode", connector: "claudecode"},
		{label: "OpenAI Codex", id: "codex", connector: "codex"},
		{label: "Ollama", id: "ollama"},
		{label: "Gemini CLI", id: "geminicli", connector: "geminicli"},
		{label: "Claude Desktop", id: "claude-desktop"},
		{label: "Notion", id: "notion"},
		{label: "Perplexity Comet", id: "perplexity-comet"},
		{label: "Cline CLI", id: "cline"},
		{label: "Continue CLI", id: "continue"},
		{label: "Aider", id: "aider"},
		{label: "Zed", id: "zed"},
		{label: "Warp", id: "warp"},
		{label: "LM Studio", id: "lmstudio"},
		{label: "Replit Agent", id: "replit"},
		{label: "Raycast", id: "raycast"},
		{label: "GPT4All", id: "gpt4all"},
		{label: "Devin", id: "devin"},
		{label: "Sourcegraph Cody CLI", id: "cody"},
		{label: "Google Antigravity", id: "antigravity", connector: "antigravity"},
		{label: "Goose", id: "goose"},
		{label: "Open WebUI", id: "open-webui"},
		{label: "AnythingLLM", id: "anythingllm"},
		{label: "Jan AI", id: "jan"},
		{label: "LobeChat", id: "lobechat"},
		{label: "Qwen Code", id: "qwen-code"},
		{label: "llama.cpp", id: "llamacpp"},
		{label: "Trae", id: "trae"},
		{label: "OpenHands", id: "openhands", connector: "openhands"},
		{label: "Pieces for Developers", id: "pieces"},
		{label: "Amp", id: "amp"},
		{label: "Void", id: "void"},
		{label: "Kiro CLI", id: "kiro"},
		{label: "Auggie (Augment Code CLI)", id: "auggie"},
		{label: "Plandex CLI", id: "plandex"},
		{label: "SWE-agent", id: "swe-agent"},
		{label: "KoboldCpp", id: "koboldcpp"},
		{label: "LocalAI", id: "localai"},
		{label: "Pinokio", id: "pinokio"},
		{label: "Mistral Vibe", id: "mistral-vibe"},
		{label: "Crush", id: "crush"},
		{label: "GPTScript", id: "gptscript"},
		{label: "Docker Agent", id: "docker-agent"},
		{label: "Msty", id: "msty"},
		{label: "BoltAI", id: "boltai"},
		{label: "UiPath Assistant", id: "uipath-assistant"},
		{label: "Wave Terminal", id: "wave-terminal"},
		{label: "Tabby Terminal", id: "tabby-terminal"},
		{label: "UI-TARS Desktop", id: "ui-tars-desktop"},
		{label: "Backyard AI", id: "backyard-ai"},
		{label: "Dia Browser", id: "dia-browser"},
		{label: "BrowserOS", id: "browseros"},
		{label: "opencode", id: "opencode", connector: "opencode"},
		{label: "RA.Aid", id: "ra-aid"},
		{label: "Chat2DB", id: "chat2db"},
		{label: "monday.com Desktop", id: "monday-desktop"},
		{label: "Eigent", id: "eigent"},
		{label: "Melty", id: "melty"},
		{label: "bloop", id: "bloop"},
		{label: "Forge", id: "forge"},
		{label: "Sculptor", id: "sculptor"},
		{label: "Crab Code", id: "crab-code"},
		{label: "cmux", id: "cmux"},
		{label: "opcode", id: "opcode"},
		{label: "Smelt", id: "smelt"},
		{label: "klaw", id: "klaw"},
		{label: "Agent Deck", id: "agent-deck"},
		{label: "Agent of Empires", id: "agent-of-empires"},
		{label: "Agent! for macOS", id: "agent-macos"},
		{label: "BetterBot", id: "betterbot"},
		{label: "Cyclop One", id: "cyclop-one"},
		{label: "Fazm", id: "fazm"},
		{label: "OpenClaw", id: "openclaw", connector: "openclaw"},
		{label: "Zia Search", id: "zia-search"},
	}
	if got, want := len(required), 76; got != want {
		t.Fatalf("requested product fixture has %d entries, want %d", got, want)
	}
	requestedIDs := make(map[string]string, len(required))
	for _, product := range required {
		if previous, duplicate := requestedIDs[product.id]; duplicate {
			t.Fatalf("requested products %q and %q share signature ID %q", previous, product.label, product.id)
		}
		requestedIDs[product.id] = product.label
	}

	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	byID := make(map[string]AISignature, len(sigs))
	for _, sig := range sigs {
		byID[sig.ID] = sig
	}
	for _, want := range required {
		sig, ok := byID[want.id]
		if !ok {
			t.Errorf("requested product %q is missing signature %q", want.label, want.id)
			continue
		}
		if sig.SupportedConnector != want.connector {
			t.Errorf("requested product %q connector = %q, want %q", want.label, sig.SupportedConnector, want.connector)
		}
		concreteEvidence := len(sig.BinaryNames) + len(sig.ProcessNames) + len(sig.ApplicationNames) +
			len(sig.ConfigPaths) + len(sig.ExtensionIDs) + len(sig.MCPPaths) + len(sig.PackageNames) +
			len(sig.EnvVarNames) + len(sig.LocalEndpoints)
		if concreteEvidence == 0 {
			t.Errorf("requested product %q signature %q has no concrete local discovery evidence", want.label, want.id)
		}
	}

	raw, err := aiSignatureFS.ReadFile("ai_signatures.json")
	if err != nil {
		t.Fatalf("read built-in AI discovery catalog: %v", err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "spiffe://") {
		t.Fatal("built-in AI discovery catalog must not embed SPIFFE identities")
	}
}

func TestContinuousDiscoveryCopilotBinaryIgnoresPlainGitHubCLI(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("executable PATH fixture uses Unix permission bits")
	}

	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	var copilot *AISignature
	for i := range sigs {
		if sigs[i].ID == "copilot" {
			copilot = &sigs[i]
			break
		}
	}
	if copilot == nil {
		t.Fatal("copilot signature missing")
	}

	binDir := t.TempDir()
	ghPath := filepath.Join(binDir, "gh")
	mustWrite(t, ghPath, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(ghPath, 0o700); err != nil {
		t.Fatalf("chmod gh fixture: %v", err)
	}
	t.Setenv("PATH", binDir)

	svc := &ContinuousDiscoveryService{catalog: []AISignature{*copilot}}
	if got := svc.detectBinaries(); len(got) != 0 {
		t.Fatalf("plain gh executable produced Copilot signals: %+v", got)
	}

	copilotPath := filepath.Join(binDir, "copilot")
	mustWrite(t, copilotPath, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(copilotPath, 0o700); err != nil {
		t.Fatalf("chmod copilot fixture: %v", err)
	}
	got := svc.detectBinaries()
	if len(got) != 1 || got[0].SignatureID != "copilot" || got[0].Detector != "binary" {
		t.Fatalf("standalone copilot executable produced unexpected signals: %+v", got)
	}
}

func TestContinuousDiscoveryDetectsRequestedCLIConfigFixtures(t *testing.T) {
	home := t.TempDir()
	fixtures := []struct {
		id       string
		relative string
	}{
		{id: "amp", relative: ".config/amp/settings.json"},
		{id: "kiro", relative: ".kiro/settings/cli.json"},
		{id: "auggie", relative: ".augment/settings.json"},
		{id: "mistral-vibe", relative: ".vibe/config.toml"},
		{id: "crush", relative: ".config/crush/crush.json"},
	}

	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	wanted := make(map[string]bool, len(fixtures))
	for _, fixture := range fixtures {
		wanted[fixture.id] = true
		mustWrite(t, filepath.Join(home, filepath.FromSlash(fixture.relative)), "{}")
	}
	var catalog []AISignature
	for _, sig := range sigs {
		if wanted[sig.ID] {
			catalog = append(catalog, sig)
		}
	}
	if len(catalog) != len(fixtures) {
		t.Fatalf("loaded %d requested CLI fixture signatures, want %d", len(catalog), len(fixtures))
	}

	svc := &ContinuousDiscoveryService{
		opts:    AIDiscoveryOptions{HomeDir: home},
		catalog: catalog,
	}
	detected := make(map[string]bool, len(fixtures))
	for _, signal := range svc.detectConfigPaths() {
		detected[signal.SignatureID] = true
	}
	for _, fixture := range fixtures {
		if !detected[fixture.id] {
			t.Errorf("config fixture %q did not detect signature %q", fixture.relative, fixture.id)
		}
	}
}

func TestEditorExtensionNameMatchesExactOrVersionedDirectory(t *testing.T) {
	for _, entry := range []string{"github.copilot", "github.copilot-1.320.0"} {
		if !editorExtensionNameMatches(entry, "github.copilot") {
			t.Errorf("expected %q to match the GitHub Copilot extension ID", entry)
		}
	}
	for _, entry := range []string{"fake-github.copilot-wrapper", "github.copilot-chat"} {
		if editorExtensionNameMatches(entry, "github.copilot") {
			t.Errorf("unexpected substring extension match for %q", entry)
		}
	}
}

func TestApplicationNameMatchesExactOrReverseDNSName(t *testing.T) {
	for _, tc := range []struct {
		have string
		want string
	}{
		{have: "Notion.app", want: "Notion.app"},
		{have: "dev.zed.Zed.desktop", want: "Zed.app"},
		{have: "Cursor.lnk", want: "Cursor.app"},
		{have: "Claude.app.lnk", want: "Claude.app"},
		{have: "LM Studio.exe", want: "LM Studio"},
		{have: "Jan.appref-ms", want: "Jan.app"},
		{have: "package-id:OpenAI.ChatGPT-Desktop", want: "package-id:OpenAI.ChatGPT-Desktop"},
	} {
		if !applicationNameMatches(tc.have, tc.want) {
			t.Errorf("expected application %q to match %q", tc.have, tc.want)
		}
	}
	for _, tc := range []struct {
		have string
		want string
	}{
		{have: "Notion Calendar.app", want: "Notion.app"},
		{have: "WaveSomething.desktop", want: "Wave.app"},
		{have: "Cursor Helper.exe", want: "Cursor.app"},
		{have: "package-id:Fake.OpenAI.ChatGPT-Desktop", want: "package-id:OpenAI.ChatGPT-Desktop"},
	} {
		if applicationNameMatches(tc.have, tc.want) {
			t.Errorf("unexpected substring application match: %q matched %q", tc.have, tc.want)
		}
	}
}

func TestLoadAISignatures_LemonadeServerSurface(t *testing.T) {
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	var lemonade *AISignature
	for i := range sigs {
		if sigs[i].ID == "lemonade" {
			lemonade = &sigs[i]
			break
		}
	}
	if lemonade == nil {
		t.Fatal("lemonade signature missing")
	}
	if lemonade.Name != "Lemonade Server" || lemonade.Vendor != "Lemonade" || lemonade.Category != SignalAICLI {
		t.Fatalf("lemonade identity mismatch: %+v", *lemonade)
	}

	assertContains := func(field string, values []string, expected ...string) {
		t.Helper()
		seen := make(map[string]bool, len(values))
		for _, value := range values {
			seen[value] = true
		}
		for _, want := range expected {
			if !seen[want] {
				t.Errorf("lemonade %s missing %q: %v", field, want, values)
			}
		}
	}
	assertContains("binary_names", lemonade.BinaryNames, "lemonade", "lemond", "lemonade-tray", "LemonadeServer.exe")
	assertContains("process_names", lemonade.ProcessNames, "lemonade", "lemond", "lemonade-tray", "LemonadeServer.exe")
	assertContains("application_names", lemonade.ApplicationNames, "Lemonade.app", "Lemonade")
	assertContains("config_paths", lemonade.ConfigPaths,
		"~/.cache/lemonade/config.json",
		"/Library/Application Support/lemonade/.cache/config.json",
		"/var/lib/lemonade/.cache/lemonade/config.json",
		"/opt/var/lib/lemonade/.cache/lemonade/config.json",
	)
	assertContains("env_var_names", lemonade.EnvVarNames,
		"LEMONADE_HOST", "LEMONADE_PORT", "LEMONADE_CACHE_DIR", "LEMONADE_API_KEY", "LEMONADE_ADMIN_API_KEY",
	)
	for _, generic := range []string{"HF_HOME", "HF_HUB_CACHE", "FLM_MODEL_PATH"} {
		if slices.Contains(lemonade.EnvVarNames, generic) {
			t.Errorf("lemonade env_var_names contains generic model-cache variable %q", generic)
		}
	}
	assertContains("domain_patterns", lemonade.DomainPatterns, "localhost:13305", "127.0.0.1:13305")
	assertContains("history_patterns", lemonade.HistoryPatterns, "lemonade", "lemond")
	assertContains("local_endpoints", lemonade.LocalEndpoints,
		"http://127.0.0.1:13305/live",
		"http://127.0.0.1:13305/v1/models",
		"http://127.0.0.1:13305/api/v1/models",
		"http://127.0.0.1:13305/v1/health",
		"http://127.0.0.1:13305/api/v1/health",
	)
}

func TestHermesSignatureIncludesNativeWindowsPaths(t *testing.T) {
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	var hermes *AISignature
	for i := range sigs {
		if sigs[i].ID == "hermes" {
			hermes = &sigs[i]
			break
		}
	}
	if hermes == nil {
		t.Fatal("Hermes signature missing")
	}
	for _, want := range []string{
		"$HERMES_HOME/config.yaml",
		"$LOCALAPPDATA/hermes/config.yaml",
		"~/.hermes/config.yaml",
	} {
		if !stringSliceContains(hermes.ConfigPaths, want) {
			t.Errorf("Hermes config paths missing %q: %v", want, hermes.ConfigPaths)
		}
		if !stringSliceContains(hermes.MCPPaths, want) {
			t.Errorf("Hermes MCP paths missing %q: %v", want, hermes.MCPPaths)
		}
	}
	if !stringSliceContains(hermes.EnvVarNames, "HERMES_HOME") {
		t.Errorf("Hermes environment variables missing HERMES_HOME: %v", hermes.EnvVarNames)
	}
}

func TestDesktopSignaturesIncludeNativeWindowsPaths(t *testing.T) {
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	byID := make(map[string]AISignature, len(sigs))
	for _, sig := range sigs {
		byID[sig.ID] = sig
	}
	wants := map[string][]string{
		"claude-desktop": {"$APPDATA/Claude/claude_desktop_config.json"},
		"jan":            {"$APPDATA/Jan/data"},
		"msty":           {"$APPDATA/Msty"},
		"wave-terminal":  {"$APPDATA/waveterm"},
		"gpt4all":        {"$LOCALAPPDATA/nomic.ai/GPT4All"},
		"anythingllm":    {"$APPDATA/anythingllm-desktop/storage"},
	}
	for id, paths := range wants {
		sig, ok := byID[id]
		if !ok {
			t.Errorf("signature %q missing", id)
			continue
		}
		for _, want := range paths {
			if !stringSliceContains(sig.ConfigPaths, want) {
				t.Errorf("%s config paths missing %q: %v", id, want, sig.ConfigPaths)
			}
		}
	}
	claude := byID["claude-desktop"]
	if !stringSliceContains(claude.MCPPaths, "$APPDATA/Claude/claude_desktop_config.json") {
		t.Errorf("claude-desktop MCP paths missing native Windows config: %v", claude.MCPPaths)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestExpandCandidatePath_ExpandsConfiguredEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OMNIGENT_CONFIG_HOME", root)
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: t.TempDir()}}

	got := service.expandCandidatePath("$OMNIGENT_CONFIG_HOME/config.yaml")
	want := filepath.Join(root, "config.yaml")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expanded paths = %v, want [%s]", got, want)
	}
}

func TestExpandCandidatePath_SkipsUnsetEnvironment(t *testing.T) {
	previous, wasSet := os.LookupEnv("OMNIGENT_CONFIG_HOME")
	if err := os.Unsetenv("OMNIGENT_CONFIG_HOME"); err != nil {
		t.Fatalf("unset OMNIGENT_CONFIG_HOME: %v", err)
	}
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv("OMNIGENT_CONFIG_HOME", previous)
		} else {
			_ = os.Unsetenv("OMNIGENT_CONFIG_HOME")
		}
	})
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: t.TempDir()}}

	if got := service.expandCandidatePath("$OMNIGENT_CONFIG_HOME/config.yaml"); got != nil {
		t.Fatalf("expanded paths = %v, want nil for unset environment", got)
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
	svc, err := NewContinuousDiscoveryService(cfg)
	if err != nil {
		t.Fatalf("NewContinuousDiscoveryService: %v", err)
	}
	if svc == nil {
		t.Fatal("service nil")
	}
	cleanupPreparedDiscoveryService(t, svc)
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
		MaxFilesPerScan:         20,
		MaxFileBytes:            64 * 1024,
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)

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
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

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
		MaxFilesPerScan:     20,
		MaxFileBytes:        64 * 1024,
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)

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
		Enabled: true,
		Mode:    "enhanced",
		DataDir: dataDir,
		HomeDir: home,
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)

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
		MaxFilesPerScan:       20,
		MaxFileBytes:          64 * 1024,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

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
		MaxFilesPerScan:       20,
		MaxFileBytes:          64 * 1024,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

	// Exercise the presence detector directly. A full scan now also runs the
	// separate local-model inventory detector, which intentionally performs a
	// bounded GET of this vetted metadata path to enumerate model IDs.
	if got := svc.detectLocalEndpoints(); len(got) != 1 {
		t.Fatalf("detectLocalEndpoints signals = %d, want 1", len(got))
	}
	if sawGet {
		t.Fatalf("detectLocalEndpoints issued a GET when HEAD was accepted; this can trigger inference on the local server")
	}
}

func TestDetectLocalEndpoints_LemonadeRequiresSuccessfulLive(t *testing.T) {
	for _, tc := range []struct {
		name       string
		liveStatus int
		want       int
	}{
		{name: "unrelated listener", liveStatus: http.StatusNotFound, want: 0},
		{name: "lemonade live", liveStatus: http.StatusOK, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/live":
					w.WriteHeader(tc.liveStatus)
				case "/v1/models":
					// A generic OpenAI-compatible listener alone must not be
					// attributed to Lemonade.
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			t.Setenv("LEMONADE_HOST", "")
			t.Setenv("LEMONADE_PORT", "")
			t.Setenv("LEMONADE_CACHE_DIR", t.TempDir())
			sig := AISignature{
				ID:             "lemonade",
				Name:           "Lemonade Server",
				Vendor:         "Lemonade",
				Category:       SignalAICLI,
				Confidence:     0.95,
				LocalEndpoints: []string{server.URL + "/v1/models"},
			}
			svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
				Enabled: true, Mode: "enhanced", DataDir: t.TempDir(), HomeDir: t.TempDir(),
			}, []AISignature{sig})
			cleanupPreparedDiscoveryService(t, svc)

			if got := len(svc.detectLocalEndpoints()); got != tc.want {
				t.Fatalf("Lemonade endpoint signals = %d, want %d", got, tc.want)
			}
		})
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
		MaxFilesPerScan:       20,
		MaxFileBytes:          64 * 1024,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

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
		MaxFilesPerScan:       20,
		MaxFileBytes:          64 * 1024,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

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
		Enabled: true,
		Mode:    "enhanced",
		DataDir: filepath.Join(tmp, "data"),
		HomeDir: filepath.Join(tmp, "home"),
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)

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

func TestIngestExternalReport_DoesNotNotifyAutomationObservers(t *testing.T) {
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		Mode:    "enhanced",
		DataDir: t.TempDir(),
		HomeDir: t.TempDir(),
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)
	called := make(chan struct{}, 1)
	svc.AddReportObserver(func(context.Context, AIDiscoveryReport) { called <- struct{}{} })
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "external-scan"},
		Signals: []AISignal{{
			Fingerprint: "fp-1",
			SignatureID: "shadowai",
			Category:    SignalAICLI,
			State:       AIStateSeen,
			Detector:    "config_path",
		}},
	}
	if err := svc.IngestExternalReport(context.Background(), &report); err != nil {
		t.Fatalf("IngestExternalReport: %v", err)
	}
	select {
	case <-called:
		t.Fatal("external report reached application-protection observer")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestIngestExternalReportRecomputesModelProvenance(t *testing.T) {
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: t.TempDir(), HomeDir: t.TempDir(),
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "external-model"},
		Signals: []AISignal{{
			Category: SignalLocalModel, State: AIStateSeen,
			Model: &LocalModelInfo{
				ID: "Qwen/Qwen3-4B", Status: "installed",
				Provenance: &LocalModelProvenance{
					Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/Llama-3",
					Source: "catalog_exact", Confidence: "high",
				},
			},
		}},
	}
	if err := svc.IngestExternalReport(context.Background(), &report); err != nil {
		t.Fatalf("IngestExternalReport: %v", err)
	}
	got := report.Signals[0].Model.Provenance
	if got == nil || got.Publisher != "Alibaba Cloud" || got.CountryCode != "CN" || got.RootModel != "Qwen/Qwen3-4B" {
		t.Fatalf("external provenance was trusted instead of recomputed: %+v", got)
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
		Enabled: true,
		Mode:    "enhanced",
		DataDir: dataDir,
		HomeDir: home,
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)

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

func TestCarryForwardAccumulatorModelAPIRules(t *testing.T) {
	const fingerprint = "model-api-fingerprint"
	old := aiStoredSignal{AISignal: AISignal{
		Fingerprint:        fingerprint,
		Detector:           "model_api",
		ModelAPISourceHash: "source-hash",
		Model:              &LocalModelInfo{Provider: "test-provider"},
	}}
	coverageKey, ok := storedModelAPICoverageKey(old)
	if !ok {
		t.Fatal("test model did not produce an API coverage key")
	}
	newAccumulator := func() (carryForwardAccumulator, *[]AISignal) {
		out := []AISignal{}
		return carryForwardAccumulator{
			current:    map[string]aiStoredSignal{},
			out:        &out,
			counts:     map[string]int{},
			emittedFps: map[string]bool{},
		}, &out
	}

	t.Run("deferred source carries", func(t *testing.T) {
		carry, out := newAccumulator()
		budget := 1
		handled := carry.handleModelAPICarryForward(fingerprint, old, scanStats{
			ModelAPIDeferred: map[string]bool{coverageKey: true},
		}, &budget)
		if !handled || budget != 0 || len(*out) != 1 || carry.current[fingerprint].State != AIStateSeen {
			t.Fatalf("deferred carry = handled:%v budget:%d out:%d stored:%+v", handled, budget, len(*out), carry.current)
		}
	})

	t.Run("attempted failure consumes grace", func(t *testing.T) {
		carry, _ := newAccumulator()
		budget := 1
		handled := carry.handleModelAPICarryForward(fingerprint, old, scanStats{
			ModelAPIAttempted: map[string]bool{coverageKey: true},
		}, &budget)
		if !handled || carry.current[fingerprint].ModelAPIMisses != 1 {
			t.Fatalf("attempted carry = handled:%v stored:%+v", handled, carry.current[fingerprint])
		}
	})

	t.Run("miss limit falls through", func(t *testing.T) {
		carry, out := newAccumulator()
		budget := 1
		atLimit := old
		atLimit.ModelAPIMisses = maxIndeterminateModelAPIMisses
		handled := carry.handleModelAPICarryForward(fingerprint, atLimit, scanStats{
			ModelAPIAttempted: map[string]bool{coverageKey: true},
		}, &budget)
		if handled || budget != 1 || len(*out) != 0 || len(carry.current) != 0 {
			t.Fatalf("at-limit carry = handled:%v budget:%d out:%d stored:%+v", handled, budget, len(*out), carry.current)
		}
	})

	t.Run("completed cycle membership carries and clears misses", func(t *testing.T) {
		carry, _ := newAccumulator()
		budget := 1
		missed := old
		missed.ModelAPIMisses = 1
		handled := carry.handleModelAPICarryForward(fingerprint, missed, scanStats{
			ModelAPIConclusive: map[string]bool{coverageKey: true},
			ModelAPICycleSeen: map[string]map[string]struct{}{
				coverageKey: {fingerprint: {}},
			},
		}, &budget)
		if !handled || carry.current[fingerprint].ModelAPIMisses != 0 {
			t.Fatalf("completed-cycle carry = handled:%v stored:%+v", handled, carry.current[fingerprint])
		}
	})

	t.Run("completed cycle absence falls through", func(t *testing.T) {
		carry, _ := newAccumulator()
		budget := 1
		handled := carry.handleModelAPICarryForward(fingerprint, old, scanStats{
			ModelAPIConclusive: map[string]bool{coverageKey: true},
			ModelAPICycleSeen:  map[string]map[string]struct{}{coverageKey: {}},
		}, &budget)
		if handled {
			t.Fatal("model absent from a completed cycle was carried")
		}
	})

	t.Run("exhausted budget suppresses unsupported gone", func(t *testing.T) {
		carry, out := newAccumulator()
		budget := 0
		handled := carry.handleModelAPICarryForward(fingerprint, old, scanStats{
			ModelAPIDeferred: map[string]bool{coverageKey: true},
		}, &budget)
		if !handled || len(*out) != 0 || len(carry.current) != 0 {
			t.Fatalf("budget-zero carry = handled:%v out:%d stored:%+v", handled, len(*out), carry.current)
		}
	})

	t.Run("completed membership respects exhausted budget", func(t *testing.T) {
		carry, out := newAccumulator()
		budget := 0
		handled := carry.handleModelAPICarryForward(fingerprint, old, scanStats{
			ModelAPIConclusive: map[string]bool{coverageKey: true},
			ModelAPICycleSeen: map[string]map[string]struct{}{
				coverageKey: {fingerprint: {}},
			},
		}, &budget)
		if !handled || len(*out) != 0 || len(carry.current) != 0 {
			t.Fatalf("budget-zero completed carry = handled:%v out:%d stored:%+v", handled, len(*out), carry.current)
		}
	})
}

func TestCarryForwardAccumulatorModelFileRules(t *testing.T) {
	const fingerprint = "model-file-fingerprint"
	old := aiStoredSignal{AISignal: AISignal{
		Fingerprint:   fingerprint,
		Detector:      "model_file",
		WorkspaceHash: "root-hash",
		Model:         &LocalModelInfo{Format: "gguf"},
	}}
	newAccumulator := func() (carryForwardAccumulator, *[]AISignal) {
		out := []AISignal{}
		return carryForwardAccumulator{
			current:    map[string]aiStoredSignal{},
			out:        &out,
			counts:     map[string]int{},
			emittedFps: map[string]bool{},
		}, &out
	}

	t.Run("deferred root carries", func(t *testing.T) {
		carry, out := newAccumulator()
		budget := 1
		handled := carry.handleModelFileCarryForward(fingerprint, old, scanStats{
			ModelFileDeferred: map[string]bool{"root-hash": true},
		}, &budget)
		if !handled || budget != 0 || len(*out) != 1 || carry.current[fingerprint].State != AIStateSeen {
			t.Fatalf("file carry = handled:%v budget:%d out:%d stored:%+v", handled, budget, len(*out), carry.current)
		}
	})

	t.Run("conclusive root falls through", func(t *testing.T) {
		carry, _ := newAccumulator()
		budget := 1
		if carry.handleModelFileCarryForward(fingerprint, old, scanStats{}, &budget) {
			t.Fatal("model from a non-deferred root was carried")
		}
	})

	t.Run("exhausted budget suppresses unsupported gone", func(t *testing.T) {
		carry, out := newAccumulator()
		budget := 0
		handled := carry.handleModelFileCarryForward(fingerprint, old, scanStats{
			ModelFileDeferred: map[string]bool{"root-hash": true},
		}, &budget)
		if !handled || len(*out) != 0 || len(carry.current) != 0 {
			t.Fatalf("budget-zero file carry = handled:%v out:%d stored:%+v", handled, len(*out), carry.current)
		}
	})
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

func TestValidateSanitizedAIDiscoveryReportValidatesModelMetadata(t *testing.T) {
	base := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-model"},
		Signals: []AISignal{{
			Category: SignalLocalModel,
			Model: &LocalModelInfo{
				ID: "Qwen3-0.6B-GGUF", Status: "installed", Format: "gguf",
				Provenance: &LocalModelProvenance{
					Publisher: "Alibaba Cloud", CountryCode: "CN", RootModel: "Qwen/Qwen3-0.6B",
					Quantized: modelBool(true), Quantization: "Q4_K_M", Derivation: "quantized",
					Source: "catalog_family", Confidence: "medium",
				},
			},
		}},
	}
	if err := ValidateSanitizedAIDiscoveryReport(base); err != nil {
		t.Fatalf("valid model metadata rejected: %v", err)
	}

	badStatus := cloneAIDiscoveryReport(base)
	badStatus.Signals[0].Model.Status = "executing"
	if err := ValidateSanitizedAIDiscoveryReport(badStatus); err == nil {
		t.Fatal("unsupported model status accepted")
	}

	badID := cloneAIDiscoveryReport(base)
	badID.Signals[0].Model.ID = "private\nmodel"
	if err := ValidateSanitizedAIDiscoveryReport(badID); err == nil {
		t.Fatal("model id containing control characters accepted")
	}
	badUnicodeControl := cloneAIDiscoveryReport(base)
	badUnicodeControl.Signals[0].Model.ID = "private\u009bmodel"
	if err := ValidateSanitizedAIDiscoveryReport(badUnicodeControl); err == nil {
		t.Fatal("model id containing a Unicode C1 control accepted")
	}

	badCountry := cloneAIDiscoveryReport(base)
	badCountry.Signals[0].Model.Provenance.CountryCode = "ZZ"
	if err := ValidateSanitizedAIDiscoveryReport(badCountry); err == nil {
		t.Fatal("unsupported model provenance country code accepted")
	}
	badDerivation := cloneAIDiscoveryReport(base)
	badDerivation.Signals[0].Model.Provenance.Derivation = "distilled"
	if err := ValidateSanitizedAIDiscoveryReport(badDerivation); err == nil {
		t.Fatal("inconsistent model derivation accepted")
	}

	missingModel := cloneAIDiscoveryReport(base)
	missingModel.Signals[0].Model = nil
	missingModel.Signals[0].Basenames = []string{"private-model.gguf"}
	if err := ValidateSanitizedAIDiscoveryReport(missingModel); err == nil {
		t.Fatal("local_model signal without model metadata accepted")
	}

	wrongCategory := cloneAIDiscoveryReport(base)
	wrongCategory.Signals[0].Category = SignalAICLI
	if err := ValidateSanitizedAIDiscoveryReport(wrongCategory); err == nil {
		t.Fatal("model metadata on non-local_model signal accepted")
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
			if filepath.ToSlash(filepath.Clean(got)) != filepath.ToSlash(filepath.Clean(tc.want)) {
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
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	signals, _, err := svc.detectPackageManifests(context.Background())
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
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	signals, _, err := svc.detectPackageManifests(context.Background())
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
	signals2, _, err := svc.detectPackageManifests(context.Background())
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

// TestRunScan_SingleFlight (H-1) verifies that two concurrent scans
// serialize on the per-service mutex instead of racing on the state
// store / detector fanout. Without the lock the JSON ai_discovery_state
// snapshot can be clobbered when the API-trigger path falls through to
// runScan() at the same moment a scheduled tick fires.
func TestRunScan_SingleFlight(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir dataDir: %v", err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:         true,
		Mode:            "enhanced",
		DataDir:         dataDir,
		HomeDir:         home,
		MaxFilesPerScan: 5,
		MaxFileBytes:    32 * 1024,
	}, []AISignature{testAISignature()})
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	cleanupPreparedDiscoveryService(t, svc)

	// Spawn N concurrent runScan goroutines; if the mutex is wired
	// correctly all of them should complete without races (a -race
	// build catches concurrent map writes / store.Save races
	// otherwise). Each call is allowed to fail due to environmental
	// reasons (e.g. detectors finding nothing on a clean tmp tree);
	// what we are asserting is the absence of a panic and a clean
	// exit for every goroutine.
	const N = 8
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = svc.runScan(context.Background(), true, "test-concurrent")
		}()
	}
	timeout := time.After(15 * time.Second)
	for i := 0; i < N; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatalf("runScan goroutines did not finish — possible deadlock or unbounded wait")
		}
	}
}

// TestRunScan_RespectsCancelledContext verifies the early-cancel
// shortcut: a caller whose context is already cancelled must NOT
// block waiting for the single-flight mutex behind a slow scan.
func TestRunScan_RespectsCancelledContext(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	home := filepath.Join(tmp, "home")
	_ = os.MkdirAll(dataDir, 0o700)
	_ = os.MkdirAll(home, 0o700)

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:         true,
		Mode:            "enhanced",
		DataDir:         dataDir,
		HomeDir:         home,
		MaxFilesPerScan: 1,
		MaxFileBytes:    1024,
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.runScan(ctx, true, "test-cancelled")
	if err == nil {
		t.Fatal("expected runScan to return ctx.Err() for already-cancelled context")
	}
	if err != context.Canceled {
		t.Fatalf("got err=%v, want context.Canceled", err)
	}
}

// TestIsSHA256Hash_AcceptsKeyedAndUnsalted is a regression test for the
// remediation (SetPathHashKey wiring). When the
// sidecar boots with a gateway token, inventory.hashPath emits the
// keyed digest form `hmac-sha256:<64 hex>`. validateAIDiscoveryReport
// must accept that prefix in addition to the legacy `sha256:` form,
// otherwise every AI-discovery payload from a fully-configured gateway
// would be rejected by validation.
//
// The test enumerates the prefix matrix (legacy / keyed / unrelated)
// crossed with shape problems (good, short, long, non-hex) and
// asserts only the two well-formed prefixes pass.
func TestIsSHA256Hash_AcceptsKeyedAndUnsalted(t *testing.T) {
	t.Parallel()
	const goodHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  // 64 hex
	const shortHex = "0123456789abcdef"                                                 // 16 hex
	const upperHex = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef" // mixed case rejected
	const nonHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"   // 'g'

	cases := []struct {
		name   string
		input  string
		expect bool
	}{
		// Accepted (legacy unsalted, set when SetPathHashKey is nil).
		{"legacy_sha256_good", "sha256:" + goodHex, true},
		// Accepted (per-installation keyed, set when SetPathHashKey
		// is wired from sidecar boot — fix).
		{"keyed_hmac_sha256_good", "hmac-sha256:" + goodHex, true},

		// Rejected: empty.
		{"empty", "", false},
		// Rejected: missing prefix.
		{"raw_hex_no_prefix", goodHex, false},
		// Rejected: wrong prefix (only the two formats above are valid).
		{"unrelated_prefix", "sha512:" + goodHex, false},
		// Rejected: too short hex tail.
		{"short_legacy", "sha256:" + shortHex, false},
		{"short_keyed", "hmac-sha256:" + shortHex, false},
		// Rejected: too long (would let a raw path through).
		{"long_legacy", "sha256:" + goodHex + "00", false},
		// Rejected: uppercase hex (we render lowercase deliberately).
		{"upper_legacy", "sha256:" + upperHex, false},
		{"upper_keyed", "hmac-sha256:" + upperHex, false},
		// Rejected: non-hex byte sneaks past length check.
		{"nonhex_legacy", "sha256:" + nonHex, false},
		{"nonhex_keyed", "hmac-sha256:" + nonHex, false},
		// Rejected: prefix only.
		{"prefix_only_legacy", "sha256:", false},
		{"prefix_only_keyed", "hmac-sha256:", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isSHA256Hash(tc.input)
			if got != tc.expect {
				t.Fatalf("isSHA256Hash(%q) = %v, want %v", tc.input, got, tc.expect)
			}
		})
	}
}

// TestHashPath_KeyedVsUnsalted is the end-to-end coverage for the
// SetPathHashKey contract. It is the assertion the cross-package
// sidecar test deliberately can't make (hashPath is unexported), and
// guards against future refactors that quietly drop keyed-mode
// emission — which would re-introduce (reversible
// path fingerprints).
//
// Properties asserted:
//
//  1. Default state (no key installed) returns the legacy
//     "sha256:<64 hex>" form so detached scan utilities, tests, and
//     pre-boot code continue to produce the documented digest.
//  2. After SetPathHashKey(non-nil), hashPath transitions to the
//     "hmac-sha256:<64 hex>" form with the same hex length, and the
//     digest itself differs from the unsalted SHA-256 of the same
//     path (which proves the key is actually feeding into HMAC and
//     not being silently ignored).
//  3. SetPathHashKey(nil) restores the legacy form, byte-for-byte
//     identical to the pre-key digest — proving the rollback path
//     used by tests and `disable_redaction` modes is symmetric.
//
// This test does NOT run with t.Parallel() because SetPathHashKey
// mutates package-level state shared across the entire process.
// Other tests in this package that depend on hashPath stay
// well-defined as long as we restore the nil key on cleanup, which
// the t.Cleanup hook guarantees.
func TestHashPath_KeyedVsUnsalted(t *testing.T) {
	// Save and restore any pre-existing key so this test is hermetic
	// when run alongside others that may have set one (sidecar tests,
	// future regression tests).
	saved := currentPathHashKey()
	t.Cleanup(func() { SetPathHashKey(saved) })

	const samplePath = "/Users/example/.codex/config.toml"

	// Property 1: legacy mode (no key installed).
	SetPathHashKey(nil)
	legacy := hashPath(samplePath)
	if !strings.HasPrefix(legacy, "sha256:") {
		t.Fatalf("legacy mode: hashPath returned %q, want sha256: prefix", legacy)
	}
	if len(legacy) != len("sha256:")+64 {
		t.Fatalf("legacy mode: hashPath length = %d, want %d", len(legacy), len("sha256:")+64)
	}

	// Property 2: keyed mode (after SetPathHashKey).
	key := []byte("test-installation-key-32-bytes-ok!!")
	SetPathHashKey(key)
	keyed := hashPath(samplePath)
	if !strings.HasPrefix(keyed, "hmac-sha256:") {
		t.Fatalf("keyed mode: hashPath returned %q, want hmac-sha256: prefix — SetPathHashKey wiring is broken", keyed)
	}
	if len(keyed) != len("hmac-sha256:")+64 {
		t.Fatalf("keyed mode: hashPath length = %d, want %d", len(keyed), len("hmac-sha256:")+64)
	}
	// Critical anti-regression: the keyed digest must differ from the
	// legacy SHA-256, otherwise SetPathHashKey is silently a no-op.
	if keyed[len("hmac-sha256:"):] == legacy[len("sha256:"):] {
		t.Fatal("keyed digest equals unsalted digest — SetPathHashKey is not affecting output, which means dictionary attacks are still possible against the redacted path hash")
	}

	// Property 3: SetPathHashKey(nil) restores legacy mode exactly.
	SetPathHashKey(nil)
	legacy2 := hashPath(samplePath)
	if legacy2 != legacy {
		t.Fatalf("after key removal, legacy digest changed: was %q, now %q — SetPathHashKey(nil) rollback is broken", legacy, legacy2)
	}
}

func TestAIStateStorePersistsInternalModelProvenanceLifecycle(t *testing.T) {
	t.Parallel()
	store := NewAIStateStore(filepath.Join(t.TempDir(), "ai-discovery-state.json"))
	resolvedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	wantHash := hashValue("hub-provenance")
	want := AISignal{
		Fingerprint:                  "model-fingerprint",
		SignalID:                     "model-signal",
		SignatureID:                  "local-model",
		Name:                         "Model",
		Vendor:                       "Local",
		Product:                      "Local Model Artifact",
		Category:                     SignalLocalModel,
		Detector:                     "model_file",
		State:                        AIStateSeen,
		Confidence:                   0.9,
		Source:                       "sidecar",
		FirstSeen:                    resolvedAt.Add(-time.Hour),
		LastSeen:                     resolvedAt,
		EvidenceHash:                 hashValue("local-evidence"),
		ModelProvenanceHubResolvedAt: resolvedAt,
		ModelProvenanceHubHash:       wantHash,
		Model: &LocalModelInfo{
			ID: "Qwen/Qwen3-4B", Status: "installed",
			Provenance: &LocalModelProvenance{
				Publisher: "Alibaba Cloud", CountryCode: "CN", RootModel: "Qwen/Qwen3-4B",
				BaseModels: []string{"Qwen/Qwen3-4B"}, Source: "huggingface_hub", Confidence: "high",
			},
		},
	}
	state := aiStateFile{Signals: map[string]aiStoredSignal{
		want.Fingerprint: {AISignal: want},
	}}
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	got, ok := loaded.Signals[want.Fingerprint]
	if !ok {
		t.Fatal("persisted model signal is missing")
	}
	if !got.ModelProvenanceHubResolvedAt.Equal(resolvedAt) ||
		got.ModelProvenanceHubHash != wantHash ||
		got.StoredModelProvenanceHubResolvedAt == nil ||
		!got.StoredModelProvenanceHubResolvedAt.Equal(resolvedAt) ||
		got.StoredModelProvenanceHubHash != wantHash {
		t.Fatalf("Hub lifecycle fields did not round trip: %+v", got)
	}
	publicJSON, err := json.Marshal(got.AISignal)
	if err != nil {
		t.Fatalf("marshal public signal: %v", err)
	}
	publicText := string(publicJSON)
	if strings.Contains(publicText, "model_provenance_hub_resolved_at") ||
		strings.Contains(publicText, "model_provenance_hub_hash") ||
		strings.Contains(publicText, wantHash) {
		t.Fatalf("public signal leaked internal Hub lifecycle fields: %s", publicJSON)
	}
}

func TestAIStoredSignalModelProvenanceHubResolvedAtJSON(t *testing.T) {
	t.Parallel()
	resolvedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	zero := time.Time{}

	for _, tc := range []struct {
		name       string
		resolvedAt *time.Time
		want       string
	}{
		{name: "absent"},
		{name: "legacy zero", resolvedAt: &zero},
		{name: "populated", resolvedAt: &resolvedAt, want: `"2026-07-20T12:00:00Z"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ai-discovery-state.json")
			store := NewAIStateStore(path)
			if err := store.Save(aiStateFile{Signals: map[string]aiStoredSignal{
				"model": {StoredModelProvenanceHubResolvedAt: tc.resolvedAt},
			}}); err != nil {
				t.Fatalf("save state: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read state: %v", err)
			}
			var state struct {
				Signals map[string]map[string]json.RawMessage `json:"signals"`
			}
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatalf("decode state: %v", err)
			}
			got, present := state.Signals["model"]["model_provenance_hub_resolved_at"]
			if tc.want == "" {
				if present {
					t.Fatalf("absent Hub timestamp serialized as %s", got)
				}
				return
			}
			if !present || string(got) != tc.want {
				t.Fatalf("Hub timestamp JSON = %s (present %t), want %s", got, present, tc.want)
			}
		})
	}
}
