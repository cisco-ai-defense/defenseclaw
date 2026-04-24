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

package connector

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- Helper tests ---

func TestExtractBearerKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Bearer sk-abc123", "sk-abc123"},
		{"bearer sk-abc123", "sk-abc123"},
		{"sk-abc123", "sk-abc123"},
		{"Bearer  sk-abc123 ", "sk-abc123"},
		{"", ""},
	}
	for _, tt := range tests {
		got := ExtractBearerKey(tt.input)
		if got != tt.want {
			t.Errorf("ExtractBearerKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractAPIKey_Priority(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("X-AI-Auth", "Bearer real-key-from-interceptor")
	r.Header.Set("Authorization", "Bearer sk-fallback")
	r.Header.Set("x-api-key", "anthropic-key")

	got := ExtractAPIKey(r)
	if got != "real-key-from-interceptor" {
		t.Errorf("expected X-AI-Auth to win, got %q", got)
	}
}

func TestExtractAPIKey_SkipsMasterKey(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("X-AI-Auth", "Bearer sk-dc-masterkey")
	r.Header.Set("x-api-key", "real-key")

	got := ExtractAPIKey(r)
	if got != "real-key" {
		t.Errorf("expected sk-dc- to be skipped, got %q", got)
	}
}

func TestExtractAPIKey_AzureHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("api-key", "azure-key-123")

	got := ExtractAPIKey(r)
	if got != "azure-key-123" {
		t.Errorf("expected azure api-key header, got %q", got)
	}
}

func TestParseModelFromBody(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	if got := ParseModelFromBody(body); got != "gpt-4o" {
		t.Errorf("ParseModelFromBody = %q, want gpt-4o", got)
	}
	if got := ParseModelFromBody(nil); got != "" {
		t.Errorf("ParseModelFromBody(nil) = %q, want empty", got)
	}
	if got := ParseModelFromBody([]byte("not json")); got != "" {
		t.Errorf("ParseModelFromBody(bad json) = %q, want empty", got)
	}
}

func TestParseStreamFromBody(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","stream":true}`)
	if !ParseStreamFromBody(body) {
		t.Error("expected stream=true")
	}
	body2 := []byte(`{"model":"gpt-4o","stream":false}`)
	if ParseStreamFromBody(body2) {
		t.Error("expected stream=false")
	}
	body3 := []byte(`{"model":"gpt-4o"}`)
	if ParseStreamFromBody(body3) {
		t.Error("expected stream absent to return false")
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       bool
	}{
		{"127.0.0.1:54321", true},
		{"[::1]:54321", true},
		{"192.168.1.5:54321", false},
		{"10.0.0.1:8080", false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remoteAddr
		got := IsLoopback(r)
		if got != tt.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", tt.remoteAddr, got, tt.want)
		}
	}
}

// --- Registry tests ---

func TestRegistry_DefaultContainsAllBuiltins(t *testing.T) {
	r := NewDefaultRegistry()
	expected := []string{"openclaw", "zeptoclaw", "claudecode", "codex"}
	for _, name := range expected {
		if _, ok := r.Get(name); !ok {
			t.Errorf("default registry missing %q", name)
		}
	}
	if r.Len() != len(expected) {
		t.Errorf("registry has %d connectors, want %d", r.Len(), len(expected))
	}
}

func TestRegistry_Available_SortOrder(t *testing.T) {
	r := NewDefaultRegistry()
	avail := r.Available()
	if len(avail) == 0 {
		t.Fatal("no connectors available")
	}
	for _, info := range avail {
		if info.Source != "built-in" {
			t.Errorf("expected all built-in, got %q for %q", info.Source, info.Name)
		}
	}
	for i := 1; i < len(avail); i++ {
		if avail[i].Name < avail[i-1].Name {
			t.Errorf("not sorted: %q before %q", avail[i-1].Name, avail[i].Name)
		}
	}
}

func TestRegistry_Get_Unknown(t *testing.T) {
	r := NewDefaultRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Error("expected Get to return false for unknown connector")
	}
}

func TestRegistry_GetAll(t *testing.T) {
	r := NewDefaultRegistry()
	connectors, err := r.GetAll([]string{"claudecode", "codex"})
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(connectors) != 2 {
		t.Fatalf("GetAll returned %d connectors, want 2", len(connectors))
	}
	if connectors[0].Name() != "claudecode" {
		t.Errorf("first connector = %q, want claudecode", connectors[0].Name())
	}
	if connectors[1].Name() != "codex" {
		t.Errorf("second connector = %q, want codex", connectors[1].Name())
	}
}

func TestRegistry_GetAll_Unknown(t *testing.T) {
	r := NewDefaultRegistry()
	_, err := r.GetAll([]string{"claudecode", "nonexistent"})
	if err == nil {
		t.Error("expected error for unknown connector")
	}
}

// --- Connector interface compliance tests ---

func TestAllConnectors_ImplementInterface(t *testing.T) {
	connectors := []Connector{
		NewOpenClawConnector(),
		NewZeptoClawConnector(),
		NewClaudeCodeConnector(),
		NewCodexConnector(),
	}
	for _, c := range connectors {
		if c.Name() == "" {
			t.Error("connector has empty Name()")
		}
		if c.Description() == "" {
			t.Errorf("connector %q has empty Description()", c.Name())
		}
		mode := c.ToolInspectionMode()
		if mode != ToolModePreExecution && mode != ToolModeResponseScan && mode != ToolModeBoth {
			t.Errorf("connector %q has invalid ToolInspectionMode: %q", c.Name(), mode)
		}
		policy := c.SubprocessPolicy()
		if policy != SubprocessSandbox && policy != SubprocessShims && policy != SubprocessNone {
			t.Errorf("connector %q has invalid SubprocessPolicy: %q", c.Name(), policy)
		}
	}
}

// --- HookEventHandler interface tests ---

func TestClaudeCode_ImplementsHookEventHandler(t *testing.T) {
	c := NewClaudeCodeConnector()
	var _ HookEventHandler = c
	if c.HookEndpointPath() != "/api/v1/claude-code/hook" {
		t.Errorf("HookEndpointPath = %q", c.HookEndpointPath())
	}
}

func TestCodex_ImplementsHookEventHandler(t *testing.T) {
	c := NewCodexConnector()
	var _ HookEventHandler = c
	if c.HookEndpointPath() != "/api/v1/codex/hook" {
		t.Errorf("HookEndpointPath = %q", c.HookEndpointPath())
	}
}

func TestOpenClaw_DoesNotImplementHookEventHandler(t *testing.T) {
	c := NewOpenClawConnector()
	if _, ok := interface{}(c).(HookEventHandler); ok {
		t.Error("OpenClaw should not implement HookEventHandler")
	}
}

func TestZeptoClaw_DoesNotImplementHookEventHandler(t *testing.T) {
	c := NewZeptoClawConnector()
	if _, ok := interface{}(c).(HookEventHandler); ok {
		t.Error("ZeptoClaw should not implement HookEventHandler")
	}
}

// --- ComponentScanner interface tests ---

func TestClaudeCode_ImplementsComponentScanner(t *testing.T) {
	c := NewClaudeCodeConnector()
	var _ ComponentScanner = c
	if !c.SupportsComponentScanning() {
		t.Error("expected SupportsComponentScanning to be true")
	}
	targets := c.ComponentTargets("/tmp/workspace")
	expectedTypes := []string{"skill", "plugin", "mcp", "agent", "command", "config"}
	for _, tp := range expectedTypes {
		if _, ok := targets[tp]; !ok {
			t.Errorf("missing component type %q", tp)
		}
	}
}

func TestCodex_ImplementsComponentScanner(t *testing.T) {
	c := NewCodexConnector()
	var _ ComponentScanner = c
	if !c.SupportsComponentScanning() {
		t.Error("expected SupportsComponentScanning to be true")
	}
	targets := c.ComponentTargets("/tmp/workspace")
	expectedTypes := []string{"skill", "plugin", "mcp"}
	for _, tp := range expectedTypes {
		if _, ok := targets[tp]; !ok {
			t.Errorf("missing component type %q", tp)
		}
	}
}

// --- StopScanner interface tests ---

func TestClaudeCode_ImplementsStopScanner(t *testing.T) {
	c := NewClaudeCodeConnector()
	var _ StopScanner = c
	if !c.SupportsStopScan() {
		t.Error("expected SupportsStopScan to be true")
	}
}

func TestCodex_ImplementsStopScanner(t *testing.T) {
	c := NewCodexConnector()
	var _ StopScanner = c
	if !c.SupportsStopScan() {
		t.Error("expected SupportsStopScan to be true")
	}
}

// --- HandleHookEvent tests ---

func TestClaudeCode_HandleHookEvent_Allow(t *testing.T) {
	c := NewClaudeCodeConnector()
	payload := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	resp, err := c.HandleHookEvent(nil, payload)
	if err != nil {
		t.Fatalf("HandleHookEvent failed: %v", err)
	}
	var result map[string]interface{}
	json.Unmarshal(resp, &result)
	if result["action"] != "allow" {
		t.Errorf("action = %v, want allow", result["action"])
	}
}

// --- OpenClaw connector tests ---

func TestOpenClaw_Authenticate_Token(t *testing.T) {
	c := NewOpenClawConnector()
	c.SetCredentials("my-token", "my-master")

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"

	if c.Authenticate(r) {
		t.Error("expected auth to fail without token")
	}

	r.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r) {
		t.Error("expected auth to pass with correct X-DC-Auth")
	}

	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	r2.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass with master key")
	}
}

func TestOpenClaw_Authenticate_NoCredentials(t *testing.T) {
	c := NewOpenClawConnector()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r) {
		t.Error("expected auth to pass when no credentials configured")
	}
}

func TestOpenClaw_Setup_InstallsExtensionAndPatchesConfig(t *testing.T) {
	// Enabling the OpenClaw connector must be sufficient to make OpenClaw
	// route through DefenseClaw — no separate `defenseclaw setup guardrail`
	// step. Setup() therefore has to copy the extension into OpenClaw's
	// extensions directory AND register it in openclaw.json.
	dir := t.TempDir()
	ocHome := filepath.Join(dir, "openclaw-home")
	if err := os.MkdirAll(ocHome, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(ocHome, "openclaw.json")
	// Start with a realistic non-empty config so we can verify we don't
	// clobber unrelated sections.
	os.WriteFile(configPath, []byte(`{
		"version": 1,
		"models": {"default": "openai/gpt-4"},
		"plugins": {"allow": ["somebody-else"]}
	}`), 0o644)

	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	c := NewOpenClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Extension directory exists with the required runtime files.
	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	for _, rel := range []string{
		"package.json",
		"openclaw.plugin.json",
		"dist/index.js",
	} {
		p := filepath.Join(extDir, rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}

	// openclaw.json is patched: plugin allowed, enabled, load path added.
	var cfg map[string]interface{}
	data, _ := os.ReadFile(configPath)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("openclaw.json not valid JSON after Setup: %v", err)
	}
	plugins, ok := cfg["plugins"].(map[string]interface{})
	if !ok {
		t.Fatal("plugins section missing")
	}
	allow, _ := plugins["allow"].([]interface{})
	foundDefenseClaw := false
	foundSomebodyElse := false
	for _, v := range allow {
		if s, _ := v.(string); s == "defenseclaw" {
			foundDefenseClaw = true
		}
		if s, _ := v.(string); s == "somebody-else" {
			foundSomebodyElse = true
		}
	}
	if !foundDefenseClaw {
		t.Error("plugins.allow does not include defenseclaw")
	}
	if !foundSomebodyElse {
		t.Error("plugins.allow clobbered the pre-existing entry")
	}
	entries, _ := plugins["entries"].(map[string]interface{})
	if entry, ok := entries["defenseclaw"].(map[string]interface{}); !ok || entry["enabled"] != true {
		t.Errorf("plugins.entries.defenseclaw not enabled, got %v", entries["defenseclaw"])
	}
	load, _ := plugins["load"].(map[string]interface{})
	paths, _ := load["paths"].([]interface{})
	foundPath := false
	for _, v := range paths {
		if s, _ := v.(string); s == extDir {
			foundPath = true
		}
	}
	if !foundPath {
		t.Errorf("plugins.load.paths missing %s, got %v", extDir, paths)
	}
	// Unrelated sections untouched.
	if cfg["version"] != float64(1) {
		t.Errorf("version clobbered: got %v", cfg["version"])
	}
	if models, _ := cfg["models"].(map[string]interface{}); models == nil || models["default"] != "openai/gpt-4" {
		t.Errorf("models section clobbered: got %v", cfg["models"])
	}
}

func TestOpenClaw_Setup_IsIdempotent(t *testing.T) {
	// Sidecar boots many times. Re-running Setup must leave the config in
	// the same shape (single allow entry, single load path), not produce
	// duplicates.
	dir := t.TempDir()
	ocHome := filepath.Join(dir, "openclaw-home")
	os.MkdirAll(ocHome, 0o755)
	configPath := filepath.Join(ocHome, "openclaw.json")
	os.WriteFile(configPath, []byte(`{}`), 0o644)

	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	c := NewOpenClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(configPath)
	json.Unmarshal(data, &cfg)
	plugins := cfg["plugins"].(map[string]interface{})

	allow := plugins["allow"].([]interface{})
	dcCount := 0
	for _, v := range allow {
		if s, _ := v.(string); s == "defenseclaw" {
			dcCount++
		}
	}
	if dcCount != 1 {
		t.Errorf("plugins.allow has %d defenseclaw entries after two Setups, want 1", dcCount)
	}

	paths := plugins["load"].(map[string]interface{})["paths"].([]interface{})
	pathCount := 0
	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	for _, v := range paths {
		if s, _ := v.(string); s == extDir {
			pathCount++
		}
	}
	if pathCount != 1 {
		t.Errorf("plugins.load.paths has %d entries after two Setups, want 1", pathCount)
	}
}

func TestOpenClaw_Teardown_RemovesExtensionAndConfig(t *testing.T) {
	dir := t.TempDir()
	ocHome := filepath.Join(dir, "openclaw-home")
	os.MkdirAll(ocHome, 0o755)
	configPath := filepath.Join(ocHome, "openclaw.json")
	os.WriteFile(configPath, []byte(`{"plugins":{"allow":["somebody-else"]}}`), 0o644)

	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	c := NewOpenClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(nil, opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	if _, err := os.Stat(extDir); !os.IsNotExist(err) {
		t.Errorf("extension dir still present after Teardown: err=%v", err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(configPath)
	json.Unmarshal(data, &cfg)
	plugins, _ := cfg["plugins"].(map[string]interface{})
	allow, _ := plugins["allow"].([]interface{})
	for _, v := range allow {
		if s, _ := v.(string); s == "defenseclaw" {
			t.Errorf("plugins.allow still contains defenseclaw after Teardown")
		}
	}
	// Pre-existing unrelated entry preserved.
	found := false
	for _, v := range allow {
		if s, _ := v.(string); s == "somebody-else" {
			found = true
		}
	}
	if !found {
		t.Error("Teardown clobbered unrelated plugins.allow entry")
	}
}

func TestOpenClaw_Route(t *testing.T) {
	c := NewOpenClawConnector()
	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[]}`)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	r.Header.Set("X-AI-Auth", "Bearer sk-real-key")

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if cs.ConnectorName != "openclaw" {
		t.Errorf("ConnectorName = %q, want openclaw", cs.ConnectorName)
	}
	if cs.RawUpstream != "https://api.openai.com" {
		t.Errorf("RawUpstream = %q", cs.RawUpstream)
	}
	if cs.RawAPIKey != "sk-real-key" {
		t.Errorf("RawAPIKey = %q", cs.RawAPIKey)
	}
	if cs.RawModel != "gpt-4o" {
		t.Errorf("RawModel = %q", cs.RawModel)
	}
	if !cs.Stream {
		t.Error("expected Stream=true")
	}
	if cs.PassthroughMode {
		t.Error("expected PassthroughMode=false for chat path")
	}
}

func TestOpenClaw_Route_PassthroughNonChat(t *testing.T) {
	c := NewOpenClawConnector()
	r := httptest.NewRequest("POST", "/v1/embeddings", nil)
	r.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	r.Header.Set("X-AI-Auth", "Bearer key")

	cs, err := c.Route(r, []byte(`{}`))
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if !cs.PassthroughMode {
		t.Error("expected PassthroughMode=true for non-chat path")
	}
}

// --- Claude Code connector tests ---

func TestClaudeCode_Route(t *testing.T) {
	c := NewClaudeCodeConnector()
	body := []byte(`{"model":"claude-sonnet-4-20250514","stream":true}`)
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("x-api-key", "sk-ant-api03-key")
	r.Header.Set("anthropic-version", "2023-06-01")

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if cs.ConnectorName != "claudecode" {
		t.Errorf("ConnectorName = %q", cs.ConnectorName)
	}
	if cs.RawAPIKey != "sk-ant-api03-key" {
		t.Errorf("RawAPIKey = %q", cs.RawAPIKey)
	}
	if v, ok := cs.ExtraHeaders["anthropic-version"]; !ok || v != "2023-06-01" {
		t.Errorf("ExtraHeaders = %v", cs.ExtraHeaders)
	}
}

func TestClaudeCode_Authenticate_Loopback(t *testing.T) {
	c := NewClaudeCodeConnector()

	// No credentials configured — loopback passes
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r) {
		t.Error("expected loopback auth to pass")
	}

	// No credentials configured — open state allows all (matches OpenClaw)
	r2 := httptest.NewRequest("POST", "/v1/messages", nil)
	r2.RemoteAddr = "10.0.0.5:54321"
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass when no credentials configured")
	}

	// With credentials configured — non-loopback without token fails
	c.SetCredentials("my-token", "")
	r3 := httptest.NewRequest("POST", "/v1/messages", nil)
	r3.RemoteAddr = "10.0.0.5:54321"
	if c.Authenticate(r3) {
		t.Error("expected non-loopback auth to fail when token configured")
	}
}

func TestClaudeCode_Authenticate_Token(t *testing.T) {
	c := NewClaudeCodeConnector()
	c.SetCredentials("my-token", "my-master")

	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if c.Authenticate(r) {
		t.Error("expected auth to fail without token")
	}

	r.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r) {
		t.Error("expected auth to pass with correct X-DC-Auth")
	}

	r2 := httptest.NewRequest("POST", "/v1/messages", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	r2.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass with master key")
	}
}

func TestClaudeCode_Authenticate_NoCredentials(t *testing.T) {
	c := NewClaudeCodeConnector()
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r) {
		t.Error("expected auth to pass when no credentials configured")
	}
}

func TestClaudeCode_Setup_PatchesSettings(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	os.MkdirAll(settingsDir, 0o755)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	os.WriteFile(settingsPath, []byte(`{"existingKey": true}`), 0o644)

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	data, _ := os.ReadFile(settingsPath)
	var settings map[string]interface{}
	json.Unmarshal(data, &settings)

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("settings missing hooks key")
	}

	expectedEvents := []string{"PreToolUse", "PostToolUse", "PreCompact", "PostCompact",
		"UserPromptSubmit", "SessionStart", "Stop", "SubagentStop"}
	for _, event := range expectedEvents {
		if _, ok := hooks[event]; !ok {
			t.Errorf("missing hook event %q", event)
		}
	}

	if _, ok := settings["existingKey"]; !ok {
		t.Error("existing key was removed")
	}
}

func TestClaudeCode_Teardown_RestoresSettings(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	os.MkdirAll(settingsDir, 0o755)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	os.WriteFile(settingsPath, []byte(`{"existingKey": true}`), 0o644)

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	c.Setup(nil, opts)
	c.Teardown(nil, opts)

	data, _ := os.ReadFile(settingsPath)
	var settings map[string]interface{}
	json.Unmarshal(data, &settings)

	if _, ok := settings["hooks"]; ok {
		t.Error("hooks should be removed after teardown")
	}
}

// --- Codex connector tests ---

func TestCodex_Authenticate_Token(t *testing.T) {
	c := NewCodexConnector()
	c.SetCredentials("my-token", "my-master")

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if c.Authenticate(r) {
		t.Error("expected auth to fail without token")
	}

	r.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r) {
		t.Error("expected auth to pass with correct X-DC-Auth")
	}

	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	r2.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass with master key")
	}
}

func TestCodex_Authenticate_Loopback(t *testing.T) {
	c := NewCodexConnector()

	// No credentials — loopback passes
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r) {
		t.Error("expected loopback auth to pass with no credentials")
	}

	// No credentials — open state allows all
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "10.0.0.5:54321"
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass when no credentials configured")
	}

	// With token — non-loopback without token fails
	c.SetCredentials("my-token", "")
	r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r3.RemoteAddr = "10.0.0.5:54321"
	if c.Authenticate(r3) {
		t.Error("expected non-loopback auth to fail when token configured")
	}

	// With token — loopback without token also fails
	r4 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r4.RemoteAddr = "127.0.0.1:54321"
	if c.Authenticate(r4) {
		t.Error("expected loopback auth to fail when token configured but not provided")
	}
}

func TestCodex_Authenticate_NoCredentials(t *testing.T) {
	c := NewCodexConnector()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "192.168.1.100:54321"
	if !c.Authenticate(r) {
		t.Error("expected auth to pass when no credentials configured (open state)")
	}
}

func TestCodex_ToolMode(t *testing.T) {
	c := NewCodexConnector()
	if c.ToolInspectionMode() != ToolModeBoth {
		t.Errorf("expected both, got %q", c.ToolInspectionMode())
	}
	policy := c.SubprocessPolicy()
	if policy != SubprocessSandbox && policy != SubprocessShims {
		t.Errorf("expected sandbox or shims, got %q", policy)
	}
}

func TestCodex_Route(t *testing.T) {
	c := NewCodexConnector()
	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello"}]}`)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-openai-key")

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if cs.ConnectorName != "codex" {
		t.Errorf("ConnectorName = %q, want codex", cs.ConnectorName)
	}
	if cs.RawAPIKey != "sk-openai-key" {
		t.Errorf("RawAPIKey = %q, want sk-openai-key", cs.RawAPIKey)
	}
	if cs.RawModel != "gpt-4o" {
		t.Errorf("RawModel = %q, want gpt-4o", cs.RawModel)
	}
	if !cs.Stream {
		t.Error("expected Stream=true")
	}
	if cs.PassthroughMode {
		t.Error("expected PassthroughMode=false for chat path")
	}
	if cs.ExtraHeaders == nil {
		t.Error("ExtraHeaders should not be nil")
	}
}

func TestCodex_Route_PassthroughNonChat(t *testing.T) {
	c := NewCodexConnector()
	r := httptest.NewRequest("POST", "/v1/embeddings", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-test")

	cs, err := c.Route(r, []byte(`{"model":"text-embedding-ada-002"}`))
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if !cs.PassthroughMode {
		t.Error("expected PassthroughMode=true for /v1/embeddings")
	}
}

func TestCodex_Route_ResponsesAPI(t *testing.T) {
	c := NewCodexConnector()
	r := httptest.NewRequest("POST", "/v1/responses", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-test")

	cs, err := c.Route(r, []byte(`{"model":"gpt-4o","input":"hello"}`))
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if cs.PassthroughMode {
		t.Error("expected PassthroughMode=false for /v1/responses (messages-like path)")
	}
}

func TestCodex_Setup(t *testing.T) {
	dir := t.TempDir()
	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify hook script was created
	hookPath := filepath.Join(dir, "hooks", "inspect-tool.sh")
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("hook script not created: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("hook script not executable")
	}
	data, _ := os.ReadFile(hookPath)
	if !strings.Contains(string(data), "127.0.0.1:18970") {
		t.Error("hook script missing API addr")
	}
}

func TestCodex_Setup_WritesConnectorPrefix(t *testing.T) {
	dir := t.TempDir()
	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	envData, _ := os.ReadFile(filepath.Join(dir, "codex_env.sh"))
	if !strings.Contains(string(envData), "/c/codex") {
		t.Error("env file missing /c/codex prefix")
	}

	dotenvData, _ := os.ReadFile(filepath.Join(dir, "codex.env"))
	if !strings.Contains(string(dotenvData), "/c/codex") {
		t.Error(".env file missing /c/codex prefix")
	}
}

func TestCodex_Teardown(t *testing.T) {
	dir := t.TempDir()
	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	// Setup first to create artifacts
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	if err := c.Teardown(nil, opts); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
}

func TestCodex_CredentialSetter(t *testing.T) {
	c := NewCodexConnector()
	var cs CredentialSetter = c // compile-time check
	cs.SetCredentials("tok", "mk")

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-DC-Auth", "tok")
	if !c.Authenticate(r) {
		t.Error("CredentialSetter interface should wire token auth")
	}
}

// --- ZeptoClaw connector tests ---

func TestZeptoClaw_Authenticate_Loopback(t *testing.T) {
	c := NewZeptoClawConnector()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r) {
		t.Error("expected loopback auth to pass")
	}
}

func TestZeptoClaw_Authenticate_Token(t *testing.T) {
	c := NewZeptoClawConnector()
	c.SetCredentials("my-token", "my-master")

	// Loopback is trusted even when the gateway token is set, because
	// ZeptoClaw is a native binary with no fetch interceptor to inject
	// X-DC-Auth. Zeptoclaw forwards the real upstream provider key in
	// Authorization (e.g. "Bearer sk-or-..."), which the connector
	// deliberately ignores for auth purposes — it's an upstream key,
	// not DefenseClaw's. The proxy binds loopback-only, which is the
	// operative security boundary here.
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-or-upstream-key")
	if !c.Authenticate(r) {
		t.Error("expected loopback auth to pass even when token configured (ZeptoClaw has no way to carry X-DC-Auth)")
	}

	// A valid X-DC-Auth still works on loopback.
	r.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r) {
		t.Error("expected auth to pass with correct X-DC-Auth token")
	}

	// The master key via Authorization still works (documented fallback
	// for non-loopback sandbox/bridge deployments).
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	r2.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass with master key")
	}

	// Non-loopback must still be strict: without a valid X-DC-Auth or
	// master-key bearer, reject. Protects sandbox / bridge deployments
	// where the proxy is exposed beyond localhost.
	r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r3.RemoteAddr = "10.0.0.5:54321"
	r3.Header.Set("Authorization", "Bearer sk-or-upstream-key")
	if c.Authenticate(r3) {
		t.Error("expected non-loopback auth to fail with only an upstream bearer token")
	}
}

func TestZeptoClaw_Route(t *testing.T) {
	c := NewZeptoClawConnector()
	body := []byte(`{"model":"gpt-4o","stream":false}`)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("Authorization", "Bearer sk-openai-key")

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if cs.ConnectorName != "zeptoclaw" {
		t.Errorf("ConnectorName = %q", cs.ConnectorName)
	}
	if cs.RawAPIKey != "sk-openai-key" {
		t.Errorf("RawAPIKey = %q", cs.RawAPIKey)
	}
	// No provider snapshot loaded → no upstream to resolve; proxy will fall
	// back to configured-model / default-provider paths as before.
	if cs.RawUpstream != "" {
		t.Errorf("RawUpstream = %q, want empty when no provider snapshot", cs.RawUpstream)
	}
}

func TestZeptoClaw_Route_MapsProviderPrefixToSnapshotUpstream(t *testing.T) {
	// Zeptoclaw submits model="openrouter/deepseek/deepseek-chat" and only
	// `openrouter` is configured in the user's zeptoclaw config. Route()
	// must resolve the upstream to that provider's real api_base and its
	// api_key so the proxy can forward.
	c := NewZeptoClawConnector()
	c.SetProviderSnapshot(map[string]ZeptoClawProviderEntry{
		"openrouter": {APIBase: "https://openrouter.ai/api/v1", APIKey: "sk-or-test"},
		"anthropic":  {APIBase: "https://api.anthropic.com", APIKey: "sk-ant-test"},
	})
	body := []byte(`{"model":"openrouter/deepseek/deepseek-chat","stream":true}`)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("Authorization", "Bearer ignored-client-key")

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if cs.RawUpstream != "https://openrouter.ai/api/v1" {
		t.Errorf("RawUpstream = %q, want openrouter api_base", cs.RawUpstream)
	}
	if cs.RawAPIKey != "sk-or-test" {
		t.Errorf("RawAPIKey = %q, want openrouter key from snapshot", cs.RawAPIKey)
	}
}

func TestZeptoClaw_Route_FallsBackToSingleConfiguredProvider(t *testing.T) {
	// The user's real zeptoclaw config only has `openrouter` configured, but
	// zeptoclaw still sends model="anthropic/claude-sonnet-4.5" because
	// anthropic is openrouter's upstream via its model router. When the
	// model's provider prefix isn't in the snapshot, fall back to the sole
	// configured provider so the request gets routed somewhere valid.
	c := NewZeptoClawConnector()
	c.SetProviderSnapshot(map[string]ZeptoClawProviderEntry{
		"openrouter": {APIBase: "https://openrouter.ai/api/v1", APIKey: "sk-or-test"},
	})
	body := []byte(`{"model":"anthropic/claude-sonnet-4.5"}`)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if cs.RawUpstream != "https://openrouter.ai/api/v1" {
		t.Errorf("RawUpstream = %q, want fallback to openrouter", cs.RawUpstream)
	}
	if cs.RawAPIKey != "sk-or-test" {
		t.Errorf("RawAPIKey = %q, want fallback openrouter key", cs.RawAPIKey)
	}
}

func TestZeptoClaw_Route_SkipsEntriesWithNoAPIKey(t *testing.T) {
	// ZeptoClaw's config seeds every provider slot with nulls (e.g.
	// "anthropic": {"api_key": null}) even when the user has not configured
	// that provider. Such entries must not count as "configured" for routing.
	c := NewZeptoClawConnector()
	c.SetProviderSnapshot(map[string]ZeptoClawProviderEntry{
		"anthropic":  {APIBase: "", APIKey: ""},
		"openrouter": {APIBase: "https://openrouter.ai/api/v1", APIKey: "sk-or-test"},
	})
	body := []byte(`{"model":"anthropic/claude-sonnet-4.5"}`)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if cs.RawAPIKey != "sk-or-test" {
		t.Errorf("RawAPIKey = %q, want fallback to openrouter (skipping keyless anthropic entry)", cs.RawAPIKey)
	}
}

func TestZeptoClaw_Setup_IsIdempotent(t *testing.T) {
	// On every sidecar boot, Setup runs. If it overwrites the backup each
	// time, the second boot captures the already-patched api_base (the
	// proxy URL) as the "original", losing the user's real upstream. The
	// snapshot used by Route() must still point at the real upstream after
	// a second Setup call.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "zeptoclaw-config.json")
	os.WriteFile(configPath, []byte(`{
		"providers": {
			"openrouter": {"api_key": "sk-or-pristine", "api_base": "https://openrouter.ai/api/v1"}
		}
	}`), 0o644)
	ZeptoClawConfigPathOverride = configPath
	defer func() { ZeptoClawConfigPathOverride = "" }()

	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}

	// First Setup (simulates first boot).
	c1 := NewZeptoClawConnector()
	if err := c1.Setup(nil, opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}

	// Second Setup on a fresh connector instance, same data dir. The
	// config on disk is now patched (api_base=proxy URL). A naive Setup
	// would read the patched config and record the proxy URL in the
	// backup, but the snapshot must still reflect the pristine upstream.
	c2 := NewZeptoClawConnector()
	if err := c2.Setup(nil, opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}

	snap := c2.ProviderSnapshot()
	entry, ok := snap["openrouter"]
	if !ok {
		t.Fatal("openrouter missing from snapshot after second Setup")
	}
	if entry.APIBase != "https://openrouter.ai/api/v1" {
		t.Errorf("APIBase = %q, want pristine upstream (not the proxy URL)", entry.APIBase)
	}
	if entry.APIKey != "sk-or-pristine" {
		t.Errorf("APIKey = %q, want pristine key", entry.APIKey)
	}
}

func TestZeptoClaw_Setup_LoadsProviderSnapshot(t *testing.T) {
	// After Setup(), the connector must retain the user's provider table
	// in memory so Route() can look up upstreams. Otherwise we'd have to
	// re-read the (already-patched) config file on every request.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "zeptoclaw-config.json")
	os.WriteFile(configPath, []byte(`{
		"providers": {
			"openrouter": {"api_key": "sk-or-test", "api_base": null}
		}
	}`), 0o644)
	ZeptoClawConfigPathOverride = configPath
	defer func() { ZeptoClawConfigPathOverride = "" }()

	c := NewZeptoClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	snap := c.ProviderSnapshot()
	entry, ok := snap["openrouter"]
	if !ok {
		t.Fatal("openrouter not in snapshot after Setup")
	}
	if entry.APIKey != "sk-or-test" {
		t.Errorf("APIKey = %q, want sk-or-test", entry.APIKey)
	}
	// api_base is null in the source config; the snapshot should fall back
	// to the provider's well-known default so Route() has somewhere to send.
	if entry.APIBase == "" {
		t.Error("APIBase must default to the provider's well-known upstream when config has null")
	}
}

// --- Subprocess policy tests ---

func TestResolveSubprocessPolicy(t *testing.T) {
	if runtime.GOOS == "linux" {
		if got := ResolveSubprocessPolicy(SubprocessSandbox); got != SubprocessSandbox {
			t.Errorf("linux: expected sandbox, got %q", got)
		}
	} else {
		if got := ResolveSubprocessPolicy(SubprocessSandbox); got != SubprocessShims {
			t.Errorf("non-linux: expected shims fallback, got %q", got)
		}
	}
	if got := ResolveSubprocessPolicy(SubprocessNone); got != SubprocessNone {
		t.Errorf("expected none, got %q", got)
	}
}

// --- Subprocess enforcement tests ---

func TestWriteShimScripts(t *testing.T) {
	dir := t.TempDir()
	if err := WriteShimScripts(dir, "127.0.0.1:18970"); err != nil {
		t.Fatalf("WriteShimScripts failed: %v", err)
	}

	for _, name := range shimBinaries {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("shim %s not created: %v", name, err)
			continue
		}
		if info.Mode()&0o111 == 0 {
			t.Errorf("shim %s not executable", name)
		}
	}

	// Check ncat symlink
	target, err := os.Readlink(filepath.Join(dir, "ncat"))
	if err != nil {
		t.Errorf("ncat symlink: %v", err)
	} else if target != "nc" {
		t.Errorf("ncat symlink target = %q, want nc", target)
	}
}

func TestWriteShimScripts_ContentHasAPIAddr(t *testing.T) {
	dir := t.TempDir()
	addr := "127.0.0.1:18970"
	if err := WriteShimScripts(dir, addr); err != nil {
		t.Fatalf("WriteShimScripts: %v", err)
	}

	for _, name := range shimBinaries {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("read shim %s: %v", name, err)
			continue
		}
		if !strings.Contains(string(data), addr) {
			t.Errorf("shim %s does not contain API addr %q", name, addr)
		}
		if !strings.Contains(string(data), "/api/v1/inspect/tool") {
			t.Errorf("shim %s does not contain inspect API path", name)
		}
	}
}

func TestWriteHookScript(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHookScript(dir, "127.0.0.1:18970"); err != nil {
		t.Fatalf("WriteHookScript failed: %v", err)
	}

	path := filepath.Join(dir, "inspect-tool.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("hook script not created: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("hook script not executable")
	}
}

func TestWriteHookScript_ContentHasAPIAddr(t *testing.T) {
	dir := t.TempDir()
	addr := "127.0.0.1:18970"
	if err := WriteHookScript(dir, addr); err != nil {
		t.Fatalf("WriteHookScript: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "inspect-tool.sh"))
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	if !strings.Contains(string(data), addr) {
		t.Error("hook script does not contain API addr")
	}
}

func TestWriteAllHookScripts_CreatesAllFour(t *testing.T) {
	dir := t.TempDir()
	addr := "127.0.0.1:18970"
	if err := WriteAllHookScripts(dir, addr); err != nil {
		t.Fatalf("WriteAllHookScripts: %v", err)
	}

	expected := []string{
		"inspect-tool.sh",
		"inspect-request.sh",
		"inspect-response.sh",
		"inspect-tool-response.sh",
	}
	for _, name := range expected {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("hook %s not created: %v", name, err)
			continue
		}
		if info.Mode()&0o111 == 0 {
			t.Errorf("hook %s not executable", name)
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), addr) {
			t.Errorf("hook %s does not contain API addr", name)
		}
		if !strings.Contains(string(data), "/api/v1/inspect/") {
			t.Errorf("hook %s does not contain inspect API path", name)
		}
	}
}

func TestHookScripts_ReturnsList(t *testing.T) {
	scripts := HookScripts()
	if len(scripts) != 6 {
		t.Errorf("HookScripts() returned %d scripts, want 6", len(scripts))
	}
}

func TestWriteSandboxPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSandboxPolicy(dir, "127.0.0.1:4000", "127.0.0.1:18970"); err != nil {
		t.Fatalf("WriteSandboxPolicy failed: %v", err)
	}

	path := filepath.Join(dir, "policies", "defenseclaw-policy.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("sandbox policy not created: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "127.0.0.1:4000") {
		t.Error("policy missing proxy addr")
	}
	if !strings.Contains(content, "127.0.0.1:18970") {
		t.Error("policy missing API addr")
	}
	if !strings.Contains(content, "enforce") {
		t.Error("policy missing enforce mode")
	}
}

func TestTeardownSubprocessEnforcement(t *testing.T) {
	dir := t.TempDir()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000"}

	// Setup first
	if err := SetupSubprocessEnforcement(SubprocessShims, opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Verify shims exist
	if _, err := os.Stat(filepath.Join(dir, "shims", "curl")); err != nil {
		t.Fatal("shim not created before teardown")
	}

	// Teardown
	if err := TeardownSubprocessEnforcement(opts); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	// Verify shims removed
	if _, err := os.Stat(filepath.Join(dir, "shims")); !os.IsNotExist(err) {
		t.Error("shims dir should be removed after teardown")
	}
}

// --- Security Surface Coverage tests ---

func TestSecuritySurfaceCoverage(t *testing.T) {
	type expectation struct {
		name      string
		toolMode  ToolInspectionMode
		wantShims bool
	}

	expectations := []expectation{
		{"openclaw", ToolModeBoth, true},
		{"zeptoclaw", ToolModeBoth, true},
		{"claudecode", ToolModeBoth, true},
		{"codex", ToolModeBoth, true},
	}

	reg := NewDefaultRegistry()
	for _, exp := range expectations {
		c, ok := reg.Get(exp.name)
		if !ok {
			t.Errorf("missing connector %q", exp.name)
			continue
		}
		if c.ToolInspectionMode() != exp.toolMode {
			t.Errorf("%s: ToolInspectionMode = %q, want %q", exp.name, c.ToolInspectionMode(), exp.toolMode)
		}
		policy := c.SubprocessPolicy()
		if policy != SubprocessSandbox && policy != SubprocessShims {
			t.Errorf("%s: SubprocessPolicy = %q, want sandbox or shims", exp.name, policy)
		}
	}
}

// --- Route correctness for all connectors ---

func TestAllConnectors_Route_ReturnsConnectorName(t *testing.T) {
	reg := NewDefaultRegistry()
	body := []byte(`{"model":"gpt-4o","stream":true}`)

	for _, info := range reg.Available() {
		c, _ := reg.Get(info.Name)
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header.Set("Authorization", "Bearer sk-test")

		if info.Name == "openclaw" {
			r.Header.Set("X-AI-Auth", "Bearer sk-test")
			r.Header.Set("X-DC-Target-URL", "https://api.openai.com")
		}

		cs, err := c.Route(r, body)
		if err != nil {
			t.Errorf("%s Route() error: %v", info.Name, err)
			continue
		}
		if cs.ConnectorName != info.Name {
			t.Errorf("%s: ConnectorName = %q, want %q", info.Name, cs.ConnectorName, info.Name)
		}
		if cs.RawModel != "gpt-4o" {
			t.Errorf("%s: RawModel = %q, want gpt-4o", info.Name, cs.RawModel)
		}
		if !cs.Stream {
			t.Errorf("%s: Stream should be true", info.Name)
		}
	}
}

// --- Passthrough mode parity ---

func TestAllConnectors_Route_PassthroughNonChat(t *testing.T) {
	reg := NewDefaultRegistry()
	body := []byte(`{"model":"gpt-4o"}`)

	for _, info := range reg.Available() {
		c, _ := reg.Get(info.Name)
		r := httptest.NewRequest("POST", "/v1/embeddings", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header.Set("Authorization", "Bearer sk-test")

		if info.Name == "openclaw" {
			r.Header.Set("X-AI-Auth", "Bearer sk-test")
			r.Header.Set("X-DC-Target-URL", "https://api.openai.com")
		}

		cs, err := c.Route(r, body)
		if err != nil {
			t.Errorf("%s Route() error: %v", info.Name, err)
			continue
		}
		if !cs.PassthroughMode {
			t.Errorf("%s: PassthroughMode should be true for /v1/embeddings", info.Name)
		}
	}
}

// --- Auth parity: all connectors accept SetCredentials(token, masterKey) ---

func TestAllConnectors_Auth_Parity(t *testing.T) {
	type credSetter interface {
		SetCredentials(gatewayToken, masterKey string)
	}

	connectors := []Connector{
		NewOpenClawConnector(),
		NewZeptoClawConnector(),
		NewClaudeCodeConnector(),
		NewCodexConnector(),
	}

	for _, c := range connectors {
		cs, ok := c.(credSetter)
		if !ok {
			t.Errorf("%s does not implement SetCredentials(token, masterKey)", c.Name())
			continue
		}
		cs.SetCredentials("test-token", "test-master")

		// Token auth
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header.Set("X-DC-Auth", "test-token")
		if !c.Authenticate(r) {
			t.Errorf("%s: X-DC-Auth should authenticate", c.Name())
		}

		// Master key auth
		r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r2.RemoteAddr = "127.0.0.1:54321"
		r2.Header.Set("Authorization", "Bearer test-master")
		if !c.Authenticate(r2) {
			t.Errorf("%s: master key should authenticate", c.Name())
		}

		// No creds should fail — except for native-binary connectors
		// that have no way to carry DefenseClaw credentials and must
		// trust loopback. Gate the assertion off .Name() rather than
		// silently weakening the invariant across the board.
		r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r3.RemoteAddr = "127.0.0.1:54321"
		switch c.Name() {
		case "zeptoclaw":
			if !c.Authenticate(r3) {
				t.Errorf("%s: loopback must be trusted (no fetch interceptor to inject X-DC-Auth)", c.Name())
			}
		default:
			if c.Authenticate(r3) {
				t.Errorf("%s: should fail without credentials when token configured", c.Name())
			}
		}
	}
}

// --- Template rendering ---

func TestShimTemplateRendering(t *testing.T) {
	data := templateData{APIAddr: "10.0.0.1:9999"}
	tmpl := `API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"`
	rendered, err := renderTemplate(tmpl, data)
	if err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}
	if !strings.Contains(rendered, "10.0.0.1:9999") {
		t.Errorf("rendered template does not contain addr: %s", rendered)
	}
}

// --- Plugin discovery on empty dir ---

func TestDiscoverPlugins_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	r := NewDefaultRegistry()
	if err := r.DiscoverPlugins(dir); err != nil {
		t.Fatalf("DiscoverPlugins on empty dir: %v", err)
	}
	// Should still have only built-in connectors
	if r.Len() != 4 {
		t.Errorf("expected 4 built-in connectors, got %d", r.Len())
	}
}

func TestDiscoverPlugins_NonexistentDir(t *testing.T) {
	r := NewDefaultRegistry()
	if err := r.DiscoverPlugins("/nonexistent/path"); err != nil {
		t.Fatalf("DiscoverPlugins on missing dir should not error: %v", err)
	}
}

// --- Surface 1: LLM traffic routing tests ---

func TestCodex_Setup_Surface1_WritesEnvFiles(t *testing.T) {
	dir := t.TempDir()
	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Check shell env file
	envData, err := os.ReadFile(filepath.Join(dir, "codex_env.sh"))
	if err != nil {
		t.Fatalf("env file not created: %v", err)
	}
	envContent := string(envData)
	if !strings.Contains(envContent, "OPENAI_BASE_URL") {
		t.Error("env file missing OPENAI_BASE_URL")
	}
	if !strings.Contains(envContent, "/c/codex") {
		t.Errorf("env file missing /c/codex prefix: %s", envContent)
	}

	// Check dotenv file
	dotenvData, err := os.ReadFile(filepath.Join(dir, "codex.env"))
	if err != nil {
		t.Fatalf("dotenv file not created: %v", err)
	}
	if !strings.Contains(string(dotenvData), "/c/codex") {
		t.Errorf("dotenv missing /c/codex prefix: %s", string(dotenvData))
	}

	// Check backup
	backupData, err := os.ReadFile(filepath.Join(dir, "codex_backup.json"))
	if err != nil {
		t.Fatalf("backup not saved: %v", err)
	}
	var backup codexBackup
	json.Unmarshal(backupData, &backup)
	if backup.HadBaseURL {
		t.Error("backup.HadBaseURL should be false when env not set")
	}
}

func TestCodex_Teardown_Surface1_RemovesEnvFiles(t *testing.T) {
	dir := t.TempDir()
	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	c.Setup(nil, opts)

	// Verify files exist
	if _, err := os.Stat(filepath.Join(dir, "codex_env.sh")); err != nil {
		t.Fatal("env file not created")
	}

	c.Teardown(nil, opts)

	if _, err := os.Stat(filepath.Join(dir, "codex_env.sh")); !os.IsNotExist(err) {
		t.Error("codex_env.sh should be removed after teardown")
	}
	if _, err := os.Stat(filepath.Join(dir, "codex.env")); !os.IsNotExist(err) {
		t.Error("codex.env should be removed after teardown")
	}
	if _, err := os.Stat(filepath.Join(dir, "codex_backup.json")); !os.IsNotExist(err) {
		t.Error("codex_backup.json should be removed after teardown")
	}
}

func TestCodex_Setup_Surface1_BackupsExistingEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	c.Setup(nil, opts)

	backupData, _ := os.ReadFile(filepath.Join(dir, "codex_backup.json"))
	var backup codexBackup
	json.Unmarshal(backupData, &backup)
	if !backup.HadBaseURL {
		t.Error("backup.HadBaseURL should be true")
	}
	if backup.OldBaseURL != "https://api.openai.com/v1" {
		t.Errorf("backup.OldBaseURL = %q", backup.OldBaseURL)
	}
}

func TestClaudeCode_Setup_Surface1_WritesEnvFiles(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	os.MkdirAll(settingsDir, 0o755)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	os.WriteFile(settingsPath, []byte(`{}`), 0o644)

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	envData, err := os.ReadFile(filepath.Join(dir, "claudecode_env.sh"))
	if err != nil {
		t.Fatalf("env file not created: %v", err)
	}
	if !strings.Contains(string(envData), "ANTHROPIC_BASE_URL") {
		t.Error("env file missing ANTHROPIC_BASE_URL")
	}
	if !strings.Contains(string(envData), "/c/claudecode") {
		t.Errorf("env file missing /c/claudecode prefix: %s", string(envData))
	}

	dotenvData, err := os.ReadFile(filepath.Join(dir, "claudecode.env"))
	if err != nil {
		t.Fatalf("dotenv file not created: %v", err)
	}
	if !strings.Contains(string(dotenvData), "/c/claudecode") {
		t.Errorf("dotenv missing /c/claudecode prefix: %s", string(dotenvData))
	}
}

func TestClaudeCode_Setup_WritesConnectorPrefix(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	os.MkdirAll(settingsDir, 0o755)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	os.WriteFile(settingsPath, []byte(`{}`), 0o644)

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	envData, _ := os.ReadFile(filepath.Join(dir, "claudecode_env.sh"))
	if !strings.Contains(string(envData), "/c/claudecode") {
		t.Error("env file missing /c/claudecode prefix")
	}
}

func TestClaudeCode_Teardown_Surface1_RemovesEnvFiles(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	os.MkdirAll(settingsDir, 0o755)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	os.WriteFile(settingsPath, []byte(`{}`), 0o644)

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	c.Setup(nil, opts)
	c.Teardown(nil, opts)

	if _, err := os.Stat(filepath.Join(dir, "claudecode_env.sh")); !os.IsNotExist(err) {
		t.Error("claudecode_env.sh should be removed after teardown")
	}
	if _, err := os.Stat(filepath.Join(dir, "claudecode.env")); !os.IsNotExist(err) {
		t.Error("claudecode.env should be removed after teardown")
	}
}

func TestZeptoClaw_Setup_Surface1_PatchesConfig(t *testing.T) {
	dir := t.TempDir()

	configDir := filepath.Join(dir, "zeptoclaw-config")
	os.MkdirAll(configDir, 0o755)
	configPath := filepath.Join(configDir, "config.json")
	original := `{
		"providers": {
			"anthropic": {"api_key": "sk-ant-test", "api_base": "https://api.anthropic.com"},
			"openai": {"api_key": "sk-test"}
		},
		"agents": {"model": "gpt-4o"}
	}`
	os.WriteFile(configPath, []byte(original), 0o644)

	ZeptoClawConfigPathOverride = configPath
	defer func() { ZeptoClawConfigPathOverride = "" }()

	c := NewZeptoClawConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	var config map[string]interface{}
	json.Unmarshal(data, &config)

	providers, ok := config["providers"].(map[string]interface{})
	if !ok {
		t.Fatal("providers not set in config")
	}
	for _, name := range []string{"anthropic", "openai"} {
		prov, ok := providers[name].(map[string]interface{})
		if !ok {
			t.Fatalf("provider %s missing", name)
		}
		apiBase, ok := prov["api_base"].(string)
		if !ok {
			t.Fatalf("provider %s missing api_base", name)
		}
		if !strings.Contains(apiBase, "/c/zeptoclaw") {
			t.Errorf("providers.%s.api_base = %q, missing /c/zeptoclaw prefix", name, apiBase)
		}
	}

	safety, ok := config["safety"].(map[string]interface{})
	if !ok {
		t.Fatal("safety not set in config")
	}
	if safety["allow_private_endpoints"] != true {
		t.Error("safety.allow_private_endpoints should be true")
	}

	agents, ok := config["agents"].(map[string]interface{})
	if !ok || agents["model"] != "gpt-4o" {
		t.Error("agents.model was clobbered")
	}

	// Setup must NOT write config["hooks"]. ZeptoClaw's hooks schema is a
	// notification config (before_tool/after_tool = []HookRule, each with
	// tools/level/target_channel fields), not a script-path map. Writing a
	// string path there makes ZeptoClaw's deserializer fail with
	// "expected a sequence". Tool-call inspection is handled by the proxy
	// route (/c/zeptoclaw) via the LLM stream; no config hook is needed.
	if _, exists := config["hooks"]; exists {
		t.Errorf("hooks should not be written by zeptoclaw Setup, got %v", config["hooks"])
	}
}

func TestZeptoClaw_Setup_PreservesExistingHooks(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "zeptoclaw-config.json")
	// ZeptoClaw's real hooks schema: before_tool/after_tool are arrays.
	original := `{
		"providers": {"anthropic": {"api_key": "sk-ant-test"}},
		"hooks": {
			"enabled": false,
			"before_tool": [],
			"after_tool": [],
			"on_error": []
		}
	}`
	os.WriteFile(configPath, []byte(original), 0o644)

	ZeptoClawConfigPathOverride = configPath
	defer func() { ZeptoClawConfigPathOverride = "" }()

	c := NewZeptoClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("config is not valid JSON after Setup: %v", err)
	}

	hooks, ok := config["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("existing hooks section was removed")
	}
	// before_tool must remain an array to satisfy ZeptoClaw's schema.
	if _, ok := hooks["before_tool"].([]interface{}); !ok {
		t.Errorf("hooks.before_tool must stay a sequence, got %T", hooks["before_tool"])
	}
	if _, ok := hooks["after_tool"].([]interface{}); !ok {
		t.Errorf("hooks.after_tool must stay a sequence, got %T", hooks["after_tool"])
	}
}

func TestZeptoClaw_Teardown_Surface1_RestoresConfig(t *testing.T) {
	dir := t.TempDir()

	configDir := filepath.Join(dir, "zeptoclaw-config")
	os.MkdirAll(configDir, 0o755)
	configPath := filepath.Join(configDir, "config.json")
	original := `{
		"providers": {
			"anthropic": {"api_key": "sk-ant-test", "api_base": "https://api.anthropic.com"}
		},
		"agents": {"model": "gpt-4o"}
	}`
	os.WriteFile(configPath, []byte(original), 0o644)

	ZeptoClawConfigPathOverride = configPath
	defer func() { ZeptoClawConfigPathOverride = "" }()

	c := NewZeptoClawConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	c.Setup(nil, opts)
	c.Teardown(nil, opts)

	data, _ := os.ReadFile(configPath)
	var config map[string]interface{}
	json.Unmarshal(data, &config)

	if _, exists := config["hooks"]; exists {
		t.Error("hooks should be removed when none existed before setup")
	}
	if _, exists := config["safety"]; exists {
		t.Error("safety should be removed when none existed before setup")
	}

	providers, ok := config["providers"].(map[string]interface{})
	if !ok {
		t.Fatal("providers should be restored")
	}
	anthropic, ok := providers["anthropic"].(map[string]interface{})
	if !ok {
		t.Fatal("anthropic provider should be restored")
	}
	if anthropic["api_base"] != "https://api.anthropic.com" {
		t.Errorf("anthropic api_base = %v, want original", anthropic["api_base"])
	}
	if anthropic["api_key"] != "sk-ant-test" {
		t.Errorf("anthropic api_key = %v, want original", anthropic["api_key"])
	}

	agents, ok := config["agents"].(map[string]interface{})
	if !ok || agents["model"] != "gpt-4o" {
		t.Error("agents.model was clobbered by teardown")
	}
}

func TestZeptoClaw_Setup_ProducesValidZeptoClawConfig(t *testing.T) {
	// Regression test: before the fix, Setup wrote config["hooks"] as
	// {before_tool: <string path>, ...}, which ZeptoClaw rejected with
	// "expected a sequence" because its HooksConfig defines before_tool as
	// Vec<HookRule>. The connector must leave the hooks section alone so
	// ZeptoClaw's own defaults remain valid.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "zeptoclaw-config.json")
	os.WriteFile(configPath, []byte(`{}`), 0o644)
	ZeptoClawConfigPathOverride = configPath
	defer func() { ZeptoClawConfigPathOverride = "" }()

	c := NewZeptoClawConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Setup produced invalid JSON: %v", err)
	}

	// If hooks is written, every before_*/after_* entry must be a sequence
	// (ZeptoClaw's HookRule array), never a string path.
	if hooks, ok := config["hooks"].(map[string]interface{}); ok {
		for k, v := range hooks {
			if k == "enabled" {
				continue
			}
			if _, isString := v.(string); isString {
				t.Errorf("hooks[%q] = string %v — ZeptoClaw expects a sequence", k, v)
			}
		}
	}
}
