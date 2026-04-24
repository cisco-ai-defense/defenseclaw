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

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if c.Authenticate(r) {
		t.Error("expected auth to fail without token when token configured")
	}

	r.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r) {
		t.Error("expected auth to pass with correct token")
	}

	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	r2.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r2) {
		t.Error("expected auth to pass with master key")
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
	if cs.RawUpstream != "" {
		t.Errorf("RawUpstream = %q, want empty", cs.RawUpstream)
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

		// No creds should fail
		r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r3.RemoteAddr = "127.0.0.1:54321"
		if c.Authenticate(r3) {
			t.Errorf("%s: should fail without credentials when token configured", c.Name())
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
	os.WriteFile(configPath, []byte(`{"model": "gpt-4o"}`), 0o644)

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

	apiBase, ok := config["api_base"].(string)
	if !ok {
		t.Fatal("api_base not set in config")
	}
	if !strings.Contains(apiBase, "/c/zeptoclaw") {
		t.Errorf("api_base = %q, missing /c/zeptoclaw prefix", apiBase)
	}
	if config["model"] != "gpt-4o" {
		t.Error("model was clobbered")
	}

	hooks := config["hooks"].(map[string]interface{})
	if !strings.Contains(hooks["before_tool"].(string), "inspect-tool.sh") {
		t.Errorf("hooks.before_tool = %q", hooks["before_tool"])
	}
}

func TestZeptoClaw_Teardown_Surface1_RestoresConfig(t *testing.T) {
	dir := t.TempDir()

	configDir := filepath.Join(dir, "zeptoclaw-config")
	os.MkdirAll(configDir, 0o755)
	configPath := filepath.Join(configDir, "config.json")
	os.WriteFile(configPath, []byte(`{"model": "gpt-4o"}`), 0o644)

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

	if _, exists := config["api_base"]; exists {
		t.Error("api_base should be removed after teardown")
	}
	if _, exists := config["hooks"]; exists {
		t.Error("hooks should be removed when none existed before setup")
	}
	if config["model"] != "gpt-4o" {
		t.Error("model was clobbered by teardown")
	}
}

func TestZeptoClaw_Setup_WritesAllHookPaths(t *testing.T) {
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
	json.Unmarshal(data, &config)

	hooks, ok := config["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("hooks not set in config")
	}
	expectedHooks := []string{"before_tool", "before_request", "after_response", "after_tool"}
	for _, hk := range expectedHooks {
		v, ok := hooks[hk]
		if !ok {
			t.Errorf("missing hook %s in config", hk)
			continue
		}
		path, _ := v.(string)
		if !strings.Contains(path, "hooks/") {
			t.Errorf("hook %s does not point to hooks dir: %s", hk, path)
		}
	}
}
