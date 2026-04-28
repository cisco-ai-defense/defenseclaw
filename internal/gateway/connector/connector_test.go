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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/pelletier/go-toml/v2"
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
		{"[::ffff:127.0.0.1]:9090", true},
		{"::1", true},
		{"[::ffff:10.0.0.1]:9090", false},
		{"", false},
		{"garbage", false},
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
// M8: ClaudeCode and Codex no longer implement HookEventHandler — the stub
// returned hardcoded "allow" which was a silent fail-open risk. Policy
// enforcement lives in the gateway's handleClaudeCodeHook/handleCodexHook.

func TestClaudeCode_DoesNotImplementHookEventHandler(t *testing.T) {
	c := NewClaudeCodeConnector()
	if _, ok := interface{}(c).(HookEventHandler); ok {
		t.Error("ClaudeCode should not implement HookEventHandler (stub removed)")
	}
}

func TestCodex_DoesNotImplementHookEventHandler(t *testing.T) {
	c := NewCodexConnector()
	if _, ok := interface{}(c).(HookEventHandler); ok {
		t.Error("Codex should not implement HookEventHandler (stub removed)")
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

// --- OpenClaw extension placeholder tests ---

// TestOpenClaw_ExtensionAvailable_OnFullBuild guards the build-time
// embed contract. When the gateway is built normally (with
// extensions/defenseclaw/dist populated and synced), the embedded
// tree contains package.json and openClawExtensionAvailable() must
// return true. If this ever flips to false, the Makefile sync step
// is broken and Setup will refuse to install the plugin even though
// it exists on disk.
func TestOpenClaw_ExtensionAvailable_OnFullBuild(t *testing.T) {
	t.Parallel()
	if _, err := openClawExtensionFS.ReadFile(filepath.Join(openClawPluginRoot, ".placeholder")); err == nil {
		t.Skip("gateway built without OpenClaw extension (placeholder present) — full-build assertion does not apply here")
	}
	if !openClawExtensionAvailable() {
		t.Fatal("openClawExtensionAvailable() = false on a non-placeholder build — sync-openclaw-extension is broken")
	}
}

// TestOpenClaw_Setup_RefusesPlaceholder is impossible to drive
// directly without rebuilding the gateway, so we encode the contract
// as documentation for future readers: if openClawExtensionAvailable()
// returns false at runtime, OpenClawConnector.Setup must return an
// actionable error mentioning `make extensions`. The body of Setup is
// the source of truth — see internal/gateway/connector/openclaw.go.
func TestOpenClaw_Setup_RefusesPlaceholder(t *testing.T) {
	t.Parallel()
	// Source-level assertion — we don't try to mutate the embedded
	// FS at runtime (//go:embed is read-only). The reverse case is
	// covered by TestOpenClaw_ExtensionAvailable_OnFullBuild.
	c := NewOpenClawConnector()
	if c == nil {
		t.Fatal("NewOpenClawConnector returned nil")
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

func TestOpenClaw_ImplementsComponentScanner(t *testing.T) {
	c := NewOpenClawConnector()
	var _ ComponentScanner = c
	if !c.SupportsComponentScanning() {
		t.Error("expected SupportsComponentScanning to be true")
	}
	targets := c.ComponentTargets("/tmp/workspace")
	expectedTypes := []string{"skill", "plugin", "mcp", "config"}
	for _, tp := range expectedTypes {
		if _, ok := targets[tp]; !ok {
			t.Errorf("missing component type %q", tp)
		}
	}
}

func TestZeptoClaw_ImplementsComponentScanner(t *testing.T) {
	c := NewZeptoClawConnector()
	var _ ComponentScanner = c
	if !c.SupportsComponentScanning() {
		t.Error("expected SupportsComponentScanning to be true")
	}
	targets := c.ComponentTargets("/tmp/workspace")
	expectedTypes := []string{"skill", "plugin", "mcp", "config"}
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

	// No credentials configured — non-loopback is denied by default
	r2 := httptest.NewRequest("POST", "/v1/messages", nil)
	r2.RemoteAddr = "10.0.0.5:54321"
	if c.Authenticate(r2) {
		t.Error("expected non-loopback auth to fail when no credentials configured")
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

// TestClaudeCode_Setup_RegistersFullEventCoverage verifies the Claude
// Code hook registration matches the coverage established by PR #140:
// 27 events across the full Claude Code lifecycle, with the event-type
// specific matchers Claude Code expects.
//
// The earlier 8-event registration missed major surfaces — in particular
// tool-use events were gated on a hard-coded regex of tool names that
// silently dropped any tool Claude added post-release (Skill, ToolSearch,
// etc. appeared and disappeared from the list over time). The PR #140
// design uses matcher "*" for tool events so new Claude tools get
// inspected by default.
func TestClaudeCode_Setup_RegistersFullEventCoverage(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude-settings.json")
	os.WriteFile(settingsPath, []byte(`{}`), 0o644)
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, _ := os.ReadFile(settingsPath)
	var settings map[string]interface{}
	json.Unmarshal(data, &settings)
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("hooks section missing")
	}

	// Full event coverage (PR #140's _CLAUDE_CODE_EVENTS, minus
	// WorktreeCreate which is intentionally excluded). Every server-side
	// case in internal/gateway/claude_code_hook.go must have a matching
	// client registration; otherwise we rely on events Claude never fires.
	wanted := []string{
		"SessionStart", "InstructionsLoaded", "UserPromptSubmit",
		"UserPromptExpansion", "PreToolUse", "PermissionRequest",
		"PostToolUse", "PostToolUseFailure", "PostToolBatch",
		"PermissionDenied", "Notification", "SubagentStart", "SubagentStop",
		"TaskCreated", "TaskCompleted", "Stop", "StopFailure", "TeammateIdle",
		"ConfigChange", "CwdChanged", "FileChanged", "WorktreeRemove",
		"PreCompact", "PostCompact", "SessionEnd", "Elicitation",
		"ElicitationResult",
	}
	for _, evt := range wanted {
		if _, ok := hooks[evt]; !ok {
			t.Errorf("missing hook event %q", evt)
		}
	}

	// Matcher invariants per PR #140.
	// Tool-use events must use "*" so we never drop coverage when
	// Claude Code adds a new builtin tool. Hard-coded tool regexes
	// silently fail to gate new tools.
	for _, evt := range []string{"PreToolUse", "PostToolUse", "PermissionRequest", "PostToolUseFailure", "PermissionDenied"} {
		m := firstMatcher(hooks[evt])
		if m != "*" {
			t.Errorf("%s matcher = %q, want \"*\" (PR #140 pattern)", evt, m)
		}
	}

	// SessionStart has distinct phases — matcher selects which to
	// observe. All four are worth inspecting for lifecycle events.
	if m := firstMatcher(hooks["SessionStart"]); m != "startup|resume|clear|compact" {
		t.Errorf("SessionStart matcher = %q, want startup|resume|clear|compact", m)
	}

	// FileChanged narrows to config files only; generic file writes
	// are already covered by PostToolUse.
	if m := firstMatcher(hooks["FileChanged"]); !strings.Contains(m, "CLAUDE.md") {
		t.Errorf("FileChanged matcher = %q, want config-file matcher including CLAUDE.md", m)
	}
}

// firstMatcher returns the "matcher" field of the first entry in a
// Claude Code hook event array, or "" when absent.
func firstMatcher(eventEntries interface{}) string {
	arr, ok := eventEntries.([]interface{})
	if !ok || len(arr) == 0 {
		return ""
	}
	entry, ok := arr[0].(map[string]interface{})
	if !ok {
		return ""
	}
	m, _ := entry["matcher"].(string)
	return m
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

	// Loopback is trusted unconditionally — see TestCodex_Authenticate_NativeBinaryLoopback
	// for the rationale. Token-based auth is exercised on non-loopback
	// addresses, which is what the gateway token actually protects.
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	if c.Authenticate(r) {
		t.Error("expected non-loopback auth to fail without token")
	}

	r.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r) {
		t.Error("expected non-loopback auth to pass with correct X-DC-Auth")
	}

	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "10.0.0.5:54321"
	r2.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r2) {
		t.Error("expected non-loopback auth to pass with master key")
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

	// No credentials — non-loopback is denied by default
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "10.0.0.5:54321"
	if c.Authenticate(r2) {
		t.Error("expected non-loopback auth to fail when no credentials configured")
	}

	// With token — non-loopback without token fails
	c.SetCredentials("my-token", "")
	r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r3.RemoteAddr = "10.0.0.5:54321"
	if c.Authenticate(r3) {
		t.Error("expected non-loopback auth to fail when token configured")
	}

	// With token — loopback WITHOUT X-DC-Auth must still pass because
	// codex-cli is a native Rust binary with no fetch interceptor that
	// could inject X-DC-Auth. Its Authorization header carries the
	// upstream provider API key, never the gateway token. Denying
	// loopback when a gateway token is configured would make codex
	// fundamentally unroutable. Non-loopback callers still require
	// the token — bridge/remote deployments stay protected.
	r4 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r4.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r4) {
		t.Error("loopback must be trusted for codex even when gateway token is set — codex cannot inject X-DC-Auth")
	}
}

// TestCodex_Authenticate_NativeBinaryLoopback documents the critical
// end-to-end auth path: codex routes LLM traffic to /c/codex/responses
// on loopback with an Authorization: Bearer <provider-api-key> header.
// DefenseClaw must accept this (stripping the provider key for
// inspection and forwarding to upstream) regardless of whether a
// gateway token is configured — otherwise codex sees a 401 and no
// traffic is ever inspected.
func TestCodex_Authenticate_NativeBinaryLoopback(t *testing.T) {
	c := NewCodexConnector()
	c.SetCredentials("gw-tok-5c80", "")

	r := httptest.NewRequest("POST", "/c/codex/responses", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-or-v1-real-openrouter-key")
	// Note: no X-DC-Auth — native binary has no way to inject it.

	if !c.Authenticate(r) {
		t.Fatal("codex loopback with provider Authorization must be accepted; " +
			"otherwise codex → proxy traffic gets 401'd and guardrail never runs")
	}
}

func TestCodex_Authenticate_NoCredentials(t *testing.T) {
	c := NewCodexConnector()
	// No credentials + non-loopback → deny
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "192.168.1.100:54321"
	if c.Authenticate(r) {
		t.Error("expected non-loopback auth to fail when no credentials configured")
	}
	// No credentials + loopback → allow
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r2) {
		t.Error("expected loopback auth to pass when no credentials configured")
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
	CodexConfigPathOverride = filepath.Join(dir, "config.toml")
	defer func() { CodexConfigPathOverride = "" }()
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

// TestCodex_Setup_PatchesConnectorPrefixInConfigToml verifies the
// /c/codex routing prefix lands in the only place codex-cli reads it:
// [model_providers.*].base_url in ~/.codex/config.toml. We
// intentionally do NOT write a global OPENAI_BASE_URL anymore (see
// S8.1 / F31 in claw-agnostic-refactor) — exporting that env var
// would silently route every other OpenAI-SDK client on the host
// through this proxy.
func TestCodex_Setup_PatchesConnectorPrefixInConfigToml(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	// Seed a model_providers entry so the codex flow has something to
	// rewrite (otherwise patchCodexConfig synthesizes a default openai
	// entry, which would also pass — but we want to pin the patch
	// path explicitly).
	original := `model_provider = "openai"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"
env_key = "OPENAI_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatalf("seed config.toml: %v", err)
	}

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	patched, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	if !strings.Contains(string(patched), "/c/codex") {
		t.Errorf("config.toml missing /c/codex prefix after Setup; got:\n%s", patched)
	}

	// Negative assertion: the legacy global env files MUST NOT
	// be written. This is the F31 contract.
	if _, err := os.Stat(filepath.Join(dir, "codex_env.sh")); !os.IsNotExist(err) {
		t.Errorf("codex_env.sh must not be written (S8.1 / F31)")
	}
	if _, err := os.Stat(filepath.Join(dir, "codex.env")); !os.IsNotExist(err) {
		t.Errorf("codex.env must not be written (S8.1 / F31)")
	}
}

// TestCodex_Route_ResolvesUpstreamFromSnapshot documents the
// critical native-binary routing path: codex sends LLM requests with
// no X-DC-Target-URL header (it's a Rust binary with no fetch
// interceptor). Route() must synthesize RawUpstream from the provider
// snapshot captured at Setup — otherwise the proxy's passthrough
// handler rejects the request with "missing X-DC-Target-URL".
func TestCodex_Route_ResolvesUpstreamFromSnapshot(t *testing.T) {
	c := NewCodexConnector()
	c.SetProviderSnapshot(map[string]CodexProviderEntry{
		"openrouter": {BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-or-snap"},
	})
	body := []byte(`{"model":"openai/gpt-4o-mini"}`)
	r := httptest.NewRequest("POST", "/responses", nil)
	r.Header.Set("Authorization", "Bearer incoming-client-key")

	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if cs.RawUpstream != "https://openrouter.ai/api/v1" {
		t.Errorf("RawUpstream = %q, want snapshot base_url", cs.RawUpstream)
	}
	if cs.RawAPIKey != "sk-or-snap" {
		t.Errorf("RawAPIKey = %q, want snapshot api_key", cs.RawAPIKey)
	}
}

// TestCodex_Setup_CapturesProviderSnapshot verifies Setup reads each
// [model_providers.*] entry from config.toml, resolves its env_key to
// a live API key from the environment, and populates the in-memory
// snapshot before overwriting base_url with the proxy URL.
func TestCodex_Setup_CapturesProviderSnapshot(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model_provider = "openrouter"

[model_providers.openrouter]
name = "openrouter"
base_url = "https://openrouter.ai/api/v1"
env_key = "OPENROUTER_API_KEY"
`
	os.WriteFile(configPath, []byte(original), 0o644)
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	t.Setenv("OPENROUTER_API_KEY", "sk-or-live-test-value")

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	snap := c.ProviderSnapshot()
	entry, ok := snap["openrouter"]
	if !ok {
		t.Fatalf("snapshot missing openrouter entry; got %v", snap)
	}
	if entry.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("snapshot BaseURL = %q, want original openrouter URL (NOT proxy)", entry.BaseURL)
	}
	if entry.APIKey != "sk-or-live-test-value" {
		t.Errorf("snapshot APIKey = %q, want resolved from OPENROUTER_API_KEY env", entry.APIKey)
	}
}

// TestCodex_Setup_RewritesModelProvidersBaseURL verifies the Codex
// connector rewrites each [model_providers.*] base_url in
// ~/.codex/config.toml to route through DefenseClaw's proxy. The env
// var OPENAI_BASE_URL is NOT sufficient because Codex honors the
// per-provider TOML value first, which means non-default providers
// (openrouter, ollama, lmstudio) otherwise skip the proxy entirely.
func TestCodex_Setup_RewritesModelProvidersBaseURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model_provider = "openrouter"

[model_providers.openrouter]
name = "openrouter"
base_url = "https://openrouter.ai/api/v1"
env_key = "OPENROUTER_API_KEY"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"
env_key = "OPENAI_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	rewritten := string(data)
	proxy := "http://127.0.0.1:4000/c/codex"
	// Accept either single- or double-quoted TOML string form.
	proxyHits := strings.Count(rewritten, "base_url = '"+proxy+"'") +
		strings.Count(rewritten, `base_url = "`+proxy+`"`)
	if proxyHits != 2 {
		t.Errorf("expected 2 base_url lines rewritten to proxy, got %d\nfile:\n%s",
			proxyHits, rewritten)
	}
	if strings.Contains(rewritten, "openrouter.ai/api/v1") {
		t.Error("original openrouter base_url still present — not rewritten")
	}
	if strings.Contains(rewritten, "api.openai.com/v1") {
		t.Error("original openai base_url still present — not rewritten")
	}
}

// TestCodex_Setup_ConfigTomlIsModeChmod600 pins the file mode of
// the patched ~/.codex/config.toml. Codex's config.toml carries
// env_key bindings and (after Setup) the DefenseClaw proxy URL. On
// shared dev hosts the historical 0o644 mode let any local user
// read those bindings — which is enough to derive provider keys
// from the matching env files. S0.15 / S0.11: the patcher must
// write the file via atomicWriteFile at 0o600.
//
// Note: the test runs *after* Setup, so it asserts the mode of
// the rewritten file (the input we wrote at 0o644 above is fine —
// Setup must clobber both the contents and the mode).
func TestCodex_Setup_ConfigTomlIsModeChmod600(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model_provider = "openai"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"
env_key = "OPENAI_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config.toml: %v", err)
	}
	// Mask off the file-type bits — only the permission bits matter
	// here. We assert exactly 0o600: any group/world bit means a
	// shared-host user can read provider env-var names + base URLs.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("config.toml mode = %#o, want 0o600", mode)
	}
}

// TestCodex_Setup_RegistersHooksInline verifies the Codex connector
// writes an inline [hooks] HookEventsToml struct into config.toml
// covering all five Codex events and pointing at the generated
// codex-hook.sh. The hooks key is NOT a path to a hooks.json file —
// that would trigger a TOML parse error at codex startup.
func TestCodex_Setup_RegistersHooksInline(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	os.WriteFile(configPath, []byte(`model_provider = "openai"
`), 0o644)
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// A stale hooks.json from the file-path approach must NOT be
	// created — codex rejects it with "invalid type: string" at startup.
	if _, err := os.Stat(filepath.Join(filepath.Dir(configPath), "hooks.json")); err == nil {
		t.Error("hooks.json was written — should be inline in config.toml instead")
	}

	raw, _ := os.ReadFile(configPath)
	content := string(raw)

	// The [hooks] table must be present with each of the five events
	// listed as sub-tables.
	for _, evt := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"} {
		if !strings.Contains(content, "hooks."+evt) && !strings.Contains(content, "hooks\n"+evt) {
			// Accept either dotted or nested rendering.
			if !strings.Contains(content, evt) {
				t.Errorf("config.toml missing event %q\nfile:\n%s", evt, content)
			}
		}
	}
	if !strings.Contains(content, "codex-hook.sh") {
		t.Errorf("config.toml [hooks] missing codex-hook.sh reference\nfile:\n%s", content)
	}

	// Re-parse to ensure it's valid TOML and codex's expected shape
	// (hooks is a table, not a string).
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("config.toml did not round-trip as valid TOML: %v", err)
	}
	if _, isString := parsed["hooks"].(string); isString {
		t.Error("hooks key is a string — codex requires HookEventsToml struct")
	}
	if _, isTable := parsed["hooks"].(map[string]interface{}); !isTable {
		t.Errorf("hooks key is not a table, got %T", parsed["hooks"])
	}
}

// TestCodex_Setup_EnablesHooksFeature confirms the connector writes
// features.codex_hooks = true into config.toml. Without this, Codex
// ignores any registered hooks because the feature gate defaults to
// off.
func TestCodex_Setup_EnablesHooksFeature(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	os.WriteFile(configPath, []byte(`model_provider = "openai"
`), 0o644)
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	content := string(data)
	if !strings.Contains(content, "codex_hooks") {
		t.Errorf("config.toml missing codex_hooks feature flag\nfile:\n%s", content)
	}
}

// TestCodex_Teardown_RestoresConfig verifies Teardown restores the
// original base_urls and removes the hooks.json + feature flag.
func TestCodex_Teardown_RestoresConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model_provider = "openai"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"
env_key = "OPENAI_API_KEY"
`
	os.WriteFile(configPath, []byte(original), 0o644)
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(nil, opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	rewritten := string(data)
	if !strings.Contains(rewritten, "api.openai.com/v1") {
		t.Errorf("Teardown did not restore original base_url\nfile:\n%s", rewritten)
	}
	if strings.Contains(rewritten, "/c/codex") {
		t.Error("Teardown left proxy base_url in config.toml")
	}
	// The inline [hooks] table we added must be gone after Teardown
	// so the operator's config.toml returns to its pre-setup shape.
	if strings.Contains(rewritten, "codex-hook.sh") {
		t.Errorf("Teardown left hook script reference in config.toml\nfile:\n%s", rewritten)
	}
}

func TestCodex_Teardown(t *testing.T) {
	dir := t.TempDir()
	CodexConfigPathOverride = filepath.Join(dir, "config.toml")
	defer func() { CodexConfigPathOverride = "" }()
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

func TestCodex_SetCredentials_OnConnectorInterface(t *testing.T) {
	c := NewCodexConnector()
	var conn Connector = c // SetCredentials is now on the core interface
	conn.SetCredentials("tok", "mk")

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-DC-Auth", "tok")
	if !c.Authenticate(r) {
		t.Error("SetCredentials on Connector interface should wire token auth")
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

	// ZeptoClaw is a native binary with no fetch interceptor (same
	// shape as codex) — its Authorization header carries the upstream
	// provider key, never DefenseClaw's gateway token. Loopback is
	// therefore trusted unconditionally; denying it would make
	// zeptoclaw fundamentally unroutable. Non-loopback callers still
	// require X-DC-Auth or the master key.
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-or-upstream-key")
	if !c.Authenticate(r) {
		t.Error("loopback must be trusted for zeptoclaw — native binary has no way to inject X-DC-Auth")
	}

	// Non-loopback: upstream bearer is NOT a valid DefenseClaw
	// credential, must reject.
	r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r3.RemoteAddr = "10.0.0.5:54321"
	r3.Header.Set("Authorization", "Bearer sk-or-upstream-key")
	if c.Authenticate(r3) {
		t.Error("expected non-loopback auth to fail with only an upstream bearer token")
	}

	// Non-loopback: valid X-DC-Auth → accept.
	r4 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r4.RemoteAddr = "10.0.0.5:54321"
	r4.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r4) {
		t.Error("expected non-loopback auth to pass with correct X-DC-Auth token")
	}

	// Non-loopback: master key → accept.
	r5 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r5.RemoteAddr = "10.0.0.5:54321"
	r5.Header.Set("Authorization", "Bearer my-master")
	if !c.Authenticate(r5) {
		t.Error("expected non-loopback auth to pass with master key")
	}
}

// TestZeptoClaw_Authenticate_NativeBinaryLoopback mirrors the codex
// test: the critical end-to-end path is zeptoclaw → proxy on loopback
// with an Authorization: Bearer <provider-api-key> header. Denying
// this 401s every request before guardrail inspection even runs, so
// loopback trust is structural not optional.
func TestZeptoClaw_Authenticate_NativeBinaryLoopback(t *testing.T) {
	c := NewZeptoClawConnector()
	c.SetCredentials("gw-tok-5c80", "")

	r := httptest.NewRequest("POST", "/c/zeptoclaw/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-or-v1-real-openrouter-key")

	if !c.Authenticate(r) {
		t.Fatal("zeptoclaw loopback with provider Authorization must be accepted; " +
			"otherwise zeptoclaw → proxy traffic gets 401'd and guardrail never runs")
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

func TestWriteHookScriptsWithToken_InjectsBearerHeader(t *testing.T) {
	// The claude-code hook posts to /api/v1/claude-code/hook, which the API
	// server's auth middleware guards with a bearer token. Without the
	// header the request is 401'd, the hook script fails-open, and no
	// inspection happens — which is exactly how claude-code queries
	// silently slipped through. Run the generated script so we exercise
	// the real runtime auth wiring, not the template shape.
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", "tok-abcdef123"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	out := runHookAndReturnCurlArgs(t, filepath.Join(dir, "claude-code-hook.sh"), nil)
	if !containsAuthBearer(out, "tok-abcdef123") {
		t.Errorf("claude-code-hook.sh curl invocation missing `Authorization: Bearer tok-abcdef123`; got curl args:\n%s", out)
	}
}

func TestWriteHookScriptsWithToken_EmptyTokenOmitsHeader(t *testing.T) {
	// Operators who never set DEFENSECLAW_GATEWAY_TOKEN rely on the
	// loopback fallback; emitting an empty Authorization header would
	// make the API middleware reject with "invalid_token" instead of
	// falling through to the loopback allow path. So the hook must omit
	// the header entirely when no token is configured.
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", ""); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	out := runHookAndReturnCurlArgs(t, filepath.Join(dir, "claude-code-hook.sh"), nil)
	if containsAuthBearer(out, "") {
		t.Errorf("claude-code-hook.sh should not emit an Authorization header when token is empty; got curl args:\n%s", out)
	}
}

func TestWriteHookScriptsWithToken_EnvVarOverridesBakedToken(t *testing.T) {
	// If the operator rotates DEFENSECLAW_GATEWAY_TOKEN without
	// regenerating hook scripts, the env var must win so the hook keeps
	// working across rotations. ${DEFENSECLAW_GATEWAY_TOKEN:-<baked>} in
	// the script expresses that.
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", "baked-stale"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	out := runHookAndReturnCurlArgs(t, filepath.Join(dir, "claude-code-hook.sh"),
		map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": "from-env"})
	if !containsAuthBearer(out, "from-env") {
		t.Errorf("env var should win over baked token; got curl args:\n%s", out)
	}
}

// runHookAndReturnCurlArgs executes the given hook script with `curl`
// replaced by a stub that writes its argv, one per line, to a file. The
// hook script pipes curl's stderr to /dev/null, so stdout/stderr capture
// would lose the evidence — the stub persists it out-of-band. This lets
// us assert on the real argv curl would have seen, including the
// runtime-computed Authorization header.
func runHookAndReturnCurlArgs(t *testing.T, scriptPath string, extraEnv map[string]string) string {
	t.Helper()
	stubDir := t.TempDir()
	argFile := filepath.Join(stubDir, "curl-args.txt")
	stub := filepath.Join(stubDir, "curl")
	stubSrc := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argFile + "; done\nprintf '{\"action\":\"allow\"}\\n200'\nexit 0\n"
	if err := os.WriteFile(stub, []byte(stubSrc), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"))
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
	if err := cmd.Run(); err != nil {
		t.Fatalf("hook script run: %v", err)
	}
	data, err := os.ReadFile(argFile)
	if err != nil {
		t.Fatalf("curl stub never recorded args: %v", err)
	}
	return string(data)
}

// containsAuthBearer returns true if the stubbed curl argv lines contain
// an `Authorization: Bearer <token>` header. When token is empty, returns
// true whenever ANY Authorization: Bearer header is present.
func containsAuthBearer(curlArgs, token string) bool {
	for _, line := range strings.Split(curlArgs, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Authorization: Bearer") {
			continue
		}
		if token == "" {
			return true
		}
		if line == "Authorization: Bearer "+token {
			return true
		}
	}
	return false
}

func TestHookScripts_ReturnsList(t *testing.T) {
	scripts := HookScripts()
	if len(scripts) != 6 {
		t.Errorf("HookScripts() returned %d scripts, want 6", len(scripts))
	}
}

// TestHookScripts_FailOpen_OnDisabledSentinel exercises the v2 fail-open
// guard in every generated hook. When `~/.defenseclaw/.disabled` exists
// the hook must exit 0 immediately without dialling the gateway —
// otherwise running `defenseclaw setup guardrail --disable` (or simply
// removing ~/.defenseclaw) would brick whichever agent already had the
// hook wired into its config.
func TestHookScripts_FailOpen_OnDisabledSentinel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook scripts are POSIX shell")
	}
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	dcHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(dcHome, ".disabled"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, name := range HookScripts() {
		t.Run(name, func(t *testing.T) {
			out := runHookAndReturnCurlArgsWithHome(t, filepath.Join(dir, name), dcHome, nil)
			if out != "" {
				t.Errorf("%s: hook called curl while .disabled sentinel is present; got curl args:\n%s", name, out)
			}
		})
	}
}

// TestHookScripts_FailOpen_OnMissingDefenseClawHome covers the
// `rm -rf ~/.defenseclaw` (full uninstall, hooks left dangling) case.
// The hook must short-circuit instead of failing with curl errors that
// the agent then surfaces as a refusal to run the tool/request.
func TestHookScripts_FailOpen_OnMissingDefenseClawHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook scripts are POSIX shell")
	}
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	missingDir := filepath.Join(t.TempDir(), "does-not-exist")

	for _, name := range HookScripts() {
		t.Run(name, func(t *testing.T) {
			out := runHookAndReturnCurlArgsWithHome(t, filepath.Join(dir, name), missingDir, nil)
			if out != "" {
				t.Errorf("%s: hook called curl with DEFENSECLAW_HOME missing; got curl args:\n%s", name, out)
			}
		})
	}
}

// TestHookScripts_TokenedHooks_FailOpen_OnMissingToken covers the
// codex / claude-code hook fast-path: if the .token sidecar file was
// never written (or was removed) AND DEFENSECLAW_GATEWAY_TOKEN is
// unset, the gateway will reject every request with 401 and the
// agent gets bricked. v2 hooks short-circuit before that happens.
func TestHookScripts_TokenedHooks_FailOpen_OnMissingToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook scripts are POSIX shell")
	}
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	if err := os.Remove(filepath.Join(dir, ".token")); err != nil {
		t.Fatal(err)
	}

	dcHome := t.TempDir()

	for _, name := range []string{"claude-code-hook.sh", "codex-hook.sh"} {
		t.Run(name, func(t *testing.T) {
			out := runHookAndReturnCurlArgsWithHome(t, filepath.Join(dir, name), dcHome, nil)
			if out != "" {
				t.Errorf("%s: hook called curl with no .token and no env override; got curl args:\n%s", name, out)
			}
		})
	}
}

// runHookAndReturnCurlArgsWithHome is the sentinel-aware variant of
// runHookAndReturnCurlArgs. It takes an explicit DEFENSECLAW_HOME so
// tests can drive the .disabled / missing-home branches deterministically
// without touching the real $HOME of the developer running the tests.
// curl args end up in a file the stub appends to; the function returns
// the file contents (empty string when the hook short-circuited and never
// reached curl). It does NOT t.Fatal on a non-zero hook exit — fail-open
// hooks legitimately exit 0, but a hook that errors out also yields an
// empty curl-args file, and the assertion in the caller covers both.
func runHookAndReturnCurlArgsWithHome(t *testing.T, scriptPath, dcHome string, extraEnv map[string]string) string {
	t.Helper()
	stubDir := t.TempDir()
	argFile := filepath.Join(stubDir, "curl-args.txt")
	stub := filepath.Join(stubDir, "curl")
	stubSrc := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argFile + "; done\nprintf '{\"action\":\"allow\"}\\n200'\nexit 0\n"
	if err := os.WriteFile(stub, []byte(stubSrc), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"DEFENSECLAW_HOME="+dcHome,
	)
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
	_ = cmd.Run() // exit 0 = fail-open path; non-zero would still record args if curl ran first
	data, err := os.ReadFile(argFile)
	if err != nil {
		// argFile only exists if the stub ran — its absence is exactly
		// what we want to assert against in the fail-open tests.
		return ""
	}
	return string(data)
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

		// No creds on loopback should fail for connectors with a fetch
		// interceptor — closes the local-process bypass vector.
		//
		// Exception: native-binary connectors (codex, zeptoclaw) have
		// no fetch interceptor and cannot inject X-DC-Auth. Their
		// primary authentication path IS loopback trust; denying it
		// would make them fundamentally unroutable through the proxy.
		// Bridge / remote deployments still require X-DC-Auth or the
		// master key — the token protects those paths.
		r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r3.RemoteAddr = "127.0.0.1:54321"
		accepted := c.Authenticate(r3)
		nativeBinary := c.Name() == "codex" || c.Name() == "zeptoclaw"
		if nativeBinary {
			if !accepted {
				t.Errorf("%s: loopback must be trusted so native-binary traffic can reach the proxy", c.Name())
			}
		} else if accepted {
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
//
// Surface 1 is the codex-cli LLM-traffic redirection: codex must hit
// the DefenseClaw proxy and not the upstream provider directly. The
// canonical path is the [model_providers.*].base_url rewrite in
// ~/.codex/config.toml; we explicitly DO NOT export a global
// OPENAI_BASE_URL because that would co-route every other OpenAI-SDK
// client on the host (see S8.1 / F31).

func TestCodex_Setup_Surface1_DoesNotExportGlobalEnv(t *testing.T) {
	dir := t.TempDir()
	CodexConfigPathOverride = filepath.Join(dir, "config.toml")
	defer func() { CodexConfigPathOverride = "" }()
	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// F31 contract: legacy env-override files MUST NOT be written.
	if _, err := os.Stat(filepath.Join(dir, "codex_env.sh")); !os.IsNotExist(err) {
		t.Errorf("codex_env.sh must not exist after Setup (S8.1 / F31)")
	}
	if _, err := os.Stat(filepath.Join(dir, "codex.env")); !os.IsNotExist(err) {
		t.Errorf("codex.env must not exist after Setup (S8.1 / F31)")
	}

	// Check forensic backup is still recorded — even though we no
	// longer overwrite the env, the backup gives Teardown / audit a
	// pristine record of whether the operator already had
	// OPENAI_BASE_URL set.
	backupData, err := os.ReadFile(filepath.Join(dir, "codex_backup.json"))
	if err != nil {
		t.Fatalf("backup not saved: %v", err)
	}
	var backup codexBackup
	if err := json.Unmarshal(backupData, &backup); err != nil {
		t.Fatalf("decode backup: %v", err)
	}
	if backup.HadBaseURL {
		t.Error("backup.HadBaseURL should be false when env not set")
	}

	// Check the routing actually landed in config.toml — that's the
	// only place codex reads provider URLs from.
	patched, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	if !strings.Contains(string(patched), "/c/codex") {
		t.Errorf("config.toml missing /c/codex prefix; got:\n%s", patched)
	}
}

// TestCodex_Teardown_RemovesLegacyEnvFiles guarantees that an
// upgrade-then-uninstall flow ends with the operator's host pristine:
// even if a previous DefenseClaw release wrote codex_env.sh /
// codex.env, today's Teardown removes them.
func TestCodex_Teardown_RemovesLegacyEnvFiles(t *testing.T) {
	dir := t.TempDir()
	CodexConfigPathOverride = filepath.Join(dir, "config.toml")
	defer func() { CodexConfigPathOverride = "" }()
	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(nil, opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Simulate an old install that left these files behind.
	for _, name := range []string{"codex_env.sh", "codex.env"} {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte("# stale legacy override\nexport OPENAI_BASE_URL=stale\n"),
			0o644); err != nil {
			t.Fatalf("seed legacy %s: %v", name, err)
		}
	}

	if err := c.Teardown(nil, opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	for _, name := range []string{"codex_env.sh", "codex.env", "codex_backup.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should be removed after Teardown", name)
		}
	}
}

func TestCodex_Setup_Surface1_BackupsExistingEnv(t *testing.T) {
	dir := t.TempDir()
	CodexConfigPathOverride = filepath.Join(dir, "config.toml")
	defer func() { CodexConfigPathOverride = "" }()
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
	os.WriteFile(configPath, []byte(`{"providers":{"anthropic":{"api_key":"sk-test-123"}}}`), 0o644)
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

// ========================================================================
// M9 — Security path test coverage
// ========================================================================

func TestAuth_NoCredentials_AllConnectors_DenyNonLoopback(t *testing.T) {
	connectors := []Connector{
		NewClaudeCodeConnector(),
		NewCodexConnector(),
		NewOpenClawConnector(),
		NewZeptoClawConnector(),
	}
	for _, conn := range connectors {
		conn.SetCredentials("", "")
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.RemoteAddr = "10.0.0.5:54321"
		if conn.Authenticate(r) {
			t.Errorf("%s: non-loopback request should be denied when no credentials configured", conn.Name())
		}
	}
}

func TestAuth_NoCredentials_AllConnectors_AllowLoopback(t *testing.T) {
	connectors := []Connector{
		NewClaudeCodeConnector(),
		NewCodexConnector(),
		NewOpenClawConnector(),
		NewZeptoClawConnector(),
	}
	for _, conn := range connectors {
		conn.SetCredentials("", "")
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		if !conn.Authenticate(r) {
			t.Errorf("%s: loopback request should be allowed when no credentials configured", conn.Name())
		}
	}
}

func TestIsLoopback_IPv6Variants(t *testing.T) {
	tests := []struct {
		addr     string
		expected bool
	}{
		{"[::1]:54321", true},
		{"::1", true},
		{"127.0.0.1:54321", true},
		{"[::ffff:127.0.0.1]:80", true},
		{"[::ffff:10.0.0.1]:80", false},
		{"10.0.0.1:80", false},
		{"192.168.1.1:80", false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.addr
		got := IsLoopback(r)
		if got != tt.expected {
			t.Errorf("IsLoopback(%q) = %v, want %v", tt.addr, got, tt.expected)
		}
	}
}

func TestHookScript_FailClosed_Default(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:99999", "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	// Run hook against an unreachable port — should exit 2 (fail-closed)
	cmd := exec.Command("bash", filepath.Join(dir, "claude-code-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"test"}`)
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH"))
	err := cmd.Run()
	if err == nil {
		t.Fatal("hook should fail-closed (exit 2) when gateway is unreachable, but got exit 0")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Errorf("exit code = %d, want 2 (fail-closed)", exitErr.ExitCode())
		}
	}
}

func TestHookScript_FailOpen_Override(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:99999", "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}

	cmd := exec.Command("bash", filepath.Join(dir, "claude-code-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"test"}`)
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH"), "DEFENSECLAW_FAIL_MODE=open")
	err := cmd.Run()
	if err != nil {
		t.Errorf("hook should fail-open (exit 0) when DEFENSECLAW_FAIL_MODE=open, got: %v", err)
	}
}

func TestInstallOpenClaw_SymlinkedExtDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-owned")
	os.MkdirAll(target, 0o755)
	os.WriteFile(filepath.Join(target, "precious.txt"), []byte("don't delete me"), 0o644)

	extParent := filepath.Join(dir, "extensions")
	os.MkdirAll(extParent, 0o755)
	symlink := filepath.Join(extParent, "defenseclaw")
	os.Symlink(target, symlink)

	err := safeRemoveAll(symlink, extParent)
	if err == nil {
		// If symlink was resolved and is outside parent, it should error
		if _, statErr := os.Stat(filepath.Join(target, "precious.txt")); statErr != nil {
			t.Error("safeRemoveAll should not delete files outside the parent directory")
		}
	}
	// The important assertion: the attack target's content is preserved
	data, err2 := os.ReadFile(filepath.Join(target, "precious.txt"))
	if err2 != nil || string(data) != "don't delete me" {
		t.Error("symlink attack: files in target directory were deleted")
	}
}

func TestPatchOpenClawConfig_Concurrent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	os.WriteFile(configPath, []byte(`{}`), 0o644)

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = patchOpenClawConfig(configPath, "/tmp/ext-"+strings.Repeat("x", idx))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: patchOpenClawConfig failed: %v", i, err)
		}
	}

	// Verify the file is valid JSON and not corrupted
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config file corrupted by concurrent writes: %v\ncontent: %s", err, string(data))
	}
}

func TestZeptoClaw_Setup_EmptyProviders_Fails(t *testing.T) {
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
	err := c.Setup(nil, opts)
	if err == nil {
		t.Fatal("Setup should fail with no usable providers")
	}
	if !strings.Contains(err.Error(), "no usable providers") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIsOwnedHook_StrictMatch(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "hooks", "claude-code-hook.sh")
	os.MkdirAll(filepath.Join(dir, "hooks"), 0o755)
	os.WriteFile(hookPath, []byte("#!/bin/bash\n"+hookMarker+"\necho test\n"), 0o755)

	// Hook with matching path should be owned
	entry := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": hookPath},
		},
	}
	if !isOwnedHook(entry, filepath.Join(dir, "hooks")) {
		t.Error("hook with matching path should be owned")
	}

	// Hook with unrelated path containing "defenseclaw" should NOT be owned
	unrelatedPath := filepath.Join(dir, "defenseclaw-clone", "bin", "my-tool")
	os.MkdirAll(filepath.Dir(unrelatedPath), 0o755)
	os.WriteFile(unrelatedPath, []byte("#!/bin/bash\necho not ours\n"), 0o755)
	unrelatedEntry := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": unrelatedPath},
		},
	}
	if isOwnedHook(unrelatedEntry, filepath.Join(dir, "hooks")) {
		t.Error("hook with unrelated path containing 'defenseclaw' should NOT be owned")
	}
}

func TestAllConnectors_ImplementSetCredentials(t *testing.T) {
	connectors := []Connector{
		NewClaudeCodeConnector(),
		NewCodexConnector(),
		NewOpenClawConnector(),
		NewZeptoClawConnector(),
	}
	for _, conn := range connectors {
		conn.SetCredentials("test-token", "test-master")
	}
}

func TestConnectorState_SaveLoadClear(t *testing.T) {
	dir := t.TempDir()

	if got := LoadActiveConnector(dir); got != "" {
		t.Errorf("LoadActiveConnector on empty dir = %q, want empty", got)
	}

	if err := SaveActiveConnector(dir, "claudecode"); err != nil {
		t.Fatalf("SaveActiveConnector: %v", err)
	}
	if got := LoadActiveConnector(dir); got != "claudecode" {
		t.Errorf("LoadActiveConnector = %q, want %q", got, "claudecode")
	}

	if err := SaveActiveConnector(dir, "openclaw"); err != nil {
		t.Fatalf("SaveActiveConnector overwrite: %v", err)
	}
	if got := LoadActiveConnector(dir); got != "openclaw" {
		t.Errorf("LoadActiveConnector after overwrite = %q, want %q", got, "openclaw")
	}

	ClearActiveConnector(dir)
	if got := LoadActiveConnector(dir); got != "" {
		t.Errorf("LoadActiveConnector after clear = %q, want empty", got)
	}
}

func TestConnectorState_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "active_connector.json"), []byte("not json"), 0o644)
	if got := LoadActiveConnector(dir); got != "" {
		t.Errorf("LoadActiveConnector on corrupt file = %q, want empty", got)
	}
}

func TestTeardownPreviousConnector_ViaRegistry(t *testing.T) {
	dir := t.TempDir()

	if err := SaveActiveConnector(dir, "codex"); err != nil {
		t.Fatalf("save: %v", err)
	}

	reg := NewDefaultRegistry()
	prev := LoadActiveConnector(dir)
	if prev != "codex" {
		t.Fatalf("expected codex, got %q", prev)
	}

	oldConn, ok := reg.Get(prev)
	if !ok {
		t.Fatal("codex not in registry")
	}

	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := oldConn.Teardown(nil, opts); err != nil {
		t.Errorf("Teardown of previous connector: %v", err)
	}

	newConn, _ := reg.Get("claudecode")
	ClaudeCodeSettingsPathOverride = filepath.Join(dir, "settings.json")
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	if err := newConn.Setup(nil, opts); err != nil {
		t.Errorf("Setup of new connector: %v", err)
	}
	if err := SaveActiveConnector(dir, "claudecode"); err != nil {
		t.Fatalf("save new: %v", err)
	}
	if got := LoadActiveConnector(dir); got != "claudecode" {
		t.Errorf("active after switch = %q, want claudecode", got)
	}
}

// --- PR-G (S1.1): AgentPathProvider / EnvRequirementsProvider /
//                  HookScriptProvider / AgentRestarter contract ---
//
// These tests pin the additive interface contract introduced for the
// claw-agnostic refactor. They are pure metadata assertions: every
// built-in connector must (a) declare the on-disk paths it touches,
// (b) declare any env vars it needs, (c) expose its hook scripts.
// AgentRestarter is optional — none of the built-ins implement it
// today; we only assert that the type assertion compiles.

func TestConnector_AgentPathProvider_AllBuiltinsImplement(t *testing.T) {
	dataDir := t.TempDir()
	opts := SetupOpts{
		DataDir:   dataDir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}

	type tc struct {
		name string
		ctor func() Connector
	}
	cases := []tc{
		{"zeptoclaw", func() Connector { return NewZeptoClawConnector() }},
		{"openclaw", func() Connector { return NewOpenClawConnector() }},
		{"codex", func() Connector { return NewCodexConnector() }},
		{"claudecode", func() Connector { return NewClaudeCodeConnector() }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := c.ctor()
			ap, ok := conn.(AgentPathProvider)
			if !ok {
				t.Fatalf("%s does not implement AgentPathProvider", c.name)
			}
			paths := ap.AgentPaths(opts)

			// Every built-in connector touches at least one file
			// the operator should know about (PatchedFiles or
			// CreatedDirs). Pure-metadata-only connectors are
			// not allowed at this layer.
			if len(paths.PatchedFiles) == 0 && len(paths.CreatedDirs) == 0 {
				t.Errorf("%s: neither PatchedFiles nor CreatedDirs declared — connector appears to be a no-op", c.name)
			}

			// Hook scripts must be absolute paths under DataDir
			// when present.
			for _, hs := range paths.HookScripts {
				if !filepath.IsAbs(hs) {
					t.Errorf("%s: hook script %q is not absolute", c.name, hs)
				}
				if !strings.HasPrefix(hs, dataDir) {
					t.Errorf("%s: hook script %q is not under DataDir %q", c.name, hs, dataDir)
				}
			}

			// Backup files must live under DataDir.
			for _, bf := range paths.BackupFiles {
				if !strings.HasPrefix(bf, dataDir) {
					t.Errorf("%s: backup file %q is not under DataDir %q", c.name, bf, dataDir)
				}
			}
		})
	}
}

func TestConnector_AgentPaths_HookScriptsCoverAll(t *testing.T) {
	dataDir := t.TempDir()
	opts := SetupOpts{DataDir: dataDir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	expected := HookScripts() // canonical list from subprocess.go

	connectors := []Connector{
		NewZeptoClawConnector(),
		NewOpenClawConnector(),
		NewCodexConnector(),
		NewClaudeCodeConnector(),
	}
	for _, conn := range connectors {
		ap, ok := conn.(AgentPathProvider)
		if !ok {
			t.Fatalf("%s missing AgentPathProvider", conn.Name())
		}
		paths := ap.AgentPaths(opts)
		// Each declared script name from the canonical list should
		// appear at <DataDir>/hooks/<name> in the connector's
		// reported HookScripts.
		got := map[string]bool{}
		for _, p := range paths.HookScripts {
			got[filepath.Base(p)] = true
		}
		for _, want := range expected {
			if !got[want] {
				t.Errorf("%s: AgentPaths.HookScripts missing %q (got %v)", conn.Name(), want, paths.HookScripts)
			}
		}
	}
}

func TestConnector_HookScriptProvider_MatchesAgentPaths(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}

	connectors := []Connector{
		NewZeptoClawConnector(),
		NewOpenClawConnector(),
		NewCodexConnector(),
		NewClaudeCodeConnector(),
	}
	for _, conn := range connectors {
		hsp, ok := conn.(HookScriptProvider)
		if !ok {
			t.Fatalf("%s missing HookScriptProvider", conn.Name())
		}
		ap, _ := conn.(AgentPathProvider)
		want := ap.AgentPaths(opts).HookScripts
		got := hsp.HookScripts(opts)
		if len(got) != len(want) {
			t.Errorf("%s: HookScripts() returned %d entries, AgentPaths reported %d", conn.Name(), len(got), len(want))
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: HookScripts()[%d] = %q, AgentPaths reported %q", conn.Name(), i, got[i], want[i])
			}
		}
	}
}

func TestConnector_EnvRequirementsProvider_AllBuiltinsImplement(t *testing.T) {
	type tc struct {
		name           string
		ctor           func() Connector
		mustHaveScopes []EnvScope
	}
	cases := []tc{
		// Native binaries route via on-disk config; document the
		// absence of env requirements with EnvScopeNone.
		{"zeptoclaw", func() Connector { return NewZeptoClawConnector() }, []EnvScope{EnvScopeNone}},
		// OpenClaw uses the fetch interceptor plugin; no env vars.
		{"openclaw", func() Connector { return NewOpenClawConnector() }, []EnvScope{EnvScopeNone}},
		// Codex routes via config.toml; OPENAI_BASE_URL is
		// optional/discouraged. Scope is process-only.
		{"codex", func() Connector { return NewCodexConnector() }, []EnvScope{EnvScopeProcess}},
		// Claude Code honors ANTHROPIC_BASE_URL at startup but
		// settings.json hooks are sufficient for guardrail
		// enforcement, so the var is recommended-not-required.
		{"claudecode", func() Connector { return NewClaudeCodeConnector() }, []EnvScope{EnvScopeProcess}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := c.ctor()
			ep, ok := conn.(EnvRequirementsProvider)
			if !ok {
				t.Fatalf("%s does not implement EnvRequirementsProvider", c.name)
			}
			reqs := ep.RequiredEnv()
			if len(reqs) == 0 {
				t.Fatalf("%s: RequiredEnv() returned empty slice; expected at least one documentation entry", c.name)
			}

			seen := map[EnvScope]bool{}
			for _, r := range reqs {
				seen[r.Scope] = true
				if r.Description == "" {
					t.Errorf("%s: env requirement %q has empty Description", c.name, r.Name)
				}
				if r.Scope != EnvScopeNone && r.Name == "" {
					t.Errorf("%s: env requirement with non-None scope %q is missing Name", c.name, r.Scope)
				}
				// Require the scope to be one of the
				// documented enum values; reject typo'd
				// strings.
				switch r.Scope {
				case EnvScopeProcess, EnvScopeShell, EnvScopeNone:
				default:
					t.Errorf("%s: env requirement %q has unknown Scope %q", c.name, r.Name, r.Scope)
				}
			}
			for _, want := range c.mustHaveScopes {
				if !seen[want] {
					t.Errorf("%s: RequiredEnv() did not declare expected scope %q", c.name, want)
				}
			}
		})
	}
}

func TestConnector_AgentRestarter_OptionalAtThisLayer(t *testing.T) {
	// None of the built-in connectors implement AgentRestarter
	// today; this test pins the contract that the type assertion
	// compiles cleanly and returns ok=false. When a future
	// connector adds restart support, the fix is to update this
	// test, not to make the assertion compile-time mandatory.
	connectors := []Connector{
		NewZeptoClawConnector(),
		NewOpenClawConnector(),
		NewCodexConnector(),
		NewClaudeCodeConnector(),
	}
	for _, conn := range connectors {
		if _, ok := conn.(AgentRestarter); ok {
			t.Logf("%s implements AgentRestarter — update this test to exercise it", conn.Name())
		}
	}
}

// TestZeptoClaw_AgentPaths_Specifics pins the exact paths the
// ZeptoClaw connector reports so a future refactor that drops
// zeptoclaw_backup.json or moves the config file is caught here
// instead of at runtime in `defenseclaw doctor`.
func TestZeptoClaw_AgentPaths_Specifics(t *testing.T) {
	dataDir := t.TempDir()
	tmpHome := t.TempDir()
	cfg := filepath.Join(tmpHome, ".zeptoclaw", "config.json")
	ZeptoClawConfigPathOverride = cfg
	defer func() { ZeptoClawConfigPathOverride = "" }()

	conn := NewZeptoClawConnector()
	paths := conn.AgentPaths(SetupOpts{DataDir: dataDir})

	if len(paths.PatchedFiles) != 1 || paths.PatchedFiles[0] != cfg {
		t.Errorf("PatchedFiles = %v, want [%q]", paths.PatchedFiles, cfg)
	}
	wantBackup := filepath.Join(dataDir, "zeptoclaw_backup.json")
	if len(paths.BackupFiles) != 1 || paths.BackupFiles[0] != wantBackup {
		t.Errorf("BackupFiles = %v, want [%q]", paths.BackupFiles, wantBackup)
	}
}

// TestCodex_AgentPaths_Specifics pins Codex's footprint. The
// connector exposes both codex_config_backup.json (config.toml
// patch) and codex_backup.json (legacy env backup).
func TestCodex_AgentPaths_Specifics(t *testing.T) {
	dataDir := t.TempDir()
	tmpHome := t.TempDir()
	cfg := filepath.Join(tmpHome, ".codex", "config.toml")
	CodexConfigPathOverride = cfg
	defer func() { CodexConfigPathOverride = "" }()

	conn := NewCodexConnector()
	paths := conn.AgentPaths(SetupOpts{DataDir: dataDir})

	if len(paths.PatchedFiles) != 1 || paths.PatchedFiles[0] != cfg {
		t.Errorf("PatchedFiles = %v, want [%q]", paths.PatchedFiles, cfg)
	}
	wantBackups := []string{
		filepath.Join(dataDir, "codex_config_backup.json"),
		filepath.Join(dataDir, "codex_backup.json"),
	}
	if len(paths.BackupFiles) != len(wantBackups) {
		t.Errorf("BackupFiles = %v, want %v", paths.BackupFiles, wantBackups)
	} else {
		for i, want := range wantBackups {
			if paths.BackupFiles[i] != want {
				t.Errorf("BackupFiles[%d] = %q, want %q", i, paths.BackupFiles[i], want)
			}
		}
	}
}

// TestClaudeCode_AgentPaths_Specifics pins the Claude Code
// footprint: settings.json + claudecode_backup.json + hook scripts.
func TestClaudeCode_AgentPaths_Specifics(t *testing.T) {
	dataDir := t.TempDir()
	tmpHome := t.TempDir()
	cfg := filepath.Join(tmpHome, ".claude", "settings.json")
	ClaudeCodeSettingsPathOverride = cfg
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	conn := NewClaudeCodeConnector()
	paths := conn.AgentPaths(SetupOpts{DataDir: dataDir})

	if len(paths.PatchedFiles) != 1 || paths.PatchedFiles[0] != cfg {
		t.Errorf("PatchedFiles = %v, want [%q]", paths.PatchedFiles, cfg)
	}
	wantBackup := filepath.Join(dataDir, "claudecode_backup.json")
	if len(paths.BackupFiles) != 1 || paths.BackupFiles[0] != wantBackup {
		t.Errorf("BackupFiles = %v, want [%q]", paths.BackupFiles, wantBackup)
	}
}

// TestOpenClaw_AgentPaths_Specifics pins OpenClaw's footprint:
// openclaw.json patched, no backup file (edits are reversible),
// extension dir created.
func TestOpenClaw_AgentPaths_Specifics(t *testing.T) {
	dataDir := t.TempDir()
	tmpHome := t.TempDir()
	OpenClawHomeOverride = filepath.Join(tmpHome, ".openclaw")
	defer func() { OpenClawHomeOverride = "" }()

	conn := NewOpenClawConnector()
	paths := conn.AgentPaths(SetupOpts{DataDir: dataDir})

	wantPatched := filepath.Join(OpenClawHomeOverride, "openclaw.json")
	if len(paths.PatchedFiles) != 1 || paths.PatchedFiles[0] != wantPatched {
		t.Errorf("PatchedFiles = %v, want [%q]", paths.PatchedFiles, wantPatched)
	}
	if len(paths.BackupFiles) != 0 {
		t.Errorf("BackupFiles = %v, want empty (openclaw.json edits are reversible without a backup)", paths.BackupFiles)
	}
	wantDir := filepath.Join(OpenClawHomeOverride, "extensions", "defenseclaw")
	found := false
	for _, d := range paths.CreatedDirs {
		if d == wantDir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CreatedDirs = %v, missing %q", paths.CreatedDirs, wantDir)
	}
}
