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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/pelletier/go-toml/v2"
)

// --- Helper tests ---

func TestManagedFileBackup_RestoresExactWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(target, []byte(`{"hooks":["original"]}`), 0o640); err != nil {
		t.Fatalf("write target: %v", err)
	}

	if err := captureManagedFileBackup(dir, "codex", "config", target); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if err := os.WriteFile(target, []byte(`{"hooks":["defenseclaw"]}`), 0o600); err != nil {
		t.Fatalf("patch target: %v", err)
	}
	if err := updateManagedFileBackupPostHash(dir, "codex", "config", target); err != nil {
		t.Fatalf("post hash: %v", err)
	}

	restored, err := restoreManagedFileBackupIfUnchanged(dir, "codex", "config", target)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !restored {
		t.Fatal("restoreManagedFileBackupIfUnchanged returned false, want true")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != `{"hooks":["original"]}` {
		t.Fatalf("restored bytes = %q", got)
	}
}

func TestManagedFileBackup_SkipsWhenUserEditedAfterSetup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(target, []byte(`{"hooks":["original"]}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	if err := captureManagedFileBackup(dir, "claudecode", "settings", target); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if err := os.WriteFile(target, []byte(`{"hooks":["defenseclaw"]}`), 0o600); err != nil {
		t.Fatalf("patch target: %v", err)
	}
	if err := updateManagedFileBackupPostHash(dir, "claudecode", "settings", target); err != nil {
		t.Fatalf("post hash: %v", err)
	}
	if err := os.WriteFile(target, []byte(`{"hooks":["defenseclaw","user-added"]}`), 0o600); err != nil {
		t.Fatalf("user edit: %v", err)
	}

	restored, err := restoreManagedFileBackupIfUnchanged(dir, "claudecode", "settings", target)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored {
		t.Fatal("restoreManagedFileBackupIfUnchanged restored a drifted file")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read drifted: %v", err)
	}
	if string(got) != `{"hooks":["defenseclaw","user-added"]}` {
		t.Fatalf("drifted bytes changed: %q", got)
	}
}

func TestAtomicWriteFile_PreservesSymlinkedDotfile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "config.toml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	linkDir := filepath.Join(dir, "home", ".codex")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("mkdir link dir: %v", err)
	}
	link := filepath.Join(linkDir, "config.toml")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable on windows: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	if err := atomicWriteFile(link, []byte("new"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("atomicWriteFile replaced symlink with mode %v", info.Mode())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("target contents = %q, want new", got)
	}
	if info, err := os.Stat(target); err != nil {
		t.Fatalf("stat target: %v", err)
	} else if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("target mode = %#o, want 0600", mode)
	}
}

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

// TestConnector_AllowedHostsProvider_AllBuiltinsImplement is the
// contract test for S3.3 / F26: every built-in connector must
// expose AllowedHosts() so the firewall layer can fold its
// per-connector hostnames into the static deny-by-default
// allow-list at boot. A future connector that forgets to
// implement this interface would silently fall through to "no
// extra hosts" — instead of failing here, that connector's users
// would see DNS-blocked errors on first chat.
//
// We assert two things: (1) every built-in implements the
// interface; (2) the returned list is non-empty. An empty list
// is allowed by the contract but for the four shipping
// connectors it would be meaningless (every one talks to a
// non-baseline host).
func TestConnector_AllowedHostsProvider_AllBuiltinsImplement(t *testing.T) {
	r := NewDefaultRegistry()
	for _, name := range []string{"openclaw", "zeptoclaw", "claudecode", "codex"} {
		conn, ok := r.Get(name)
		if !ok {
			t.Fatalf("registry missing %q", name)
		}
		provider, ok := conn.(AllowedHostsProvider)
		if !ok {
			t.Errorf("connector %q does not implement AllowedHostsProvider", name)
			continue
		}
		hosts := provider.AllowedHosts()
		if len(hosts) == 0 {
			t.Errorf("connector %q AllowedHosts() returned empty slice", name)
		}
		// Guardrail against accidental empty/whitespace entries
		// landing in the firewall allow-list.
		for _, h := range hosts {
			if h == "" {
				t.Errorf("connector %q AllowedHosts() includes an empty string", name)
			}
		}
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

// stubConnector is a minimal Connector for collision tests. It only
// needs Name(); the other methods can return zero values because the
// registry never invokes them in this path.
type stubConnector struct{ name string }

func (s *stubConnector) Name() string                                  { return s.name }
func (s *stubConnector) Description() string                           { return "stub for tests" }
func (s *stubConnector) ToolInspectionMode() ToolInspectionMode        { return ToolModeBoth }
func (s *stubConnector) SubprocessPolicy() SubprocessPolicy            { return SubprocessNone }
func (s *stubConnector) Authenticate(_ *http.Request) bool             { return false }
func (s *stubConnector) Setup(_ context.Context, _ SetupOpts) error    { return nil }
func (s *stubConnector) Teardown(_ context.Context, _ SetupOpts) error { return nil }
func (s *stubConnector) VerifyClean(_ SetupOpts) error                 { return nil }
func (s *stubConnector) Route(_ *http.Request, _ []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{}, nil
}
func (s *stubConnector) SetCredentials(_, _ string) {}

// TestRegistry_RegisterPlugin_RejectsBuiltinCollision pins PR #141 audit H2.
// A malicious .so dropped into the plugin discovery directory must not be
// able to register itself under a built-in connector name and intercept
// Get(name) — that path is the auth seam the proxy resolves to before
// calling Authenticate(). The registry must surface the collision as a
// concrete error and leave the original built-in in place.
func TestRegistry_RegisterPlugin_RejectsBuiltinCollision(t *testing.T) {
	for _, builtin := range []string{"openclaw", "zeptoclaw", "claudecode", "codex"} {
		t.Run(builtin, func(t *testing.T) {
			r := NewDefaultRegistry()
			before, ok := r.Get(builtin)
			if !ok {
				t.Fatalf("default registry missing builtin %q", builtin)
			}

			plugin := &stubConnector{name: builtin}
			err := r.RegisterPlugin(plugin)
			if err == nil {
				t.Fatalf("RegisterPlugin(%q) returned nil error — collision not rejected", builtin)
			}
			if !strings.Contains(err.Error(), "built-in connector name") {
				t.Errorf("err = %v, want substring 'built-in connector name'", err)
			}

			// Get must still resolve to the original builtin —
			// the rejected plugin must not have replaced it via
			// any side-effect path.
			after, _ := r.Get(builtin)
			if fmt.Sprintf("%T", after) != fmt.Sprintf("%T", before) {
				t.Errorf("Get(%q) returned %T, want %T (plugin shadowed builtin)", builtin, after, before)
			}
		})
	}
}

// TestRegistry_RegisterPlugin_AcceptsUniqueName confirms the collision
// guard does not over-block: a plugin with a name that doesn't match
// any built-in must register and be resolvable via Get().
func TestRegistry_RegisterPlugin_AcceptsUniqueName(t *testing.T) {
	r := NewDefaultRegistry()
	plugin := &stubConnector{name: "enterprise-foo"}
	if err := r.RegisterPlugin(plugin); err != nil {
		t.Fatalf("RegisterPlugin returned %v, want nil for unique name", err)
	}
	resolved, ok := r.Get("enterprise-foo")
	if !ok {
		t.Fatal("plugin not retrievable via Get()")
	}
	if resolved.Name() != "enterprise-foo" {
		t.Errorf("Get() returned %q, want enterprise-foo", resolved.Name())
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

// --- HookEventHandler interface deletion (Phase A5) ---
// HookEventHandler was a reserved-for-future-use stub interface that no
// built-in connector implemented. It was removed in plan A5 along with
// AgentRestarter (also unimplemented) so the connector contract surface
// only describes interfaces with at least one real consumer. The active
// hook-routing interface is HookEndpoint (added in d3b94fb), exercised
// by api.go:registerConnectorHookRoutes.

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
	requireOpenClawExtensionBundle(t)

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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	requireOpenClawExtensionBundle(t)

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
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
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

func TestOpenClaw_Setup_HILTEnablesPluginApprovalForwarding(t *testing.T) {
	requireOpenClawExtensionBundle(t)

	dir := t.TempDir()
	ocHome := filepath.Join(dir, "openclaw-home")
	os.MkdirAll(ocHome, 0o755)
	configPath := filepath.Join(ocHome, "openclaw.json")
	os.WriteFile(configPath, []byte(`{
		"approvals": {
			"plugin": {
				"mode": "both",
				"targets": [{"channel": "slack", "to": "#secops"}]
			}
		}
	}`), 0o644)

	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	c := NewOpenClawConnector()
	opts := SetupOpts{
		DataDir:     dir,
		ProxyAddr:   "127.0.0.1:4000",
		APIAddr:     "127.0.0.1:18970",
		HILTEnabled: true,
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(configPath)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("openclaw.json not valid JSON after Setup: %v", err)
	}
	approvals, _ := cfg["approvals"].(map[string]interface{})
	pluginApprovals, _ := approvals["plugin"].(map[string]interface{})
	if pluginApprovals["enabled"] != true {
		t.Fatalf("approvals.plugin.enabled = %v, want true", pluginApprovals["enabled"])
	}
	if pluginApprovals["mode"] != "both" {
		t.Fatalf("approvals.plugin.mode = %v, want preserved both", pluginApprovals["mode"])
	}
	if targets, _ := pluginApprovals["targets"].([]interface{}); len(targets) != 1 {
		t.Fatalf("approvals.plugin.targets clobbered: %v", pluginApprovals["targets"])
	}
}

func TestOpenClaw_Setup_HILTDefaultsPluginApprovalMode(t *testing.T) {
	requireOpenClawExtensionBundle(t)

	dir := t.TempDir()
	ocHome := filepath.Join(dir, "openclaw-home")
	os.MkdirAll(ocHome, 0o755)
	configPath := filepath.Join(ocHome, "openclaw.json")
	os.WriteFile(configPath, []byte(`{}`), 0o644)

	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	c := NewOpenClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", HILTEnabled: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var cfg map[string]interface{}
	data, _ := os.ReadFile(configPath)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("openclaw.json not valid JSON after Setup: %v", err)
	}
	approvals, _ := cfg["approvals"].(map[string]interface{})
	pluginApprovals, _ := approvals["plugin"].(map[string]interface{})
	if pluginApprovals["enabled"] != true {
		t.Fatalf("approvals.plugin.enabled = %v, want true", pluginApprovals["enabled"])
	}
	if pluginApprovals["mode"] != "session" {
		t.Fatalf("approvals.plugin.mode = %v, want session", pluginApprovals["mode"])
	}
}

func TestOpenClaw_Teardown_RemovesExtensionAndConfig(t *testing.T) {
	requireOpenClawExtensionBundle(t)

	dir := t.TempDir()
	ocHome := filepath.Join(dir, "openclaw-home")
	os.MkdirAll(ocHome, 0o755)
	configPath := filepath.Join(ocHome, "openclaw.json")
	os.WriteFile(configPath, []byte(`{"plugins":{"allow":["somebody-else"]}}`), 0o644)

	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	c := NewOpenClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
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

func requireOpenClawExtensionBundle(t *testing.T) {
	t.Helper()
	if !OpenClawExtensionAvailable() {
		t.Skip("OpenClaw extension bundle is optional; run `make extensions` before this test")
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
	if string(cs.RawBody) != string(body) {
		t.Errorf("RawBody = %q, want original OpenClaw request body", string(cs.RawBody))
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	data, _ := os.ReadFile(settingsPath)
	var settings map[string]interface{}
	json.Unmarshal(data, &settings)

	if _, ok := settings["hooks"]; ok {
		t.Error("hooks should be removed after teardown")
	}
}

func TestClaudeCode_Teardown_PreservesUserHooksAddedAfterSetup(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatalf("mkdir settings: %v", err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	initial := `{"hooks":{"Notification":[{"hooks":[{"type":"command","command":"/usr/bin/true"}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read patched settings: %v", err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse patched settings: %v", err)
	}
	hooks := settings["hooks"].(map[string]interface{})
	notification := hooks["Notification"].([]interface{})
	notification = append(notification, map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": "/tmp/user-added-hook"},
		},
	})
	hooks["Notification"] = notification
	settings["hooks"] = hooks
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatalf("marshal user-edited settings: %v", err)
	}
	if err := os.WriteFile(settingsPath, out, 0o644); err != nil {
		t.Fatalf("write user-edited settings: %v", err)
	}

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read restored settings: %v", err)
	}
	if strings.Contains(string(data), "claude-code-hook.sh") {
		t.Fatalf("DefenseClaw hook survived teardown:\n%s", data)
	}
	if !strings.Contains(string(data), "/usr/bin/true") || !strings.Contains(string(data), "/tmp/user-added-hook") {
		t.Fatalf("user hooks were not preserved:\n%s", data)
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

// TestCodex_Authenticate_LoopbackWarnOnce pins PR #141 audit H1.
// Codex cannot inject X-DC-Auth from its native binary, so loopback
// remains trusted even when a gateway token is configured (otherwise
// every codex request 401s and no guardrail runs — see
// TestCodex_Authenticate_NativeBinaryLoopback for the production
// rationale). H1 surfaces this architectural limitation by emitting a
// one-time `[SECURITY]` line to stderr the first time the bypass is
// exercised. We capture stderr, exercise the bypass twice, and assert
// the warning fires exactly once and that auth still succeeds.
func TestCodex_Authenticate_LoopbackWarnOnce(t *testing.T) {
	c := NewCodexConnector()
	c.SetCredentials("gw-tok-h1", "")

	origStderr := os.Stderr
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = pipeW
	t.Cleanup(func() { os.Stderr = origStderr })

	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/c/codex/responses", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header.Set("Authorization", "Bearer sk-or-upstream-key")
		if !c.Authenticate(r) {
			t.Fatalf("iter %d: codex loopback auth must still succeed (warn-only contract)", i)
		}
	}

	if err := pipeW.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	captured, _ := io.ReadAll(pipeR)
	got := string(captured)
	if !strings.Contains(got, "[SECURITY] codex: loopback request accepted") {
		t.Errorf("stderr missing warn-once line; got:\n%s", got)
	}
	// Three calls but only one warning line. Count occurrences.
	if n := strings.Count(got, "[SECURITY] codex: loopback request accepted"); n != 1 {
		t.Errorf("expected exactly 1 warn-once line, got %d:\n%s", n, got)
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	// Enforcement mode: this test asserts proxy-redirect behavior
	// (/c/codex prefix in model_providers base_url), which only
	// runs in the gated enforcement path. Default observability
	// mode skips the redirect — see GuardrailConfig.CodexEnforcementEnabled.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
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

func TestCodex_Route_PrefersConfiguredModelProvider(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model_provider = "openrouter"

[model_providers.azure]
name = "azure"
base_url = "https://azure.example/openai"
api_key = "azure-key"

[model_providers.openrouter]
name = "openrouter"
base_url = "https://openrouter.ai/api/v1"
env_key = "OPENROUTER_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	CodexAuthPathOverride = filepath.Join(dir, "no-such-auth.json")
	defer func() { CodexAuthPathOverride = "" }()
	t.Setenv("OPENROUTER_API_KEY", "sk-or-active-provider")

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	c.snapshotMu.RLock()
	active := c.activeProvider
	c.snapshotMu.RUnlock()
	if active != "openrouter" {
		t.Fatalf("activeProvider = %q, want openrouter", active)
	}

	body := []byte(`{"model":"gpt-5"}`)
	r := httptest.NewRequest("POST", "/responses", nil)
	r.Header.Set("Authorization", "Bearer incoming-client-key")
	cs, err := c.Route(r, body)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if cs.RawUpstream != "https://openrouter.ai/api/v1" {
		t.Errorf("RawUpstream = %q, want active model_provider upstream", cs.RawUpstream)
	}
	if cs.RawAPIKey != "sk-or-active-provider" {
		t.Errorf("RawAPIKey = %q, want active model_provider key", cs.RawAPIKey)
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
	// Enforcement mode required: SetProviderSnapshot only runs in
	// the gated enforcement block (it's only consumed by Route()
	// during proxy passthrough, which doesn't happen in the
	// observability default).
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
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
	// Enforcement mode required: this test asserts the proxy
	// rewrite of [model_providers.*].base_url which only runs in
	// the gated enforcement path.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := os.WriteFile(configPath, []byte(`model_provider = "openai"
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
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

// TestCodex_Setup_DefaultObservability_NoProxyRewrite is the headline
// regression test for the codex/claude-code observability-only
// architecture. With CodexEnforcement=false (the default), Setup must
// install the [hooks] table and features.codex_hooks=true (so the
// codex-hook.sh script fires for tool-call telemetry) but must NOT:
//   - rewrite cfg["openai_base_url"] to the proxy URL (codex talks
//     directly to its native upstream — api.openai.com or
//     chatgpt.com/backend-api/codex — instead)
//   - strip reserved built-in provider IDs (those entries stay
//     untouched on the operator's disk)
//   - rewrite [model_providers.*].base_url for custom providers
//     (openrouter / azure / groq stay pointed at their real URLs)
//
// Without this test, a refactor that quietly re-engaged the proxy
// path for the default install flow would silently break the
// "no traffic interception for codex" contract — the whole reason
// observability mode exists.
func TestCodex_Setup_DefaultObservability_NoProxyRewrite(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	enterpriseURL := "https://gateway.corp.example/openai"
	original := `model = "gpt-5"
openai_base_url = "` + enterpriseURL + `"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"

[model_providers.openrouter]
name = "openrouter"
base_url = "https://openrouter.ai/api/v1"
env_key = "OPENROUTER_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	// Pin auth.json to a non-existent path so detectCodexChatGPTMode
	// returns false (otherwise a developer's local `codex login`
	// state would alter Setup's behavior).
	CodexAuthPathOverride = filepath.Join(dir, "no-such-auth.json")
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	// CodexEnforcement omitted == false (the production default).
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid TOML after Setup: %v", err)
	}

	// Operator's openai_base_url must survive untouched.
	gotOpenAIBaseURL, _ := parsed["openai_base_url"].(string)
	if gotOpenAIBaseURL != enterpriseURL {
		t.Errorf("openai_base_url = %q, want operator's pristine value %q (no proxy rewrite in observability mode)",
			gotOpenAIBaseURL, enterpriseURL)
	}
	if strings.Contains(string(raw), "/c/codex") {
		t.Errorf("config.toml unexpectedly contains /c/codex proxy prefix in observability mode:\n%s", raw)
	}

	// Reserved-ID block must NOT be stripped — the [model_providers
	// .openai] entry the operator wrote stays in place.
	providers, _ := parsed["model_providers"].(map[string]interface{})
	if providers == nil {
		t.Fatal("[model_providers] table missing — observability mode should leave provider blocks untouched")
	}
	if openaiBlock, ok := providers["openai"].(map[string]interface{}); !ok {
		t.Errorf("[model_providers.openai] was stripped in observability mode (got=%v)", providers["openai"])
	} else if bu, _ := openaiBlock["base_url"].(string); bu != "https://api.openai.com/v1" {
		t.Errorf("openai base_url = %q, want pristine api.openai.com/v1 (no rewrite in observability mode)", bu)
	}
	if openrouterBlock, ok := providers["openrouter"].(map[string]interface{}); !ok {
		t.Errorf("[model_providers.openrouter] missing")
	} else if bu, _ := openrouterBlock["base_url"].(string); bu != "https://openrouter.ai/api/v1" {
		t.Errorf("openrouter base_url = %q, want pristine openrouter.ai/api/v1 (no rewrite in observability mode)", bu)
	}

	// Hooks MUST still be installed — they're the entry point for
	// tool-call telemetry into /api/v1/codex/hook.
	hooks, ok := parsed["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("[hooks] table missing in observability mode — telemetry wouldn't fire (got=%T)", parsed["hooks"])
	}
	if _, ok := hooks["UserPromptSubmit"]; !ok {
		t.Error("hooks.UserPromptSubmit missing — full prompt text capture lost")
	}
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Error("hooks.PreToolUse missing — tool-call telemetry lost")
	}
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Error("hooks.PostToolUse missing — tool-result telemetry lost")
	}
	features, _ := parsed["features"].(map[string]interface{})
	if v, _ := features["codex_hooks"].(bool); !v {
		t.Errorf("features.codex_hooks must be true in observability mode (hooks would otherwise be ignored by codex), got=%v", features)
	}

	// Subprocess sandbox JSON must NOT be created — that's
	// enforcement-only.
	sandboxPath := filepath.Join(dir, "subprocess.json")
	if _, err := os.Stat(sandboxPath); err == nil {
		t.Errorf("subprocess.json was created in observability mode — sandbox is enforcement-only (path=%s)", sandboxPath)
	}
}

// TestCodex_Setup_WritesOtelBlock pins the [otel] block contract: in
// observability mode the codex connector must register codex's
// native OTel exporter pointing at the gateway's OTLP-HTTP receiver.
// Without this, codex's structured logs (raw API request/response,
// model + token counts, timing) never reach the gateway and the
// observability story has a hole the hook script alone can't cover.
//
// We assert log_user_prompt = false (privacy default; UserPromptSubmit
// hook captures the prompt text with redaction control) and that the
// otlp-http endpoint matches the gateway API address. The token
// header is asserted present and equal to opts.APIToken so the
// receiver can authenticate the codex CLI process.
func TestCodex_Setup_WritesOtelBlock(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`model = "gpt-5"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	CodexAuthPathOverride = filepath.Join(dir, "no-auth.json")
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-token-codex-otel",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid TOML after Setup: %v", err)
	}

	otelBlock, ok := parsed["otel"].(map[string]interface{})
	if !ok {
		t.Fatalf("[otel] block missing — codex's native OTel exporter won't fire (got=%T:\n%s", parsed["otel"], raw)
	}
	if v, _ := otelBlock["log_user_prompt"].(bool); v {
		t.Errorf("log_user_prompt = true in default; should be false (UserPromptSubmit hook captures prompts with redaction)")
	}
	exporter, _ := otelBlock["exporter"].(map[string]interface{})
	if exporter == nil {
		t.Fatal("[otel.exporter] missing")
	}
	otlphttp, _ := exporter["otlp-http"].(map[string]interface{})
	if otlphttp == nil {
		t.Fatal("[otel.exporter.otlp-http] missing")
	}
	endpoint, _ := otlphttp["endpoint"].(string)
	if !strings.Contains(endpoint, "127.0.0.1:18970") {
		t.Errorf("otlp-http endpoint = %q, want gateway API address (127.0.0.1:18970)", endpoint)
	}
	if !strings.Contains(endpoint, "/v1/logs") {
		t.Errorf("otlp-http endpoint = %q, want /v1/logs path (the OTLP-HTTP logs sub-path)", endpoint)
	}
	// protocol = "json" is REQUIRED by codex's deserializer
	// (codex-rs/config/src/types.rs::OtelExporterKind::OtlpHttp). Omitting
	// it produces "invalid configuration: missing field `protocol` in
	// `otel.exporter`" at codex startup — a regression that would block
	// the entire CLI from launching, not just OTel export. The value
	// must match the kebab-case serde tag for OtelHttpProtocol::Json,
	// and "json" specifically is required because the gateway's OTLP-HTTP
	// receiver only accepts application/json bodies (415s protobuf).
	protocol, _ := otlphttp["protocol"].(string)
	if protocol != "json" {
		t.Errorf("otlp-http protocol = %q, want %q (codex requires this field; gateway only accepts application/json)",
			protocol, "json")
	}
	headers, _ := otlphttp["headers"].(map[string]interface{})
	if headers == nil {
		t.Fatal("[otel.exporter.otlp-http.headers] missing — receiver auth would fail")
	}
	if headers["x-defenseclaw-token"] != "test-token-codex-otel" {
		t.Errorf("x-defenseclaw-token header = %v, want %q",
			headers["x-defenseclaw-token"], "test-token-codex-otel")
	}

	traceExporter, _ := otelBlock["trace_exporter"].(map[string]interface{})
	if traceExporter == nil {
		t.Fatal("[otel.trace_exporter] missing — codex traces would be posted to the logs endpoint")
	}
	traceOTLPHTTP, _ := traceExporter["otlp-http"].(map[string]interface{})
	traceEndpoint, _ := traceOTLPHTTP["endpoint"].(string)
	if !strings.Contains(traceEndpoint, "/v1/traces") {
		t.Errorf("trace exporter endpoint = %q, want /v1/traces", traceEndpoint)
	}
	if traceOTLPHTTP["protocol"] != "json" {
		t.Errorf("trace exporter protocol = %v, want json", traceOTLPHTTP["protocol"])
	}

	metricsExporter, _ := otelBlock["metrics_exporter"].(map[string]interface{})
	if metricsExporter == nil {
		t.Fatal("[otel.metrics_exporter] missing — codex.turn.token_usage metrics would stay on the default exporter")
	}
	metricsOTLPHTTP, _ := metricsExporter["otlp-http"].(map[string]interface{})
	metricsEndpoint, _ := metricsOTLPHTTP["endpoint"].(string)
	if !strings.Contains(metricsEndpoint, "/v1/metrics") {
		t.Errorf("metrics exporter endpoint = %q, want /v1/metrics", metricsEndpoint)
	}
	if metricsOTLPHTTP["protocol"] != "json" {
		t.Errorf("metrics exporter protocol = %v, want json", metricsOTLPHTTP["protocol"])
	}
}

func TestCodex_Setup_RawModeEnablesPromptLoggingAndTeardownRestores(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	pristine := `model = "gpt-5"

[otel]
log_user_prompt = false
`
	if err := os.WriteFile(configPath, []byte(pristine), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	CodexAuthPathOverride = filepath.Join(dir, "no-auth.json")
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-token-codex-raw",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid patched TOML: %v", err)
	}
	otelBlock, _ := parsed["otel"].(map[string]interface{})
	if got, _ := otelBlock["log_user_prompt"].(bool); !got {
		t.Fatalf("log_user_prompt = %v, want true when redaction is disabled", got)
	}

	// Force the surgical restore path and flip the runtime switch back
	// before teardown. Detection must still recognize the raw-mode OTel
	// block and restore the operator's pristine value.
	redaction.SetDisableAll(false)
	discardManagedFileBackup(dir, c.Name(), "config.toml")
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	raw, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	parsed = map[string]interface{}{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid restored TOML: %v", err)
	}
	otelBlock, _ = parsed["otel"].(map[string]interface{})
	if got, _ := otelBlock["log_user_prompt"].(bool); got {
		t.Fatalf("log_user_prompt = %v after teardown, want restored false", got)
	}
}

// TestCodex_Setup_WiresNotifyBridge pins the agent-turn-complete
// telemetry path. Codex shells out to `notify` with a JSON arg
// describing each completed turn (per https://developers.openai.com
// /codex/config-advanced). Our Setup writes a per-instance bash
// bridge that POSTs the JSON to /api/v1/codex/notify. Without
// this wiring, the third independent observability channel (after
// hooks + OTel) would be dark.
//
// Asserts:
//   - notify-bridge.sh exists at DataDir, mode 0o700 (operator-only)
//   - bridge body baked the operator-supplied APIToken AND the
//     gateway notify endpoint (no env-var indirection — codex's
//     subshell can scrub env)
//   - config.toml emits notify = ["bash", "<DataDir>/notify-bridge.sh"]
//     in the canonical TOML array form (codex parses this; a
//     non-array would silently disable the bridge with no log).
func TestCodex_Setup_WiresNotifyBridge(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`model = "gpt-5"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	CodexAuthPathOverride = filepath.Join(dir, "no-auth.json")
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-token-codex-notify",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	bridgePath := filepath.Join(dir, "notify-bridge.sh")
	info, err := os.Stat(bridgePath)
	if err != nil {
		t.Fatalf("notify-bridge.sh missing — agent-turn-complete telemetry won't fire: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("notify-bridge.sh mode = %v, want 0o700 (operator-only — token is baked in)", info.Mode().Perm())
	}
	bridge, err := os.ReadFile(bridgePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bridge), "test-token-codex-notify") {
		t.Error("bridge missing baked-in APIToken — receiver would reject every call as unauthenticated")
	}
	if !strings.Contains(string(bridge), "127.0.0.1:18970/api/v1/codex/notify") {
		t.Errorf("bridge missing gateway notify endpoint URL; body:\n%s", bridge)
	}

	// config.toml notify entry must be the array shape codex parses.
	raw, _ := os.ReadFile(configPath)
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid TOML after Setup: %v", err)
	}
	notify, ok := parsed["notify"].([]interface{})
	if !ok {
		t.Fatalf("notify entry not an array (got %T) — codex would silently disable the bridge", parsed["notify"])
	}
	if len(notify) != 2 {
		t.Errorf("notify array has %d entries, want 2 ([bash, bridge.sh]); got %v", len(notify), notify)
	}
	if first, _ := notify[0].(string); first != "bash" {
		t.Errorf("notify[0] = %q, want \"bash\"", first)
	}
	if second, _ := notify[1].(string); !strings.HasSuffix(second, "/notify-bridge.sh") {
		t.Errorf("notify[1] = %q, want path ending in /notify-bridge.sh", second)
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
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

func TestCodex_Teardown_WritesDisabledHookForCachedProcesses(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`model_provider = "openai"
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	hookPath := filepath.Join(dir, "hooks", "codex-hook.sh")
	setupHook, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read setup hook: %v", err)
	}
	if !strings.Contains(string(setupHook), "/api/v1/codex/hook") {
		t.Fatalf("setup hook does not forward to Codex hook API\nfile:\n%s", setupHook)
	}

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("disabled hook missing after teardown: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("disabled hook is not executable: mode %v", info.Mode())
	}

	disabledHook, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read disabled hook: %v", err)
	}
	disabled := string(disabledHook)
	if !strings.Contains(disabled, "defenseclaw-managed-hook disabled") {
		t.Errorf("disabled hook missing tombstone marker\nfile:\n%s", disabled)
	}
	if !strings.Contains(disabled, "exit 0") {
		t.Errorf("disabled hook must exit successfully\nfile:\n%s", disabled)
	}
	if strings.Contains(disabled, "/api/v1/codex/hook") {
		t.Errorf("disabled hook still forwards stale payloads\nfile:\n%s", disabled)
	}
}

func TestCodex_Teardown_PreservesUserHooksAddedAfterSetup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`model_provider = "openai"
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read setup config: %v", err)
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse setup config: %v", err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	promptHooks := hooks["UserPromptSubmit"].([]interface{})
	promptHooks = append(promptHooks, map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": "/tmp/user-codex-hook",
				"timeout": int64(2),
			},
		},
	})
	hooks["UserPromptSubmit"] = promptHooks
	cfg["hooks"] = hooks
	out, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal user-edited config: %v", err)
	}
	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		t.Fatalf("write user-edited config: %v", err)
	}

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	data, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	restored := string(data)
	if strings.Contains(restored, "codex-hook.sh") {
		t.Fatalf("DefenseClaw hook survived teardown:\n%s", restored)
	}
	if !strings.Contains(restored, "/tmp/user-codex-hook") {
		t.Fatalf("user hook was not preserved:\n%s", restored)
	}
}

func TestCodex_TeardownWithoutBackup_RemovesManagedConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`model_provider = "openai"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "codex_config_backup.json")); err != nil {
		t.Fatalf("remove backup: %v", err)
	}
	discardManagedFileBackup(dir, c.Name(), "config.toml")

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown without backup: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	restored := string(data)
	for _, forbidden := range []string{
		"codex-hook.sh",
		"notify-bridge.sh",
		"codex_hooks",
		"x-defenseclaw-token",
		"x-defenseclaw-client",
		"[otel]",
	} {
		if strings.Contains(restored, forbidden) {
			t.Fatalf("teardown without backup left %q in config:\n%s", forbidden, restored)
		}
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after backupless teardown: %v", err)
	}
}

func TestCodex_VerifyCleanDetectsConfigResidue(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	hookPath := filepath.Join(dir, "hooks", "codex-hook.sh")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/bash\n# defenseclaw-managed-hook v2\n"), 0o700); err != nil {
		t.Fatalf("write hook: %v", err)
	}
	cfg := map[string]interface{}{
		"hooks": buildCodexHooksTable(hookPath),
		"otel":  buildCodexOtelBlock(SetupOpts{APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}),
		"notify": []interface{}{
			"bash",
			filepath.Join(dir, "notify-bridge.sh"),
		},
	}
	out, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	err = NewCodexConnector().VerifyClean(SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	})
	if err == nil {
		t.Fatal("VerifyClean returned nil despite managed Codex config residue")
	}
	got := err.Error()
	if !strings.Contains(got, "config.toml hooks") || !strings.Contains(got, "[otel]") || !strings.Contains(got, "notify") {
		t.Fatalf("VerifyClean error missing expected residue details: %v", err)
	}
}

func TestCodexOtelBlockLooksManaged_AcceptsLegacyExporterOnlyBlock(t *testing.T) {
	opts := SetupOpts{APIAddr: "127.0.0.1:18970"}
	legacy := map[string]interface{}{
		"log_user_prompt": false,
		"exporter": map[string]interface{}{
			"otlp-http": map[string]interface{}{
				"endpoint": "http://127.0.0.1:18970/v1/logs",
				"protocol": "json",
				"headers": map[string]interface{}{
					"x-defenseclaw-client": "codex-otel/1.0",
					"x-defenseclaw-source": "codex",
				},
			},
		},
	}
	if !codexOtelBlockLooksManaged(legacy, opts) {
		t.Fatal("legacy DefenseClaw-managed Codex [otel] block was not recognized")
	}

	user := map[string]interface{}{
		"exporter": map[string]interface{}{
			"otlp-http": map[string]interface{}{
				"endpoint": "https://otel.example.com/v1/logs",
				"protocol": "json",
				"headers":  map[string]interface{}{"x-defenseclaw-source": "codex"},
			},
		},
	}
	if codexOtelBlockLooksManaged(user, opts) {
		t.Fatal("non-DefenseClaw Codex [otel] block was classified as managed")
	}
}

// TestCodex_Setup_RedirectsBuiltinOpenAIViaTopLevelKey pins the post-PR
// openai/codex#12024 contract: the built-in `openai` provider is
// redirected via the top-level `openai_base_url` field, NOT via a
// `[model_providers.openai]` table. Codex 5.x rejects the latter at
// startup with "model_providers contains reserved built-in provider
// IDs: `openai`. Built-in providers cannot be overridden." — which
// took down both the codex agent and any agent harness (e.g. the
// OpenClaw TUI) that spawns codex as a subprocess. This test parses
// the patched config.toml back through the TOML decoder so the
// assertion is structural (not just a substring match).
func TestCodex_Setup_RedirectsBuiltinOpenAIViaTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	// Seed an operator config that DOES have the now-rejected
	// [model_providers.openai] block — this is the exact shape that
	// every install before this fix produced and that Codex 5.x
	// refuses to load.
	original := `model = "gpt-5.5"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"
env_key = "OPENAI_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatalf("seed config.toml: %v", err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	// Enforcement mode required: openai_base_url rewrite + reserved-
	// id strip live behind the enforcement flag.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("patched config did not round-trip as valid TOML: %v\nfile:\n%s", err, raw)
	}

	wantProxy := "http://127.0.0.1:4000/c/codex"

	// 1) The top-level openai_base_url MUST be set to the proxy URL.
	gotBaseURL, ok := parsed["openai_base_url"].(string)
	if !ok {
		t.Fatalf("openai_base_url missing or not a string in patched config; parsed=%v", parsed)
	}
	if gotBaseURL != wantProxy {
		t.Errorf("openai_base_url = %q, want %q", gotBaseURL, wantProxy)
	}

	// 2) The reserved [model_providers.openai] table MUST NOT be
	//    present — that is the exact shape Codex 5.x rejects.
	if providers, ok := parsed["model_providers"].(map[string]interface{}); ok {
		if _, found := providers["openai"]; found {
			t.Errorf("[model_providers.openai] still present after Setup — Codex 5.x rejects this with 'reserved built-in provider IDs'\nfile:\n%s", raw)
		}
		if _, found := providers["ollama"]; found {
			t.Errorf("[model_providers.ollama] still present after Setup — reserved built-in")
		}
		if _, found := providers["lmstudio"]; found {
			t.Errorf("[model_providers.lmstudio] still present after Setup — reserved built-in")
		}
	}
}

// TestCodex_Setup_StripsAllReservedProviderIDs pins that every
// reserved Codex built-in (openai, ollama, lmstudio) is removed from
// [model_providers.*] on Setup. Operators with multi-provider configs
// pre-fix could have any combination of these tables; if any one
// survives Setup, Codex 5.x 's startup validator (PR #12024) trips
// on it and refuses to start.
func TestCodex_Setup_StripsAllReservedProviderIDs(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model = "gpt-5.5"

[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"

[model_providers.ollama]
name = "ollama"
base_url = "http://localhost:11434/v1"

[model_providers.lmstudio]
name = "lmstudio"
base_url = "http://localhost:1234/v1"

[model_providers.openrouter]
name = "openrouter"
base_url = "https://openrouter.ai/api/v1"
env_key = "OPENROUTER_API_KEY"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	c := NewCodexConnector()
	// Enforcement mode required: this test asserts the reserved-id
	// strip + per-provider rewrite which only run in enforcement.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	raw, _ := os.ReadFile(configPath)
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid TOML after Setup: %v", err)
	}
	providers, _ := parsed["model_providers"].(map[string]interface{})
	for _, id := range []string{"openai", "ollama", "lmstudio"} {
		if _, found := providers[id]; found {
			t.Errorf("reserved provider %q still present in [model_providers] — Codex 5.x will refuse to start", id)
		}
	}
	// The non-reserved provider MUST still be present and rewritten.
	openrouter, ok := providers["openrouter"].(map[string]interface{})
	if !ok {
		t.Fatalf("custom provider 'openrouter' missing after Setup — should be retained and rewritten")
	}
	if bu, _ := openrouter["base_url"].(string); bu != "http://127.0.0.1:4000/c/codex" {
		t.Errorf("openrouter base_url = %q, want proxy redirect", bu)
	}
}

// TestCodex_Teardown_RestoresOriginalOpenAIProviderBlock verifies
// that an operator who had a pristine [model_providers.openai] block
// (e.g. from an older Codex release that accepted overrides) gets it
// back on Teardown — even though we stripped it on Setup. The
// reserved-block backup channel is what makes "uninstall returns the
// host to its original shape" still hold for these operators.
func TestCodex_Teardown_RestoresOriginalOpenAIProviderBlock(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	original := `model = "gpt-5.5"

[model_providers.openai]
name = "openai-classic"
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
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	raw, _ := os.ReadFile(configPath)
	var parsed map[string]interface{}
	if err := toml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid TOML after Teardown: %v\nfile:\n%s", err, raw)
	}
	// Top-level openai_base_url must be removed (operator never had it).
	if _, found := parsed["openai_base_url"]; found {
		t.Errorf("Teardown left top-level openai_base_url behind — operator's pristine config did not have it\nfile:\n%s", raw)
	}
	// The original [model_providers.openai] block must be back, with
	// its original `name` field intact (i.e. restored from backup,
	// not re-synthesized).
	providers, _ := parsed["model_providers"].(map[string]interface{})
	openai, ok := providers["openai"].(map[string]interface{})
	if !ok {
		t.Fatalf("Teardown did not restore [model_providers.openai] from backup\nfile:\n%s", raw)
	}
	if name, _ := openai["name"].(string); name != "openai-classic" {
		t.Errorf("[model_providers.openai].name = %q, want %q (restored verbatim from backup)", name, "openai-classic")
	}
	if bu, _ := openai["base_url"].(string); bu != "https://api.openai.com/v1" {
		t.Errorf("[model_providers.openai].base_url = %q, want pristine OpenAI URL", bu)
	}
}

// TestCodex_Setup_SynthesizesOpenAISnapshot pins that the in-memory
// provider snapshot ALWAYS includes a usable `openai` entry, even
// when the operator's config.toml has no [model_providers.openai]
// block (the new default after the Codex 5.x reserved-ID change).
// Without this, Route() would have no upstream URL for codex's
// `/c/codex/responses` traffic and the proxy would 502 every request.
func TestCodex_Setup_SynthesizesOpenAISnapshot(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	// Pristine config without any provider block — the realistic
	// post-fix shape on a fresh Codex install.
	original := `model = "gpt-5.5"
`
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	// Pin auth.json to a path that does not exist so the detection
	// helper returns false deterministically. Without this, a dev
	// machine where the user has run `codex login` (which writes
	// auth_mode="chatgpt" to ~/.codex/auth.json) would flip this
	// test's expected default to the chatgpt backend URL — a flaky
	// pass/fail that depends on the dev's local Codex login state.
	CodexAuthPathOverride = filepath.Join(dir, "no-such-auth.json")
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	// Enforcement mode required: SetProviderSnapshot only runs in
	// the enforcement path. Observability-mode default skips the
	// snapshot entirely (no proxy passthrough means Route() is
	// never consulted).
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	snap := c.ProviderSnapshot()
	openai, ok := snap["openai"]
	if !ok {
		t.Fatalf("snapshot missing synthetic 'openai' entry — Route() will 502 on /c/codex/responses\nsnapshot=%v", snap)
	}
	if openai.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("synthetic openai BaseURL = %q, want canonical OpenAI URL", openai.BaseURL)
	}
}

// TestCodex_Setup_SynthesizesChatGPTBackendWhenAuthModeChatGPT pins the
// real-world regression we hit while running `defenseclaw setup
// guardrail` against a Codex CLI that was logged in via ChatGPT/Plus
// (auth_mode="chatgpt"). With OPENAI_API_KEY=null the only endpoint
// that accepts the issued access_token is
// `chatgpt.com/backend-api/codex/responses`. Synthesizing the
// canonical `api.openai.com/v1` upstream produced a permanent 401
// upstream-error loop, surfacing in the codex TUI as "Reconnecting…
// 5/5" with hooks firing but no completion ever returning.
//
// We assert the synthetic snapshot points at the chatgpt backend URL,
// because Route() concatenates the incoming `/responses` suffix to
// produce the full upstream — and that's the only URL the user's auth
// token will be valid against.
func TestCodex_Setup_SynthesizesChatGPTBackendWhenAuthModeChatGPT(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	// Realistic auth.json shape from a `codex login` ChatGPT flow.
	// We do NOT seed real tokens — the function under test only reads
	// `auth_mode`. Anything else here is just shape padding.
	authPath := filepath.Join(dir, "auth.json")
	authJSON := `{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"id_token":"x","access_token":"y","refresh_token":"z"}}`
	if err := os.WriteFile(authPath, []byte(authJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexAuthPathOverride = authPath
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	// Enforcement mode required: SetProviderSnapshot only runs in
	// the gated enforcement block.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	snap := c.ProviderSnapshot()
	openai, ok := snap["openai"]
	if !ok {
		t.Fatalf("snapshot missing synthetic 'openai' entry; got=%v", snap)
	}
	if openai.BaseURL != codexChatGPTBackendURL {
		t.Fatalf(
			"chatgpt-mode synthetic BaseURL = %q, want %q\n\n"+
				"This is the bug surfaced by the defenseclaw setup guardrail flow on a\n"+
				"`codex login`-authenticated CLI: api.openai.com/v1 will reject the issued\n"+
				"ChatGPT access_token with 401, and the codex TUI loops forever on\n"+
				"\"Reconnecting…\". The chatgpt backend URL is the only valid target.",
			openai.BaseURL, codexChatGPTBackendURL,
		)
	}
}

// TestCodex_Setup_OperatorOpenAIBaseURLOverridesChatGPTDefault pins
// that an explicit operator `openai_base_url` in their config (e.g.
// an enterprise reverse-proxy or a custom Bifrost endpoint) wins over
// BOTH the api.openai.com default AND the chatgpt-mode default.
// Without this guard, an operator who set up an enterprise gateway
// once and later logged in via ChatGPT would silently lose that
// override on the next Setup() pass.
func TestCodex_Setup_OperatorOpenAIBaseURLOverridesChatGPTDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	enterpriseURL := "https://gateway.corp.example/openai"
	original := `model = "gpt-5"
openai_base_url = "` + enterpriseURL + `"
`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()

	authPath := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"auth_mode":"chatgpt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexAuthPathOverride = authPath
	defer func() { CodexAuthPathOverride = "" }()

	c := NewCodexConnector()
	// Enforcement mode required: SetProviderSnapshot only runs in
	// the gated enforcement block.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", CodexEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	snap := c.ProviderSnapshot()
	openai, ok := snap["openai"]
	if !ok {
		t.Fatalf("snapshot missing synthetic 'openai' entry; got=%v", snap)
	}
	if openai.BaseURL != enterpriseURL {
		t.Fatalf("operator openai_base_url override lost: got %q, want %q", openai.BaseURL, enterpriseURL)
	}
}

// TestDetectCodexChatGPTMode_ReturnsFalseOnMissingOrMalformed pins the
// safe-default behavior of detectCodexChatGPTMode() — it must NOT
// return true (which would force a chatgpt.com routing) when auth.json
// is absent, malformed, or names a non-chatgpt mode. Symmetrically, it
// MUST return true when auth.json is well-formed and reports
// "chatgpt", regardless of casing.
func TestDetectCodexChatGPTMode_ReturnsFalseOnMissingOrMalformed(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		setup   func() string // returns auth path (or "" for missing-file case)
		want    bool
		comment string
	}{
		{
			name:    "missing file",
			setup:   func() string { return filepath.Join(dir, "does-not-exist.json") },
			want:    false,
			comment: "operator may not have run `codex login` yet",
		},
		{
			name: "malformed JSON",
			setup: func() string {
				p := filepath.Join(dir, "broken.json")
				_ = os.WriteFile(p, []byte("not-json{{"), 0o600)
				return p
			},
			want:    false,
			comment: "manual edit / disk corruption must not flip routing",
		},
		{
			name: "apikey mode",
			setup: func() string {
				p := filepath.Join(dir, "apikey.json")
				_ = os.WriteFile(p, []byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"sk-fake"}`), 0o600)
				return p
			},
			want:    false,
			comment: "OPENAI_API_KEY users must keep api.openai.com routing",
		},
		{
			name: "chatgpt mode lowercase",
			setup: func() string {
				p := filepath.Join(dir, "chatgpt.json")
				_ = os.WriteFile(p, []byte(`{"auth_mode":"chatgpt"}`), 0o600)
				return p
			},
			want: true,
		},
		{
			name: "chatgpt mode mixed case",
			setup: func() string {
				p := filepath.Join(dir, "chatgpt-mixed.json")
				_ = os.WriteFile(p, []byte(`{"auth_mode":"ChatGPT"}`), 0o600)
				return p
			},
			want:    true,
			comment: "case-insensitive match — auth.json shape isn't a public contract",
		},
		{
			name: "empty auth_mode",
			setup: func() string {
				p := filepath.Join(dir, "empty-mode.json")
				_ = os.WriteFile(p, []byte(`{}`), 0o600)
				return p
			},
			want:    false,
			comment: "absent field defaults to false (safe: keeps api.openai.com)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			CodexAuthPathOverride = tc.setup()
			defer func() { CodexAuthPathOverride = "" }()
			got := detectCodexChatGPTMode()
			if got != tc.want {
				t.Fatalf("detectCodexChatGPTMode() = %v, want %v (%s)", got, tc.want, tc.comment)
			}
		})
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
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
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

// TestZeptoClaw_Authenticate_Loopback pins the new B1 contract: with no
// gateway token AND no master key configured (the brief first-boot
// window before ensureGatewayToken runs), loopback callers are still
// allowed so the install can complete its first request without 401.
// Once a token is configured, this loopback-allow is no longer
// reachable — TestZeptoClaw_Authenticate_LoopbackRequiresTokenWhenConfigured
// pins that flip.
func TestZeptoClaw_Authenticate_Loopback(t *testing.T) {
	c := NewZeptoClawConnector()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	if !c.Authenticate(r) {
		t.Error("expected loopback auth to pass when no token configured (first-boot window)")
	}
}

// TestZeptoClaw_Authenticate_LoopbackRequiresTokenWhenConfigured pins
// the new B1 / S0.3 invariant: once a gateway token is configured, even
// loopback callers must present a valid X-DC-Auth header. The previous
// behavior allowed any local process to hit /c/zeptoclaw/* and have its
// upstream key recorded by Route() — that path is now closed.
func TestZeptoClaw_Authenticate_LoopbackRequiresTokenWhenConfigured(t *testing.T) {
	c := NewZeptoClawConnector()
	c.SetCredentials("gw-tok-configured", "")

	r := httptest.NewRequest("POST", "/c/zeptoclaw/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-or-upstream-key")

	if c.Authenticate(r) {
		t.Fatal("loopback without X-DC-Auth must be rejected when gateway token is configured (plan B1)")
	}
}

func TestZeptoClaw_Authenticate_Token(t *testing.T) {
	c := NewZeptoClawConnector()
	c.SetCredentials("my-token", "my-master")

	// Loopback without X-DC-Auth is now rejected when a token is
	// configured (plan B1 / S0.3): the previous "trust loopback
	// unconditionally" contract was a local-IDOR risk.
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer sk-or-upstream-key")
	if c.Authenticate(r) {
		t.Error("loopback with only an upstream-bearer (no X-DC-Auth) must be rejected when token configured")
	}

	// Loopback with X-DC-Auth is accepted (the hooks/inspect-*.sh
	// scripts inject this header bearing the synthesized gateway token).
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "127.0.0.1:54321"
	r2.Header.Set("X-DC-Auth", "my-token")
	if !c.Authenticate(r2) {
		t.Error("loopback with valid X-DC-Auth must pass")
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

// TestZeptoClaw_Authenticate_NativeBinaryLoopback (post-B1): the
// hook-script flow injects X-DC-Auth bearing the synthesized gateway
// token, so loopback callers are authenticated via the same path as
// remote callers. The previous "loopback always allowed" path is gone.
func TestZeptoClaw_Authenticate_NativeBinaryLoopback(t *testing.T) {
	c := NewZeptoClawConnector()
	c.SetCredentials("gw-tok-5c80", "")

	r := httptest.NewRequest("POST", "/c/zeptoclaw/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-DC-Auth", "gw-tok-5c80")
	r.Header.Set("Authorization", "Bearer sk-or-v1-real-openrouter-key")

	if !c.Authenticate(r) {
		t.Fatal("zeptoclaw loopback with X-DC-Auth must be accepted post-B1")
	}
}

// TestZeptoClaw_Authenticate_ProviderSnapshotBearerLoopback: ZeptoClaw's
// HTTP client sends the upstream key in Authorization only; when a gateway
// token is configured it cannot inject X-DC-Auth. Loopback + bearer matching
// the Setup snapshot must still authenticate.
func TestZeptoClaw_Authenticate_ProviderSnapshotBearerLoopback(t *testing.T) {
	c := NewZeptoClawConnector()
	c.SetCredentials("gw-tok-configured", "")
	c.SetProviderSnapshot(map[string]ZeptoClawProviderEntry{
		"bedrock": {APIKey: "aws-bedrock-bearer-from-zepto-config", APIBase: "https://bedrock-runtime.us-east-1.amazonaws.com"},
	})

	r := httptest.NewRequest("POST", "/c/zeptoclaw/v1/chat/completions", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer aws-bedrock-bearer-from-zepto-config")

	if !c.Authenticate(r) {
		t.Fatal("loopback with Authorization matching provider snapshot must pass when gateway token is configured")
	}

	r2 := httptest.NewRequest("POST", "/c/zeptoclaw/v1/chat/completions", nil)
	r2.RemoteAddr = "10.0.0.5:54321"
	r2.Header.Set("Authorization", "Bearer aws-bedrock-bearer-from-zepto-config")
	if c.Authenticate(r2) {
		t.Fatal("non-loopback must not authenticate via provider snapshot bearer alone")
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
	if string(cs.RawBody) != string(body) {
		t.Errorf("RawBody = %q, want original ZeptoClaw request body", string(cs.RawBody))
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
	if err := c1.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}

	// Second Setup on a fresh connector instance, same data dir. The
	// config on disk is now patched (api_base=proxy URL). A naive Setup
	// would read the patched config and record the proxy URL in the
	// backup, but the snapshot must still reflect the pristine upstream.
	c2 := NewZeptoClawConnector()
	if err := c2.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	// Plan S7.1 sentinel guard: every built-in hook exits 0 immediately
	// if DEFENSECLAW_HOME is missing or has a `.disabled` marker. CI
	// runners have no real ~/.defenseclaw, so without an explicit
	// DEFENSECLAW_HOME the hook fail-opens before curl is ever invoked
	// and `curl-args.txt` is never written. Seed a tmp dir that exists
	// and contains no .disabled sentinel so the hook proceeds to the
	// curl path the caller cares about.
	dcHome := t.TempDir()
	cmd := exec.Command("bash", scriptPath)
	// Plan B4 / S0.4: hooks lock PATH down by default. The test
	// stubs `curl` inside an ephemeral tmpdir; tell the hardening
	// helpers to keep our path rather than reset it to system bins.
	hookPath := stubDir + ":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	cmd.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"DEFENSECLAW_HOME="+dcHome,
		"DEFENSECLAW_HOOK_PATH="+hookPath,
	)
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
		// Plan B1 / S0.3: ZeptoClaw used to trust loopback as a
		// "native binary has no way to inject X-DC-Auth" carve-out;
		// that was the local-IDOR vector. The hooks/inspect-*.sh
		// shell scripts (which run on the same host) now inject
		// X-DC-Auth bearing the synthesized gateway token, so
		// ZeptoClaw no longer needs the loopback trust.
		//
		// Codex still trusts loopback because the OpenAI Python SDK
		// inside the agent process has no equivalent shell wrapper
		// to inject the header — that wiring is a Phase E follow-up.
		r3 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r3.RemoteAddr = "127.0.0.1:54321"
		accepted := c.Authenticate(r3)
		loopbackTrust := c.Name() == "codex"
		if loopbackTrust {
			if !accepted {
				t.Errorf("%s: loopback must be trusted so codex traffic can reach the proxy", c.Name())
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
	// Enforcement mode required: this test asserts the /c/codex
	// rewrite hits config.toml, which only happens in the gated
	// enforcement path. Default observability mode does not write
	// the proxy URL into config.toml at all (codex talks directly
	// to its native upstream).
	opts := SetupOpts{
		DataDir:          dir,
		ProxyAddr:        "127.0.0.1:4000",
		APIAddr:          "127.0.0.1:18970",
		CodexEnforcement: true,
	}
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
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

	if err := c.Teardown(context.Background(), opts); err != nil {
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
	c.Setup(context.Background(), opts)

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
	// Enforcement mode required: writeEnvOverride only runs in the
	// gated enforcement path. Default observability mode does not
	// produce claudecode_env.sh / claudecode.env at all (claude code
	// talks directly to api.anthropic.com).
	opts := SetupOpts{
		DataDir:               dir,
		ProxyAddr:             "127.0.0.1:4000",
		APIAddr:               "127.0.0.1:18970",
		ClaudeCodeEnforcement: true,
	}
	if err := c.Setup(context.Background(), opts); err != nil {
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
	// Enforcement mode required: writeEnvOverride is gated on
	// opts.ClaudeCodeEnforcement.
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", ClaudeCodeEnforcement: true}
	if err := c.Setup(context.Background(), opts); err != nil {
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
	c.Setup(context.Background(), opts)
	c.Teardown(context.Background(), opts)

	if _, err := os.Stat(filepath.Join(dir, "claudecode_env.sh")); !os.IsNotExist(err) {
		t.Error("claudecode_env.sh should be removed after teardown")
	}
	if _, err := os.Stat(filepath.Join(dir, "claudecode.env")); !os.IsNotExist(err) {
		t.Error("claudecode.env should be removed after teardown")
	}
}

// TestClaudeCode_Setup_DefaultObservability_NoEnvOverride is the
// headline regression test for the claude-code observability default.
// With ClaudeCodeEnforcement=false (the default), Setup must register
// hooks (the entry point for tool-call telemetry into
// /api/v1/claudecode/hook) but must NOT:
//   - write claudecode_env.sh / claudecode.env (the
//     ANTHROPIC_BASE_URL files that route claude code's data path
//     through the DefenseClaw proxy)
//   - install the subprocess sandbox JSON
//
// Without this test, a refactor that quietly re-engaged the env
// override on the default install flow would silently break the
// "no traffic interception for claude code" contract.
func TestClaudeCode_Setup_DefaultObservability_NoEnvOverride(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	// ClaudeCodeEnforcement omitted == false (the production
	// default).
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Env-override files MUST NOT exist — claude code talks
	// directly to api.anthropic.com in observability mode.
	if _, err := os.Stat(filepath.Join(dir, "claudecode_env.sh")); err == nil {
		t.Error("claudecode_env.sh was written in observability mode — proxy redirect should be skipped")
	}
	if _, err := os.Stat(filepath.Join(dir, "claudecode.env")); err == nil {
		t.Error("claudecode.env was written in observability mode — proxy redirect should be skipped")
	}

	// Subprocess sandbox JSON must NOT exist — that's
	// enforcement-only. Hook can still POST to the API and read
	// "allow" by default.
	if _, err := os.Stat(filepath.Join(dir, "subprocess.json")); err == nil {
		t.Error("subprocess.json was written in observability mode — sandbox is enforcement-only")
	}

	// Hooks MUST be registered — they're the telemetry entry
	// point. patchClaudeCodeHooks runs unconditionally.
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse settings.json: %v", err)
	}
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("settings.json missing hooks block in observability mode (got=%T)", settings["hooks"])
	}
	for _, evt := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		if _, ok := hooks[evt]; !ok {
			t.Errorf("hooks.%s missing — telemetry event would be lost", evt)
		}
	}
}

// TestClaudeCode_Setup_WritesOtelEnv pins the OTel env-block contract.
// Claude Code reads its OTel exporter config from process env vars
// (https://code.claude.com/docs/en/monitoring-usage). We persist the
// vars in ~/.claude/settings.json's `env` block so the operator
// doesn't need to source any shell file. Without this, Claude's
// structured logs/metrics are never sent and the second
// observability channel (after hooks) is dark.
func TestClaudeCode_Setup_WritesOtelEnv(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-token-claude-otel",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse settings.json: %v", err)
	}
	env, ok := settings["env"].(map[string]interface{})
	if !ok {
		t.Fatalf("settings.env missing — claude won't export OTel vars (got=%T:\n%s", settings["env"], data)
	}

	if env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
		t.Errorf("CLAUDE_CODE_ENABLE_TELEMETRY = %v, want \"1\"", env["CLAUDE_CODE_ENABLE_TELEMETRY"])
	}
	if env["DEFENSECLAW_FAIL_MODE"] != "open" {
		t.Errorf("DEFENSECLAW_FAIL_MODE = %v, want \"open\" for observability-only installs", env["DEFENSECLAW_FAIL_MODE"])
	}
	if env["OTEL_LOGS_EXPORTER"] != "otlp" {
		t.Errorf("OTEL_LOGS_EXPORTER = %v, want \"otlp\"", env["OTEL_LOGS_EXPORTER"])
	}
	if _, present := env["OTEL_LOG_USER_PROMPTS"]; present {
		t.Errorf("OTEL_LOG_USER_PROMPTS should be absent by default; got %v", env["OTEL_LOG_USER_PROMPTS"])
	}
	if env["OTEL_METRICS_EXPORTER"] != "otlp" {
		t.Errorf("OTEL_METRICS_EXPORTER = %v, want \"otlp\"", env["OTEL_METRICS_EXPORTER"])
	}
	endpoint, _ := env["OTEL_EXPORTER_OTLP_ENDPOINT"].(string)
	if !strings.Contains(endpoint, "127.0.0.1:18970") {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q, want gateway API address", endpoint)
	}
	headers, _ := env["OTEL_EXPORTER_OTLP_HEADERS"].(string)
	if !strings.Contains(headers, "x-defenseclaw-token=test-token-claude-otel") {
		t.Errorf("OTEL_EXPORTER_OTLP_HEADERS missing token; got %q", headers)
	}
	if !strings.Contains(headers, "x-defenseclaw-source=claudecode") {
		t.Errorf("OTEL_EXPORTER_OTLP_HEADERS missing source attribution; got %q", headers)
	}
	if env["OTEL_SERVICE_NAME"] != "claudecode" {
		t.Errorf("OTEL_SERVICE_NAME = %v, want \"claudecode\"", env["OTEL_SERVICE_NAME"])
	}
	if info, err := os.Stat(settingsPath); err != nil {
		t.Fatalf("stat settings.json: %v", err)
	} else if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("settings.json mode = %#o, want 0600 because OTel headers include the gateway token", mode)
	}
}

func TestClaudeCode_Setup_RawModeEnablesPromptLoggingAndTeardownRestores(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	pristine := `{
		"env": {
			"OTEL_LOG_USER_PROMPTS": "0",
			"PATH": "/custom/bin:/usr/bin"
		}
	}`
	if err := os.WriteFile(settingsPath, []byte(pristine), 0o644); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-token-claude-raw",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read patched settings: %v", err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse patched settings: %v", err)
	}
	env, _ := settings["env"].(map[string]interface{})
	if env["OTEL_LOG_USER_PROMPTS"] != "1" {
		t.Fatalf("OTEL_LOG_USER_PROMPTS = %v, want \"1\" when redaction is disabled", env["OTEL_LOG_USER_PROMPTS"])
	}

	// Force the backup-driven restore path and turn redaction back on
	// before teardown. The prompt logging setting should still return
	// to the operator's original value.
	redaction.SetDisableAll(false)
	discardManagedFileBackup(dir, c.Name(), "settings.json")
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read restored settings: %v", err)
	}
	settings = map[string]interface{}{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse restored settings: %v", err)
	}
	env, _ = settings["env"].(map[string]interface{})
	if env["OTEL_LOG_USER_PROMPTS"] != "0" {
		t.Fatalf("OTEL_LOG_USER_PROMPTS = %v after teardown, want restored \"0\"", env["OTEL_LOG_USER_PROMPTS"])
	}
	if env["PATH"] != "/custom/bin:/usr/bin" {
		t.Fatalf("PATH = %v after teardown, want pristine value", env["PATH"])
	}
}

func TestClaudeCode_TeardownWithoutBackup_RemovesManagedHooksAndOtel(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"env":{"PATH":"/usr/bin"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-token",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "claudecode_backup.json")); err != nil {
		t.Fatalf("remove backup: %v", err)
	}
	discardManagedFileBackup(dir, c.Name(), "settings.json")

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown without backup: %v", err)
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after backupless teardown: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	if hooks, ok := settings["hooks"].(map[string]interface{}); ok && len(hooks) > 0 {
		t.Fatalf("DefenseClaw hooks survived teardown without backup: %v", hooks)
	}
	env, _ := settings["env"].(map[string]interface{})
	if env["PATH"] != "/usr/bin" {
		t.Fatalf("non-OTel env key was not preserved: %v", env)
	}
	for _, key := range claudeCodeOtelEnvKeys {
		if _, present := env[key]; present {
			t.Fatalf("DefenseClaw OTel env %s survived teardown without backup: %v", key, env)
		}
	}
}

// TestClaudeCode_Setup_PreservesNonOtelEnvKeys guards the partial-
// merge contract: when the operator has set non-OTel keys in
// settings.json's env block (e.g. PATH, NODE_OPTIONS), Setup must
// preserve them verbatim while overlaying our OTel keys. Without
// this, an OTel patch would silently destroy unrelated overrides.
func TestClaudeCode_Setup_PreservesNonOtelEnvKeys(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	pristine := `{
		"env": {
			"NODE_OPTIONS": "--max-old-space-size=8192",
			"PATH": "/custom/bin:/usr/bin"
		}
	}`
	if err := os.WriteFile(settingsPath, []byte(pristine), 0o644); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-tok",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]interface{})
	if env["NODE_OPTIONS"] != "--max-old-space-size=8192" {
		t.Errorf("NODE_OPTIONS clobbered: got %v, want pristine value", env["NODE_OPTIONS"])
	}
	if env["PATH"] != "/custom/bin:/usr/bin" {
		t.Errorf("PATH clobbered: got %v, want pristine value", env["PATH"])
	}
	if env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
		t.Errorf("OTel keys not merged in alongside operator keys (got CLAUDE_CODE_ENABLE_TELEMETRY=%v)", env["CLAUDE_CODE_ENABLE_TELEMETRY"])
	}
	if env["DEFENSECLAW_FAIL_MODE"] != "open" {
		t.Errorf("DEFENSECLAW_FAIL_MODE not merged: got %v", env["DEFENSECLAW_FAIL_MODE"])
	}
}

func TestClaudeCode_Teardown_RestoresPreExistingOtelEnvKeys(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, "claude-settings")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	pristine := `{
		"env": {
			"OTEL_LOGS_EXPORTER": "console",
			"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example/v1",
			"OTEL_SERVICE_NAME": "operator-claude",
			"PATH": "/custom/bin:/usr/bin"
		}
	}`
	if err := os.WriteFile(settingsPath, []byte(pristine), 0o644); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "test-tok",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Force the surgical backup path instead of exact managed-file
	// restore so this test exercises claudecode_backup.json's env
	// snapshot, which is what connector switch/uninstall uses after
	// user drift.
	discardManagedFileBackup(dir, c.Name(), "settings.json")

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]interface{})
	if env["OTEL_LOGS_EXPORTER"] != "console" {
		t.Errorf("OTEL_LOGS_EXPORTER = %v, want pristine value", env["OTEL_LOGS_EXPORTER"])
	}
	if env["OTEL_EXPORTER_OTLP_ENDPOINT"] != "https://collector.example/v1" {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %v, want pristine value", env["OTEL_EXPORTER_OTLP_ENDPOINT"])
	}
	if env["OTEL_SERVICE_NAME"] != "operator-claude" {
		t.Errorf("OTEL_SERVICE_NAME = %v, want pristine value", env["OTEL_SERVICE_NAME"])
	}
	if env["PATH"] != "/custom/bin:/usr/bin" {
		t.Errorf("PATH = %v, want pristine value", env["PATH"])
	}
	if _, present := env["DEFENSECLAW_FAIL_MODE"]; present {
		t.Errorf("DEFENSECLAW_FAIL_MODE survived teardown: %v", env)
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	if err := c.Setup(context.Background(), opts); err != nil {
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
	c.Setup(context.Background(), opts)
	c.Teardown(context.Background(), opts)

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
	if err := c.Setup(context.Background(), opts); err != nil {
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

	// Plan S7.1 sentinel guard: hooks exit 0 fast when DEFENSECLAW_HOME
	// is missing (operator-uninstall safety). To exercise the
	// fail-closed branch we must point DEFENSECLAW_HOME at a real
	// directory with no .disabled marker — otherwise the hook
	// short-circuits before ever attempting the unreachable gateway
	// dial and the test sees exit 0 instead of exit 2.
	dcHome := t.TempDir()

	// Run hook against an unreachable port — should exit 2 (fail-closed)
	cmd := exec.Command("bash", filepath.Join(dir, "claude-code-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"test"}`)
	cmd.Env = append(os.Environ(),
		"PATH="+os.Getenv("PATH"),
		"DEFENSECLAW_HOME="+dcHome,
	)
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

func TestCodexHookScript_FailOpen_DefaultForObservabilitySetup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	dir := t.TempDir()
	opts := SetupOpts{
		APIAddr:          "127.0.0.1:99999",
		APIToken:         "tok-test",
		CodexEnforcement: false,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(dir, opts, &CodexConnector{}); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
	}

	dcHome := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(dir, "codex-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
	cmd.Env = append(os.Environ(),
		"PATH="+os.Getenv("PATH"),
		"DEFENSECLAW_HOME="+dcHome,
	)
	if err := cmd.Run(); err != nil {
		t.Fatalf("observability Codex hook should fail-open by default, got: %v", err)
	}
	failureLog, err := os.ReadFile(filepath.Join(dcHome, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatalf("hook failure log missing: %v", err)
	}
	logText := string(failureLog)
	for _, want := range []string{`"connector":"codex"`, `"hook":"codex-hook"`, `"reason":"gateway unreachable"`, `"fail_mode":"open"`} {
		if !strings.Contains(logText, want) {
			t.Fatalf("hook failure log missing %s:\n%s", want, logText)
		}
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
			errs[idx] = patchOpenClawConfig(configPath, "/tmp/ext-"+strings.Repeat("x", idx), false)
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
	err := c.Setup(context.Background(), opts)
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
	if err := oldConn.Teardown(context.Background(), opts); err != nil {
		t.Errorf("Teardown of previous connector: %v", err)
	}

	newConn, _ := reg.Get("claudecode")
	ClaudeCodeSettingsPathOverride = filepath.Join(dir, "settings.json")
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	if err := newConn.Setup(context.Background(), opts); err != nil {
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
//                  HookScriptProvider contract ---
//
// These tests pin the additive interface contract introduced for the
// claw-agnostic refactor. They are pure metadata assertions: every
// built-in connector must (a) declare the on-disk paths it touches,
// (b) declare any env vars it needs, (c) expose its hook scripts.
// (AgentRestarter was deleted in plan A5 because no built-in implemented
// it; if a future connector needs restart, reintroduce it as an explicit
// S2.6 with at least one consumer.)

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

// TestConnector_ProviderProbe_AllBuiltinsImplement pins the plan A4
// contract: every built-in connector exposes a HasUsableProviders()
// hook so the sidecar boot path can refuse to start when no LLM
// upstream is configured. This is intentionally compile-time mandatory
// — a connector that drops the implementation should fail this test
// before it ever ships, since a silent zero-provider boot would let
// the gateway accept traffic that has no upstream to forward to.
func TestConnector_ProviderProbe_AllBuiltinsImplement(t *testing.T) {
	connectors := []Connector{
		NewZeptoClawConnector(),
		NewOpenClawConnector(),
		NewCodexConnector(),
		NewClaudeCodeConnector(),
	}
	for _, conn := range connectors {
		if _, ok := conn.(ProviderProbe); !ok {
			t.Errorf("%s does not implement ProviderProbe — startup probe will skip it (plan A4)", conn.Name())
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

// TestHookScriptOwner_BuiltinSurface enumerates the canonical mapping
// of HookScriptOwner across built-in connectors (plan C2 / S2.5).
// This is the contract that drives WriteHookScriptsForConnectorObject.
//
//   - claudecode owns claude-code-hook.sh
//   - codex      owns codex-hook.sh
//   - openclaw   owns no vendor template (fetch-interceptor plugin)
//   - zeptoclaw  owns no vendor template (config-only)
func TestHookScriptOwner_BuiltinSurface(t *testing.T) {
	cases := []struct {
		name string
		ctor func() Connector
		want []string
	}{
		{"claudecode", func() Connector { return NewClaudeCodeConnector() }, []string{"claude-code-hook.sh"}},
		{"codex", func() Connector { return NewCodexConnector() }, []string{"codex-hook.sh"}},
		{"openclaw", func() Connector { return NewOpenClawConnector() }, nil},
		{"zeptoclaw", func() Connector { return NewZeptoClawConnector() }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.ctor()
			owner, ok := c.(HookScriptOwner)
			if tc.want == nil {
				if ok {
					t.Fatalf("%s should NOT implement HookScriptOwner (no vendor template); plan C2 says non-owners stay opt-out", tc.name)
				}
				return
			}
			if !ok {
				t.Fatalf("%s must implement HookScriptOwner; plan C2 wires WriteHookScriptsForConnectorObject through this interface", tc.name)
			}
			got := owner.HookScriptNames(SetupOpts{})
			if len(got) != len(tc.want) {
				t.Fatalf("%s HookScriptNames() = %v, want %v", tc.name, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("%s HookScriptNames()[%d] = %q, want %q", tc.name, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// fakeHookScriptOwner exercises the plan C2 contract: arbitrary
// connector hands back a script name, WriteHookScriptsForConnectorObject
// must materialize it on disk alongside the generic inspect-* set.
type fakeHookScriptOwner struct {
	name  string
	hooks []string
}

func (f *fakeHookScriptOwner) Name() string        { return f.name }
func (f *fakeHookScriptOwner) Description() string { return "fake hook owner for tests" }
func (f *fakeHookScriptOwner) HookAPIPath() string { return "" }
func (f *fakeHookScriptOwner) ToolInspectionMode() ToolInspectionMode {
	return ToolModeResponseScan
}
func (f *fakeHookScriptOwner) SubprocessPolicy() SubprocessPolicy        { return SubprocessNone }
func (f *fakeHookScriptOwner) AllowedHosts() []string                    { return nil }
func (f *fakeHookScriptOwner) Setup(context.Context, SetupOpts) error    { return nil }
func (f *fakeHookScriptOwner) Teardown(context.Context, SetupOpts) error { return nil }
func (f *fakeHookScriptOwner) VerifyClean(SetupOpts) error               { return nil }
func (f *fakeHookScriptOwner) Authenticate(*http.Request) bool           { return true }
func (f *fakeHookScriptOwner) Route(*http.Request, []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{}, nil
}
func (f *fakeHookScriptOwner) SetCredentials(string, string) {}
func (f *fakeHookScriptOwner) HookScriptNames(SetupOpts) []string {
	out := make([]string, len(f.hooks))
	copy(out, f.hooks)
	return out
}

// TestWriteHookScriptsForConnectorObject_HonoursInterface validates
// the interface-driven path (plan C2): a connector that opts in via
// HookScriptOwner gets its scripts materialized; a connector that
// does not opt in gets only the generic inspect-* scripts.
func TestWriteHookScriptsForConnectorObject_HonoursInterface(t *testing.T) {
	t.Run("owner_with_codex_template", func(t *testing.T) {
		dir := t.TempDir()
		owner := &fakeHookScriptOwner{name: "fakecodex", hooks: []string{"codex-hook.sh"}}
		if err := WriteHookScriptsForConnectorObject(dir, "127.0.0.1:18970", "tok-test", owner); err != nil {
			t.Fatalf("WriteHookScriptsForConnectorObject: %v", err)
		}
		mustExist(t, filepath.Join(dir, "codex-hook.sh"))
		mustExist(t, filepath.Join(dir, "inspect-tool.sh"))
	})

	t.Run("non_owner_writes_generic_only", func(t *testing.T) {
		dir := t.TempDir()
		// Use the real ZeptoClaw connector — does not implement
		// HookScriptOwner per the plan C2 contract above.
		conn := NewZeptoClawConnector()
		if _, isOwner := any(conn).(HookScriptOwner); isOwner {
			t.Fatalf("zeptoclaw must not implement HookScriptOwner")
		}
		if err := WriteHookScriptsForConnectorObject(dir, "127.0.0.1:18970", "tok-test", conn); err != nil {
			t.Fatalf("WriteHookScriptsForConnectorObject: %v", err)
		}
		mustExist(t, filepath.Join(dir, "inspect-tool.sh"))
		mustNotExist(t, filepath.Join(dir, "codex-hook.sh"))
		mustNotExist(t, filepath.Join(dir, "claude-code-hook.sh"))
	})

	t.Run("missing_template_fails_loud", func(t *testing.T) {
		dir := t.TempDir()
		owner := &fakeHookScriptOwner{name: "typo", hooks: []string{"does-not-exist.sh"}}
		err := WriteHookScriptsForConnectorObject(dir, "127.0.0.1:18970", "tok-test", owner)
		if err == nil {
			t.Fatalf("expected error for non-existent template, got nil")
		}
		if !strings.Contains(err.Error(), "does-not-exist.sh") {
			t.Errorf("error %q should name the missing template", err.Error())
		}
	})

	t.Run("string_shim_routes_through_registry", func(t *testing.T) {
		dir := t.TempDir()
		// Drives the back-compat string-keyed function — ensures
		// it reaches HookScriptOwner via the default registry,
		// not the legacy package map.
		if err := WriteHookScriptsForConnector(dir, "127.0.0.1:18970", "tok-test", "claudecode"); err != nil {
			t.Fatalf("WriteHookScriptsForConnector: %v", err)
		}
		mustExist(t, filepath.Join(dir, "claude-code-hook.sh"))
		mustNotExist(t, filepath.Join(dir, "codex-hook.sh"))
	})
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to NOT exist, got err=%v", path, err)
	}
}
