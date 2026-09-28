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

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fakeMCP is an MCPInventory.
type fakeMCP struct {
	entries []config.MCPServerEntry
	skipped []MCPSkip
	err     error
	calls   []string
}

func (f *fakeMCP) SandboxMCPServers(_ context.Context, harness string) ([]config.MCPServerEntry, []MCPSkip, error) {
	f.calls = append(f.calls, harness)
	return f.entries, f.skipped, f.err
}

func withMCP(e *harnessEnv, inv MCPInventory) {
	e.t.Helper()
	e.m.opts.MCP = inv
}

// runFiles returns the in-sandbox target → host content of every read-only
// run mount of sandbox name.
func (e *harnessEnv) runFiles(name string) map[string][]byte {
	e.t.Helper()
	got, err := e.client.GetSandbox(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	docker, _ := got.Spec.Template.DriverConfig["docker"].(map[string]any)
	mounts, _ := docker["mounts"].([]any)
	out := map[string][]byte{}
	for _, raw := range mounts {
		mt := raw.(map[string]any)
		source, _ := mt["source"].(string)
		if !strings.HasPrefix(source, e.m.runConfigDir(name)) {
			continue
		}
		if mt["read_only"] != true || mt["type"] != "bind" {
			e.t.Fatalf("run mount %v is not a read-only bind", mt)
		}
		data, err := os.ReadFile(source)
		if err != nil {
			e.t.Fatal(err)
		}
		info, _ := os.Stat(source)
		if info.Mode().Perm() != 0o644 {
			e.t.Fatalf("run file %s mode %v", source, info.Mode())
		}
		out[mt["target"].(string)] = data
	}
	return out
}

func decodeJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("%v in %s", err, data)
	}
	return out
}

func TestRunConfigClaudeCodePinsProviderAndLocksMCP(t *testing.T) {
	e := newEnv(t, nil)
	inv := &fakeMCP{
		entries: []config.MCPServerEntry{
			{Name: "github", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}, Env: map[string]string{"GITHUB_TOKEN": "ghp-not-real"}},
			{Name: "linear", URL: "https://mcp.linear.app/mcp", Transport: "http", Headers: map[string]string{"Authorization": "Bearer x"}},
			{Name: "local-db", URL: "http://localhost:5432/mcp"},
			{Name: "off", Command: "srv", Disabled: true},
			{Name: "codex_apps", URL: "https://example.com/bundled", Bundled: true},
			{Name: "bad name!", Command: "srv"},
		},
		skipped: []MCPSkip{{Name: "risky", Reason: "blocked by DefenseClaw"}},
	}
	withMCP(e, inv)
	if err := os.WriteFile(filepath.Join(e.project, ".mcp.json"),
		[]byte(`{"mcpServers":{"repo-tool":{"command":"./tool"},"zeta":{"url":"https://x"},"\u001b[31mred":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sb := e.create(sandboxapi.CreateRequest{
		Name: "cc-run",
		LLM:  &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test-secret"}},
		Env:  map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:28921"},
	})
	if !slices.Equal(inv.calls, []string{"claudecode"}) {
		t.Fatalf("inventory calls = %v", inv.calls)
	}
	files := e.runFiles("cc-run")
	if len(files) != 2 {
		t.Fatalf("run files = %v", keys(files))
	}
	dropIn := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])
	env := dropIn["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != "http://host.openshell.internal:28921" || env["CLAUDE_CODE_USE_BEDROCK"] != "" {
		t.Fatalf("provider pins = %v", env)
	}
	if _, pinned := env["ANTHROPIC_API_KEY"]; pinned {
		t.Fatal("a credential placeholder was pinned")
	}
	if _, safe := dropIn["permissions"]; safe {
		t.Fatal("a yolo run disabled bypassPermissions")
	}
	if dropIn["allowManagedMcpServersOnly"] != true {
		t.Fatalf("drop-in = %v", dropIn)
	}
	allowed, _ := json.Marshal(dropIn["allowedMcpServers"])
	if string(allowed) != `[{"serverCommand":["npx","-y","@modelcontextprotocol/server-github"]},{"serverUrl":"https://mcp.linear.app/mcp"}]` {
		t.Fatalf("allowedMcpServers = %s", allowed)
	}
	managed := decodeJSON(t, files[connector.ClaudeCodeSandboxManagedMCPPath])
	servers := managed["mcpServers"].(map[string]any)
	if len(servers) != 2 || servers["github"] == nil || servers["linear"] == nil {
		t.Fatalf("managed-mcp.json = %v", managed)
	}
	if strings.Contains(string(files[connector.ClaudeCodeSandboxManagedMCPPath]), "ghp-not-real") ||
		strings.Contains(string(files[connector.ClaudeCodeSandboxManagedMCPPath]), "Bearer") {
		t.Fatal("an MCP server secret entered the sandbox")
	}

	if sb.MCP == nil || !slices.Equal(sb.MCP.Imported, []string{"github", "linear"}) || sb.MCP.ProjectServers != "block" ||
		!slices.Equal(sb.MCP.Project, []string{"repo-tool", "zeta"}) {
		t.Fatalf("mcp summary = %+v", sb.MCP)
	}
	var left []string
	for _, l := range sb.MCP.LeftBehind {
		left = append(left, l.Name+"="+l.Reason)
	}
	for _, want := range []string{"risky=blocked by DefenseClaw", "off=disabled", "local-db=runs on this machine, which the sandbox cannot reach; run the sandbox with --host-port 5432 to bring it along", "(unprintable name)=not usable in a sandbox"} {
		if !slices.Contains(left, want) {
			t.Fatalf("left behind = %v, missing %q", left, want)
		}
	}
	notice := findWarning(sb.Warnings, "MCP: blocked the repository's servers")
	if notice != "MCP: blocked the repository's servers repo-tool, zeta and 1 with an unprintable name (mcp.project_servers: block; a sandbox pack with mcp.project_servers: allow runs them)" {
		t.Fatalf("notice = %q in %q", notice, sb.Warnings)
	}
	if n := findWarning(sb.Warnings, "MCP: github:"); !strings.Contains(n, "GITHUB_TOKEN") || !strings.Contains(findWarning(sb.Warnings, "MCP: "), "--credential") {
		t.Fatalf("dropped-secret notice = %q in %q", n, sb.Warnings)
	}
	for _, w := range sb.Warnings {
		if strings.ContainsAny(w, "\x1b\n") {
			t.Fatalf("a notice carries control characters: %q", w)
		}
	}
	// The summary is part of the stored record.
	got, err := e.m.Get(context.Background(), "cc-run")
	if err != nil || got.MCP == nil || !slices.Equal(got.MCP.Imported, sb.MCP.Imported) {
		t.Fatalf("stored summary = %+v, %v", got, err)
	}
}

func TestRunConfigSafeModeDisablesBypass(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-safe", Safe: true})
	if sb.Yolo {
		t.Fatal("--safe run is yolo")
	}
	dropIn := decodeJSON(t, e.runFiles("cc-safe")[connector.ClaudeCodeSandboxRunDropInPath])
	perms, _ := dropIn["permissions"].(map[string]any)
	if perms["disableBypassPermissionsMode"] != "disable" || dropIn["skipDangerousModePermissionPrompt"] != false {
		t.Fatalf("safe drop-in = %v", dropIn)
	}
	// Admin allow_yolo=false is safe mode too.
	e2 := newEnv(t, func(c *config.Config) { f := false; c.OpenShell.Admin.AllowYolo = &f })
	e2.create(sandboxapi.CreateRequest{Name: "cc-admin"})
	dropIn = decodeJSON(t, e2.runFiles("cc-admin")[connector.ClaudeCodeSandboxRunDropInPath])
	if perms, _ := dropIn["permissions"].(map[string]any); perms["disableBypassPermissionsMode"] != "disable" {
		t.Fatalf("admin allow_yolo=false drop-in = %v", dropIn)
	}
}

func TestRunConfigNoMCPStillLocksDown(t *testing.T) {
	e := newEnv(t, nil)
	inv := &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx"}}}
	withMCP(e, inv)
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-nomcp", NoMCP: true})
	if len(inv.calls) != 0 {
		t.Fatal("--no-mcp read the MCP inventory")
	}
	files := e.runFiles("cc-nomcp")
	if managed := decodeJSON(t, files[connector.ClaudeCodeSandboxManagedMCPPath]); len(managed["mcpServers"].(map[string]any)) != 0 {
		t.Fatalf("managed-mcp.json = %v", managed)
	}
	if dropIn := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath]); len(dropIn["allowedMcpServers"].([]any)) != 0 {
		t.Fatalf("drop-in = %v", dropIn)
	}
	if sb.MCP == nil || len(sb.MCP.Imported) != 0 {
		t.Fatalf("summary = %+v", sb.MCP)
	}
}

func TestRunConfigProjectServersAllow(t *testing.T) {
	pack, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "sandbox", "open", "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	custom := strings.Replace(strings.Replace(string(pack), "name: open", "name: open-mcp", 1), "project_servers: block", "project_servers: allow", 1)
	path := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Pack = path })
	withMCP(e, &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx", Args: []string{"srv"}}}})
	if err := os.WriteFile(filepath.Join(e.project, ".mcp.json"), []byte(`{"mcpServers":{"repo-tool":{"command":"./tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-allow"})
	files := e.runFiles("cc-allow")
	if _, exclusive := files[connector.ClaudeCodeSandboxManagedMCPPath]; exclusive {
		t.Fatal("allow mode mounted the exclusive managed-mcp.json")
	}
	dropIn := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])
	if _, restricted := dropIn["allowedMcpServers"]; restricted {
		t.Fatalf("allow mode restricted MCP servers: %v", dropIn)
	}
	imported := decodeJSON(t, files[connector.ClaudeCodeSandboxRunMCPServersPath])
	if imported["mcpServers"].(map[string]any)["github"] == nil {
		t.Fatalf("imported servers = %v", imported)
	}
	if sb.MCP.ProjectServers != "allow" || findWarning(sb.Warnings, "MCP: the repository's servers repo-tool start without a DefenseClaw check") == "" {
		t.Fatalf("summary %+v, warnings %q", sb.MCP, sb.Warnings)
	}
}

func TestRunConfigCodexReplacesManagedFiles(t *testing.T) {
	e := newEnv(t, nil)
	e.images.rec.HarnessVersion = "0.146.0"
	res := connector.ResolveSandboxHookContract("codex", "0.146.0")
	e.images.rec.HookContract = res.Contract.ContractID
	e.images.rec.NetworkBinaries = []image.Binary{{Name: "codex", Realpath: "/opt/defenseclaw-harness/codex/bin/codex"}}
	withMCP(e, &fakeMCP{entries: []config.MCPServerEntry{
		{Name: "github", Command: "npx", Args: []string{"srv"}},
		{Name: "shadowed", Command: "srv"},
		{Name: "events", URL: "https://mcp.example.com/sse", Transport: "sse"},
	}})
	if err := os.MkdirAll(filepath.Join(e.project, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.project, ".codex", "config.toml"),
		[]byte("[mcp_servers.shadowed]\ncommand = \"./evil\"\n\n[mcp_servers.repo]\ncommand = \"./repo\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb := e.create(sandboxapi.CreateRequest{Name: "cx-run", Harness: "codex", Safe: true})
	files := e.runFiles("cx-run")
	if len(files) != 2 || files[connector.CodexSandboxManagedConfigPath] == nil || files[connector.CodexSandboxRequirementsPath] == nil {
		t.Fatalf("codex run files = %v", keys(files))
	}
	var req, managed map[string]any
	if err := toml.Unmarshal(files[connector.CodexSandboxRequirementsPath], &req); err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal(files[connector.CodexSandboxManagedConfigPath], &managed); err != nil {
		t.Fatal(err)
	}
	allow := req["mcp_servers"].(map[string]any)
	if len(allow) != 1 || allow["github"] == nil {
		t.Fatalf("requirements mcp_servers = %v", allow)
	}
	if req["allow_managed_hooks_only"] != true || req["hooks"] == nil {
		t.Fatal("the run requirements lost the image's hooks")
	}
	if policies, _ := req["allowed_approval_policies"].([]any); slices.Contains(policies, any("never")) || len(policies) == 0 {
		t.Fatalf("safe approval policies = %v", policies)
	}
	defined := managed["mcp_servers"].(map[string]any)
	if gh, _ := defined["github"].(map[string]any); gh["cwd"] != sb.Workdir || gh["command"] != "npx" {
		t.Fatalf("managed github = %v", defined["github"])
	}
	var left []string
	for _, l := range sb.MCP.LeftBehind {
		left = append(left, l.Name)
	}
	if !slices.Contains(left, "shadowed") || !slices.Contains(left, "events") {
		t.Fatalf("left behind = %v", left)
	}
	if findWarning(sb.Warnings, "MCP: blocked the repository's servers repo, shadowed") == "" {
		t.Fatalf("warnings = %q", sb.Warnings)
	}
}

func TestRunConfigCodexPinsProfileProvider(t *testing.T) {
	e := newEnv(t, nil)
	e.images.rec.HarnessVersion = "0.146.0"
	e.images.rec.HookContract = connector.ResolveSandboxHookContract("codex", "0.146.0").Contract.ContractID
	e.images.rec.NetworkBinaries = []image.Binary{{Name: "codex", Realpath: "/opt/defenseclaw-harness/codex/bin/codex"}}
	e.create(sandboxapi.CreateRequest{
		Name: "cx-openai", Harness: "codex",
		LLM: &sandboxapi.LLMCredential{Profile: profiles.OpenAIID, Credentials: map[string]string{"OPENAI_API_KEY": "sk-test"}},
	})
	var managed map[string]any
	if err := toml.Unmarshal(e.runFiles("cx-openai")[connector.CodexSandboxManagedConfigPath], &managed); err != nil {
		t.Fatal(err)
	}
	if managed["model_provider"] != "openai" || managed["openai_base_url"] != "https://api.openai.com/v1" || managed["model"] != nil {
		t.Fatalf("provider pin = %v %v, model %v", managed["model_provider"], managed["openai_base_url"], managed["model"])
	}

	// Mantle does not serve Codex's own default model: the run pins the
	// profile's, so every Codex the sandbox starts without -m uses it.
	e.create(sandboxapi.CreateRequest{
		Name: "cx-mantle", Harness: "codex", Project: e.otherProject("mantle"),
		LLM: &sandboxapi.LLMCredential{Profile: profiles.CodexBedrockMantleID, BedrockRegion: "eu-west-1",
			Credentials: map[string]string{"BEDROCK_MANTLE_API_KEY": "bedrock-test"}},
	})
	managed = nil
	if err := toml.Unmarshal(e.runFiles("cx-mantle")[connector.CodexSandboxManagedConfigPath], &managed); err != nil {
		t.Fatal(err)
	}
	if managed["model_provider"] != "mantle" || managed["model"] != harness.CodexMantleDefaultModel {
		t.Fatalf("mantle pin = %v, model %v", managed["model_provider"], managed["model"])
	}
}

func TestRunConfigFailuresAndCleanup(t *testing.T) {
	e := newEnv(t, nil)
	withMCP(e, &fakeMCP{err: errors.New("inventory unavailable")})
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{Name: "cc-fail", Harness: "claudecode", Project: e.project})
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeInternal {
		t.Fatalf("create with a failing inventory = %v", err)
	}
	if _, err := os.Stat(e.m.runConfigDir("cc-fail")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run config left after a failed create: %v", err)
	}

	withMCP(e, nil)
	e.create(sandboxapi.CreateRequest{Name: "cc-del"})
	dir := e.m.runConfigDir("cc-del")
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Delete(context.Background(), "cc-del", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run config left after delete: %v", err)
	}

}

func TestImportMCPServers(t *testing.T) {
	servers, skipped, dropped := importMCPServers("codex", []config.MCPServerEntry{
		{Name: "a", Command: "npx", Transport: "stdio"},
		{Name: "a", Command: "dup"},
		{Name: "b", URL: "https://example.com/mcp", Transport: "streamable-http"},
		{Name: "c", URL: "https://example.com/sse", Transport: "sse"},
		{Name: "d", URL: "http://10.0.0.5/mcp"},
		{Name: "e", URL: "http://[::1]:9/mcp"},
		{Name: "f", Command: "x", Transport: "http"},
		{Name: "g"},
		{Name: "h", URL: "https://user:pw@example.com/mcp"},
		{Name: "i", Command: "srv", Env: map[string]string{"B": "2", "A": "1"}},
	}, nil, nil)
	var names []string
	for _, s := range servers {
		names = append(names, s.Name)
		if len(s.Env) != 0 {
			t.Fatalf("%s kept its environment", s.Name)
		}
	}
	if !slices.Equal(names, []string{"a", "b", "i"}) || servers[0].Command != "npx" || servers[1].Transport != "http" {
		t.Fatalf("imported = %+v", servers)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Name] = s.Reason
	}
	want := map[string]string{
		"c": "Codex does not support SSE servers", "d": "runs on this machine, which the sandbox cannot reach",
		"e": "runs on this machine, which the sandbox cannot reach; run the sandbox with --host-port 9 to bring it along", "f": "unsupported transport http",
		"g": "no command or URL", "h": "not usable in a sandbox",
	}
	for name, reason := range want {
		if reasons[name] != reason {
			t.Fatalf("%s skipped for %q, want %q (all %v)", name, reasons[name], reason, reasons)
		}
	}
	if !slices.Equal(dropped, []string{"i: A, B"}) {
		t.Fatalf("dropped = %v", dropped)
	}
}

func TestRunFileNameAndMounts(t *testing.T) {
	if got := runFileName("/etc/claude-code/managed-settings.d/60-defenseclaw-run.json"); got != "etc__claude-code__managed-settings.d__60-defenseclaw-run.json" {
		t.Fatalf("runFileName = %q", got)
	}
	driver := withRunConfigMounts(nil, []any{map[string]any{"target": "/x"}})
	if len(driver["docker"].(map[string]any)["mounts"].([]any)) != 1 {
		t.Fatalf("driver = %v", driver)
	}
	if withRunConfigMounts(nil, nil) != nil {
		t.Fatal("no mounts made a driver config")
	}
	if packs.MCPProjectServersBlock != "block" {
		t.Fatal("block constant changed")
	}
}

func findWarning(warnings []string, prefix string) string {
	for _, w := range warnings {
		if strings.HasPrefix(w, prefix) {
			return w
		}
	}
	return ""
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestStartRendersTheRunConfigOfTheCurrentPolicy pins that a sandbox
// created in skip-permissions mode starts again with its harness's
// permission prompts once the administrator disallows the mode, and with
// the MCP servers its policy brings along now: its run files are rendered
// again and rewritten in place before it starts.
func TestStartRendersTheRunConfigOfTheCurrentPolicy(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	inv := &fakeMCP{entries: []config.MCPServerEntry{
		{Name: "github", Command: "npx", Args: []string{"srv"}},
		{Name: "linear", URL: "https://mcp.linear.app/mcp"},
	}}
	withMCP(e, inv)
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-restart", Yolo: true,
		LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test-secret"}},
		Env: map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:28921"}})
	if !sb.Yolo {
		t.Fatal("the run is not in skip-permissions mode")
	}
	if _, safe := decodeJSON(t, e.runFiles(sb.Name)[connector.ClaudeCodeSandboxRunDropInPath])["permissions"]; safe {
		t.Fatal("a yolo run disabled bypassPermissions")
	}

	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	inv.entries = inv.entries[:1] // linear is blocked by the MCP policy now
	e.m.refreshEgress()
	got, err := e.m.Get(ctx, sb.Name)
	if err != nil || findWarning(got.Warnings, "the sandbox policy no longer lets the harness skip its permission prompts") == "" {
		t.Fatalf("drift warnings = %q, %v", got.Warnings, err)
	}
	if _, err := e.m.Stop(ctx, sb.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	files := e.runFiles(sb.Name)
	dropIn := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])
	if perms, _ := dropIn["permissions"].(map[string]any); perms["disableBypassPermissionsMode"] != "disable" {
		t.Fatalf("the restarted sandbox can still skip permissions: %v", dropIn)
	}
	env := dropIn["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != "http://host.openshell.internal:28921" {
		t.Fatalf("the provider pins changed: %v", env)
	}
	if _, pinned := env["ANTHROPIC_API_KEY"]; pinned {
		t.Fatal("a credential placeholder was pinned")
	}
	servers := decodeJSON(t, files[connector.ClaudeCodeSandboxManagedMCPPath])["mcpServers"].(map[string]any)
	if len(servers) != 1 || servers["github"] == nil {
		t.Fatalf("managed-mcp.json after the start = %v", servers)
	}
	got, _ = e.m.Get(ctx, sb.Name)
	if got.Yolo || !slices.Equal(got.MCP.Imported, []string{"github"}) ||
		findWarning(got.Warnings, "the sandbox policy no longer lets the harness skip") != "" {
		t.Fatalf("after the start: yolo %v, mcp %+v, warnings %q", got.Yolo, got.MCP, got.Warnings)
	}
}

// TestStartRefusesARunConfigItsMountsCannotCarry pins that a start whose
// policy now blocks the project's own MCP servers, which needs a managed
// file the sandbox does not mount, is refused instead of running with the
// servers allowed.
func TestStartRefusesARunConfigItsMountsCannotCarry(t *testing.T) {
	pack, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "sandbox", "open", "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	custom := strings.Replace(strings.Replace(string(pack), "name: open", "name: open-mcp", 1), "project_servers: block", "project_servers: allow", 1)
	path := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Pack = path })
	ctx := context.Background()
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-tighten"})
	if sb.MCP.ProjectServers != "allow" {
		t.Fatalf("mcp = %+v", sb.MCP)
	}
	if _, err := e.m.Stop(ctx, sb.Name); err != nil {
		t.Fatal(err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Pack = "" })
	_, err = e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodePolicyViolation)
}
