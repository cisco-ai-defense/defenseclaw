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

//go:build !windows

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

// useCodex makes the environment's image a Codex build.
func useCodex(e *harnessEnv) {
	e.images.rec.HarnessVersion = "0.146.0"
	e.images.rec.HookContract = connector.ResolveSandboxHookContract("codex", "0.146.0").Contract.ContractID
	e.images.rec.NetworkBinaries = []image.Binary{{Name: "codex", Realpath: "/opt/defenseclaw-harness/codex/bin/codex"}}
}

// runFiles returns the in-sandbox target → host content of every read-only
// run mount of sandbox name.
func (e *harnessEnv) runFiles(name string) map[string][]byte {
	e.t.Helper()
	got, err := e.client.GetSandbox(context.Background(), name)
	must(e.t, err)
	docker, _ := got.Spec.Template.DriverConfig["docker"].(map[string]any)
	mounts, _ := docker["mounts"].([]any)
	out := map[string][]byte{}
	for _, raw := range mounts {
		mt := raw.(map[string]any)
		source, _ := mt["source"].(string)
		if !strings.HasPrefix(source, e.m.runConfigDir(name)) {
			continue
		}
		info, err := os.Stat(source)
		must(e.t, err)
		if mt["read_only"] != true || mt["type"] != "bind" || info.Mode().Perm() != 0o644 {
			e.t.Fatalf("run mount %v (mode %v) is not a read-only bind of a 0644 file", mt, info.Mode())
		}
		data, err := os.ReadFile(source)
		must(e.t, err)
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

func decodeTOML(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	must(t, toml.Unmarshal(data, &out))
	return out
}

// openMCPPack writes the open pack with mcp.project_servers: allow.
func openMCPPack(t *testing.T) string {
	t.Helper()
	pack, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "sandbox", "open", "pack.yaml"))
	must(t, err)
	custom := strings.Replace(strings.Replace(string(pack), "name: open", "name: open-mcp", 1), "project_servers: block", "project_servers: allow", 1)
	return writeFile(t, filepath.Join(t.TempDir(), "pack.yaml"), custom)
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
	e.m.opts.MCP = inv
	writeFile(t, filepath.Join(e.project, ".mcp.json"), `{"mcpServers":{"repo-tool":{"command":"./tool"},"zeta":{"url":"https://x"},"\u001b[31mred":{"command":"x"}}}`)
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-run", LLM: anthropicLLM, Env: map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:28921"}})
	files := e.runFiles("cc-run")
	if !slices.Equal(inv.calls, []string{"claudecode"}) || len(files) != 2 {
		t.Fatalf("inventory calls = %v, run files = %d", inv.calls, len(files))
	}
	dropIn := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])
	env := dropIn["env"].(map[string]any)
	_, pinned := env["ANTHROPIC_API_KEY"]
	_, safe := dropIn["permissions"]
	if env["ANTHROPIC_BASE_URL"] != "http://host.openshell.internal:28921" || env["CLAUDE_CODE_USE_BEDROCK"] != "" || pinned || safe ||
		dropIn["allowManagedMcpServersOnly"] != true {
		t.Fatalf("drop-in = %v; want the provider pinned, no credential placeholder, bypass allowed (yolo), managed MCP only", dropIn)
	}
	const wantAllowed = `[{"serverCommand":["npx","-y","@modelcontextprotocol/server-github"]},{"serverUrl":"https://mcp.linear.app/mcp"}]`
	if allowed, _ := json.Marshal(dropIn["allowedMcpServers"]); string(allowed) != wantAllowed {
		t.Fatalf("allowedMcpServers = %s", allowed)
	}
	managed := files[connector.ClaudeCodeSandboxManagedMCPPath]
	if servers := decodeJSON(t, managed)["mcpServers"].(map[string]any); len(servers) != 2 || servers["github"] == nil || servers["linear"] == nil {
		t.Fatalf("managed-mcp.json = %s", managed)
	}
	if strings.Contains(string(managed), "ghp-not-real") || strings.Contains(string(managed), "Bearer") {
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
	for _, want := range []string{"risky=blocked by DefenseClaw", "off=disabled", "(unprintable name)=not usable in a sandbox",
		"local-db=runs on this machine, which the sandbox cannot reach; run the sandbox with --host-port 5432 to bring it along"} {
		if !slices.Contains(left, want) {
			t.Fatalf("left behind = %v, missing %q", left, want)
		}
	}
	if notice := findWarning(sb.Warnings, "MCP: blocked the repository's servers"); !strings.Contains(notice, "repo-tool, zeta and 1 with an unprintable name") ||
		!strings.Contains(notice, "mcp.project_servers: allow") {
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
	if got := e.get("cc-run"); got.MCP == nil || !slices.Equal(got.MCP.Imported, sb.MCP.Imported) {
		t.Fatalf("stored summary = %+v", got.MCP)
	}
}

// --safe, and an administrator's allow_yolo: false, disable the bypass mode.
func TestRunConfigSafeModeDisablesBypass(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*config.Config)
		safe bool
	}{"--safe": {nil, true}, "allow_yolo false": {func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) }, false}} {
		e := newEnv(t, tc.edit)
		if sb := e.create(sandboxapi.CreateRequest{Name: "cc-safe", Safe: tc.safe}); sb.Yolo {
			t.Fatalf("%s: the run is yolo", name)
		}
		dropIn := decodeJSON(t, e.runFiles("cc-safe")[connector.ClaudeCodeSandboxRunDropInPath])
		if perms, _ := dropIn["permissions"].(map[string]any); perms["disableBypassPermissionsMode"] != "disable" || dropIn["skipDangerousModePermissionPrompt"] != false {
			t.Fatalf("%s: drop-in = %v", name, dropIn)
		}
	}
}

func TestRunConfigNoMCPStillLocksDown(t *testing.T) {
	e := newEnv(t, nil)
	inv := &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx"}}}
	e.m.opts.MCP = inv
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-nomcp", NoMCP: true})
	files := e.runFiles("cc-nomcp")
	managed := decodeJSON(t, files[connector.ClaudeCodeSandboxManagedMCPPath])["mcpServers"].(map[string]any)
	allowed := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])["allowedMcpServers"].([]any)
	if len(inv.calls) != 0 || len(managed) != 0 || len(allowed) != 0 || sb.MCP == nil || len(sb.MCP.Imported) != 0 {
		t.Fatalf("--no-mcp: inventory calls %v, managed %v, allowed %v, summary %+v", inv.calls, managed, allowed, sb.MCP)
	}
}

func TestRunConfigProjectServersAllow(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Pack = openMCPPack(t) })
	e.m.opts.MCP = &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx", Args: []string{"srv"}}}}
	writeFile(t, filepath.Join(e.project, ".mcp.json"), `{"mcpServers":{"repo-tool":{"command":"./tool"}}}`)
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-allow"})
	files := e.runFiles("cc-allow")
	_, exclusive := files[connector.ClaudeCodeSandboxManagedMCPPath]
	_, restricted := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])["allowedMcpServers"]
	if exclusive || restricted {
		t.Fatal("allow mode mounted the exclusive managed-mcp.json or restricted MCP servers")
	}
	if imported := decodeJSON(t, files[connector.ClaudeCodeSandboxRunMCPServersPath]); imported["mcpServers"].(map[string]any)["github"] == nil {
		t.Fatalf("imported servers = %v", imported)
	}
	if sb.MCP.ProjectServers != "allow" || findWarning(sb.Warnings, "MCP: the repository's servers repo-tool start without a DefenseClaw check") == "" {
		t.Fatalf("summary %+v, warnings %q", sb.MCP, sb.Warnings)
	}
}

// Codex's run files replace its managed configuration and requirements: the
// allowed MCP servers, the image's hooks, and the safe approval policies; a
// repository server that shadows an imported one is left behind.
func TestRunConfigCodexReplacesManagedFiles(t *testing.T) {
	e := newEnv(t, nil)
	useCodex(e)
	e.m.opts.MCP = &fakeMCP{entries: []config.MCPServerEntry{
		{Name: "github", Command: "npx", Args: []string{"srv"}}, {Name: "shadowed", Command: "srv"},
		{Name: "events", URL: "https://mcp.example.com/sse", Transport: "sse"},
	}}
	writeFile(t, filepath.Join(e.project, ".codex", "config.toml"), "[mcp_servers.shadowed]\ncommand = \"./evil\"\n\n[mcp_servers.repo]\ncommand = \"./repo\"\n")
	sb := e.create(sandboxapi.CreateRequest{Name: "cx-run", Harness: "codex", Safe: true})
	files := e.runFiles("cx-run")
	if len(files) != 2 || files[connector.CodexSandboxManagedConfigPath] == nil || files[connector.CodexSandboxRequirementsPath] == nil {
		t.Fatalf("codex run files = %d", len(files))
	}
	req, managed := decodeTOML(t, files[connector.CodexSandboxRequirementsPath]), decodeTOML(t, files[connector.CodexSandboxManagedConfigPath])
	if allow := req["mcp_servers"].(map[string]any); len(allow) != 1 || allow["github"] == nil || req["allow_managed_hooks_only"] != true || req["hooks"] == nil {
		t.Fatalf("requirements = %v; want github only and the image's hooks", req)
	}
	if policies, _ := req["allowed_approval_policies"].([]any); slices.Contains(policies, any("never")) || len(policies) == 0 {
		t.Fatalf("safe approval policies = %v", policies)
	}
	if gh, _ := managed["mcp_servers"].(map[string]any)["github"].(map[string]any); gh["cwd"] != sb.Workdir || gh["command"] != "npx" {
		t.Fatalf("managed github = %v", gh)
	}
	var left []string
	for _, l := range sb.MCP.LeftBehind {
		left = append(left, l.Name)
	}
	if !slices.Contains(left, "shadowed") || !slices.Contains(left, "events") || findWarning(sb.Warnings, "MCP: blocked the repository's servers repo, shadowed") == "" {
		t.Fatalf("left behind = %v, warnings %q", left, sb.Warnings)
	}
}

// A Codex run pins the profile's provider; Mantle does not serve Codex's own
// default model, so the run pins the profile's model too.
func TestRunConfigCodexPinsProfileProvider(t *testing.T) {
	e := newEnv(t, nil)
	useCodex(e)
	e.create(sandboxapi.CreateRequest{Name: "cx-openai", Harness: "codex",
		LLM: &sandboxapi.LLMCredential{Profile: profiles.OpenAIID, Credentials: map[string]string{"OPENAI_API_KEY": "sk-test"}}})
	if m := decodeTOML(t, e.runFiles("cx-openai")[connector.CodexSandboxManagedConfigPath]); m["model_provider"] != "openai" ||
		m["openai_base_url"] != "https://api.openai.com/v1" || m["model"] != nil {
		t.Fatalf("provider pin = %v", m)
	}
	e.create(sandboxapi.CreateRequest{Name: "cx-mantle", Harness: "codex", Project: e.otherProject("mantle"),
		LLM: &sandboxapi.LLMCredential{Profile: profiles.CodexBedrockMantleID, BedrockRegion: "eu-west-1",
			Credentials: map[string]string{"BEDROCK_MANTLE_API_KEY": "bedrock-test"}}})
	if m := decodeTOML(t, e.runFiles("cx-mantle")[connector.CodexSandboxManagedConfigPath]); m["model_provider"] != "mantle" || m["model"] != harness.CodexMantleDefaultModel {
		t.Fatalf("mantle pin = %v", m)
	}
}

func TestRunConfigFailuresAndCleanup(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.MCP = &fakeMCP{err: errors.New("inventory unavailable")}
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "cc-fail"})
	wantCode(t, err, sandboxapi.CodeInternal)
	if fileExists(e.m.runConfigDir("cc-fail")) {
		t.Fatal("run config left after a failed create")
	}
	e.m.opts.MCP = nil
	e.create(sandboxapi.CreateRequest{Name: "cc-del"})
	dir := e.m.runConfigDir("cc-del")
	if !fileExists(dir) {
		t.Fatal("no run config")
	}
	e.deleteBox("cc-del", sandboxapi.DeleteRequest{})
	if fileExists(dir) {
		t.Fatal("run config left after delete")
	}
}

// Servers come along without their environment or are left behind with the
// reason; a loopback server on an accepted host port comes via the host alias.
func TestImportMCPServers(t *testing.T) {
	servers, skipped, dropped := importMCPServers("codex", []config.MCPServerEntry{
		{Name: "a", Command: "npx", Transport: "stdio"}, {Name: "a", Command: "dup"},
		{Name: "b", URL: "https://example.com/mcp", Transport: "streamable-http"}, {Name: "c", URL: "https://example.com/sse", Transport: "sse"},
		{Name: "d", URL: "http://10.0.0.5/mcp"}, {Name: "e", URL: "http://[::1]:9/mcp"}, {Name: "f", Command: "x", Transport: "http"},
		{Name: "g"}, {Name: "h", URL: "https://user:pw@example.com/mcp"}, {Name: "i", Command: "srv", Env: map[string]string{"B": "2", "A": "1"}},
		{Name: "local", URL: "http://localhost:38830/mcp?x=1", Transport: "http"}, {Name: "loop", URL: "http://127.0.0.1:38831/mcp"},
		{Name: "tls", URL: "https://localhost:38830/mcp"}, {Name: "lan", URL: "http://10.0.0.5:38830/mcp"},
	}, nil, []int{38830})
	var names []string
	for _, s := range servers {
		names = append(names, s.Name)
		if len(s.Env) != 0 {
			t.Fatalf("%s kept its environment", s.Name)
		}
	}
	if !slices.Equal(names, []string{"a", "b", "i", "local"}) || servers[0].Command != "npx" || servers[1].Transport != "http" ||
		servers[3].URL != "http://host.openshell.internal:38830/mcp?x=1" {
		t.Fatalf("imported = %+v", servers)
	}
	if port, ok := hostPortOfMCP(servers[3].URL); !ok || port != 38830 {
		t.Fatalf("hostPortOfMCP = %d, %v", port, ok)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Name] = s.Reason
	}
	for name, reason := range map[string]string{
		"c": "Codex does not support SSE servers", "d": localMCPUnreachable, "lan": localMCPUnreachable,
		"e": "runs on this machine, which the sandbox cannot reach; run the sandbox with --host-port 9 to bring it along",
		"f": "unsupported transport http", "g": "no command or URL", "h": "not usable in a sandbox",
	} {
		if reasons[name] != reason {
			t.Fatalf("%s skipped for %q, want %q (all %v)", name, reasons[name], reason, reasons)
		}
	}
	if !strings.HasSuffix(reasons["loop"], "--host-port 38831 to bring it along") || !strings.Contains(reasons["tls"], "HTTPS") || !slices.Equal(dropped, []string{"i: A, B"}) {
		t.Fatalf("left behind = %v, dropped %v", reasons, dropped)
	}
}

// The banner says a localhost MCP server comes along over an accepted host
// port, and how it connects.
func TestCreateBringsLocalMCPOverAHostPort(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.MCP = &fakeMCP{entries: []config.MCPServerEntry{{Name: "r2g-local", URL: "http://localhost:38830/mcp", Transport: "http"}}}
	sb := e.create(sandboxapi.CreateRequest{Name: "mcphp", HostPorts: []int{38830}})
	if sb.MCP == nil || !slices.Contains(sb.MCP.Imported, "r2g-local") || len(sb.MCP.LeftBehind) != 0 ||
		!slices.ContainsFunc(sb.Warnings, func(w string) bool {
			return strings.Contains(w, "r2g-local reaches port 38830 on this machine as host.openshell.internal:38830")
		}) {
		t.Fatalf("mcp = %+v, warnings %q", sb.MCP, sb.Warnings)
	}
}

// A start renders the run files of the current policy: permission prompts
// back once skip-permissions is disallowed, and the MCP servers allowed now.
func TestStartRendersTheRunConfigOfTheCurrentPolicy(t *testing.T) {
	e := newEnv(t, nil)
	inv := &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx", Args: []string{"srv"}}, {Name: "linear", URL: "https://mcp.linear.app/mcp"}}}
	e.m.opts.MCP = inv
	sb := e.create(sandboxapi.CreateRequest{Name: "cc-restart", Yolo: true, LLM: anthropicLLM,
		Env: map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:28921"}})
	if _, safe := decodeJSON(t, e.runFiles(sb.Name)[connector.ClaudeCodeSandboxRunDropInPath])["permissions"]; !sb.Yolo || safe {
		t.Fatal("the run is not in skip-permissions mode")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	inv.entries = inv.entries[:1] // linear is blocked by the MCP policy now
	e.m.refreshEgress()
	const drift = "the sandbox policy no longer lets the harness skip its permission prompts"
	if got := e.get(sb.Name); findWarning(got.Warnings, drift) == "" {
		t.Fatalf("drift warnings = %q", got.Warnings)
	}
	e.stopBox(sb.Name)
	e.startBox(sb.Name, sandboxapi.StartRequest{})
	files := e.runFiles(sb.Name)
	dropIn := decodeJSON(t, files[connector.ClaudeCodeSandboxRunDropInPath])
	env := dropIn["env"].(map[string]any)
	_, pinned := env["ANTHROPIC_API_KEY"]
	if perms, _ := dropIn["permissions"].(map[string]any); perms["disableBypassPermissionsMode"] != "disable" ||
		env["ANTHROPIC_BASE_URL"] != "http://host.openshell.internal:28921" || pinned {
		t.Fatalf("the restarted sandbox's drop-in = %v", dropIn)
	}
	if servers := decodeJSON(t, files[connector.ClaudeCodeSandboxManagedMCPPath])["mcpServers"].(map[string]any); len(servers) != 1 || servers["github"] == nil {
		t.Fatalf("managed-mcp.json after the start = %v", servers)
	}
	if got := e.get(sb.Name); got.Yolo || !slices.Equal(got.MCP.Imported, []string{"github"}) || findWarning(got.Warnings, drift) != "" {
		t.Fatalf("after the start: yolo %v, mcp %+v, warnings %q", got.Yolo, got.MCP, got.Warnings)
	}
}

// A start whose policy now blocks the project's own MCP servers, which needs
// a managed file the sandbox does not mount, is refused instead of running
// with the servers allowed.
func TestStartRefusesARunConfigItsMountsCannotCarry(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Pack = openMCPPack(t) })
	if sb := e.create(sandboxapi.CreateRequest{Name: "cc-tighten"}); sb.MCP.ProjectServers != "allow" {
		t.Fatalf("mcp = %+v", sb.MCP)
	}
	e.stopBox("cc-tighten")
	e.setConfig(func(c *config.Config) { c.OpenShell.Pack = "" })
	_, err := e.m.Start(t.Context(), "cc-tighten", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodePolicyViolation)
}
