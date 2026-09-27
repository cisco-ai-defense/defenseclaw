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
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

var (
	claudeRunTarget = SandboxRenderTarget{IngressPort: 18971, AgentVersion: "2.1.156"}
	codexRunTarget  = SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.146.0"}
)

func runFileMap(t *testing.T, files []SandboxFile) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range files {
		if f.Mode != 0o644 || f.Owner != SandboxOwnerRoot {
			t.Fatalf("%s: mode %v owner %s", f.Path, f.Mode, f.Owner)
		}
		out[f.Path] = f.Data
	}
	return out
}

func TestClaudeCodeSandboxRunFiles(t *testing.T) {
	stdio := SandboxMCPServer{Name: "github", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}}
	remote := SandboxMCPServer{Name: "linear", URL: "https://mcp.linear.app/mcp", Transport: "sse"}
	cases := []struct {
		name      string
		run       SandboxRunConfig
		files     []string
		safe      bool
		allowlist string // JSON of allowedMcpServers; "" when unrestricted
	}{
		{
			name:      "yolo-block-none",
			run:       SandboxRunConfig{},
			files:     []string{ClaudeCodeSandboxManagedMCPPath, ClaudeCodeSandboxRunDropInPath},
			allowlist: `[]`,
		},
		{
			name:      "safe-block-servers",
			run:       SandboxRunConfig{Safe: true, MCPServers: []SandboxMCPServer{remote, stdio}},
			files:     []string{ClaudeCodeSandboxManagedMCPPath, ClaudeCodeSandboxRunDropInPath},
			safe:      true,
			allowlist: `[{"serverCommand":["npx","-y","@modelcontextprotocol/server-github"]},{"serverUrl":"https://mcp.linear.app/mcp"}]`,
		},
		{
			name:  "allow-servers",
			run:   SandboxRunConfig{AllowProjectMCPServers: true, MCPServers: []SandboxMCPServer{stdio}},
			files: []string{ClaudeCodeSandboxRunDropInPath, ClaudeCodeSandboxRunMCPServersPath},
		},
		{
			name:  "allow-none",
			run:   SandboxRunConfig{AllowProjectMCPServers: true},
			files: []string{ClaudeCodeSandboxRunDropInPath},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run.Env = map[string]string{"ANTHROPIC_BASE_URL": "https://bedrock-mantle.us-east-1.api.aws/anthropic", "MY_FLAG": "1"}
			tc.run.Credentials = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_CUSTOM_HEADERS"}
			files, err := NewClaudeCodeConnector().SandboxRunFiles(claudeRunTarget, tc.run)
			if err != nil {
				t.Fatal(err)
			}
			got := runFileMap(t, files)
			var paths []string
			for _, f := range files {
				paths = append(paths, f.Path)
			}
			if strings.Join(sortedStrings(paths), ",") != strings.Join(tc.files, ",") {
				t.Fatalf("files = %v, want %v", paths, tc.files)
			}
			if err := validateClaudeCodeRunSettingsSchema(got[ClaudeCodeSandboxRunDropInPath]); err != nil {
				t.Fatal(err)
			}
			var dropIn map[string]interface{}
			if err := json.Unmarshal(got[ClaudeCodeSandboxRunDropInPath], &dropIn); err != nil {
				t.Fatal(err)
			}
			env := dropIn["env"].(map[string]interface{})
			if env["ANTHROPIC_BASE_URL"] != "https://bedrock-mantle.us-east-1.api.aws/anthropic" || env["CLAUDE_CODE_USE_VERTEX"] != "" {
				t.Fatalf("env pins = %v", env)
			}
			if _, ok := env["ANTHROPIC_CUSTOM_HEADERS"]; ok {
				t.Fatal("a credential variable was pinned")
			}
			if _, ok := env["MY_FLAG"]; ok {
				t.Fatal("a non-provider variable was pinned")
			}
			if len(env) != len(claudeCodeSandboxProviderEnv)-1 {
				t.Fatalf("pinned %d provider variables", len(env))
			}
			perms, _ := dropIn["permissions"].(map[string]interface{})
			if tc.safe != (perms["disableBypassPermissionsMode"] == "disable") || tc.safe != (dropIn["skipDangerousModePermissionPrompt"] == false) {
				t.Fatalf("safe=%t drop-in = %v", tc.safe, dropIn)
			}
			allowed, present := dropIn["allowedMcpServers"]
			if tc.allowlist == "" {
				if present || dropIn["allowManagedMcpServersOnly"] != nil {
					t.Fatalf("unrestricted run has an allowlist: %v", dropIn)
				}
			} else {
				body, _ := json.Marshal(allowed)
				if string(body) != tc.allowlist || dropIn["allowManagedMcpServersOnly"] != true {
					t.Fatalf("allowlist = %s", body)
				}
			}
			for _, path := range []string{ClaudeCodeSandboxManagedMCPPath, ClaudeCodeSandboxRunMCPServersPath} {
				data, ok := got[path]
				if !ok {
					continue
				}
				var doc struct {
					MCPServers map[string]map[string]interface{} `json:"mcpServers"`
				}
				if err := json.Unmarshal(data, &doc); err != nil || doc.MCPServers == nil {
					t.Fatalf("%s = %s (%v)", path, data, err)
				}
				for _, s := range tc.run.MCPServers {
					entry := doc.MCPServers[s.Name]
					if s.Remote() && (entry["url"] != s.URL || entry["type"] != s.Transport) {
						t.Fatalf("%s: %s = %v", path, s.Name, entry)
					}
					if !s.Remote() && (entry["command"] != s.Command || entry["type"] != "stdio") {
						t.Fatalf("%s: %s = %v", path, s.Name, entry)
					}
				}
			}
		})
	}
}

func TestClaudeCodeSandboxRunFilesKeepImageControls(t *testing.T) {
	files, err := NewClaudeCodeConnector().SandboxRunFiles(claudeRunTarget, SandboxRunConfig{Safe: true})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := resolveSandboxTarget("claudecode", claudeRunTarget)
	if err != nil {
		t.Fatal(err)
	}
	base, err := renderClaudeCodeSandboxDropIn(rt)
	if err != nil {
		t.Fatal(err)
	}
	source, err := stageClaudeCodeManagedSettings(map[string][]byte{
		claudeCodeSandboxDropInName: base, claudeCodeSandboxRunDropInName: runFileMap(t, files)[ClaudeCodeSandboxRunDropInPath],
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyClaudeCodeSandboxManagedSource(source, rt); err != nil {
		t.Fatalf("merged managed tier: %v", err)
	}
	if source.settings["skipDangerousModePermissionPrompt"] != false {
		t.Fatal("safe mode kept the image's pre-accepted bypass prompt")
	}
	var baseDoc map[string]interface{}
	_ = json.Unmarshal(base, &baseDoc)
	merged, _ := json.Marshal(source.settings["hooks"])
	image, _ := json.Marshal(baseDoc["hooks"])
	if string(merged) != string(image) {
		t.Fatalf("the run drop-in changed the image's hooks:\n%s\n%s", merged, image)
	}
}

func TestClaudeCodeRunSettingsSchema(t *testing.T) {
	valid := `{"env":{"ANTHROPIC_BASE_URL":""},"permissions":{"disableBypassPermissionsMode":"disable"},` +
		`"skipDangerousModePermissionPrompt":false,"allowManagedMcpServersOnly":true,` +
		`"allowedMcpServers":[{"serverCommand":["npx"]},{"serverUrl":"https://x"},{"serverName":"gh_1-x"}]}`
	if err := validateClaudeCodeRunSettingsSchema([]byte(valid)); err != nil {
		t.Fatalf("valid document refused: %v", err)
	}
	// Each of these would make Claude Code 2.1.156 drop the whole file.
	for name, doc := range map[string]string{
		"string allowlist entry": `{"allowedMcpServers":["github"]}`,
		"two identities":         `{"allowedMcpServers":[{"serverName":"a","serverUrl":"https://x"}]}`,
		"empty entry":            `{"allowedMcpServers":[{}]}`,
		"empty command":          `{"allowedMcpServers":[{"serverCommand":[]}]}`,
		"command not strings":    `{"allowedMcpServers":[{"serverCommand":["npx",1]}]}`,
		"bad server name":        `{"allowedMcpServers":[{"serverName":"a b"}]}`,
		"unknown entry field":    `{"allowedMcpServers":[{"serverPath":"/x"}]}`,
		"string bool":            `{"allowManagedMcpServersOnly":"yes"}`,
		"bypass enable":          `{"permissions":{"disableBypassPermissionsMode":"enable"}}`,
		"other permission":       `{"permissions":{"defaultMode":"default"}}`,
		"env number":             `{"env":{"A":1}}`,
		"env not object":         `{"env":"A=1"}`,
		"statusLine string":      `{"statusLine":""}`,
		"unknown key":            `{"mcpServers":{}}`,
		"not an object":          `[]`,
	} {
		if err := validateClaudeCodeRunSettingsSchema([]byte(doc)); err == nil {
			t.Errorf("%s: accepted %s", name, doc)
		}
	}
}

func TestSandboxRunConfigRejectsBadInput(t *testing.T) {
	cc, cx := NewClaudeCodeConnector(), NewCodexConnector()
	for name, run := range map[string]SandboxRunConfig{
		"bad name":        {MCPServers: []SandboxMCPServer{{Name: "a/b", Command: "x"}}},
		"duplicate":       {MCPServers: []SandboxMCPServer{{Name: "a", Command: "x"}, {Name: "a", Command: "y"}}},
		"command and url": {MCPServers: []SandboxMCPServer{{Name: "a", Command: "x", URL: "https://x"}}},
		"neither":         {MCPServers: []SandboxMCPServer{{Name: "a"}}},
		"newline arg":     {MCPServers: []SandboxMCPServer{{Name: "a", Command: "x", Args: []string{"a\nb"}}}},
		"wildcard url":    {MCPServers: []SandboxMCPServer{{Name: "a", URL: "https://*.example.com/mcp"}}},
		"file url":        {MCPServers: []SandboxMCPServer{{Name: "a", URL: "file:///etc/passwd"}}},
		"url credentials": {MCPServers: []SandboxMCPServer{{Name: "a", URL: "https://u:p@example.com"}}},
		"remote env":      {MCPServers: []SandboxMCPServer{{Name: "a", URL: "https://example.com", Env: map[string]string{"A": "1"}}}},
		"bad env name":    {MCPServers: []SandboxMCPServer{{Name: "a", Command: "x", Env: map[string]string{"A-B": "1"}}}},
		"stdio transport": {MCPServers: []SandboxMCPServer{{Name: "a", Command: "x", Transport: "http"}}},
		"ws transport":    {MCPServers: []SandboxMCPServer{{Name: "a", URL: "https://example.com", Transport: "ws"}}},
	} {
		if _, err := cc.SandboxRunFiles(claudeRunTarget, run); err == nil {
			t.Errorf("claudecode %s: accepted", name)
		}
		if _, err := cx.SandboxRunFiles(codexRunTarget, run); err == nil {
			t.Errorf("codex %s: accepted", name)
		}
	}
	if _, err := cc.SandboxRunFiles(claudeRunTarget, SandboxRunConfig{Env: map[string]string{"ANTHROPIC_BASE_URL": "http://x\n"}}); err == nil {
		t.Error("a provider value with a line break was pinned")
	}
	if _, err := cc.SandboxRunFiles(SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.0.0"}, SandboxRunConfig{}); err == nil {
		t.Error("an unreviewed Claude Code version rendered run files")
	}
	if _, err := cx.SandboxRunFiles(codexRunTarget, SandboxRunConfig{MCPServers: []SandboxMCPServer{{Name: "a", URL: "https://x.example", Transport: "sse"}}}); err == nil {
		t.Error("codex accepted an SSE server")
	}
	for name, p := range map[string]*SandboxModelProvider{
		"bad id":          {ID: "a b", BaseURL: "https://x"},
		"openai extras":   {ID: SandboxModelProviderOpenAI, BaseURL: "https://x", EnvKey: "K"},
		"custom no name":  {ID: "m", BaseURL: "https://x", EnvKey: "K", WireAPI: "responses"},
		"custom bad wire": {ID: "m", Name: "m", BaseURL: "https://x", EnvKey: "K", WireAPI: "grpc"},
		"bad url":         {ID: "m", Name: "m", BaseURL: "ftp://x", EnvKey: "K", WireAPI: "responses"},
	} {
		if _, err := cx.SandboxRunFiles(codexRunTarget, SandboxRunConfig{ModelProvider: p}); err == nil {
			t.Errorf("codex provider %s: accepted", name)
		}
	}
}

func TestCodexSandboxRunFiles(t *testing.T) {
	stdio := SandboxMCPServer{Name: "github", Command: "npx", Args: []string{"-y", "srv"}, Env: map[string]string{"LOG": "1"}}
	remote := SandboxMCPServer{Name: "linear", URL: "https://mcp.linear.app/mcp"}
	mantle := &SandboxModelProvider{ID: "mantle", Name: "mantle", BaseURL: "https://bedrock-mantle.us-east-1.api.aws/v1", EnvKey: "BEDROCK_MANTLE_API_KEY", WireAPI: "responses"}
	for _, tc := range []struct {
		name string
		run  SandboxRunConfig
	}{
		{"block-none", SandboxRunConfig{}},
		{"safe-block-servers-openai", SandboxRunConfig{Safe: true, Workdir: "/work/app", MCPServers: []SandboxMCPServer{stdio, remote},
			ModelProvider: &SandboxModelProvider{ID: SandboxModelProviderOpenAI, BaseURL: "https://api.openai.com/v1"}}},
		{"allow-servers-mantle", SandboxRunConfig{AllowProjectMCPServers: true, MCPServers: []SandboxMCPServer{stdio}, ModelProvider: mantle}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, err := NewCodexConnector().SandboxRunFiles(codexRunTarget, tc.run)
			if err != nil {
				t.Fatal(err)
			}
			got := runFileMap(t, files)
			if len(got) != 2 {
				t.Fatalf("files = %v", got)
			}
			rt, _ := resolveSandboxTarget("codex", codexRunTarget)
			if err := verifyCodexSandboxPolicy(got[CodexSandboxRequirementsPath], got[CodexSandboxManagedConfigPath], rt, codexSandboxOtelEnvironment); err != nil {
				t.Fatalf("run files fail the image verifier: %v", err)
			}
			var req, managed map[string]interface{}
			if err := toml.Unmarshal(got[CodexSandboxRequirementsPath], &req); err != nil {
				t.Fatal(err)
			}
			if err := toml.Unmarshal(got[CodexSandboxManagedConfigPath], &managed); err != nil {
				t.Fatal(err)
			}
			policies, _ := req["allowed_approval_policies"].([]interface{})
			if tc.run.Safe != (len(policies) == 3) {
				t.Fatalf("approval policies = %v", policies)
			}
			for _, p := range policies {
				if p == "never" {
					t.Fatal("safe mode allows never")
				}
			}
			if modes, _ := req["allowed_sandbox_modes"].([]interface{}); tc.run.Safe && (len(modes) != 2 || modes[0] != "read-only") {
				t.Fatalf("sandbox modes = %v", modes)
			}
			allow, restricted := req["mcp_servers"].(map[string]interface{})
			if restricted == tc.run.AllowProjectMCPServers || (restricted && len(allow) != len(tc.run.MCPServers)) {
				t.Fatalf("mcp allowlist = %v (allow project %t)", req["mcp_servers"], tc.run.AllowProjectMCPServers)
			}
			if tc.name == "block-none" && !strings.Contains(string(got[CodexSandboxRequirementsPath]), "[mcp_servers]") {
				t.Fatalf("empty allowlist not rendered:\n%s", got[CodexSandboxRequirementsPath])
			}
			defined, _ := managed["mcp_servers"].(map[string]interface{})
			if len(defined) != len(tc.run.MCPServers) {
				t.Fatalf("defined servers = %v", defined)
			}
			if gh, ok := defined["github"].(map[string]interface{}); ok {
				if gh["command"] != "npx" || !reflect.DeepEqual(gh["env_vars"], []interface{}{}) || gh["env"].(map[string]interface{})["LOG"] != "1" {
					t.Fatalf("github = %v", gh)
				}
				if tc.run.Workdir != "" && gh["cwd"] != tc.run.Workdir {
					t.Fatalf("github cwd = %v", gh["cwd"])
				}
				if restricted {
					identity := allow["github"].(map[string]interface{})["identity"].(map[string]interface{})
					if !reflect.DeepEqual(identity, map[string]interface{}{"command": "npx"}) {
						t.Fatalf("identity = %v", identity)
					}
				}
			}
			switch p := tc.run.ModelProvider; {
			case p == nil:
				if managed["model_provider"] != nil {
					t.Fatal("pinned a provider without one")
				}
			case p.ID == SandboxModelProviderOpenAI:
				if managed["model_provider"] != "openai" || managed["openai_base_url"] != p.BaseURL || managed["model_providers"] != nil {
					t.Fatalf("openai pin = %v", managed)
				}
			default:
				table := managed["model_providers"].(map[string]interface{})[p.ID].(map[string]interface{})
				if managed["model_provider"] != p.ID || table["base_url"] != p.BaseURL || table["wire_api"] != "responses" {
					t.Fatalf("custom pin = %v", table)
				}
			}
		})
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
